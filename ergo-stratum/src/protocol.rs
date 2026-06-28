//! Kadia stratum wire protocol — the **EthereumStratum/1.0.0** dialect that real
//! Ergo Autolykos2 miners speak (verified against `gpu-mining-rs`).
//!
//! Newline-delimited JSON-RPC: `{"id","method","params"}` requests,
//! `{"id","result","error"}` responses, and `{"method","params"}` notifications.
//! This module is the pure (de)serialization + dispatch layer; it holds no session
//! state. [`parse_inbound`] turns a line into a typed [`Inbound`]; the builders
//! produce outbound frames.
//!
//! Dialect specifics (the param tuples, verified against the miner):
//! - `mining.subscribe` params `[agent, "EthereumStratum/1.0.0"]`; the response
//!   carries the connection's **extraNonce1** and **extraNonce2 size** at
//!   `result[1]`/`result[2]` (the miner partitions its nonce search from these).
//! - `mining.notify` params `[job_id, height, msg_hex, _, _, _, boundary, ntime,
//!   clean]` — the share **boundary** (target) sits at index 6, decimal-encoded.
//! - `mining.submit` params `[worker, job_id, extraNonce2, ntime, full_nonce]` —
//!   the full 8-byte nonce is at index 4 (we grade *that*; the extraNonce2 slice
//!   at index 2 is redundant given the full nonce).
//! - `mining.set_extranonce` re-keys the lane mid-session.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use num_bigint::BigUint;

use crate::job::Job;

/// The subprotocol id miners announce in `mining.subscribe` and we echo back.
pub const PROTOCOL_ID: &str = "EthereumStratum/1.0.0";

/// A JSON-RPC request from a miner.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Request {
    #[serde(default)]
    pub id: Option<u64>,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

/// A JSON-RPC response to a miner request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Response {
    pub id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<Value>,
}

/// A server-initiated notification (no response expected).
#[derive(Debug, Clone, PartialEq)]
pub struct Notification {
    pub method: String,
    pub params: Value,
}

impl Notification {
    fn to_value(&self) -> Value {
        json!({ "id": Value::Null, "method": self.method, "params": self.params })
    }
    /// Serialize to a single newline-terminated wire line.
    pub fn to_line(&self) -> String {
        format!("{}\n", self.to_value())
    }
}

impl Response {
    /// Serialize to a single newline-terminated wire line.
    pub fn to_line(&self) -> String {
        // Response always serializes cleanly; fall back to a literal error frame.
        serde_json::to_string(self)
            .map(|s| format!("{s}\n"))
            .unwrap_or_else(|_| "{\"id\":null,\"error\":\"serialize\"}\n".to_string())
    }
}

/// A typed, validated inbound message.
#[derive(Debug, Clone, PartialEq)]
pub enum Inbound {
    /// `mining.subscribe` — user-agent + announced subprotocol.
    Subscribe {
        id: Option<u64>,
        agent: Option<String>,
        protocol: Option<String>,
    },
    /// `mining.authorize` — worker name (+ optional password).
    Authorize {
        id: Option<u64>,
        worker: String,
        password: Option<String>,
    },
    /// `mining.submit` — worker, job id, optional ntime, and the full 8-byte nonce.
    Submit {
        id: Option<u64>,
        worker: String,
        job_id: u64,
        ntime: Option<String>,
        nonce: [u8; 8],
    },
    /// A recognised JSON-RPC frame with an unhandled method.
    Unknown { id: Option<u64>, method: String },
}

/// Why a line could not be turned into a typed [`Inbound`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProtocolError {
    /// The line was not valid JSON-RPC.
    #[error("malformed JSON-RPC: {0}")]
    Json(String),
    /// A known method carried params that don't match its schema.
    #[error("bad params for {0}")]
    BadParams(String),
}

/// Standard JSON-RPC-ish error codes for [`error_response`].
pub mod err {
    pub const UNAUTHORIZED: i64 = 24;
    pub const STALE: i64 = 21;
    pub const DUPLICATE: i64 = 22;
    pub const LOW_DIFFICULTY: i64 = 23;
    pub const BAD_PARAMS: i64 = 20;
}

/// Parse one wire line into a typed [`Inbound`]. Unknown methods are returned as
/// [`Inbound::Unknown`] (so the caller can answer with an error frame rather than
/// dropping the connection); malformed JSON or bad params for a known method are
/// surfaced as a [`ProtocolError`] — never silently swallowed.
pub fn parse_inbound(line: &str) -> Result<Inbound, ProtocolError> {
    let req: Request =
        serde_json::from_str(line.trim()).map_err(|e| ProtocolError::Json(e.to_string()))?;
    let id = req.id;
    match req.method.as_str() {
        "mining.subscribe" => Ok(Inbound::Subscribe {
            id,
            agent: str_param(&req.params, 0),
            protocol: str_param(&req.params, 1),
        }),
        "mining.authorize" => {
            let worker = str_param(&req.params, 0)
                .ok_or_else(|| ProtocolError::BadParams("mining.authorize".into()))?;
            Ok(Inbound::Authorize {
                id,
                worker,
                password: str_param(&req.params, 1),
            })
        }
        "mining.submit" => {
            let p = &req.params;
            let worker =
                str_param(p, 0).ok_or_else(|| ProtocolError::BadParams("mining.submit".into()))?;
            let job_id = p
                .get(1)
                .and_then(parse_job_id)
                .ok_or_else(|| ProtocolError::BadParams("mining.submit".into()))?;
            // The full 8-byte nonce is at index 4 (the extraNonce2 slice at index 2
            // is redundant). Grade the full nonce.
            let nonce = p
                .get(4)
                .and_then(Value::as_str)
                .and_then(parse_nonce8)
                .ok_or_else(|| ProtocolError::BadParams("mining.submit".into()))?;
            Ok(Inbound::Submit {
                id,
                worker,
                job_id,
                ntime: str_param(p, 3),
                nonce,
            })
        }
        other => Ok(Inbound::Unknown {
            id,
            method: other.to_string(),
        }),
    }
}

/// Fetch a string param at `idx`, if present and a string.
fn str_param(params: &Value, idx: usize) -> Option<String> {
    params.get(idx).and_then(Value::as_str).map(str::to_string)
}

/// Parse a job id given as a JSON number, a decimal string, or a `0x`-prefixed
/// hex string. We always emit decimal job ids, so decimal is the primary path;
/// only an explicit `0x` is treated as hex (no silent hex-vs-decimal guessing).
fn parse_job_id(v: &Value) -> Option<u64> {
    if let Some(n) = v.as_u64() {
        return Some(n);
    }
    let s = v.as_str()?;
    match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => s.parse().ok(),
    }
}

/// Parse a 16-hex-char (8-byte) nonce, tolerating a `0x` prefix.
fn parse_nonce8(s: &str) -> Option<[u8; 8]> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).ok()?;
    bytes.as_slice().try_into().ok()
}

// ----- outbound builders -----

/// `mining.subscribe` response. Advertises the connection's nonce lane: the
/// **extraNonce1** prefix (`result[1]`) and the **extraNonce2 byte size**
/// (`result[2]`) the miner searches under. `result[0]` is the NiceHash-style
/// subscription detail (the miner ignores it, but other clients read it as an
/// array).
pub fn subscribe_response(
    id: Option<u64>,
    session_id: u64,
    extra_nonce1: &str,
    extra_nonce2_bytes: usize,
) -> Response {
    Response {
        id,
        result: Some(json!([
            ["mining.notify", format!("{session_id:08x}"), PROTOCOL_ID],
            extra_nonce1,
            extra_nonce2_bytes,
        ])),
        error: None,
    }
}

/// A `result: true` acknowledgement (e.g. authorize/submit accepted).
pub fn ok_response(id: Option<u64>) -> Response {
    Response {
        id,
        result: Some(Value::Bool(true)),
        error: None,
    }
}

/// A `result: false` + `[code, message]` error frame.
pub fn error_response(id: Option<u64>, code: i64, message: &str) -> Response {
    Response {
        id,
        result: Some(Value::Bool(false)),
        error: Some(json!([code, message])),
    }
}

/// Encode a target as the `mining.notify` boundary string the miner expects.
///
/// Decimal is the standard Ergo stratum format. We clamp to the 256-bit hash
/// space (a target can't exceed it) and, in the practically-unreachable window
/// where the decimal is exactly 64 chars (which `gpu-mining-rs` would misread as a
/// hex target), fall back to an unambiguous `0x` hex form.
pub fn boundary_decimal(target: &BigUint) -> String {
    let max = (BigUint::from(1u8) << 256) - 1u8;
    let clamped = target.clone().min(max);
    let dec = clamped.to_str_radix(10);
    if dec.len() == 64 {
        format!("0x{}", clamped.to_str_radix(16))
    } else {
        dec
    }
}

/// `mining.notify` for a job at a given share `boundary` (the per-worker share
/// target = network target × vardiff factor): params
/// `[job_id, height, msg_hex, "", "", "", boundary, ntime, clean]`. Ergo has no
/// per-job ntime, so it is sent empty (the miner echoes it back verbatim).
pub fn notify(job: &Job, boundary: &BigUint) -> Notification {
    Notification {
        method: "mining.notify".to_string(),
        params: json!([
            job.id.to_string(),
            job.height,
            hex::encode(job.msg),
            "",
            "",
            "",
            boundary_decimal(boundary),
            "",
            job.clean,
        ]),
    }
}

/// `mining.set_extranonce` — re-key the connection's nonce lane mid-session.
pub fn set_extranonce(extra_nonce1: &str, extra_nonce2_bytes: usize) -> Notification {
    Notification {
        method: "mining.set_extranonce".to_string(),
        params: json!([extra_nonce1, extra_nonce2_bytes]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use ergo_crypto::difficulty::get_target;

    fn job() -> Job {
        Job {
            id: 42,
            msg: [0xAB; 32],
            height: 1_500_000,
            version: 3,
            target: get_target(0x1b00_ffff),
            clean: true,
        }
    }

    #[test]
    fn parse_subscribe_carries_agent_and_protocol() {
        let a = parse_inbound(
            r#"{"id":1,"method":"mining.subscribe","params":["gpu-mining-rs/0.1.0","EthereumStratum/1.0.0"]}"#,
        )
        .unwrap();
        assert_eq!(
            a,
            Inbound::Subscribe {
                id: Some(1),
                agent: Some("gpu-mining-rs/0.1.0".to_string()),
                protocol: Some("EthereumStratum/1.0.0".to_string()),
            }
        );
        // Bare subscribe (no params) is still accepted.
        let b = parse_inbound(r#"{"id":2,"method":"mining.subscribe","params":[]}"#).unwrap();
        assert_eq!(
            b,
            Inbound::Subscribe {
                id: Some(2),
                agent: None,
                protocol: None,
            }
        );
    }

    #[test]
    fn parse_authorize() {
        let i =
            parse_inbound(r#"{"id":3,"method":"mining.authorize","params":["wallet.rig1","x"]}"#)
                .unwrap();
        assert_eq!(
            i,
            Inbound::Authorize {
                id: Some(3),
                worker: "wallet.rig1".to_string(),
                password: Some("x".to_string())
            }
        );
    }

    #[test]
    fn parse_submit_takes_full_nonce_from_index_four() {
        // [worker, job_id, extraNonce2, ntime, full_nonce]
        let i = parse_inbound(
            r#"{"id":1000,"method":"mining.submit","params":["w.r1","7","0a0b0c0d","",
            "0102030405060708"]}"#,
        )
        .unwrap();
        assert_eq!(
            i,
            Inbound::Submit {
                id: Some(1000),
                worker: "w.r1".to_string(),
                job_id: 7,
                ntime: Some("".to_string()),
                nonce: [1, 2, 3, 4, 5, 6, 7, 8],
            }
        );
    }

    #[test]
    fn submit_job_id_decimal_is_not_misread_as_hex() {
        // "123" must be 123 (decimal), not 0x123 = 291 — the wire id is decimal.
        let i = parse_inbound(
            r#"{"id":1,"method":"mining.submit","params":["w","123","00","","0000000000000001"]}"#,
        )
        .unwrap();
        match i {
            Inbound::Submit { job_id, .. } => assert_eq!(job_id, 123),
            other => panic!("expected Submit, got {other:?}"),
        }
    }

    #[test]
    fn submit_with_bad_nonce_length_is_bad_params_not_silent() {
        let e =
            parse_inbound(r#"{"id":4,"method":"mining.submit","params":["w","7","00","","00"]}"#)
                .unwrap_err();
        assert_eq!(e, ProtocolError::BadParams("mining.submit".to_string()));
    }

    #[test]
    fn submit_missing_full_nonce_is_bad_params() {
        // Only four params (no index-4 nonce) must not silently succeed.
        let e = parse_inbound(r#"{"id":4,"method":"mining.submit","params":["w","7","00",""]}"#)
            .unwrap_err();
        assert_eq!(e, ProtocolError::BadParams("mining.submit".to_string()));
    }

    #[test]
    fn missing_authorize_worker_is_bad_params() {
        let e = parse_inbound(r#"{"id":4,"method":"mining.authorize","params":[]}"#).unwrap_err();
        assert_eq!(e, ProtocolError::BadParams("mining.authorize".to_string()));
    }

    #[test]
    fn malformed_json_is_an_error() {
        assert!(matches!(
            parse_inbound("not json"),
            Err(ProtocolError::Json(_))
        ));
    }

    #[test]
    fn unknown_method_round_trips_as_unknown() {
        let i = parse_inbound(r#"{"id":9,"method":"mining.hello","params":[]}"#).unwrap();
        assert_eq!(
            i,
            Inbound::Unknown {
                id: Some(9),
                method: "mining.hello".to_string()
            }
        );
    }

    #[test]
    fn notify_line_matches_the_ethereumstratum_layout() {
        // boundary = network target * factor; use a small synthetic target so the
        // decimal is short and exact.
        let boundary = BigUint::from(1_000_000u64);
        let line = notify(&job(), &boundary).to_line();
        assert!(line.ends_with('\n'));
        let v: Value = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(v["method"], "mining.notify");
        assert_eq!(v["params"][0], "42"); // job id (decimal)
        assert_eq!(v["params"][1], 1_500_000); // height
        assert_eq!(v["params"][2], hex::encode([0xAB; 32])); // msg
        assert_eq!(v["params"][6], "1000000"); // boundary (decimal)
        assert_eq!(v["params"][8], true); // clean
        assert_eq!(v["id"], Value::Null);
    }

    #[test]
    fn boundary_decimal_round_trips_through_base10() {
        // A realistic Ergo-scale share target encodes to decimal and parses back.
        let target = get_target(0x1b00_ffff) * BigUint::from(1024u64);
        let s = boundary_decimal(&target);
        assert_ne!(s.len(), 64, "must avoid the hex-ambiguous 64-char window");
        let back = BigUint::parse_bytes(s.as_bytes(), 10).unwrap();
        assert_eq!(back, target);
    }

    #[test]
    fn boundary_is_clamped_to_the_256_bit_space() {
        let over = BigUint::from(1u8) << 300; // > 2^256
        let s = boundary_decimal(&over);
        let max = (BigUint::from(1u8) << 256) - 1u8;
        assert_eq!(BigUint::parse_bytes(s.as_bytes(), 10).unwrap(), max);
    }

    #[test]
    fn error_and_ok_responses_serialize() {
        let ok = ok_response(Some(1)).to_line();
        let okv: Value = serde_json::from_str(ok.trim()).unwrap();
        assert_eq!(okv["result"], true);
        assert!(okv.get("error").is_none(), "ok frame omits error");

        let er = error_response(Some(2), err::DUPLICATE, "duplicate share").to_line();
        let erv: Value = serde_json::from_str(er.trim()).unwrap();
        assert_eq!(erv["result"], false);
        assert_eq!(erv["error"][0], err::DUPLICATE);
        assert_eq!(erv["error"][1], "duplicate share");
    }

    #[test]
    fn subscribe_response_advertises_the_nonce_lane() {
        let v: Value = serde_json::from_str(
            subscribe_response(Some(1), 0xDEADBEEF, "deadbeef", 4)
                .to_line()
                .trim(),
        )
        .unwrap();
        // result[0] is the subscription detail array (miner ignores it).
        assert_eq!(v["result"][0][0], "mining.notify");
        assert_eq!(v["result"][0][2], PROTOCOL_ID);
        // result[1]/result[2] are what the miner reads for nonce partitioning.
        assert_eq!(v["result"][1], "deadbeef");
        assert_eq!(v["result"][2], 4);
    }

    #[test]
    fn set_extranonce_carries_prefix_and_size() {
        let v: Value =
            serde_json::from_str(set_extranonce("01020304", 4).to_line().trim()).unwrap();
        assert_eq!(v["method"], "mining.set_extranonce");
        assert_eq!(v["params"][0], "01020304");
        assert_eq!(v["params"][1], 4);
    }
}
