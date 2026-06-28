//! Minimal async Ergo-node client for the mining endpoints the daemon needs:
//! `GET /mining/candidate` (work) and `POST /mining/solution` (block submit).
//!
//! The candidate's target `b` is a ~256-bit integer that overflows `u64`; default
//! `serde_json` would parse it lossily into an `f64`. We sidestep that without the
//! global `arbitrary_precision` switch by deserializing each field as a
//! [`RawValue`] and reading its exact source text, so `b` round-trips to a
//! [`BigUint`] byte-for-byte (oracle parity with the node's own number).

use std::collections::BTreeMap;

use num_bigint::BigUint;
use serde_json::value::RawValue;

/// A parsed mining candidate: the work a miner solves.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Candidate {
    /// 32-byte header message to solve.
    pub msg: [u8; 32],
    /// Network target `b` (a real block needs `hit <= target`).
    pub target: BigUint,
    /// Candidate height (sets the Autolykos2 table size N).
    pub height: u32,
    /// Miner public key the node expects (informational; the solution carries
    /// only the nonce).
    pub pk: Option<String>,
}

/// What can go wrong talking to the node.
#[derive(Debug, thiserror::Error)]
pub enum NodeError {
    #[error("HTTP transport error: {0}")]
    Http(String),
    #[error("node returned {status}: {body}")]
    Status { status: u16, body: String },
    #[error("malformed candidate: {0}")]
    Parse(String),
}

/// Parse a `/mining/candidate` response body into a [`Candidate`].
///
/// Pure and offline-testable. Keys are matched case-insensitively (the node sends
/// lowercase `msg`/`b`/`h`/`pk`; some forks vary the case). The exact integer
/// digits of `b` and `h` are preserved via [`RawValue`].
pub fn parse_candidate(body: &str) -> Result<Candidate, NodeError> {
    let map: BTreeMap<String, Box<RawValue>> =
        serde_json::from_str(body).map_err(|e| NodeError::Parse(e.to_string()))?;

    let raw = |names: &[&str]| -> Option<&str> {
        map.iter()
            .find(|(k, _)| names.iter().any(|n| k.eq_ignore_ascii_case(n)))
            .map(|(_, v)| v.get())
    };

    let msg_hex = raw(&["msg"]).ok_or_else(|| NodeError::Parse("missing msg".into()))?;
    let b_raw = raw(&["b"]).ok_or_else(|| NodeError::Parse("missing b".into()))?;
    let h_raw = raw(&["h", "height"]).ok_or_else(|| NodeError::Parse("missing h".into()))?;

    let msg = decode_msg(unquote(msg_hex))?;
    let target = BigUint::parse_bytes(unquote(b_raw).as_bytes(), 10)
        .ok_or_else(|| NodeError::Parse(format!("b not a base-10 integer: {b_raw}")))?;
    let height: u32 = unquote(h_raw)
        .parse()
        .map_err(|_| NodeError::Parse(format!("h not a u32: {h_raw}")))?;

    Ok(Candidate {
        msg,
        target,
        height,
        // A JSON `null` pk reads back as the literal "null" via RawValue; treat it
        // (and an absent pk) as None rather than Some("null").
        pk: raw(&["pk"])
            .map(unquote)
            .filter(|s| *s != "null")
            .map(str::to_string),
    })
}

/// Strip a single pair of surrounding JSON double-quotes, if present. Candidate
/// fields are plain hex / integers, so no escape handling is needed.
fn unquote(raw: &str) -> &str {
    let t = raw.trim();
    t.strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(t)
}

fn decode_msg(hex_str: &str) -> Result<[u8; 32], NodeError> {
    let bytes = hex::decode(hex_str).map_err(|e| NodeError::Parse(format!("msg hex: {e}")))?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| NodeError::Parse(format!("msg is {} bytes, want 32", bytes.len())))
}

/// Async client for the node mining HTTP endpoints.
pub struct NodeClient {
    http: reqwest::Client,
    candidate_url: String,
    solution_url: String,
    api_key: Option<String>,
}

impl NodeClient {
    /// New client against `base_url` (e.g. `http://127.0.0.1:9052`) with an
    /// optional `api_key`.
    pub fn new(base_url: &str, api_key: Option<String>) -> Self {
        let base = base_url.trim_end_matches('/');
        Self {
            // Timeouts so a hung/slow node can't park the candidate poller or the
            // share consumer forever.
            http: reqwest::Client::builder()
                .connect_timeout(std::time::Duration::from_secs(10))
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .expect("reqwest client builds"),
            candidate_url: format!("{base}/mining/candidate"),
            solution_url: format!("{base}/mining/solution"),
            api_key,
        }
    }

    fn auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.api_key {
            Some(k) => req.header("api_key", k),
            None => req,
        }
    }

    /// Fetch the current mining candidate.
    pub async fn candidate(&self) -> Result<Candidate, NodeError> {
        let resp = self
            .auth(self.http.get(&self.candidate_url))
            .send()
            .await
            .map_err(|e| NodeError::Http(e.to_string()))?;
        let status = resp.status();
        let body = resp
            .text()
            .await
            .map_err(|e| NodeError::Http(e.to_string()))?;
        if !status.is_success() {
            return Err(NodeError::Status {
                status: status.as_u16(),
                body: body_snippet(&body),
            });
        }
        parse_candidate(&body)
    }

    /// Submit a found block: the node `/mining/solution` takes just the nonce as
    /// big-endian hex (`{"n": "..."}`) and reconstructs the rest.
    pub async fn submit_solution(&self, nonce: &[u8; 8]) -> Result<(), NodeError> {
        let payload = serde_json::json!({ "n": hex::encode(nonce) });
        let resp = self
            .auth(self.http.post(&self.solution_url).json(&payload))
            .send()
            .await
            .map_err(|e| NodeError::Http(e.to_string()))?;
        let status = resp.status();
        if status.is_success() {
            return Ok(());
        }
        let body = resp.text().await.unwrap_or_default();
        Err(NodeError::Status {
            status: status.as_u16(),
            body: body_snippet(&body),
        })
    }
}

/// Trim + length-cap a node error body for logging (the node explains refusals in
/// the body, which a bare status code would drop).
fn body_snippet(body: &str) -> String {
    const MAX: usize = 300;
    let t = body.trim();
    if t.is_empty() {
        return "<empty body>".to_string();
    }
    let mut s: String = t.chars().take(MAX).collect();
    if t.chars().nth(MAX).is_some() {
        s.push('…');
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_candidate_with_large_numeric_boundary() {
        // The node sends `b` as a bare JSON number that exceeds u64 on mainnet;
        // it must parse exactly (no f64 scientific-notation loss).
        let boundary = "28948022309329048855892746252171976963209391069768726095651290785380";
        let body = format!(
            r#"{{"msg":"0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20","b":{boundary},"pk":"03deadbeef","h":1415098}}"#
        );
        let c = parse_candidate(&body).expect("candidate with 256-bit b must parse");
        assert_eq!(c.height, 1_415_098);
        assert_eq!(
            c.target,
            BigUint::parse_bytes(boundary.as_bytes(), 10).unwrap()
        );
        assert_eq!(c.msg[0], 0x01);
        assert_eq!(c.msg[31], 0x20);
        assert_eq!(c.pk.as_deref(), Some("03deadbeef"));
    }

    #[test]
    fn parses_candidate_with_string_fields_and_ci_keys() {
        let body = r#"{"MSG":"0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20","B":"12345678","HEIGHT":"900000"}"#;
        let c = parse_candidate(body).expect("case-insensitive candidate must parse");
        assert_eq!(c.height, 900_000);
        assert_eq!(c.target, BigUint::from(12_345_678u64));
        assert!(c.pk.is_none());
    }

    #[test]
    fn json_null_pk_is_none_not_the_literal_null() {
        let body = r#"{"msg":"0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20","b":5,"h":1,"pk":null}"#;
        let c = parse_candidate(body).expect("null pk must parse");
        assert!(c.pk.is_none(), "null pk must be None, got {:?}", c.pk);
    }

    #[test]
    fn missing_required_field_is_a_parse_error() {
        let body = r#"{"msg":"00","b":5}"#; // no height
        assert!(matches!(parse_candidate(body), Err(NodeError::Parse(_))));
    }

    #[test]
    fn wrong_length_msg_is_rejected() {
        let body = r#"{"msg":"0102","b":5,"h":1}"#;
        assert!(matches!(parse_candidate(body), Err(NodeError::Parse(_))));
    }

    #[test]
    fn body_snippet_passes_through_and_caps() {
        assert_eq!(body_snippet("  "), "<empty body>");
        assert_eq!(body_snippet(r#" {"error":"x"} "#), r#"{"error":"x"}"#);
        let long = "a".repeat(400);
        assert!(body_snippet(&long).ends_with('…'));
    }
}
