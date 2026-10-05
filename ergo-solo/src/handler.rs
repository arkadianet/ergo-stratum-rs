//! Pure per-connection protocol driver: one inbound wire line in, a [`LineResult`]
//! (reply frames + side effects) out. The async server ([`crate::server`]) owns
//! the socket and clock and simply pumps lines through here, so all of the
//! parse → dispatch → grade logic is deterministic and unit-testable without a
//! network.

use ergo_stratum::protocol::{
    err, error_response, ok_response, parse_inbound, peek_id, subscribe_response, Inbound,
    ProtocolError,
};
use ergo_stratum::session::{RejectReason, SubmitOutcome};
use ergo_stratum::Session;

/// Longest worker name accepted in `mining.authorize`.
pub const MAX_WORKER_LEN: usize = 128;

/// Per-connection context the driver needs besides the session itself.
#[derive(Clone, Debug, Default)]
pub struct LineCtx {
    /// Seeds the subscribe response's subscription id.
    pub session_id: u64,
    /// If set, `mining.authorize` must carry exactly this password.
    pub password: Option<String>,
}

/// A validated block-winning nonce, to be POSTed to the node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FoundBlock {
    /// The authorized worker that found it.
    pub worker: String,
    /// Height of the template it solves.
    pub height: u32,
    pub nonce: [u8; 8],
}

/// What handling one line produced.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LineResult {
    /// Newline-terminated frames to write back to the miner.
    pub replies: Vec<String>,
    /// Set when the line was a block-winning submission. The server must hand
    /// this to the block submitter BEFORE writing any reply — a socket error on
    /// the reply must never cost a block.
    pub block: Option<FoundBlock>,
    /// The grading outcome, when the line was a well-formed `mining.submit`.
    pub outcome: Option<SubmitOutcome>,
    /// The line was a `mining.submit` (exempt from the control-message limiter).
    pub is_submit: bool,
    /// The line was malformed or an invalid submission (counts toward the
    /// connection's invalid-share budget). Stale shares are not invalid.
    pub invalid: bool,
    /// True right after a successful `mining.authorize` — the server should push
    /// the current job to this freshly-authorized connection.
    pub just_authorized: bool,
    /// `mining.authorize` was refused; the server should close the connection.
    pub auth_failed: bool,
}

/// Drive one inbound `line` through `session` at monotonic time `now_secs`.
pub fn handle_line(session: &mut Session, ctx: &LineCtx, line: &str, now_secs: f64) -> LineResult {
    let inbound = match parse_inbound(line) {
        Ok(i) => i,
        Err(e) => {
            return LineResult {
                replies: vec![parse_error_frame(&e, line)],
                invalid: true,
                is_submit: matches!(&e, ProtocolError::BadParams(m) if m == "mining.submit"),
                ..LineResult::default()
            }
        }
    };

    match inbound {
        Inbound::Subscribe { id, agent, .. } => {
            session.subscribe();
            if let Some(agent) = agent {
                session.set_agent(&agent);
            }
            let ex = session.extra_nonce();
            reply(
                subscribe_response(
                    id,
                    ctx.session_id,
                    &ex.prefix_hex(),
                    ex.extra_nonce2_bytes(),
                )
                .to_line(),
            )
        }
        Inbound::ExtranonceSubscribe { id } => reply(ok_response(id).to_line()),
        Inbound::Authorize {
            id,
            worker,
            password,
        } => {
            let password_ok = match &ctx.password {
                Some(want) => password.as_deref() == Some(want.as_str()),
                None => true,
            };
            if password_ok && valid_worker_name(&worker) && session.authorize(&worker) {
                LineResult {
                    replies: vec![ok_response(id).to_line()],
                    just_authorized: true,
                    ..LineResult::default()
                }
            } else {
                LineResult {
                    replies: vec![
                        error_response(id, err::UNAUTHORIZED, "authorize failed").to_line()
                    ],
                    auth_failed: true,
                    ..LineResult::default()
                }
            }
        }
        Inbound::Submit {
            id, job_id, nonce, ..
        } => {
            let outcome = session.submit(job_id, nonce, now_secs);
            // Credit the authorized worker (authoritative), not the submit param.
            let worker = session.worker().unwrap_or_default().to_string();
            let mut result = LineResult {
                outcome: Some(outcome),
                is_submit: true,
                ..LineResult::default()
            };
            match outcome {
                SubmitOutcome::Accepted { .. } => {
                    result.replies.push(ok_response(id).to_line());
                }
                SubmitOutcome::Block { height, .. } => {
                    result.block = Some(FoundBlock {
                        worker,
                        height,
                        nonce,
                    });
                    result.replies.push(ok_response(id).to_line());
                }
                SubmitOutcome::Rejected(reason) => {
                    let (code, msg) = reject_frame(reason);
                    result.invalid = reason != RejectReason::StaleJob;
                    result.replies.push(error_response(id, code, msg).to_line());
                }
            }
            result
        }
        Inbound::Unknown { id, method } => reply(
            error_response(id, err::BAD_PARAMS, &format!("unknown method {method}")).to_line(),
        ),
    }
}

/// Worker names end up in logs and stats: printable ASCII only, bounded length.
fn valid_worker_name(worker: &str) -> bool {
    !worker.is_empty()
        && worker.len() <= MAX_WORKER_LEN
        && worker.bytes().all(|b| b.is_ascii_graphic())
}

fn reply(line: String) -> LineResult {
    LineResult {
        replies: vec![line],
        ..LineResult::default()
    }
}

fn parse_error_frame(e: &ProtocolError, line: &str) -> String {
    let msg = match e {
        ProtocolError::Json(_) => "malformed JSON-RPC".to_string(),
        ProtocolError::BadParams(m) => format!("bad params for {m}"),
    };
    // Answer the request the miner is waiting on, if its id is recoverable.
    error_response(peek_id(line), err::BAD_PARAMS, &msg).to_line()
}

fn reject_frame(reason: RejectReason) -> (i64, &'static str) {
    match reason {
        RejectReason::NotAuthorized => (err::UNAUTHORIZED, "not authorized"),
        RejectReason::StaleJob => (err::STALE, "stale job"),
        RejectReason::WrongLane => (err::BAD_PARAMS, "nonce outside assigned lane"),
        RejectReason::DuplicateShare => (err::DUPLICATE, "duplicate share"),
        RejectReason::BelowTarget => (err::LOW_DIFFICULTY, "share below target"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use num_bigint::BigUint;
    use serde_json::{json, Value};

    use ergo_stratum::{ExtraNonce, Job, VarDiff};

    fn session() -> Session {
        Session::new(ExtraNonce::whole(), VarDiff::new(1000, 10.0, 1, 100_000))
    }

    fn ctx() -> LineCtx {
        LineCtx {
            session_id: 1,
            password: None,
        }
    }

    // A target of 1 is so hard that any real Autolykos2 hit (a ~256-bit value)
    // exceeds it, so an arbitrary nonce deterministically classifies BelowTarget —
    // no need to forge a winning solution.
    fn hard_job() -> Job {
        Job {
            id: 1,
            msg: [0u8; 32],
            height: 1_786_189,
            version: 3,
            target: BigUint::from(1u64),
        }
    }

    // A target of 2^256 is met by EVERY hit, so any nonce is a block.
    fn always_block_job() -> Job {
        Job {
            target: BigUint::from(1u8) << 256,
            ..hard_job()
        }
    }

    fn parse_reply(r: &LineResult) -> Value {
        assert_eq!(r.replies.len(), 1, "expected one reply");
        serde_json::from_str(r.replies[0].trim()).unwrap()
    }

    fn handshake(s: &mut Session) {
        handle_line(
            s,
            &ctx(),
            r#"{"id":1,"method":"mining.subscribe","params":[]}"#,
            0.0,
        );
        let auth = handle_line(
            s,
            &ctx(),
            r#"{"id":2,"method":"mining.authorize","params":["wallet.rig"]}"#,
            0.0,
        );
        assert!(auth.just_authorized);
    }

    #[test]
    fn subscribe_then_authorize_then_handshake_flags() {
        let mut s = session();
        let c = LineCtx {
            session_id: 0xABCD,
            password: None,
        };
        let sub = handle_line(
            &mut s,
            &c,
            r#"{"id":1,"method":"mining.subscribe","params":["gpu-mining-rs/0.1.0","EthereumStratum/1.0.0"]}"#,
            0.0,
        );
        let v = parse_reply(&sub);
        // Whole-space lane: empty extranonce1, 8-byte extranonce2.
        assert_eq!(v["result"][1], "");
        assert_eq!(v["result"][2], 8);
        assert!(!sub.just_authorized);

        let auth = handle_line(
            &mut s,
            &c,
            r#"{"id":2,"method":"mining.authorize","params":["wallet.rig","x"]}"#,
            0.0,
        );
        assert_eq!(parse_reply(&auth)["result"], true);
        assert!(auth.just_authorized, "server must push a job after auth");
    }

    #[test]
    fn password_is_enforced_when_configured() {
        let c = LineCtx {
            session_id: 1,
            password: Some("s3cret".into()),
        };
        let sub = r#"{"id":1,"method":"mining.subscribe","params":[]}"#;

        let mut s = session();
        handle_line(&mut s, &c, sub, 0.0);
        let bad = handle_line(
            &mut s,
            &c,
            r#"{"id":2,"method":"mining.authorize","params":["rig","wrong"]}"#,
            0.0,
        );
        assert!(bad.auth_failed && !bad.just_authorized);
        assert_eq!(parse_reply(&bad)["error"][0], err::UNAUTHORIZED);

        let mut s = session();
        handle_line(&mut s, &c, sub, 0.0);
        let missing = handle_line(
            &mut s,
            &c,
            r#"{"id":2,"method":"mining.authorize","params":["rig"]}"#,
            0.0,
        );
        assert!(missing.auth_failed);

        let mut s = session();
        handle_line(&mut s, &c, sub, 0.0);
        let good = handle_line(
            &mut s,
            &c,
            r#"{"id":2,"method":"mining.authorize","params":["rig","s3cret"]}"#,
            0.0,
        );
        assert!(good.just_authorized);
    }

    #[test]
    fn worker_names_with_control_characters_or_excess_length_are_refused() {
        for worker in [
            "rig\nFAKE LOG LINE",
            "rig one",
            &"x".repeat(MAX_WORKER_LEN + 1),
        ] {
            let mut s = session();
            handle_line(
                &mut s,
                &ctx(),
                r#"{"id":1,"method":"mining.subscribe","params":[]}"#,
                0.0,
            );
            let line =
                json!({"id": 2, "method": "mining.authorize", "params": [worker]}).to_string();
            assert!(
                handle_line(&mut s, &ctx(), &line, 0.0).auth_failed,
                "{worker:?}"
            );
        }
    }

    #[test]
    fn reauthorizing_as_a_different_worker_fails_so_the_server_closes() {
        let mut s = session();
        handshake(&mut s); // authorized as wallet.rig
        let same = handle_line(
            &mut s,
            &ctx(),
            r#"{"id":3,"method":"mining.authorize","params":["wallet.rig"]}"#,
            0.0,
        );
        assert!(same.just_authorized && !same.auth_failed);
        let other = handle_line(
            &mut s,
            &ctx(),
            r#"{"id":4,"method":"mining.authorize","params":["fresh.identity"]}"#,
            0.0,
        );
        assert!(other.auth_failed && !other.just_authorized);
        assert_eq!(s.worker(), Some("wallet.rig"));
    }

    #[test]
    fn extranonce_subscribe_is_acknowledged() {
        let mut s = session();
        let r = handle_line(
            &mut s,
            &ctx(),
            r#"{"id":5,"method":"mining.extranonce.subscribe","params":[]}"#,
            0.0,
        );
        let v = parse_reply(&r);
        assert_eq!(v["id"], 5);
        assert_eq!(v["result"], true);
        assert_eq!(v["error"], Value::Null);
    }

    #[test]
    fn submit_below_target_is_a_low_difficulty_error_and_invalid() {
        let mut s = session();
        handshake(&mut s);
        let a = s.assign_job(hard_job(), 0.0).unwrap();
        let line = format!(
            r#"{{"id":1000,"method":"mining.submit","params":["wallet.rig","{}","00","","0000000000000000"]}}"#,
            a.id
        );
        let r = handle_line(&mut s, &ctx(), &line, 0.0);
        let v = parse_reply(&r);
        assert_eq!(v["result"], false);
        assert_eq!(v["error"][0], err::LOW_DIFFICULTY);
        assert!(r.block.is_none());
        assert!(r.is_submit && r.invalid);
        assert_eq!(
            r.outcome,
            Some(SubmitOutcome::Rejected(RejectReason::BelowTarget))
        );
    }

    #[test]
    fn winning_submit_yields_a_block_credited_to_the_authorized_worker() {
        let mut s = session();
        handshake(&mut s);
        let a = s.assign_job(always_block_job(), 0.0).unwrap();
        // A spoofed params[0] must not change attribution.
        let line = format!(
            r#"{{"id":"x7","method":"mining.submit","params":["spoofed.worker","{}","","","0102030405060708"]}}"#,
            a.id
        );
        let r = handle_line(&mut s, &ctx(), &line, 0.0);
        assert_eq!(
            r.block,
            Some(FoundBlock {
                worker: "wallet.rig".into(),
                height: 1_786_189,
                nonce: [1, 2, 3, 4, 5, 6, 7, 8],
            })
        );
        let v = parse_reply(&r);
        assert_eq!(v["result"], true);
        assert_eq!(v["id"], "x7", "string ids are echoed");
        assert!(!r.invalid);
    }

    #[test]
    fn submit_for_unknown_job_is_stale_but_not_invalid() {
        let mut s = session();
        handshake(&mut s);
        // No job assigned -> stale. Stale is latency, not misbehaviour.
        let r = handle_line(
            &mut s,
            &ctx(),
            r#"{"id":1000,"method":"mining.submit","params":["wallet.rig","9","00","","0000000000000001"]}"#,
            0.0,
        );
        assert_eq!(parse_reply(&r)["error"][0], err::STALE);
        assert!(!r.invalid);
    }

    #[test]
    fn malformed_line_is_a_bad_params_error_frame() {
        let mut s = session();
        let r = handle_line(&mut s, &ctx(), "not json", 0.0);
        let v = parse_reply(&r);
        assert_eq!(v["result"], false);
        assert_eq!(v["error"][0], err::BAD_PARAMS);
        assert_eq!(v["id"], Value::Null);
        assert!(r.invalid);
    }

    #[test]
    fn bad_submit_params_answer_the_request_id_and_count_as_a_submit() {
        let mut s = session();
        let r = handle_line(
            &mut s,
            &ctx(),
            r#"{"id":42,"method":"mining.submit","params":["w","1","00",""]}"#,
            0.0,
        );
        assert_eq!(parse_reply(&r)["id"], 42);
        assert!(r.is_submit && r.invalid);
    }

    #[test]
    fn unknown_method_is_rejected_not_dropped() {
        let mut s = session();
        let r = handle_line(
            &mut s,
            &ctx(),
            r#"{"id":7,"method":"mining.hello","params":[]}"#,
            0.0,
        );
        let v = parse_reply(&r);
        assert_eq!(v["error"][0], err::BAD_PARAMS);
        assert_eq!(v["id"], 7);
        assert!(!r.is_submit);
    }
}
