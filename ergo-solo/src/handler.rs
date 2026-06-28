//! Pure per-connection protocol driver: one inbound wire line in, a [`LineResult`]
//! (reply frames + side effects) out. The async server ([`crate::server`]) owns
//! the socket and clock and simply pumps lines through here, so all of the
//! parse → dispatch → grade logic is deterministic and unit-testable without a
//! network.

use ergo_stratum::protocol::{
    err, error_response, ok_response, parse_inbound, subscribe_response, Inbound, ProtocolError,
};
use ergo_stratum::session::{RejectReason, SubmitOutcome};
use ergo_stratum::Session;

/// An accepted share's bookkeeping, surfaced to the server for PPLNS + block
/// submission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcceptedShare {
    /// The authorized worker the share is credited to (the login string, whose
    /// address part the accountant resolves to a ledger key).
    pub worker: String,
    /// PPLNS weight of the share.
    pub weight: u128,
    /// Candidate height the share was found at — drives the block reward lookup.
    pub height: u32,
    /// `Some(nonce)` if the share is a full block to submit to the node.
    pub block_nonce: Option<[u8; 8]>,
}

/// What handling one line produced.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LineResult {
    /// Newline-terminated frames to write back to the miner.
    pub replies: Vec<String>,
    /// Set on an accepted share/block.
    pub accepted: Option<AcceptedShare>,
    /// True right after a successful `mining.authorize` — the server should push
    /// the current job to this freshly-authorized connection.
    pub just_authorized: bool,
}

/// Drive one inbound `line` through `session` at monotonic time `now_secs`.
/// `session_id` seeds the subscribe response's nonce-lane advertisement.
pub fn handle_line(
    session: &mut Session,
    session_id: u64,
    line: &str,
    now_secs: f64,
) -> LineResult {
    let inbound = match parse_inbound(line) {
        Ok(i) => i,
        Err(e) => return reply(parse_error_frame(&e)),
    };

    match inbound {
        Inbound::Subscribe { id, .. } => {
            session.subscribe();
            let ex = session.extra_nonce();
            reply(
                subscribe_response(id, session_id, &ex.prefix_hex(), ex.extra_nonce2_bytes())
                    .to_line(),
            )
        }
        Inbound::Authorize { id, worker, .. } => {
            if session.authorize(&worker) {
                LineResult {
                    replies: vec![ok_response(id).to_line()],
                    accepted: None,
                    just_authorized: true,
                }
            } else {
                reply(error_response(id, err::UNAUTHORIZED, "authorize failed").to_line())
            }
        }
        Inbound::Submit {
            id,
            worker,
            job_id,
            nonce,
            ..
        } => {
            let outcome = session.submit(job_id, nonce, now_secs);
            // Credit the authorized worker (authoritative), not the submit param.
            let credited = session.worker().map(str::to_string).unwrap_or(worker);
            // Height of the job just graded (drives the reward on a block).
            let height = session.current_job().map(|j| j.height).unwrap_or(0);
            match outcome {
                SubmitOutcome::Accepted { weight } => LineResult {
                    replies: vec![ok_response(id).to_line()],
                    accepted: Some(AcceptedShare {
                        worker: credited,
                        weight,
                        height,
                        block_nonce: None,
                    }),
                    just_authorized: false,
                },
                SubmitOutcome::Block { weight } => LineResult {
                    replies: vec![ok_response(id).to_line()],
                    accepted: Some(AcceptedShare {
                        worker: credited,
                        weight,
                        height,
                        block_nonce: Some(nonce),
                    }),
                    just_authorized: false,
                },
                SubmitOutcome::Rejected(reason) => {
                    let (code, msg) = reject_frame(reason);
                    reply(error_response(id, code, msg).to_line())
                }
            }
        }
        Inbound::Unknown { id, method } => reply(
            error_response(id, err::BAD_PARAMS, &format!("unknown method {method}")).to_line(),
        ),
    }
}

fn reply(line: String) -> LineResult {
    LineResult {
        replies: vec![line],
        accepted: None,
        just_authorized: false,
    }
}

fn parse_error_frame(e: &ProtocolError) -> String {
    let msg = match e {
        ProtocolError::Json(_) => "malformed JSON-RPC".to_string(),
        ProtocolError::BadParams(m) => format!("bad params for {m}"),
    };
    // No reliable id on a parse failure.
    error_response(None, err::BAD_PARAMS, &msg).to_line()
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
    use serde_json::Value;

    use ergo_stratum::{ExtraNonce, Job, VarDiff};

    fn session() -> Session {
        Session::new(ExtraNonce::whole(), VarDiff::new(1000, 10.0, 1, 100_000))
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
            clean: true,
        }
    }

    fn parse_reply(r: &LineResult) -> Value {
        assert_eq!(r.replies.len(), 1, "expected one reply");
        serde_json::from_str(r.replies[0].trim()).unwrap()
    }

    #[test]
    fn subscribe_then_authorize_then_handshake_flags() {
        let mut s = session();
        let sub = handle_line(
            &mut s,
            0xABCD,
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
            0xABCD,
            r#"{"id":2,"method":"mining.authorize","params":["wallet.rig","x"]}"#,
            0.0,
        );
        assert_eq!(parse_reply(&auth)["result"], true);
        assert!(auth.just_authorized, "server must push a job after auth");
    }

    #[test]
    fn submit_below_target_is_a_low_difficulty_error_no_credit() {
        let mut s = session();
        handle_line(
            &mut s,
            1,
            r#"{"id":1,"method":"mining.subscribe","params":[]}"#,
            0.0,
        );
        handle_line(
            &mut s,
            1,
            r#"{"id":2,"method":"mining.authorize","params":["wallet.rig"]}"#,
            0.0,
        );
        s.assign_job(hard_job());
        let r = handle_line(
            &mut s,
            1,
            r#"{"id":1000,"method":"mining.submit","params":["wallet.rig","1","00","","0000000000000000"]}"#,
            0.0,
        );
        let v = parse_reply(&r);
        assert_eq!(v["result"], false);
        assert_eq!(v["error"][0], err::LOW_DIFFICULTY);
        assert!(r.accepted.is_none());
    }

    #[test]
    fn submit_for_unknown_job_is_stale() {
        let mut s = session();
        handle_line(
            &mut s,
            1,
            r#"{"id":1,"method":"mining.subscribe","params":[]}"#,
            0.0,
        );
        handle_line(
            &mut s,
            1,
            r#"{"id":2,"method":"mining.authorize","params":["wallet.rig"]}"#,
            0.0,
        );
        // No job assigned -> stale.
        let r = handle_line(
            &mut s,
            1,
            r#"{"id":1000,"method":"mining.submit","params":["wallet.rig","9","00","","0000000000000001"]}"#,
            0.0,
        );
        assert_eq!(parse_reply(&r)["error"][0], err::STALE);
    }

    #[test]
    fn malformed_line_is_a_bad_params_error_frame() {
        let mut s = session();
        let r = handle_line(&mut s, 1, "not json", 0.0);
        let v = parse_reply(&r);
        assert_eq!(v["result"], false);
        assert_eq!(v["error"][0], err::BAD_PARAMS);
        assert_eq!(v["id"], Value::Null);
    }

    #[test]
    fn unknown_method_is_rejected_not_dropped() {
        let mut s = session();
        let r = handle_line(
            &mut s,
            1,
            r#"{"id":7,"method":"mining.hello","params":[]}"#,
            0.0,
        );
        let v = parse_reply(&r);
        assert_eq!(v["error"][0], err::BAD_PARAMS);
        assert_eq!(v["id"], 7);
    }

    #[test]
    fn submit_attributes_to_the_authorized_worker_not_the_param() {
        // A real winning nonce can't be forged in a test, so we lock in the
        // attribution invariant the credit path relies on: the authorized worker
        // name is authoritative and a spoofed `params[0]` cannot change it.
        let mut s = session();
        handle_line(
            &mut s,
            1,
            r#"{"id":1,"method":"mining.subscribe","params":[]}"#,
            0.0,
        );
        handle_line(
            &mut s,
            1,
            r#"{"id":2,"method":"mining.authorize","params":["authoritative.worker"]}"#,
            0.0,
        );
        s.assign_job(hard_job());
        let _ = handle_line(
            &mut s,
            1,
            r#"{"id":1000,"method":"mining.submit","params":["spoofed.worker","1","00","","0000000000000000"]}"#,
            0.0,
        );
        assert_eq!(s.worker(), Some("authoritative.worker"));
    }
}
