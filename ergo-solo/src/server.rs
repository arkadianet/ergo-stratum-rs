//! The async runtime: a tokio TCP stratum server for solo mining.
//!
//! Three concerns:
//! - **Work poll** — one task polls `/mining/candidate` on a timer, turns new
//!   templates into [`Job`]s ([`JobSource`]) and broadcasts them over a [`watch`].
//! - **Connections** — each accepted socket gets a [`Session`] and a task that
//!   pumps lines through the pure [`handle_line`] driver, writes replies, and
//!   forwards new jobs as `mining.notify` frames.
//! - **Block sink** — accepted full-block solutions flow over an [`mpsc`] channel
//!   to one task that POSTs them to the node. (There is no PPLNS accounting or
//!   on-chain payout: solo rewards go to the node's own reward address.)
//!
//! All protocol/grading logic lives in [`crate::handler`] and `ergo-stratum`
//! and is unit-tested; this module is the thin IO shell around it.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures_util::StreamExt;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch, OwnedSemaphorePermit, Semaphore};
use tokio_util::codec::{FramedRead, LinesCodec};

use ergo_stratum::protocol::notify;
use ergo_stratum::session::SessionState;
use ergo_stratum::{ExtraNonce, Job, Session};

use crate::config::Config;
use crate::handler::{handle_line, AcceptedShare};
use crate::job_source::JobSource;
use crate::node::NodeClient;

/// Maximum length of a single inbound stratum line (memory-exhaustion guard); real
/// frames are tiny. Matches the miner's own 64 KiB cap.
const MAX_LINE_BYTES: usize = 64 * 1024;

/// A connection that has not completed `subscribe` + `authorize` within this
/// window is dropped (slow-loris / scanner connection-exhaustion guard).
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// Connection admission control: a global concurrent-connection cap and an
/// optional per-source-IP cap, enforced at accept time.
struct Admission {
    sem: Arc<Semaphore>,
    per_ip: Arc<Mutex<HashMap<IpAddr, u32>>>,
    max_per_ip: u32,
}

impl Admission {
    fn new(max_connections: usize, max_per_ip: u32) -> Self {
        Self {
            sem: Arc::new(Semaphore::new(max_connections.max(1))),
            per_ip: Arc::new(Mutex::new(HashMap::new())),
            max_per_ip,
        }
    }

    /// Try to admit a connection from `ip`. Returns a [`Ticket`] that releases the
    /// global slot and decrements the per-IP count when dropped, or `None` if a cap
    /// is hit.
    fn try_admit(&self, ip: IpAddr) -> Option<Ticket> {
        let permit = self.sem.clone().try_acquire_owned().ok()?;
        let mut map = self.per_ip.lock().unwrap_or_else(|e| e.into_inner());
        let count = map.entry(ip).or_insert(0);
        if self.max_per_ip != 0 && *count >= self.max_per_ip {
            return None; // `permit` drops here, releasing the global slot
        }
        *count += 1;
        Some(Ticket {
            _permit: permit,
            per_ip: self.per_ip.clone(),
            ip,
        })
    }
}

/// Held for a connection's lifetime; on drop releases the global permit and
/// decrements the per-IP counter.
struct Ticket {
    _permit: OwnedSemaphorePermit,
    per_ip: Arc<Mutex<HashMap<IpAddr, u32>>>,
    ip: IpAddr,
}

impl Drop for Ticket {
    fn drop(&mut self) {
        let mut map = self.per_ip.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(count) = map.get_mut(&self.ip) {
            *count -= 1;
            if *count == 0 {
                map.remove(&self.ip);
            }
        }
    }
}

/// Per-connection fixed-window flood guard for **control** messages only. Counts
/// inbound lines that are NOT share submissions; if a one-second window exceeds
/// `max`, the peer is flooding junk and is dropped. `max == 0` disables it.
///
/// Share submissions are deliberately exempt: a fast GPU at low difficulty submits
/// many valid shares per second, and dropping its connection for that is the wrong
/// response — vardiff raises its difficulty instead. (The original pool daemon
/// counted submits here and would drop a legitimate fast miner; this is the fix.)
struct RateLimiter {
    max: u32,
    window_start: Instant,
    count: u32,
}

impl RateLimiter {
    fn new(max: u32, now: Instant) -> Self {
        Self {
            max,
            window_start: now,
            count: 0,
        }
    }

    /// Record one inbound control message; returns `false` if the per-second budget
    /// is exceeded (the caller drops the connection).
    fn allow(&mut self, now: Instant) -> bool {
        if self.max == 0 {
            return true;
        }
        if now.duration_since(self.window_start) >= Duration::from_secs(1) {
            self.window_start = now;
            self.count = 0;
        }
        self.count += 1;
        self.count <= self.max
    }
}

/// Run the solo server until the listener errors or the process is signalled.
pub async fn run(config: Config) -> std::io::Result<()> {
    let node = Arc::new(NodeClient::new(&config.node_url, config.api_key.clone()));

    let (job_tx, job_rx) = watch::channel::<Option<Job>>(None);
    let (share_tx, share_rx) = mpsc::unbounded_channel::<AcceptedShare>();
    let start = Instant::now();
    let next_session = Arc::new(AtomicU64::new(1));
    let admission = Admission::new(config.max_connections, config.max_conns_per_ip);

    tokio::spawn(poll_candidates(node.clone(), config.clone(), job_tx));
    tokio::spawn(submit_blocks(node.clone(), share_rx));

    let listener = TcpListener::bind(&config.bind_addr).await?;
    tracing::info!(
        bind = %config.bind_addr,
        node = %config.node_url,
        "ergo-solo stratum server listening — point your GPU miner here"
    );

    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);

    loop {
        let accept = tokio::select! {
            _ = &mut shutdown => {
                tracing::info!("shutdown signal received — stopping accept loop");
                return Ok(());
            }
            accept = listener.accept() => accept,
        };
        let (sock, peer) = match accept {
            Ok(pair) => pair,
            Err(e) => {
                tracing::warn!(error = %e, "accept failed");
                continue;
            }
        };
        let ticket = match admission.try_admit(peer.ip()) {
            Some(t) => t,
            None => {
                tracing::debug!(%peer, "connection refused: admission cap reached");
                continue; // `sock` drops here -> closed
            }
        };
        let session_id = next_session.fetch_add(1, Ordering::Relaxed);
        let lane = if config.partition_nonce {
            ExtraNonce::from_session_id(session_id)
        } else {
            ExtraNonce::whole()
        };
        let session = Session::new(lane, config.vardiff.controller());
        let conn = Connection {
            session,
            session_id,
            job_rx: job_rx.clone(),
            share_tx: share_tx.clone(),
            start,
            limiter: RateLimiter::new(config.max_msgs_per_sec, Instant::now()),
        };
        tokio::spawn(async move {
            let _ticket = ticket; // released when the task ends
            tracing::info!(%peer, "miner connected");
            if let Err(e) = conn.run(sock).await {
                tracing::debug!(%peer, error = %e, "connection ended");
            }
            tracing::info!(%peer, "miner disconnected");
        });
    }
}

/// Resolves on SIGINT (Ctrl-C) or, on Unix, SIGTERM.
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("install SIGTERM handler");
        tokio::select! {
            _ = ctrl_c => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        ctrl_c.await;
    }
}

/// Periodically poll the node candidate and broadcast new jobs.
async fn poll_candidates(node: Arc<NodeClient>, config: Config, job_tx: watch::Sender<Option<Job>>) {
    let mut source = JobSource::new(config.block_version);
    loop {
        match node.candidate().await {
            Ok(candidate) => {
                if let Some(job) = source.make_job(&candidate) {
                    tracing::info!(job_id = job.id, height = job.height, "new job from candidate");
                    let _ = job_tx.send(Some(job));
                }
            }
            Err(e) => tracing::warn!(error = %e, "candidate poll failed"),
        }
        tokio::time::sleep(config.poll_interval).await;
    }
}

/// The single mpsc consumer: submit found blocks to the node. (Solo: no PPLNS, no
/// on-chain payout — the block reward goes to the node's own reward address.)
async fn submit_blocks(node: Arc<NodeClient>, mut share_rx: mpsc::UnboundedReceiver<AcceptedShare>) {
    while let Some(share) = share_rx.recv().await {
        match share.block_nonce {
            Some(nonce) => {
                tracing::info!(worker = %share.worker, height = share.height, "BLOCK found — submitting to node");
                match node.submit_solution(&nonce).await {
                    Ok(()) => tracing::info!(
                        nonce = %hex::encode(nonce),
                        height = share.height,
                        "★ BLOCK ACCEPTED by node — reward goes to the node's reward address"
                    ),
                    Err(e) => tracing::error!(error = %e, "block submission rejected by node"),
                }
            }
            None => tracing::debug!(worker = %share.worker, "share accepted"),
        }
    }
}

/// One miner connection's mutable state + the channels it talks to.
struct Connection {
    session: Session,
    session_id: u64,
    job_rx: watch::Receiver<Option<Job>>,
    share_tx: mpsc::UnboundedSender<AcceptedShare>,
    start: Instant,
    limiter: RateLimiter,
}

impl Connection {
    async fn run(mut self, sock: TcpStream) -> std::io::Result<()> {
        let _ = sock.set_nodelay(true);
        let (read, mut write) = sock.into_split();
        let mut lines = FramedRead::new(read, LinesCodec::new_with_max_length(MAX_LINE_BYTES));

        let handshake = tokio::time::sleep(HANDSHAKE_TIMEOUT);
        tokio::pin!(handshake);

        loop {
            tokio::select! {
                _ = &mut handshake, if self.session.state() != SessionState::Authorized => {
                    tracing::debug!("dropping connection: handshake not completed in time");
                    return Ok(());
                }
                changed = self.job_rx.changed() => {
                    if changed.is_err() {
                        return Ok(()); // work source gone
                    }
                    let job = self.job_rx.borrow_and_update().clone();
                    if let Some(job) = job {
                        self.assign_and_maybe_notify(&job, &mut write).await?;
                    }
                }
                line = lines.next() => {
                    let line = match line {
                        Some(Ok(l)) => l,
                        Some(Err(e)) => {
                            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, e));
                        }
                        None => return Ok(()), // EOF
                    };
                    // Flood guard for CONTROL messages only. A share submission is
                    // never counted — a fast GPU legitimately submits many per second,
                    // and vardiff (not a connection drop) is the right throttle.
                    let is_submit = line.contains("mining.submit");
                    if !is_submit && !self.limiter.allow(Instant::now()) {
                        tracing::debug!("dropping connection: inbound control-message rate exceeded");
                        return Ok(());
                    }
                    let now = self.start.elapsed().as_secs_f64();
                    let result = handle_line(&mut self.session, self.session_id, &line, now);
                    for frame in &result.replies {
                        write.write_all(frame.as_bytes()).await?;
                    }
                    if result.just_authorized {
                        let job = self.job_rx.borrow_and_update().clone();
                        if let Some(job) = job {
                            self.assign_and_maybe_notify(&job, &mut write).await?;
                        }
                    }
                    if let Some(share) = result.accepted {
                        let _ = self.share_tx.send(share);
                    }
                }
            }
        }
    }

    /// Assign `job` to the session and, if authorized, send a `mining.notify`
    /// carrying the per-worker share boundary.
    async fn assign_and_maybe_notify(
        &mut self,
        job: &Job,
        write: &mut (impl AsyncWriteExt + Unpin),
    ) -> std::io::Result<()> {
        self.session.assign_job(job.clone());
        if self.session.state() == SessionState::Authorized {
            if let Some(boundary) = self.session.share_target() {
                let frame = notify(job, &boundary).to_line();
                write.write_all(frame.as_bytes()).await?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limiter_caps_control_messages_and_refills() {
        let t0 = Instant::now();
        let mut rl = RateLimiter::new(3, t0);
        assert!(rl.allow(t0));
        assert!(rl.allow(t0));
        assert!(rl.allow(t0));
        assert!(!rl.allow(t0), "4th in the same window is over budget");
        assert!(rl.allow(t0 + Duration::from_millis(1001)), "window refills");
    }

    #[test]
    fn rate_limiter_zero_is_disabled() {
        let t0 = Instant::now();
        let mut rl = RateLimiter::new(0, t0);
        for _ in 0..10_000 {
            assert!(rl.allow(t0));
        }
    }

    #[test]
    fn admission_enforces_the_global_cap() {
        let a = Admission::new(2, 0);
        let ip1: IpAddr = "1.1.1.1".parse().unwrap();
        let ip2: IpAddr = "2.2.2.2".parse().unwrap();
        let t1 = a.try_admit(ip1).expect("first admitted");
        let _t2 = a.try_admit(ip2).expect("second admitted");
        assert!(a.try_admit(ip1).is_none(), "global cap of 2 reached");
        drop(t1);
        assert!(a.try_admit(ip1).is_some(), "a freed slot is reusable");
    }

    #[test]
    fn admission_enforces_the_per_ip_cap() {
        let a = Admission::new(100, 2);
        let ip: IpAddr = "9.9.9.9".parse().unwrap();
        let _t1 = a.try_admit(ip).unwrap();
        let t2 = a.try_admit(ip).unwrap();
        assert!(a.try_admit(ip).is_none(), "3rd from the same IP refused");
        drop(t2);
        assert!(a.try_admit(ip).is_some(), "a freed per-IP slot is reusable");
    }
}
