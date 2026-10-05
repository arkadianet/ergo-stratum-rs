//! The async runtime: a tokio TCP stratum server for solo mining.
//!
//! Four concerns:
//! - **Work poll** — one task fetches `/mining/candidate` (long-polled when the
//!   node supports it, so a new block is picked up the instant the node has it),
//!   turns new templates into [`Job`]s ([`JobSource`]) and broadcasts them over a
//!   [`watch`]. If the node stops serving work for too long the job is withdrawn
//!   and miners are disconnected so their backup pool can take over.
//! - **Connections** — each accepted socket gets a [`Session`] and a task that
//!   pumps lines through the pure [`handle_line`] driver, writes replies, and
//!   forwards new jobs / difficulty changes as `mining.notify` frames.
//! - **Block sink** — validated winning nonces flow over an [`mpsc`] channel to
//!   one task that POSTs them to the node, retrying transient failures and
//!   draining the queue on shutdown. (There is no accounting or on-chain payout:
//!   solo rewards go to the node's own reward address.)
//! - **Stats** — per-worker accounting ([`Stats`]) logged periodically and
//!   optionally served as JSON.
//!
//! All protocol/grading logic lives in [`crate::handler`] and `ergo-stratum`
//! and is unit-tested; this module is the thin IO shell around it.

use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures_util::StreamExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch, Notify, OwnedSemaphorePermit, Semaphore};
use tokio_util::codec::{FramedRead, LinesCodec};

use ergo_stratum::protocol::{mrr_difficulty, nicehash_difficulty, notify, set_difficulty};
use ergo_stratum::session::SessionState;
use ergo_stratum::{Assignment, ExtraNonce, Job, LanePool, Session};

use crate::config::{Config, DifficultyValue};
use crate::handler::{handle_line, FoundBlock, LineCtx};
use crate::job_source::JobSource;
use crate::node::{NodeClient, NodeError};
use crate::stats::{format_hashrate, Stats};

/// Maximum length of a single inbound stratum line (memory-exhaustion guard); real
/// frames are tiny. Matches the miner's own 64 KiB cap.
const MAX_LINE_BYTES: usize = 64 * 1024;

/// A connection that has not completed `subscribe` + `authorize` within this
/// window is dropped (slow-loris / scanner connection-exhaustion guard).
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// A write to a miner that doesn't complete in this long drops the connection
/// (a stalled peer must not pin its task forever).
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);

/// Per-connection housekeeping cadence (vardiff idle easing, no-work check).
const TICK: Duration = Duration::from_secs(5);

/// An authorized connection that has had no work for this long is closed, so
/// the miner fails over instead of idling against a node that isn't serving.
const NO_WORK_TIMEOUT: Duration = Duration::from_secs(30);

/// Block submission: attempts for transient failures, with doubling backoff.
const SUBMIT_ATTEMPTS: u32 = 5;
const SUBMIT_BACKOFF: Duration = Duration::from_millis(250);

/// On shutdown, how long to wait for queued blocks to be delivered.
const SHUTDOWN_DRAIN: Duration = Duration::from_secs(15);

/// Repeated candidate-poll failures are logged at WARN at most this often.
const POLL_ERROR_LOG_EVERY: Duration = Duration::from_secs(30);

/// Candidate failures shorter than this are routine and logged at DEBUG: right
/// after every new block the node answers 503 ("no candidate published for the
/// current tip yet") for a moment while it builds the template.
const POLL_ERROR_GRACE: Duration = Duration::from_secs(5);

/// First retry delay after a failed candidate fetch; doubles per consecutive
/// failure up to the poll interval.
const POLL_ERROR_RETRY: Duration = Duration::from_millis(100);

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

/// A connection's nonce lane, returned to the pool when the connection ends.
struct LaneGuard {
    pool: Arc<Mutex<LanePool>>,
    lane: ExtraNonce,
}

impl Drop for LaneGuard {
    fn drop(&mut self) {
        self.pool
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .release(&self.lane);
    }
}

/// Per-connection fixed-window counter: at most `max` events per `window`;
/// `max == 0` disables it. Used for the control-message flood guard (share
/// submissions are exempt — a fast GPU legitimately submits many, and vardiff,
/// not a disconnect, is the right throttle) and the invalid-share budget.
struct RateLimiter {
    max: u32,
    window: Duration,
    window_start: Instant,
    count: u32,
}

impl RateLimiter {
    fn new(max: u32, window: Duration, now: Instant) -> Self {
        Self {
            max,
            window,
            window_start: now,
            count: 0,
        }
    }

    /// Record one event; returns `false` if the budget is exceeded (the caller
    /// drops the connection).
    fn allow(&mut self, now: Instant) -> bool {
        if self.max == 0 {
            return true;
        }
        if now.duration_since(self.window_start) >= self.window {
            self.window_start = now;
            self.count = 0;
        }
        self.count += 1;
        self.count <= self.max
    }
}

/// Run the solo server on `config.bind_addr` until SIGINT/SIGTERM or a fatal
/// background-task failure.
pub async fn run(config: Config) -> std::io::Result<()> {
    let listener = TcpListener::bind(&config.bind_addr).await?;
    serve(config, listener, shutdown_signal()).await
}

/// Serve stratum on `listener` until `shutdown` resolves (then deliver any queued
/// blocks and return `Ok`) or a background task dies (`Err`, so a supervisor
/// restarts a clean process).
pub async fn serve(
    config: Config,
    listener: TcpListener,
    shutdown: impl Future<Output = ()>,
) -> std::io::Result<()> {
    let node = Arc::new(NodeClient::new(&config.node_url, config.api_key.clone()));
    let stats = Arc::new(Stats::default());
    let refresh = Arc::new(Notify::new());

    let (job_tx, job_rx) = watch::channel::<Option<Job>>(None);
    let (block_tx, block_rx) = mpsc::unbounded_channel::<FoundBlock>();
    let (stop_tx, stop_rx) = watch::channel(false);
    let start = Instant::now();
    let next_session = AtomicU64::new(1);
    let admission = Admission::new(config.max_connections, config.max_conns_per_ip);
    let lanes = config
        .partition_bytes
        .map(|bytes| Arc::new(Mutex::new(LanePool::new(bytes))));

    // Keep the handles: these are forever-loops, so if either ever *ends* (a panic
    // inside the task) the process is silently broken — the poller's death means
    // miners grind a dead template forever, and the submitter's death means found
    // blocks never reach the node. A live-but-wedged process is invisible to a
    // `Restart=` supervisor, so we watch both below and exit non-zero.
    let mut poll_task = tokio::spawn(poll_candidates(
        node.clone(),
        config.clone(),
        job_tx,
        stats.clone(),
        refresh.clone(),
    ));
    let mut submit_task = tokio::spawn(submit_blocks(
        node.clone(),
        block_rx,
        stats.clone(),
        refresh.clone(),
        stop_rx,
    ));
    if let Some(every) = config.stats_interval {
        tokio::spawn(log_stats(stats.clone(), every));
    }
    if let Some(addr) = &config.stats_bind {
        let stats_listener = TcpListener::bind(addr).await?;
        tracing::info!(bind = %stats_listener.local_addr()?, "JSON stats endpoint listening");
        tokio::spawn(serve_stats(stats_listener, stats.clone()));
    }

    tracing::info!(
        bind = %listener.local_addr()?,
        node = %config.node_url,
        "ergo-solo stratum server listening — point your GPU miner here"
    );

    tokio::pin!(shutdown);

    loop {
        let accept = tokio::select! {
            _ = &mut shutdown => {
                tracing::info!("shutdown signal received — stopping accept loop");
                break;
            }
            outcome = &mut poll_task => {
                tracing::error!(?outcome, "candidate poller task ended — exiting so the supervisor restarts a clean process");
                return Err(std::io::Error::other("candidate poller task ended unexpectedly"));
            }
            outcome = &mut submit_task => {
                tracing::error!(?outcome, "block submitter task ended — exiting so the supervisor restarts a clean process");
                return Err(std::io::Error::other("block submitter task ended unexpectedly"));
            }
            accept = listener.accept() => accept,
        };
        let (sock, peer) = match accept {
            Ok(pair) => pair,
            Err(e) => {
                // e.g. EMFILE: back off briefly instead of spinning on the error.
                tracing::warn!(error = %e, "accept failed");
                tokio::time::sleep(Duration::from_millis(100)).await;
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
        let lane = match &lanes {
            Some(pool) => {
                let acquired = pool.lock().unwrap_or_else(|e| e.into_inner()).acquire();
                match acquired {
                    Some(lane) => Some(LaneGuard {
                        pool: pool.clone(),
                        lane,
                    }),
                    None => {
                        tracing::warn!(%peer, "connection refused: every nonce lane is in use");
                        continue;
                    }
                }
            }
            None => None,
        };
        let session_id = next_session.fetch_add(1, Ordering::Relaxed);
        let extra_nonce = lane.as_ref().map_or(ExtraNonce::whole(), |g| g.lane);
        let now = Instant::now();
        // React only to job changes from here on: the job current at connect
        // time is picked up at authorization. (Without this, a connection made
        // during an outage would see the withdrawn `None` as a fresh change and
        // be dropped before it could wait for the node to come back.)
        let mut conn_job_rx = job_rx.clone();
        conn_job_rx.borrow_and_update();
        let conn = Connection {
            session: Session::new(extra_nonce, config.vardiff.controller()),
            ctx: LineCtx {
                session_id,
                password: config.stratum_password.clone(),
            },
            peer,
            job_rx: conn_job_rx,
            block_tx: block_tx.clone(),
            stats: stats.clone(),
            start,
            limiter: RateLimiter::new(config.max_msgs_per_sec, Duration::from_secs(1), now),
            invalid: RateLimiter::new(config.max_invalid_per_min, Duration::from_secs(60), now),
            worker: None,
            send_difficulty: config.set_difficulty,
            difficulty_value: config.set_difficulty_value,
        };
        tokio::spawn(async move {
            // Released when the task ends.
            let _ticket = ticket;
            let _lane = lane;
            tracing::info!(%peer, session_id, "miner connected");
            if let Err(e) = conn.run(sock).await {
                tracing::debug!(%peer, error = %e, "connection ended");
            }
            tracing::info!(%peer, session_id, "miner disconnected");
        });
    }

    // Deliver anything already found before exiting — a block validated a moment
    // before Ctrl-C/SIGTERM is still a block.
    let _ = stop_tx.send(true);
    drop(block_tx);
    if tokio::time::timeout(SHUTDOWN_DRAIN, &mut submit_task)
        .await
        .is_err()
    {
        tracing::warn!("timed out delivering queued blocks during shutdown");
    }
    Ok(())
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

/// Fetch node candidates forever and broadcast new jobs.
///
/// Long-poll first: the request names the template we hold and a supporting
/// node answers only when it changes, so there is no poll delay at all. After a
/// success each round waits out whatever is left of `poll_interval` — zero
/// after a held long-poll, the full interval when the node answered at once (no
/// long-poll support) — or less if a block was just submitted. After a failure
/// it retries quickly ([`error_backoff`]): the commonest failure is the node's
/// brief "no candidate for the new tip yet", and every 100 ms of that delay is
/// hashrate spent on a dead block.
async fn poll_candidates(
    node: Arc<NodeClient>,
    config: Config,
    job_tx: watch::Sender<Option<Job>>,
    stats: Arc<Stats>,
    refresh: Arc<Notify>,
) {
    let mut source = JobSource::new(config.block_version);
    let mut last_ok = Instant::now();
    let mut failures: u32 = 0;
    let mut failing_since: Option<Instant> = None;
    let mut last_warn: Option<Instant> = None;
    loop {
        let started = Instant::now();
        let longpoll = if config.longpoll {
            source.last_msg()
        } else {
            None
        };
        match node.candidate(longpoll.as_ref()).await {
            Ok(candidate) => {
                if failures > 0 {
                    if last_warn.is_some() {
                        tracing::info!(failures, "node candidate fetch recovered");
                    } else {
                        tracing::debug!(failures, "node candidate fetch recovered");
                    }
                    failures = 0;
                    failing_since = None;
                    last_warn = None;
                }
                last_ok = Instant::now();
                let job = source.make_job(&candidate);
                stats.candidate_ok(candidate.height, job.is_some(), last_ok);
                if let Some(job) = job {
                    tracing::info!(
                        job_id = job.id,
                        height = job.height,
                        "new job from candidate"
                    );
                    job_tx.send_replace(Some(job));
                    if config.longpoll {
                        continue; // straight back to waiting for the next change
                    }
                }
            }
            Err(e) => {
                failures = failures.saturating_add(1);
                stats.candidate_err();
                let failing_for = failing_since.get_or_insert_with(Instant::now).elapsed();
                if failing_for >= POLL_ERROR_GRACE
                    && last_warn.is_none_or(|t| t.elapsed() >= POLL_ERROR_LOG_EVERY)
                {
                    tracing::warn!(
                        error = %e,
                        failures,
                        failing_for_secs = failing_for.as_secs(),
                        "candidate poll failing"
                    );
                    last_warn = Some(Instant::now());
                } else {
                    tracing::debug!(error = %e, failures, "candidate poll failed");
                }
                if let Some(limit) = config.stale_work {
                    if job_tx.borrow().is_some() && last_ok.elapsed() >= limit {
                        tracing::warn!(
                            secs = limit.as_secs(),
                            "no fresh work from the node — withdrawing the stale job and \
                             disconnecting miners so they can fail over"
                        );
                        job_tx.send_replace(None);
                        source.reset();
                    }
                }
            }
        }
        let wait = if failures > 0 {
            error_backoff(failures, config.poll_interval)
        } else {
            config.poll_interval.saturating_sub(started.elapsed())
        };
        tokio::select! {
            _ = tokio::time::sleep(wait) => {}
            _ = refresh.notified() => {}
        }
    }
}

/// Delay before retry number `failures` (1-based) of a failed candidate fetch:
/// 100 ms, 200 ms, 400 ms, … capped at `poll_interval`.
fn error_backoff(failures: u32, poll_interval: Duration) -> Duration {
    let doublings = failures.saturating_sub(1).min(16);
    (POLL_ERROR_RETRY * 2u32.pow(doublings)).min(poll_interval)
}

/// The single block consumer: submit found blocks to the node. On shutdown
/// (`stop` flips) it delivers whatever is already queued, then returns.
async fn submit_blocks(
    node: Arc<NodeClient>,
    mut blocks: mpsc::UnboundedReceiver<FoundBlock>,
    stats: Arc<Stats>,
    refresh: Arc<Notify>,
    mut stop: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            biased;
            block = blocks.recv() => match block {
                Some(block) => submit_block(&node, &stats, &refresh, block).await,
                None => return,
            },
            _ = stop.changed() => {
                while let Ok(block) = blocks.try_recv() {
                    submit_block(&node, &stats, &refresh, block).await;
                }
                return;
            }
        }
    }
}

/// POST one winning nonce, retrying transient failures (node restarting, busy,
/// connection blip). A `4xx` verdict is final.
async fn submit_block(node: &NodeClient, stats: &Stats, refresh: &Notify, block: FoundBlock) {
    let nonce = hex::encode(block.nonce);
    // A transport error may strike after the node received the request, so a
    // later "stale"/"invalid" verdict could mean an earlier attempt landed.
    let mut maybe_delivered = false;
    for attempt in 1..=SUBMIT_ATTEMPTS {
        match node.submit_solution(&block.nonce).await {
            Ok(()) => {
                tracing::info!(
                    worker = %block.worker,
                    height = block.height,
                    %nonce,
                    attempt,
                    "★ BLOCK ACCEPTED by node — reward goes to the node's reward address once confirmed on chain"
                );
                stats.block_accepted();
                refresh.notify_one();
                return;
            }
            Err(e) if e.is_transient() && attempt < SUBMIT_ATTEMPTS => {
                maybe_delivered |= matches!(e, NodeError::Http(_));
                tracing::warn!(error = %e, attempt, %nonce, "block submission failed — retrying");
                tokio::time::sleep(SUBMIT_BACKOFF * 2u32.pow(attempt - 1)).await;
            }
            Err(e) => {
                if maybe_delivered {
                    tracing::error!(
                        error = %e, worker = %block.worker, height = block.height, %nonce,
                        "block submission refused — an earlier attempt failed in transit and \
                         may have been accepted; check the chain"
                    );
                } else {
                    tracing::error!(
                        error = %e, worker = %block.worker, height = block.height, %nonce,
                        "block submission rejected by node"
                    );
                }
                stats.block_rejected();
                refresh.notify_one();
                return;
            }
        }
    }
}

/// Periodic per-worker summary at INFO.
async fn log_stats(stats: Arc<Stats>, every: Duration) {
    let mut interval = tokio::time::interval(every);
    interval.tick().await; // the first tick is immediate; skip the empty report
    loop {
        interval.tick().await;
        let snap = stats.snapshot(Instant::now());
        tracing::info!(
            height = ?snap.node.height,
            blocks_found = snap.blocks.found,
            blocks_accepted = snap.blocks.accepted,
            blocks_rejected = snap.blocks.rejected,
            poll_errors = snap.node.poll_errors,
            "stats"
        );
        for w in snap
            .workers
            .iter()
            .filter(|w| w.connections > 0 || w.hashrate_recent > 0.0)
        {
            let c = &w.counts;
            tracing::info!(
                worker = %w.worker,
                connections = w.connections,
                hashrate = %format_hashrate(w.hashrate_recent),
                hashrate_avg = %format_hashrate(w.hashrate_avg),
                accepted = c.accepted,
                stale = c.stale,
                rejected = c.low_diff + c.duplicate + c.wrong_lane + c.invalid,
                blocks = c.blocks,
                "worker stats"
            );
        }
    }
}

/// Minimal read-only HTTP endpoint: any request gets the JSON [`Stats`]
/// snapshot. Hand-rolled to avoid an HTTP-server dependency for one route.
async fn serve_stats(listener: TcpListener, stats: Arc<Stats>) {
    loop {
        let mut sock = match listener.accept().await {
            Ok((sock, _)) => sock,
            Err(e) => {
                tracing::debug!(error = %e, "stats accept failed");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let stats = stats.clone();
        tokio::spawn(async move {
            // Consume (and ignore) the request head, bounded in size and time.
            let mut head = Vec::new();
            let mut buf = [0u8; 2048];
            let _ = tokio::time::timeout(Duration::from_secs(5), async {
                while head.len() < 16 * 1024 && !head.windows(4).any(|w| w == b"\r\n\r\n") {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => head.extend_from_slice(&buf[..n]),
                    }
                }
            })
            .await;
            let body = serde_json::to_string_pretty(&stats.snapshot(Instant::now()))
                .unwrap_or_else(|_| "{}".to_string());
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}\n",
                body.len() + 1
            );
            let _ = sock.write_all(response.as_bytes()).await;
            let _ = sock.shutdown().await;
        });
    }
}

/// One miner connection's mutable state + the channels it talks to.
struct Connection {
    session: Session,
    ctx: LineCtx,
    peer: SocketAddr,
    job_rx: watch::Receiver<Option<Job>>,
    block_tx: mpsc::UnboundedSender<FoundBlock>,
    stats: Arc<Stats>,
    start: Instant,
    limiter: RateLimiter,
    invalid: RateLimiter,
    /// The login this connection is counted under in [`Stats`].
    worker: Option<String>,
    /// Precede every job with `mining.set_difficulty`...
    send_difficulty: bool,
    /// ...announcing this.
    difficulty_value: DifficultyValue,
}

/// Which `mining.set_difficulty` (if any) precedes a job.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DifficultyMsg {
    Off,
    /// `[1]`: the share target is in the notify itself (Miningcore convention).
    Unit,
    /// NiceHash units, derived from the job's share target.
    NiceHash,
    /// MiningRigRentals units, derived from the job's share target.
    Mrr,
}

impl Connection {
    async fn run(mut self, sock: TcpStream) -> std::io::Result<()> {
        let result = self.pump(sock).await;
        if let Some(worker) = self.worker.take() {
            self.stats.worker_disconnected(&worker);
        }
        result
    }

    fn now(&self) -> f64 {
        self.start.elapsed().as_secs_f64()
    }

    fn difficulty_msg(&self) -> DifficultyMsg {
        if !self.send_difficulty {
            DifficultyMsg::Off
        } else if self.session.is_nicehash() {
            DifficultyMsg::NiceHash
        } else if self.difficulty_value == DifficultyValue::Mrr {
            DifficultyMsg::Mrr
        } else {
            DifficultyMsg::Unit
        }
    }

    fn authorized(&self) -> bool {
        self.session.state() == SessionState::Authorized
    }

    async fn pump(&mut self, sock: TcpStream) -> std::io::Result<()> {
        let _ = sock.set_nodelay(true);
        let (read, mut write) = sock.into_split();
        let mut lines = FramedRead::new(read, LinesCodec::new_with_max_length(MAX_LINE_BYTES));

        let handshake = tokio::time::sleep(HANDSHAKE_TIMEOUT);
        tokio::pin!(handshake);
        let mut tick = tokio::time::interval(TICK);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut no_work_since: Option<Instant> = None;

        loop {
            tokio::select! {
                _ = &mut handshake, if !self.authorized() => {
                    tracing::debug!(peer = %self.peer, "dropping connection: handshake not completed in time");
                    return Ok(());
                }
                changed = self.job_rx.changed() => {
                    if changed.is_err() {
                        return Ok(()); // work source gone
                    }
                    let job = self.job_rx.borrow_and_update().clone();
                    match job {
                        Some(job) => {
                            no_work_since = None;
                            let now = self.now();
                            if let Some(a) = self.session.assign_job(job, now) {
                                send_job(&mut write, &a, self.difficulty_msg()).await?;
                            }
                        }
                        None => {
                            tracing::info!(peer = %self.peer, "node work withdrawn — disconnecting miner so it can fail over");
                            return Ok(());
                        }
                    }
                }
                _ = tick.tick() => {
                    let now = self.now();
                    self.session.tick(now);
                    self.send_retarget(&mut write).await?;
                    if self.authorized() && self.session.current_job().is_none() {
                        let since = *no_work_since.get_or_insert_with(Instant::now);
                        if since.elapsed() >= NO_WORK_TIMEOUT {
                            tracing::info!(peer = %self.peer, "no work available from the node — disconnecting miner so it can fail over");
                            return Ok(());
                        }
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
                    if !self.handle_line(&line, &mut write).await? {
                        return Ok(());
                    }
                }
            }
        }
    }

    /// Process one inbound line. `Ok(false)` closes the connection.
    async fn handle_line(
        &mut self,
        line: &str,
        write: &mut (impl AsyncWriteExt + Unpin),
    ) -> std::io::Result<bool> {
        // Raw frames live at TRACE (high-volume). `mining.authorize` carries the
        // stratum password, so it is never logged verbatim.
        if line.contains("mining.authorize") {
            tracing::trace!(
                session_id = self.ctx.session_id,
                "→ inbound mining.authorize (redacted)"
            );
        } else {
            tracing::trace!(session_id = self.ctx.session_id, frame = %line, "→ inbound");
        }
        let now = self.now();
        let result = handle_line(&mut self.session, &self.ctx, line, now);

        // 1. A winning nonce reaches the submitter before ANY socket I/O: a miner
        //    that vanishes (or stalls) mid-reply must never cost a block.
        if let Some(block) = &result.block {
            tracing::info!(
                worker = %block.worker,
                height = block.height,
                nonce = %hex::encode(block.nonce),
                "BLOCK found — submitting to node"
            );
            self.stats.block_found();
            if self.block_tx.send(block.clone()).is_err() {
                tracing::error!(
                    nonce = %hex::encode(block.nonce),
                    "block submitter is gone — this winning nonce cannot be delivered"
                );
            }
        }

        // 2. Accounting (authorized workers only — anonymous junk isn't a worker).
        if let Some(worker) = self.session.worker() {
            if let Some(outcome) = &result.outcome {
                tracing::debug!(%worker, ?outcome, "share graded");
                self.stats.record_submit(worker, outcome, Instant::now());
            } else if result.invalid {
                self.stats.record_invalid(worker, Instant::now());
            }
        }

        // 3. Abuse limits, on the PARSED method (a `mining.submit` substring in
        //    some other frame can't dodge the control-message cap).
        if result.invalid && !self.invalid.allow(Instant::now()) {
            tracing::warn!(peer = %self.peer, worker = ?self.session.worker(), "dropping connection: too many invalid submissions");
            return Ok(false);
        }
        if !result.is_submit && !self.limiter.allow(Instant::now()) {
            tracing::debug!(peer = %self.peer, "dropping connection: inbound control-message rate exceeded");
            return Ok(false);
        }

        // 4. Replies.
        for frame in &result.replies {
            tracing::trace!(session_id = self.ctx.session_id, frame = %frame.trim_end(), "← reply");
            write_frame(write, frame).await?;
        }
        if result.auth_failed {
            tracing::info!(peer = %self.peer, "authorization refused — closing connection");
            return Ok(false);
        }

        // 5. A fresh login gets the current job straight away.
        if result.just_authorized {
            let worker = self.session.worker().unwrap_or_default().to_string();
            // The session refuses a rename, so this only fires on first login
            // (a same-name re-authorize is already counted).
            if self.worker.is_none() {
                self.worker = Some(worker.clone());
                self.stats.worker_connected(&worker, Instant::now());
            }
            tracing::info!(
                peer = %self.peer,
                session_id = self.ctx.session_id,
                %worker,
                agent = self.session.agent().unwrap_or("-"),
                factor = self.session.factor(),
                "miner authorized"
            );
            let job = self.job_rx.borrow_and_update().clone();
            if let Some(job) = job {
                if let Some(a) = self.session.assign_job(job, now) {
                    send_job(write, &a, self.difficulty_msg()).await?;
                }
            }
        }

        // 6. Deliver a vardiff change immediately.
        self.send_retarget(write).await?;
        Ok(true)
    }

    /// If vardiff moved, re-advertise the current job at the new difficulty.
    async fn send_retarget(
        &mut self,
        write: &mut (impl AsyncWriteExt + Unpin),
    ) -> std::io::Result<()> {
        let now = self.now();
        if let Some(a) = self.session.take_retarget(now) {
            tracing::debug!(
                peer = %self.peer,
                worker = ?self.session.worker(),
                factor = a.factor,
                "vardiff retarget"
            );
            send_job(write, &a, self.difficulty_msg()).await?;
        }
        Ok(())
    }
}

/// Send one assignment: `mining.set_difficulty` (per `difficulty`) immediately
/// followed by its `mining.notify`, in a single write. The order matters —
/// some miners apply whichever of the two arrives last, and the notify carries
/// the real share target.
async fn send_job(
    write: &mut (impl AsyncWriteExt + Unpin),
    a: &Assignment,
    difficulty: DifficultyMsg,
) -> std::io::Result<()> {
    let boundary = a.boundary();
    let mut frames = match difficulty {
        DifficultyMsg::Off => String::new(),
        DifficultyMsg::Unit => set_difficulty(1.0).to_line(),
        DifficultyMsg::NiceHash => set_difficulty(nicehash_difficulty(&boundary)).to_line(),
        DifficultyMsg::Mrr => set_difficulty(mrr_difficulty(&boundary)).to_line(),
    };
    frames.push_str(&notify(a.id, &a.job, &boundary, a.clean).to_line());
    write_frame(write, &frames).await
}

async fn write_frame(write: &mut (impl AsyncWriteExt + Unpin), frame: &str) -> std::io::Result<()> {
    match tokio::time::timeout(WRITE_TIMEOUT, write.write_all(frame.as_bytes())).await {
        Ok(result) => result,
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "write to miner timed out",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limiter_caps_events_and_refills() {
        let t0 = Instant::now();
        let mut rl = RateLimiter::new(3, Duration::from_secs(1), t0);
        assert!(rl.allow(t0));
        assert!(rl.allow(t0));
        assert!(rl.allow(t0));
        assert!(!rl.allow(t0), "4th in the same window is over budget");
        assert!(rl.allow(t0 + Duration::from_millis(1001)), "window refills");
    }

    #[test]
    fn rate_limiter_zero_is_disabled() {
        let t0 = Instant::now();
        let mut rl = RateLimiter::new(0, Duration::from_secs(1), t0);
        for _ in 0..10_000 {
            assert!(rl.allow(t0));
        }
    }

    #[test]
    fn candidate_errors_retry_fast_then_back_off_to_the_poll_interval() {
        let poll = Duration::from_secs(5);
        assert_eq!(error_backoff(1, poll), Duration::from_millis(100));
        assert_eq!(error_backoff(2, poll), Duration::from_millis(200));
        assert_eq!(error_backoff(4, poll), Duration::from_millis(800));
        assert_eq!(error_backoff(7, poll), poll, "capped");
        assert_eq!(error_backoff(u32::MAX, poll), poll, "no overflow");
        assert_eq!(
            error_backoff(1, Duration::from_millis(50)),
            Duration::from_millis(50)
        );
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

    #[test]
    fn lane_guard_returns_its_lane_on_drop() {
        let pool = Arc::new(Mutex::new(LanePool::new(1)));
        let lane = pool.lock().unwrap().acquire().unwrap();
        let guard = LaneGuard {
            pool: pool.clone(),
            lane,
        };
        assert_eq!(pool.lock().unwrap().in_use(), 1);
        drop(guard);
        assert_eq!(pool.lock().unwrap().in_use(), 0);
    }

    // The supervision mechanism `serve()` relies on: a spawned forever-task that
    // dies (panics) resolves its JoinHandle to Err, so a `select!` on `&mut handle`
    // fires — that's what lets `serve()` exit non-zero for a supervised restart.
    #[tokio::test]
    async fn a_dead_background_task_is_observable_via_its_join_handle() {
        let mut task = tokio::spawn(async { panic!("simulated poller death") });
        let fired_on_death = tokio::select! {
            outcome = &mut task => outcome.is_err(), // JoinError from the panic
            _ = tokio::time::sleep(Duration::from_secs(5)) => false,
        };
        assert!(
            fired_on_death,
            "a panicked task must resolve its handle to Err so serve() can react"
        );
    }
}

/// End-to-end: a real TCP miner against [`serve`], with a mock node over HTTP.
#[cfg(test)]
mod e2e {
    use super::*;

    use std::sync::atomic::AtomicU32;

    use serde_json::{json, Value};
    use tokio::io::{AsyncBufReadExt, BufReader};
    use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
    use tokio::sync::oneshot;

    use crate::config::VardiffCfg;

    const MSG_HEX: &str = "1111111111111111111111111111111111111111111111111111111111111111";

    /// 2^256: every Autolykos2 hit is below it, so ANY nonce is a block.
    fn candidate_body() -> String {
        let b = num_bigint::BigUint::from(1u8) << 256;
        format!(r#"{{"msg":"{MSG_HEX}","b":{b},"h":1000,"pk":null}}"#)
    }

    #[derive(Default)]
    struct MockNode {
        /// Body served for `/mining/candidate`; `None` -> 503 (node unavailable).
        candidate: Mutex<Option<String>>,
        candidate_queries: Mutex<Vec<String>>,
        solutions: Mutex<Vec<String>>,
        /// Answer this many solution POSTs with 503 before accepting.
        fail_solutions: AtomicU32,
    }

    async fn spawn_mock_node(state: Arc<MockNode>) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (sock, _) = listener.accept().await.unwrap();
                let state = state.clone();
                tokio::spawn(async move {
                    let _ = mock_exchange(sock, state).await;
                });
            }
        });
        addr
    }

    async fn mock_exchange(mut sock: TcpStream, st: Arc<MockNode>) -> std::io::Result<()> {
        let mut data = Vec::new();
        let mut buf = [0u8; 1024];
        let head_end = loop {
            let n = sock.read(&mut buf).await?;
            if n == 0 {
                return Ok(());
            }
            data.extend_from_slice(&buf[..n]);
            if let Some(p) = data.windows(4).position(|w| w == b"\r\n\r\n") {
                break p + 4;
            }
        };
        let head = String::from_utf8_lossy(&data[..head_end]).to_string();
        let target = head
            .lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .unwrap_or_default()
            .to_string();
        let len = head
            .lines()
            .filter_map(|l| l.split_once(':'))
            .find(|(k, _)| k.trim().eq_ignore_ascii_case("content-length"))
            .and_then(|(_, v)| v.trim().parse::<usize>().ok())
            .unwrap_or(0);
        while data.len() < head_end + len {
            let n = sock.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            data.extend_from_slice(&buf[..n]);
        }
        let body = String::from_utf8_lossy(&data[head_end..]).to_string();

        let (status, reply) = if target.starts_with("/mining/candidate") {
            st.candidate_queries.lock().unwrap().push(target.clone());
            match st.candidate.lock().unwrap().clone() {
                Some(c) => (200, c),
                None => (503, r#"{"error":503,"reason":"unavailable"}"#.to_string()),
            }
        } else if target.starts_with("/mining/solution") {
            st.solutions.lock().unwrap().push(body);
            let fail = st
                .fail_solutions
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                .is_ok();
            if fail {
                (503, r#"{"error":503,"reason":"unavailable"}"#.to_string())
            } else {
                (200, "{}".to_string())
            }
        } else {
            (404, "{}".to_string())
        };
        let resp = format!(
            "HTTP/1.1 {status} MOCK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}",
            reply.len()
        );
        sock.write_all(resp.as_bytes()).await?;
        sock.shutdown().await
    }

    fn test_config(node: SocketAddr) -> Config {
        Config {
            node_url: format!("http://{node}"),
            bind_addr: "127.0.0.1:0".into(),
            api_key: None,
            poll_interval: Duration::from_millis(50),
            longpoll: true,
            stale_work: None,
            block_version: 3,
            partition_bytes: None,
            vardiff: VardiffCfg {
                initial: 1000,
                min: 1,
                max: 10_000_000,
                interval_secs: 15.0,
            },
            stratum_password: None,
            set_difficulty: true,
            set_difficulty_value: DifficultyValue::One,
            max_msgs_per_sec: 0,
            max_invalid_per_min: 0,
            max_connections: 16,
            max_conns_per_ip: 0,
            stats_interval: None,
            stats_bind: None,
        }
    }

    struct Server {
        addr: SocketAddr,
        stop: oneshot::Sender<()>,
        task: tokio::task::JoinHandle<std::io::Result<()>>,
    }

    async fn start_server(config: Config) -> Server {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (stop, stopped) = oneshot::channel::<()>();
        let task = tokio::spawn(serve(config, listener, async {
            let _ = stopped.await;
        }));
        Server { addr, stop, task }
    }

    impl Server {
        async fn shutdown(self) {
            let _ = self.stop.send(());
            let result = tokio::time::timeout(Duration::from_secs(20), self.task)
                .await
                .expect("server shuts down");
            result.expect("server task").expect("clean exit");
        }
    }

    struct Miner {
        lines: tokio::io::Lines<BufReader<OwnedReadHalf>>,
        write: OwnedWriteHalf,
    }

    impl Miner {
        async fn connect(addr: SocketAddr) -> Self {
            let (read, write) = TcpStream::connect(addr).await.unwrap().into_split();
            Self {
                lines: BufReader::new(read).lines(),
                write,
            }
        }

        async fn send(&mut self, v: Value) {
            self.write
                .write_all(format!("{v}\n").as_bytes())
                .await
                .unwrap();
        }

        /// Next frame, or `None` on EOF/reset.
        async fn recv(&mut self) -> Option<Value> {
            let line = tokio::time::timeout(Duration::from_secs(5), self.lines.next_line())
                .await
                .expect("frame within 5s");
            match line {
                Ok(Some(l)) => Some(serde_json::from_str(&l).unwrap()),
                _ => None,
            }
        }

        /// Subscribe (as `agent`) + authorize; every frame up to and including
        /// the first `mining.notify`.
        async fn handshake_as(&mut self, agent: &str) -> Vec<Value> {
            self.send(json!({"id": 1, "method": "mining.subscribe", "params": [agent, "EthereumStratum/1.0.0"]}))
                .await;
            self.send(json!({"id": 2, "method": "mining.authorize", "params": ["rig", "x"]}))
                .await;
            let mut frames = Vec::new();
            loop {
                let frame = self.recv().await.expect("connection open");
                let done = frame["method"] == "mining.notify";
                frames.push(frame);
                if done {
                    return frames;
                }
            }
        }

        /// Subscribe + authorize; returns the first `mining.notify`.
        async fn handshake(&mut self) -> Value {
            self.handshake_as("test/1.0").await.pop().unwrap()
        }
    }

    async fn wait_until(what: &str, cond: impl Fn() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !cond() {
            assert!(Instant::now() < deadline, "timed out waiting for: {what}");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    #[tokio::test]
    async fn a_block_is_delivered_even_if_the_miner_vanishes_and_the_node_blips() {
        let node = Arc::new(MockNode::default());
        *node.candidate.lock().unwrap() = Some(candidate_body());
        node.fail_solutions.store(1, Ordering::SeqCst); // first POST: 503
        let server = start_server(test_config(spawn_mock_node(node.clone()).await)).await;

        let mut miner = Miner::connect(server.addr).await;
        let job = miner.handshake().await;
        assert_eq!(job["params"][2], MSG_HEX);
        assert_eq!(job["params"][8], true, "first job is clean");
        let job_id = job["params"][0].as_str().unwrap().to_string();
        miner
            .send(json!({"id": 4, "method": "mining.submit", "params": ["rig", job_id, "", "", "0a0b0c0d0e0f1011"]}))
            .await;
        drop(miner); // gone before the reply could be written

        wait_until("block retried after the 503 and accepted", || {
            node.solutions.lock().unwrap().len() >= 2
        })
        .await;
        for body in node.solutions.lock().unwrap().iter() {
            assert!(body.contains("0a0b0c0d0e0f1011"), "{body}");
        }
        server.shutdown().await;
    }

    #[tokio::test]
    async fn every_job_is_preceded_by_set_difficulty() {
        let node = Arc::new(MockNode::default());
        *node.candidate.lock().unwrap() = Some(candidate_body());
        let server = start_server(test_config(spawn_mock_node(node.clone()).await)).await;

        // A regular miner gets `[1]` immediately before the notify...
        let mut miner = Miner::connect(server.addr).await;
        let frames = miner.handshake_as("Rigel/1.23.2").await;
        let n = frames.len();
        assert!(n >= 2, "{frames:?}");
        assert_eq!(frames[n - 2]["method"], "mining.set_difficulty");
        assert_eq!(frames[n - 2]["params"], json!([1]));
        assert_eq!(frames[n - 1]["method"], "mining.notify");

        // ...NiceHash gets the share difficulty in its own units, derived from
        // the job's share target: network target 2^256 x vardiff factor 1000.
        let mut nicehash = Miner::connect(server.addr).await;
        let frames = nicehash.handshake_as("NiceHash/1.0.0").await;
        let set = &frames[frames.len() - 2];
        assert_eq!(set["method"], "mining.set_difficulty");
        let d = set["params"][0].as_f64().unwrap();
        let share_target =
            (num_bigint::BigUint::from(1u8) << 256u32) * num_bigint::BigUint::from(1000u32);
        let want = nicehash_difficulty(&share_target);
        assert!((d / want - 1.0).abs() < 1e-9, "{d} vs {want}");
        server.shutdown().await;
    }

    #[tokio::test]
    async fn an_mrr_instance_announces_the_share_difficulty_in_mrr_units() {
        let node = Arc::new(MockNode::default());
        *node.candidate.lock().unwrap() = Some(candidate_body());
        let mut config = test_config(spawn_mock_node(node.clone()).await);
        config.set_difficulty_value = DifficultyValue::Mrr;
        let server = start_server(config).await;
        let mut miner = Miner::connect(server.addr).await;
        let frames = miner.handshake_as("MRR-Hash/1.0.0").await;
        let set = &frames[frames.len() - 2];
        assert_eq!(set["method"], "mining.set_difficulty");
        let share_target =
            (num_bigint::BigUint::from(1u8) << 256u32) * num_bigint::BigUint::from(1000u32);
        let want = mrr_difficulty(&share_target);
        let got = set["params"][0].as_f64().unwrap();
        assert!((got / want - 1.0).abs() < 1e-9, "{got} vs {want}");
        server.shutdown().await;
    }

    #[tokio::test]
    async fn set_difficulty_can_be_disabled() {
        let node = Arc::new(MockNode::default());
        *node.candidate.lock().unwrap() = Some(candidate_body());
        let mut config = test_config(spawn_mock_node(node.clone()).await);
        config.set_difficulty = false;
        let server = start_server(config).await;
        let mut miner = Miner::connect(server.addr).await;
        let frames = miner.handshake_as("Rigel/1.23.2").await;
        assert!(frames
            .iter()
            .all(|f| f["method"] != "mining.set_difficulty"));
        server.shutdown().await;
    }

    #[tokio::test]
    async fn candidates_are_long_polled_with_the_held_template() {
        let node = Arc::new(MockNode::default());
        *node.candidate.lock().unwrap() = Some(candidate_body());
        let server = start_server(test_config(spawn_mock_node(node.clone()).await)).await;

        let want = format!("longpoll={MSG_HEX}");
        wait_until("a long-poll request naming the held msg", || {
            node.candidate_queries
                .lock()
                .unwrap()
                .iter()
                .any(|q| q.contains(&want))
        })
        .await;
        server.shutdown().await;
    }

    #[tokio::test]
    async fn stale_work_is_withdrawn_and_reissued_when_the_node_recovers() {
        let node = Arc::new(MockNode::default());
        *node.candidate.lock().unwrap() = Some(candidate_body());
        let mut config = test_config(spawn_mock_node(node.clone()).await);
        config.stale_work = Some(Duration::from_millis(300));
        let server = start_server(config).await;

        let mut miner = Miner::connect(server.addr).await;
        miner.handshake().await;

        // Node goes away: the miner must be disconnected (so it can fail over)
        // instead of grinding a dead template.
        *node.candidate.lock().unwrap() = None;
        loop {
            match miner.recv().await {
                None => break, // disconnected
                Some(frame) => assert_ne!(frame["method"], "mining.notify"),
            }
        }

        // Node is back with the SAME template: a reconnecting miner gets it again.
        *node.candidate.lock().unwrap() = Some(candidate_body());
        let mut again = Miner::connect(server.addr).await;
        let job = again.handshake().await;
        assert_eq!(job["params"][2], MSG_HEX);
        server.shutdown().await;
    }

    #[tokio::test]
    async fn queued_blocks_are_drained_on_shutdown() {
        let node = Arc::new(MockNode::default());
        let addr = spawn_mock_node(node.clone()).await;
        let client = Arc::new(NodeClient::new(&format!("http://{addr}"), None));
        let (tx, rx) = mpsc::unbounded_channel();
        let (stop_tx, stop_rx) = watch::channel(false);
        tx.send(FoundBlock {
            worker: "rig".into(),
            height: 1,
            nonce: [7; 8],
        })
        .unwrap();
        stop_tx.send(true).unwrap(); // shutdown already requested
        let stats = Arc::new(Stats::default());
        tokio::time::timeout(
            Duration::from_secs(10),
            submit_blocks(client, rx, stats.clone(), Arc::new(Notify::new()), stop_rx),
        )
        .await
        .expect("submitter drains and returns");
        assert_eq!(node.solutions.lock().unwrap().len(), 1);
        assert_eq!(stats.snapshot(Instant::now()).blocks.accepted, 1);
    }

    #[tokio::test]
    async fn stats_endpoint_serves_json() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let stats = Arc::new(Stats::default());
        stats.candidate_ok(1234, true, Instant::now());
        tokio::spawn(serve_stats(listener, stats));

        let mut sock = TcpStream::connect(addr).await.unwrap();
        sock.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        let mut resp = String::new();
        sock.read_to_string(&mut resp).await.unwrap();
        assert!(resp.starts_with("HTTP/1.1 200 OK"), "{resp}");
        let body = resp.split("\r\n\r\n").nth(1).unwrap();
        let v: Value = serde_json::from_str(body).unwrap();
        assert_eq!(v["node"]["height"], 1234);
    }
}
