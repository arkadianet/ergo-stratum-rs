# ergo-stratum-rs

A modern **Rust Stratum server for solo GPU mining to any Ergo node** (Autolykos2) —
the `ergo-solo` binary.

> Clone, `cargo build`, point Rigel at it. A single static binary — no runtime and
> no native build dependencies.

Point your GPU miner (Rigel, lolMiner, …) at `ergo-solo`, point `ergo-solo` at your
Ergo node, and mine. Block rewards go straight to **your node's own reward
address** — there is no custody, no pool account, and nothing to configure for
payouts.

`ergo-solo` is a single static Rust binary — no runtime and no native build
dependencies — that reuses the Ergo node's **own consensus Autolykos2** for share
validation, never a re-implementation.

## Why this exists

An Ergo node speaks only the **HTTP mining API** (`GET /mining/candidate`,
`POST /mining/solution`). GPU miners speak **Stratum**. So something has to bridge
the two — the node has no Stratum server, and no built-in GPU/CPU miner. `ergo-solo`
is that bridge:

```
  GPU miner (Rigel)            ergo-solo                 Ergo node
  ───────────────────  stratum  ─────────────  HTTP  ───────────────
  Autolykos2 hashing  ───────▶  serve jobs    ─────▶  /mining/candidate
  submit share        ◀───────  validate PoW          /mining/solution
                                submit block  ─────▶  (reward → node address)
```

Because the Ergo HTTP mining API is identical on the reference (Scala) node and on
Rust nodes, `ergo-solo` works against **any** Ergo node with mining enabled.

## Quick start

**1. Run your node with mining enabled** and a reward address set (the block reward
goes there). Confirm it serves work:

```bash
curl http://127.0.0.1:9052/mining/candidate
# -> {"msg":"...","b":...,"h":...,"pk":"..."}
```

**2. Run ergo-solo:**

```bash
ergo-solo --node-url http://127.0.0.1:9052 --network mainnet
# stratum server listening on 0.0.0.0:3055
```

**3. Point your GPU miner at it:**

```bash
# Rigel
rigel -a autolykos2 -o stratum+tcp://<HOST>:3055 -u rig1 -w rig1

# lolMiner
lolMiner --algo AUTOLYKOS2 --pool <HOST>:3055 --user rig1
```

Solo: the username is just a label — the reward follows your **node's** reward
address. Run as many rigs as you like against one node.

## Testnet

Testnet difficulty is trivially low, so a fast GPU would flood a mainnet-tuned
share difficulty. Pass `--network testnet` and `ergo-solo` pins a hard vardiff floor
automatically:

```bash
ergo-solo --node-url http://127.0.0.1:9052 --network testnet
```

## Configuration

Every flag has an `ERGO_SOLO_*` environment equivalent.

| Flag | Default | Meaning |
|------|---------|---------|
| `--node-url` | `http://127.0.0.1:9052` | Ergo node base URL |
| `--bind` | `0.0.0.0:3055` | stratum listen address (miners connect here) |
| `--api-key` | — | node API key, if the node's API is key-protected |
| `--network` | `mainnet` | `mainnet` or `testnet` (sets the default vardiff floor) |
| `--poll-secs` | `5` | candidate poll interval — only the fallback when the node doesn't support long-poll |
| `--no-longpoll` | off | disable `/mining/candidate?longpoll=<msg>` (new work the instant the node has it) |
| `--stale-work-secs` | `60` | after this long without a fresh candidate, withdraw the job and disconnect miners so their backup pool takes over (`0` = never) |
| `--block-version` | `3` | block version stamped on jobs (`>= 2`; selects the Autolykos2 table schedule) |
| `--vardiff-initial/min/max` | network-based | override the share-difficulty envelope (validated at startup) |
| `--vardiff-interval` | `15` | target seconds between shares per worker |
| `--stratum-password` | — | require this password in `mining.authorize`; set it before exposing the port |
| `--no-set-difficulty` | off | stop sending `mining.set_difficulty` before each job (see below) |
| `--max-msgs-per-sec` | `0` (off) | control-message flood cap (share submits are never counted) |
| `--max-invalid-per-min` | `0` (off) | drop a connection sending more invalid shares than this per minute (stale shares don't count) |
| `--max-connections` | `1024` | global connection cap |
| `--max-conns-per-ip` | `0` (off) | per-source-IP connection cap |
| `--partition` | off | give each connection its own nonce lane (see below) |
| `--partition-bytes` | `2` | pool-owned prefix bytes per lane when partitioning (2 → 2⁴⁸ nonces per connection) |
| `--stats-interval-secs` | `300` | per-worker stats line in the log (`0` = off) |
| `--stats-bind` | — | serve a JSON stats snapshot at `http://HOST:PORT/` (keep it private) |

Logging: `RUST_LOG=debug ergo-solo …` for per-share detail. Colour codes are only
emitted on a terminal, so journald logs stay clean.

### One rig vs. a farm (`--partition`)

By default every connection is handed the **whole 8-byte nonce space**, which is
right for one or a few of your own rigs (miners randomize where they start, and
an overlap between your own rigs just wastes a little duplicate work — never wrong
for solo).

`--partition` gives each live connection its own disjoint lane instead. The lane
size is what matters: the miner's slice must outlast a job at its hashrate. The
default `--partition-bytes 2` leaves every connection 2⁴⁸ nonces (~78 hours of
work at 1 GH/s, ~4.7 minutes at 1 TH/s) and allows 65,536 concurrent connections.
**Don't use 4** — that leaves only 2³² nonces (~4.3 s at 1 GH/s), which starves any
modern rig and floods stale rejects (this is what the old 4-byte default did).

> **Migration:** partitioning used to be **on** by default (flag `--no-partition` /
> env `ERGO_SOLO_NO_PARTITION`). It is now **off** by default and the flag is
> `--partition` (env `ERGO_SOLO_PARTITION=true`). A multi-rig farm that relied on the
> old default must now pass `--partition` explicitly. Lanes are now 2 bytes
> (was 4) — pass `--partition-bytes 4` only if a miner insists on a 4-byte
> extranonce1.

## How it works

- A **work poller** long-polls `/mining/candidate?longpoll=<msg>`: a node that
  supports it (the Rust node does) answers the moment its template changes, so a
  new block reaches miners immediately. Other nodes answer at once and are polled
  every `--poll-secs`. A fresh Stratum job is emitted only when the template
  changes.
- Miners are told to drop their work (`clean_jobs`) only when the **height**
  changes. The node refreshes its template several times per block (an empty one
  first, then with transactions) and accepts solutions for recent ones, so shares
  for any recent template at the current height are still graded — and a block
  found on one is still submitted.
- Each connection gets a **vardiff** controller that judges the share rate over a
  window (8 shares, or 8 target intervals) and eases a worker that has gone quiet;
  share targets adapt so any GPU (or a whole farm) sits near one share every ~15s.
  Every share is graded at the difficulty **it was sent** — a retarget is
  delivered as a new job and never retroactively rejects in-flight shares.
- Submitted nonces are graded with the node's **consensus Autolykos2 PoW**
  (`hit < target`, exactly as consensus). A block is queued for submission
  *before* the miner is even answered, POSTed to `/mining/solution` with retries
  on transient node errors, and queued blocks are still delivered on shutdown.
- If the node stops serving work (down, restarting, resyncing) for
  `--stale-work-secs`, miners are disconnected instead of grinding a dead
  template, so a configured backup pool can take over.
- Solo means there is **no payout accounting** — the node mints the block to its
  configured reward address.

## Monitoring

Every `--stats-interval-secs` the log gets one line per active worker:

```
INFO worker stats worker=popos.rtx3090 connections=1 hashrate="251.40 MH/s" hashrate_avg="248.97 MH/s" accepted=412 stale=3 rejected=0 blocks=1
```

`hashrate` is **measured from accepted shares** — each share counts the expected
hashes at the difficulty it was assigned — over the last 10 minutes;
`hashrate_avg` is since the worker first connected, downtime included. Totals
survive reconnects (not restarts). `--stats-bind 127.0.0.1:3057` serves the same
data, plus node health and block outcomes, as JSON:

```bash
curl -s http://127.0.0.1:3057/
```

## Rented hashrate / exposing the port

You can point rented hashrate (or rigs elsewhere) at a public `ergo-solo`. Things
to do first:

- Set `--stratum-password` and give it to the rental as the pool password.
- Forward **only** the stratum port; never expose the node API or `--stats-bind`.
- Consider `--max-invalid-per-min` (e.g. `60`) so junk submissions can't burn CPU
  on PoW checks.
- If the rental service splits your connection across many rigs and needs its own
  extranonce space, try the default whole-space mode first; otherwise
  `--partition` (2-byte lanes).
- Use the measured `hashrate_avg` for the rental's worker to check you received
  what you paid for. Over an hour at ~15 s/share the estimate is good to roughly
  ±6%; shorter windows are noisier.

Every job is preceded by `mining.set_difficulty`, as rental proxies expect
(MiningRigRentals' pool test fails without it). Following Miningcore's Ergo
convention the value is `1`, because the real share target is already in the
job; a client that announces itself as NiceHash instead gets the share
difficulty in NiceHash's units. `--no-set-difficulty` turns this off if a miner
ever misbehaves on receiving it.

Caveats: compatibility with NiceHash / MiningRigRentals proxies is still to be
proven end-to-end (run their pool checkers, then a short rental, and compare the
service's hashrate figure with ours); runtime `mining.set_extranonce` is not
implemented; there is no TLS (terminate it in front with e.g. stunnel or haproxy if
the service requires `stratum+ssl`). And remember solo mining with rented hashrate
is a lottery — expected value is usually at or below the rental price, with large
variance.

## Building from source

```bash
cargo build --release   # binary at target/release/ergo-solo
```

Builds out of the box — no private dependencies. The workspace has two crates:

- **`ergo-stratum`** — the reusable share-validation + Stratum (EthereumStratum/1.0.0)
  protocol + vardiff core. It reuses the Ergo node's own **`ergo-crypto`** consensus
  Autolykos2, pulled as a git dependency from the public
  [`arkadianet/ergo`](https://github.com/arkadianet/ergo) node repo — never a
  re-implementation, never sigma-rust.
- **`ergo-solo`** — the thin async TCP server binary.

For a tagged release, pin `ergo-crypto` to a specific rev in the root `Cargo.toml`
for reproducibility, and ship a static `x86_64-unknown-linux-musl` binary as the
release artifact.

## License

Licensed under either of [Apache License 2.0](LICENSE-APACHE) or
[MIT License](LICENSE-MIT) at your option.
