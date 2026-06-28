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
| `--poll-secs` | `5` | `/mining/candidate` poll interval |
| `--block-version` | `3` | block version stamped on jobs |
| `--vardiff-initial/min/max` | network-based | override the share-difficulty envelope |
| `--max-msgs-per-sec` | `0` (off) | control-message flood cap (share submits are never counted) |
| `--max-connections` | `1024` | global connection cap |

Logging: `RUST_LOG=debug ergo-solo …` for per-share detail.

## How it works

- A **work poller** hits `/mining/candidate` on a timer and emits a fresh Stratum
  job only when the template changes.
- Each connection gets a **vardiff** controller; share targets adapt per worker so
  any GPU (or a whole farm) sits near one share every ~15s.
- Submitted nonces are graded with the node's **consensus Autolykos2 PoW**. A nonce
  that meets the network target is a block and is POSTed to `/mining/solution`.
- Solo means there is **no accounting and no on-chain payout** — the node mints the
  block to its configured reward address.

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
