# Design

homedrive is built milestone by milestone, following
[PLAN.md](PLAN.md). The plan is the authoritative design until each
part is built. When a milestone lands, the design it settled is written
up here, describing the code as it is.

## Crates

| Crate | Role | State |
|---|---|---|
| `hd-sys` | The only `unsafe`: libcrypto (SHA-256 one-shot and streaming, HMAC, CSPRNG, constant-time compare, cleanse), getrandom, and signal handling | M0 |
| `hd-crypto` | Safe wrappers: `sha256`, the streaming `Sha256`, HMAC, HKDF, `SecretBytes`, `hex` | M0 |
| `hd-common` | Errors, bounded buffers, bounded and durable file IO (`fsio`), strict JSON, base64, randomness, UTC time | M0 |
| `hd-http` | A bounded HTTP/1.1 server, one thread per connection, with Range and streamed response bodies | M0 (streamed requests and keep-alive: M4) |
| `hd-server` | Configuration, routing, and the `hd-server` binary. It answers `/healthz` | M0 |

## Process model

The server is one process. As PID 1 in its container it blocks SIGTERM and
SIGINT before starting any thread, and a dedicated thread takes them and
exits. This is safe because the server acknowledges a write only once it is
durable on disk, so there is never anything in memory to flush.

## Enforced rules

`scripts/check-rust.sh` enforces the rules from [AGENTS.md](../AGENTS.md)
that can be checked mechanically:
- the workspace-only dependency graph;
- the native library allowlist (`crypto`, `ssl`, `pthread`);
- `unsafe` only in `hd-sys`;
- no subprocesses;
- file writes only through `fsio`;
- deletion only in `fsio`, GC and the client trash.
