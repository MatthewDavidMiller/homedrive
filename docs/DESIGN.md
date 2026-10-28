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
| `hd-chunk` | FastCDC content-defined chunking and `ObjectId` (SHA-256), shared by the server and the client | M1 |
| `hd-store` | The storage engine: the store sentinel and lock, and content-addressed objects | M1 (journal and namespace: M2; versions and GC: M3) |
| `hd-server` | Configuration, routing, and the `hd-server` binary. It opens the store and answers `/healthz` | M0, M1 |

## Chunking (`hd-chunk`)

Files are cut with FastCDC using normalised chunking at level 2. Chunks are
at least 256 KiB (except a file's last), aim for 1 MiB, and are at most
4 MiB. Before the 1 MiB point a cut needs the top 22 bits of the gear hash
to be zero, and after it the top 18.

Gear entry `i` is the first eight bytes, big-endian, of
SHA-256(`"homedrive/fastcdc/gear/v1"` || `i`). Tests pin the table's hash
and the cut points of a fixed pseudo-random input. Both pins were
reproduced by a separate Python implementation, so they check the format,
not the code against itself. Changing any of this is a format change.

A chunk's ID is the plain SHA-256 of its bytes, so a client computes it
without knowing anything about the store.

## The store (`hd-store`)

```text
store.id                   sentinel: "homedrive store", format 1, a random id
meta/LOCK                  exclusive lock held by the open store
chunks/ab/cd/<id>          object files (manifests/ the same way)
quarantine/<kind>-<id>-<ms>-<rand>   objects that failed verification
tmp/                       staging for writes
```

- **Fail closed.** `Store::open` refuses a directory with no valid
  `store.id`, because that is what an unmounted disk looks like.
  `hd-server init` writes the sentinel, and only into an empty directory
  (`lost+found` is allowed).
- **Object files** are a 16-byte header (`HDO1`, version 1, kind,
  little-endian length) followed by the bytes, with mode 0400.
- **Writes never replace anything.** `fsio::write_new_durable` stages in
  `tmp/`, fsyncs, hard-links into place (the commit point; a link never
  replaces a name), and fsyncs the directory. Fan-out directories are made
  with `fsio::mkdir_durable`, which fsyncs each parent. Staging leftovers
  from a crash are removed when the store opens, under the lock.
- **Every read is verified**: header, file size against the header length,
  no trailing bytes, then SHA-256 against the name. A failing object is
  moved to `quarantine/`, never deleted, and then reads as missing. The
  next upload of the same content writes a good copy, so the store heals.
  `put` on an existing name verifies the existing copy first and replaces
  it the same way if it is bad.
- **Free-space reserve.** Writes are refused while the filesystem has
  less than `HD_MIN_FREE_GB` free (statvfs). Reads, and puts of content
  already stored, keep working.

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
