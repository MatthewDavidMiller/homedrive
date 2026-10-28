# Design

homedrive is built milestone by milestone, following
[PLAN.md](PLAN.md). The plan is the authoritative design until each
part is built. When a milestone lands, the design it settled is written
up here, describing the code as it is.

## Crates

| Crate | Role | State |
|---|---|---|
| `hd-sys` | The only `unsafe`: libcrypto (SHA-256 one-shot and streaming, HMAC, CSPRNG, constant-time compare, cleanse), getrandom, signals, statvfs, inotify, and (feature `tls`, client only) a libssl client | M0, M7 |
| `hd-crypto` | Safe wrappers: `sha256`, the streaming `Sha256`, HMAC, HKDF, `SecretBytes`, `hex` | M0 |
| `hd-common` | Errors, bounded buffers, bounded and durable file IO (`fsio`), strict JSON, base64, randomness, UTC time | M0 |
| `hd-http` | A bounded HTTP/1.1 server, one thread per connection: keep-alive, streamed request bodies (length or chunked, with 100-continue), streamed and ranged responses, the WebDAV methods | M0, M4 |
| `hd-api` | The sync protocol's JSON messages, shared by the server and the client | M4 |
| `hd-chunk` | FastCDC content-defined chunking and `ObjectId` (SHA-256), shared by the server and the client | M1 |
| `hd-store` | The storage engine: the sentinel and lock, content-addressed objects, the metadata journal, snapshots and model, manifests and whole files, conflicts, retention, GC, scrub, and fsck | M1–M3 |
| `hd-server` | Configuration, accounts and sign-in, the sync API, WebDAV, the web UI, background maintenance, and the `hd-server` binary | M0–M6 |
| `hd-client` | The sync engine, its state, the client trash, an HTTP/TLS client, and the `homedrive` command | M7 |

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

## Metadata (`hd-store`: `model`, `journal`, `meta`)

**The model.** Each user has a namespace: a sorted map from path to entry
(a directory, or a file with its versions oldest first), a trash, and the
paths removed (for the change feed). Paths are validated by
`hd_common::pathname`: relative, `/`-separated, UTF-8, no empty, `.` or
`..` component, no control characters, at most 255 bytes per name and 64
deep. `State::apply` is deterministic (no clock, no randomness, no I/O),
and every ID comes from the state's own counter, so replaying the journal
always rebuilds the same state. Every operation is validated before it is
written, so a record that fails to apply on replay stops the store.

No operation destroys content: overwrites add versions, deletes move a
subtree into the trash, and moves keep history. Only `DropVersion` (never
the current version) and `Purge` release anything, and only retention
issues them.

**The journal.** `meta/journal.<first seq>` holds a 16-byte header, then
records:

```
len (u32) · !len (u32) · body (seq u64 + op) · SHA-256(len · !len · body)
```

A commit validates the op, appends its record and fdatasyncs, and only
then applies it in memory. Any write failure *poisons* the metadata: later
writes are refused until a restart, because a partial record must never
be buried under later ones.

**Torn tails.** On recovery, only the newest journal may end badly, in one
of two ways:
- **Torn:** the length is intact but the record runs past the end of the
  file, or the tail is all zero bytes. This is set aside automatically.
- **Corrupt:** anything else that fails its check. The store refuses to
  open; `repair_tail` (`fsck --repair-tail`) sets it aside.

"Set aside" always means copied durably to `quarantine/` first, then cut.
The length is stored with its complement so a flipped length bit reads as
corruption, never as "torn": otherwise recovery could cut off records that
were acknowledged.

**Snapshots.** `meta/snapshot.<seq>` is the whole state with a SHA-256
trailer, written with the no-replace durable write. A checkpoint writes
one, starts `journal.<seq+1>`, and prunes. The newest three snapshots are
kept, and a journal is deleted only once the next journal starts at or
before the record after the oldest kept snapshot. If a snapshot fails
verification it is quarantined and the next older one is used.

**Recovery** (`Meta::open`) finds the newest good snapshot and replays
every later record. A gap in the records refuses to open. Appends continue
the newest journal only if its own numbering leads straight to the next
record; otherwise a new journal is started (an empty out-of-sequence one
is quarantined).

**Tests** (`crates/hd-store/tests/crash.rs`) cover the guarantee that an
acknowledged change is never lost and none is invented:
- cut the journal at every byte;
- fail every durable-write step (write, fsync, link, rename, mkdir) in a
  script that uses every operation, with manual and with automatic
  checkpoints;
- fail every step of recovery itself;
- flip bytes in middle and final records;
- damage the newest snapshots;
- remove a journal.

The fault hooks live in `fsio` and are compiled in only with
`hd-common`'s `faults` feature (tests).

## Files, conflicts, and maintenance (`hd-store`: `manifest`, `files`, `retention`, `gc`, `scrub`, `fsck`)

**Manifests** list a file's chunks with its size and SHA-256 (`HDM1`). A
file with more than about 116,000 chunks gets an *indirect* manifest: the
list is stored as chunks and the manifest points to those. A manifest is an
object named by its hash, so identical files share one.

**Writing.**
- `write_file` chunks a stream (WebDAV PUT, import).
- `commit_chunks` takes a client's list of already-uploaded chunks. Every
  chunk must be present and intact, and together they must hash to the
  claimed SHA-256, or nothing is recorded; a missing chunk is reported so
  the client uploads it.

Content identical to the current version adds no version.

**Conflicts.** A commit names the version it was based on (`Base::Version`),
expects nothing there (`Base::Absent`), or accepts anything (`Base::Any`).
When the expectation fails, or a directory is in the way, the content is
stored as a sibling: `<stem> (conflict <device> <yyyy-mm-dd hhmm>).<ext>`,
numbered if that name is taken. Both copies are kept and nothing is
overwritten.

**Reading.** `FileReader` verifies every chunk against its ID, and on a
read from the start also checks the whole-file hash at the end. A failure
is an error, never a short or wrong body.

**Retention** plans `DropVersion` and `Purge` operations as a pure function
of the state and the time:
- every version younger than 30 days is kept;
- then the newest per day to 90 days, per week to a year, and per month
  after that;
- the current version always stays;
- trash is purged after 90 days.

**GC** is mark-and-sweep:
- Mark everything the live and trashed versions reference. An unreadable
  manifest aborts the run.
- Stage 1 moves an unreferenced object older than the 48-hour grace period
  to `gc-trash/<day>/`.
- Stage 2 deletes it after a 7-day hold, unless a fresh mark shows it is
  referenced again, in which case it is put back.

Commits run under the read side of a GC gate. While a collection runs they
record the objects they use (a deduplicated upload can reuse an old
unreferenced object). The collector moves each object under the write side
and skips any that a commit has used since the mark.

**Scrub** re-verifies every object, throttled, and quarantines damage.
**fsck** is read-only: it checks that every live and trashed version's
manifest and chunks are present (or, with `--deep`, intact and hashing
correctly), and names each damaged file.

**Tests.**
- `tests/files.rs` covers round trips with ranges, deduplication,
  verification of chunked commits, every conflict case, damage that is
  reported, never served, and healed by a re-upload, GC stages and its
  dry run, reuse of unreferenced content, and indirect manifests.
- `tests/model.rs` runs hundreds of random operations against a reference
  model, then retention, two maximally aggressive collections, and a
  reopen. Every live file must match the model, and every listed version
  must read back byte for byte with a clean deep fsck.

## HTTP (`hd-http`)

There is one thread per connection, at most 128 connections. A connection
is kept alive only after a cleanly finished exchange:
- the body was fully read, or under 64 KiB and drained;
- the response is framed by its length;
- neither side asked to close.

The first request must arrive within 15 s, and later ones within 10 s of
idleness.

Bodies are read lazily through `Request::body()`, which decodes
Content-Length or chunked framing and sends `100 Continue` on first use.
A request with both framings, two lengths, or an unknown transfer coding
is refused (the classic smuggling shapes). A streamed response that fails
part-way is never completed: the connection closes short of its
Content-Length, so a client cannot take a partial body for a whole one.

## Accounts, devices, and the sync API (`hd-server`: `auth`, `api`)

**Accounts** come from the users file at start-up. Each password is
replaced by an HMAC under a random key made for that process, and checked
in constant time. An unknown name costs the same as a wrong password.

**Devices.** `POST /api/v1/devices` with the account password returns a
token, `hd1_<device id>_<64 hex>`. The journal keeps only the SHA-256 of
its secret (`DeviceAdd`), and revoking it is a `DeviceRevoke`. A token
works as `Authorization: Bearer`, or as the password in Basic auth for its
own user, which is what rclone and phone apps store.

**Throttling.** After 10 failed sign-ins in 15 minutes from one address,
that address is refused with 429. Behind Traefik the address is the
right-most `X-Forwarded-For` entry, believed only from
`HD_TRUSTED_PROXIES`.

**The API** is listed in `crates/hd-api/src/lib.rs`. Its essentials:
- The change feed returns each user's entries changed after a cursor
  (the global sequence number), with deletions. Pages never split one
  record's changes, and `wait=` long-polls on a condition variable that
  every commit signals. A cursor from the future (a store restored from
  an older backup) gets a full listing flagged `reset`.
- Uploads: ask which chunks are missing, `PUT` those (each is re-hashed
  against its ID, and a mismatch is 422), then commit with a base. Missing
  chunks get 409 with the list. The commit re-hashes the whole file from
  the stored chunks.
- Downloads stream the version through `FileReader` (verified), with
  Range and an `ETag` of the version ID.

Chunks are shared across users for deduplication, so a user who knows a
chunk's SHA-256 can fetch it, or learn that it is stored. Knowing the hash
of a chunk means already knowing its content, so the exposure is limited
to confirming that some user stores a given chunk. That is accepted for a
homelab and noted here.

**Maintenance.** While serving, the server runs:
- a checkpoint every 10 minutes when something has changed;
- retention then GC every `HD_MAINTENANCE_HOURS`, the first an hour after
  start;
- a throttled scrub every `HD_SCRUB_DAYS`.

`/healthz` answers 503 once the store has stopped accepting writes.

## WebDAV (`hd-server`: `dav`)

`/dav/<user>/<path>` serves the signed-in user's own drive. Any other user
segment gets 403. It is mapped onto the same journaled operations as the
API, so it keeps every guarantee:
- PUT adds a version.
- DELETE, and an overwriting MOVE or COPY, move what they replace to the
  trash first.
- GET is verified as it is sent.

Paths are percent-decoded strictly: anything that is not UTF-8 or does not
validate is refused with 400, never mapped to some other name.
Conditional PUTs (`If-Match`, `If-None-Match: *`) answer 412 before
reading the body. `X-OC-Mtime` sets the modification time.

PROPFIND supports depth 0 and 1 (infinity is refused) and returns a fixed
set of properties: resourcetype, getcontentlength, getlastmodified, getetag
(`"v<version>"`, or `"d<seq>"` for collections), getcontenttype and
displayname. PROPPATCH is accepted and ignored. LOCK hands out
non-enforcing tokens, so macOS Finder and the Windows client will write.

`crates/hd-server/tests/rclone.rs` drives the real rclone from the toolbox
against the server: copy, `check --download`, sync with changes and
deletions, server-side moveto, copyto and purge. It also checks that what
sync replaced or deleted survives as a version or in the trash.
`tests/dav.rs` covers the cases rclone does not reach.

## The web UI (`hd-server`: `web`, `html`, `session`, `multipart`)

Server-rendered HTML with no JavaScript, so it works from a phone:
- **Files:** browse, download, upload (several files at once), new folder,
  move or rename, and move to trash.
- **History:** download any version, or restore one, which adds it as the
  newest version.
- **Trash:** restore to the original place, or beside it as
  "(restored <date>)" if something has taken that name.
- **Devices:** a new token is shown once.
- **Admin** (admins only): store state, free space, quarantined objects,
  what the last start recovered, the outcome of each maintenance job, and
  the accounts.

Sessions are random IDs held in memory, keyed by HMAC under a key that is
random for each process. A restart signs everyone out, and nothing on disk
can be turned into a cookie. Every POST needs the session cookie
(`HttpOnly; SameSite=Strict`, and `Secure` behind HTTPS), a CSRF token
bound to it, and a same-origin request.

Uploads are parsed as a stream (`multipart`): parts go straight into the
chunker, a delimiter split across reads is still found, and the CSRF field
(placed first in the form) is checked before any file data is stored.

## The sync client (`hd-client`)

For each path the engine weighs three things:
- **S**, what it held when last in sync, from the client's state;
- **L**, what is on disk;
- **R**, the server's side, mirrored from the change feed.

The decision table is at the top of `crates/hd-client/src/engine.rs`. In
short:
- One side changed: that change is copied to the other.
- Both changed differently: both are kept.
- An edit always beats a delete.

**Keep both.** The local file is uploaded as new. The server stores it as
a "(conflict ...)" sibling, the client renames its file to match, and then
downloads the other version under the original name.

**The rules that keep files safe:**
- A local file is replaced or deleted only after it is re-checked, right
  before acting, against S: the same size, mtime and inode, or failing
  that the same SHA-256. Its old content goes to the client trash,
  `.homedrive/trash/<time>/` inside the folder: replaced files are
  hard-linked there (no extra space), and deleted files are moved there.
  Items expire after 30 days.
- A file that changes while it is being uploaded is not committed, and is
  retried next round.
- A download is staged beside its target, verified against the server's
  SHA-256 and size, fsynced, and only then given its name, replacing the
  old file or taking an empty name.
- **Losing the state is safe.** Without S the engine can only upload,
  download into an empty place, adopt identical content, or keep both. A
  change feed that reports a `reset` (the server was restored from an
  older backup) wipes S on purpose.
- **Root guard.** A missing folder, or one without its `.homedrive-root`
  marker, stops the round before anything happens, because an unmounted
  disk looks like an empty folder.
- **Mass-delete guard.** A round that would delete more than 50 files, or
  more than 10 that are over 20% of the synced files, performs none of
  those deletions until they are confirmed
  (`homedrive sync --confirm-deletes`). Everything else in the round
  still runs.

**State.** Each folder has `state.snap`, checksummed and atomically
replaced, plus `log.<gen>`, append-only with checksummed records. Opening
compacts them into a new generation. Damage is logged and the damaged part
forgotten, which by the rules above costs only time.

**Watching.** The daemon rescans each folder every 15 seconds, sooner when
inotify reports a change (with a 2-second settle). The scan is the source
of truth, and inotify is only a hint.

**TLS.** OpenSSL's libssl through `hd-sys`, behind a feature, so the
server never links it. It requires TLS 1.2 or newer, verifies the peer
against the system's CA store (or `ca_file`), and checks the hostname with
SNI.

**Tests.** `crates/hd-client/tests/sync.rs` runs two clients and the real
server over loopback:
- round trips with the client trash;
- conflicts, identical adoption, and an edit beating a delete;
- the missing-root, missing-marker and mass-delete guards;
- lost client state;
- a randomized run on two machines. It asserts the machines converge and
  that every content on disk when a sync saw it still exists somewhere: a
  file, a server version, a conflict copy, or a trash.

The randomized run was also checked once with `HD_E2E_SEEDS=60`.

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
