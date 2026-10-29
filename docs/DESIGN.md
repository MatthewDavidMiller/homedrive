# Design

> [!WARNING]
> **Prerelease.** homedrive is prerelease software (0.x) and may have
> issues. Keep an independent backup of anything you store in it. See the
> [README](../README.md).

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
| `hd-server` | Configuration, accounts and sign-in, the sync API, WebDAV, the web UI, exports, the admin socket, background maintenance, and the `hd-server` binary | M0–M8 |
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
history.id                 the identity of this store's history; made when missing
meta/LOCK                  exclusive lock held by the open store
chunks/ab/cd/<id>          object files (manifests/ the same way)
quarantine/<kind>-<id>-<ms>-<rand>   objects that failed verification
tmp/                       staging for writes
```

- **Fail closed.** `Store::open` refuses a directory with no valid
  `store.id`, because that is what an unmounted disk looks like.
  `hd-server init` writes the sentinel, and only into an empty directory
  (`lost+found` is allowed).
- **A restored store starts a new history.** Backups leave out
  `history.id`, and opening a store without one makes a new random one.
  The change feed names it, and a client that sees it change forgets its
  view and compares everything afresh. Sequence numbers alone cannot show
  a restore once new commits carry the restored store past a client's
  cursor, and version numbers from the lost history would then mean other
  content.
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
A read error (a failing disk) is retried once and then quarantined like
damage, and scrub carries on past it. Scrub also verifies every metadata
snapshot and journal, and repairs a damaged one by setting it aside and
writing a fresh checkpoint from the state in memory. Scrub only reads
objects that exist, so a **reference check** (a non-deep fsck) runs after
every collection and scrub, whenever anything is quarantined, and every
10 minutes while damage remains. It finds versions whose manifest or
chunks are gone, which the admin page reports and `GET /api/v1/damaged`
offers to clients that can heal them.

**Retention distrusts a clock that ran ahead.** It runs only while the
store has seen activity within 7 days of the clock's present, and the
server skips it if the wall clock jumps against the monotonic one while it
runs. A clock a year fast would otherwise purge the trash and thin every
history at once.

**Rewind** (`rewind`) puts a user's folder back as it was at a time, for
ransomware, a sync gone wrong, or a mistake across many files. It adds
and never removes:
- a file changed since gets the newest version stored at or before that
  time, as a new version (`Origin::Restore`, device `rewind`);
- an item deleted since comes back from the trash. For each path, the
  first deletion after that time is the one that removed what was there
  then. Items whose files were all made since stay in the trash. A folder
  goes back before a file deleted from it earlier, so the file lands in
  it. An item whose name has been taken since goes beside it as
  `<name> (restored <date>)`;
- a file made since stays, and is reported.

The plan is made from the metadata alone, so the preview and the rewind
agree. Each step is then decided again under the commit lock. A file
changed since the plan, or whose old version retention has dropped
meanwhile, is skipped and reported, never forced. Moves made since are
not undone.

**Activity** (`activity`) finds drives with unusual activity from the
metadata alone, so it needs no state of its own and survives restarts.
Within any one-hour window of the last week it counts distinct files
changed in place (an uploaded version over an older one), files
deleted, and changes that look like encryption, judged on the first
64 KiB of the old and new content with `hd_common::suspect`, as the
client does. Verdicts are cached by version. Imports, restores, rewinds
and copies are not counted. The caller passes when each drive's last
alert was dismissed, and nothing at or before that counts again.
`apply_retention_holding` leaves the drives with alerts alone.

**Executable files.** A version records whether the file is executable.
The flag is the top bit of the origin byte in the record and snapshot
encodings: origins are 1 to 5, so everything written before the flag
existed reads as not executable, which is what it was, and no format
version changed. A commit that does not say (WebDAV, the browser, an
older client) keeps the current version's flag. A change of the flag
alone is a new version.

**Usage** (`Namespace::stored_bytes`) is every version, live and
trashed, at full size: what a quota limits. Deduplication makes the disk
hold less, but counting it per drive would let one user's usage depend on
another's files.

**Repair** (`hd-server repair --from DIR...`) reads every version in full
and replaces each missing, damaged or unreadable object with a verified
copy from another copy of the store (a backup) or from `quarantine/`.
Objects are named by content, so any copy of any age serves.
**fsck** is read-only: it checks that every live and trashed version's
manifest and chunks are present (or, with `--deep`, intact and hashing
correctly), and names each damaged file.

**Tests.**
- `tests/files.rs` covers round trips with ranges, deduplication,
  verification of chunked commits, every conflict case, damage that is
  reported, never served, and healed by a re-upload, GC stages and its
  dry run, reuse of unreferenced content, and indirect manifests.
- `tests/files.rs` also rewinds a folder through in-place encryption,
  renames, a folder deleted after a file in it, and a reused name, and
  checks that nothing since is lost and that a second rewind does nothing.
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
  an older backup) gets a full listing flagged `reset`. Every page names
  the store's `history`.
- Trash takes a precondition: `version` (the file must still be at that
  version) or `if_empty` (the folder must hold nothing). The check and
  the trash are one decision under the commit lock, and a failed check is
  412 with nothing changed. The sync client always sends one: what it
  deletes on the server is what it saw, and another machine's newer edit,
  or a file put in the folder since, is never deleted on a stale view.
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

**Rewind** (`POST /api/v1/rewind`) previews unless `"apply": true`, and
answers with what it did or would do. The web UI offers it under every
folder as a number of hours or days, with a preview page whose second
button carries it out.

**Quotas** (`quota_gb`, required for every account) make it impossible
for the drives to fill the store's disk. At start, the quotas, the
drives of accounts no longer in the users file, and the free-space
reserve must fit on the disk, or the server refuses to start. Usage
counts every version at full size, and storage only ever deduplicates,
so the disk holds at most the sum.

Each drive's room is its quota less its usage less the new chunks it
uploaded for commits not yet made (kept in memory; a restart forgets
them, and GC collects them, while the free-space reserve covers the gap).
Commits check usage plus their size, and then replace their chunks in
the count. Chunk uploads, copies, WebDAV PUT and COPY, web uploads and
admin imports answer 507 (or fail, for imports) with the reason. A
stream of unknown length is written with the room as its size limit, so
it stops at the quota rather than passing it. Restores and rewinds are
not checked: they add versions of content already stored, and are how a
drive is recovered. `whoami` reports `used_bytes` and `quota_bytes`.
When the room left across drives exceeds the disk's free space
(something else uses the disk), admins are warned.

**Alerts.** The maintenance thread runs the activity check every five
minutes and just before retention, which skips drives with an alert. An
alert reaches its owner through `GET /api/v1/status` (and so the sync
clients' notifications), a web UI banner, the admin page, and an `ALERT`
log line. It is dismissed only from a signed-in browser
(`POST /alerts/dismiss`, with CSRF), never with a device token, since
ransomware on a computer holds that computer's token. A dismissal is
written to `alerts-dismissed.json` in the data directory.

**Restores and the drill** (`drill`). `restore_tree` writes a drive's
current files (or a folder's) as plain files, each verified against its
SHA-256 as it is written, with executables executable, and a manifest in
`sha256sum` format (`hd_api::manifest_line`). It runs on any store copy
and never writes into a non-empty directory. `drill` runs a deep fsck on a
store extracted from a backup, restores every drive, and reports the
newest activity in the copy as the time it was taken. `compare` checks a
manifest against the live drive: every file with a version from before
that time must be in the backup, by path or by one of those versions'
content (it may have moved since), and every content in the backup must
be one the drive has held. A restore that passes is therefore complete
as of the backup, byte for byte.

**Copies off the server** (`copy` in `hd-store` and `hd-server`,
`copy` in the client). An administrator's copy is the store's own layout,
so it opens as a store. The server lists, after a checkpoint, `store.id`
and the metadata files with their current lengths, then pages through
every object file name in order; administrators fetch files by their names
in the store, which are checked against a strict pattern (no other path
can be named). The client stages the metadata, fetches only the objects it
lacks, verifies each (header, length, and SHA-256 against its name) before
it takes its name, and only then installs the metadata, removing metadata
files the server no longer keeps. Objects are written before the journal
records naming them, and collection holds unreferenced objects for days,
so every object the installed metadata names is present, even after a run
that was cut off. The web UI streams the same files as a tar.

**Encrypted copies** (`sealed`, on request). A passphrase is stretched
with scrypt (N = 2^17, r = 8, p = 1) and a random salt into a sealing key
and a naming key; the parameters and an HMAC check value (to tell a wrong
passphrase from damage) are kept beside the copy. A sealed file is
`"HDE1"`, a random 12-byte nonce, then AES-256-GCM segments of up to
1 MiB, each with its own nonce (the counter added in) and authenticating
the file's sealed name and whether it is the last. Its plaintext begins
with the store path. On disk it is named by the naming key's HMAC of that
path, which opening checks, so a copy hides paths and content hashes, and
a file altered, swapped, renamed or cut short (even at a segment boundary)
does not open. The client verifies each object in memory and seals it
there, so a copy never holds plaintext even briefly. The web download
wraps the tar stream the same way, behind a header (`"HDK1"`) carrying its
key parameters. The crypto is OpenSSL's (`EVP_PBE_scrypt`,
`EVP_aes_256_gcm`), checked against RFC 7914 and NIST vectors.

**Backup results** (`backups`) are kept in `backups.json` in the data
directory, per kind: the last success, the last failure, and what the run
said. Kinds report through the admin socket (`report`) or, from another
machine, `POST /api/v1/backup-report` with an administrator's token. A
kind whose last run failed, or which has not succeeded for two days (eight
for `drill`), is an administrator problem, as is any failed import in the
last two days (imports are how the other services' backups land) and
quotas that promise more than the disk has free. Administrator problems
appear on the admin page and in administrators' `GET /api/v1/status`, so
their sync clients notify them.

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

**Two machines editing one file at once.** The server decides every
commit and records it under one lock, so commits are strictly ordered
even when they arrive together. Each commit names the version it was
based on. The first to arrive finds that version still current and takes
the name; every later one finds the file has moved on and is stored as a
conflict sibling with a name no other file has. The machine whose edit
became the sibling renames its local copy to match on that round, and on
the next round downloads the winner under the original name. Both
machines end up with both files, and the original stays in the history.

**The rules that keep files safe:**
- A local file is replaced or deleted by first moving whatever is at its
  name into the client trash, `.homedrive/trash/<time>/` inside the
  folder, and then checking what was moved against S: the same size,
  mtime and inode, or failing that the same SHA-256. If it no longer
  matches, it goes back. A download then takes the empty name only if it
  is still empty. Checking first and moving second would leave a moment
  in which an editor's save could land and then be overwritten. A write
  through a handle opened before the move lands in the trashed copy, and
  is kept there. Items expire after 30 days. A changed copy that cannot
  go back (a new file took the name meanwhile) may be the only copy of an
  edit, so it moves on to `.homedrive/kept/`, which never expires.
- Size, mtime and inode are trusted to prove a file unchanged only if
  they were recorded more than 3 seconds after the file last changed. A
  second write in the same timestamp tick (coarse clocks, FAT's 2 s) of
  the same size would leave all three as they were, so a file recorded
  sooner is compared by SHA-256 next time.
- A file that changes while it is being uploaded is not committed, and is
  retried next round.
- A download is staged beside its target, verified against the server's
  SHA-256 and size, fsynced, and only then given its name, replacing the
  old file or taking an empty name.
- **Losing the state is safe.** Without S the engine can only upload,
  download into an empty place, adopt identical content, or keep both. A
  change feed that reports a `reset` (the server was restored from an
  older backup), or names a different `history`, wipes S on purpose.
- **Remote deletes are conditional.** A file is trashed on the server
  only at the version this client last synced, and a folder only if it is
  empty there. Otherwise nothing happens, and the next round downloads
  what the other machine added.
- **Root guard.** A missing folder, or one without its `.homedrive-root`
  marker, stops the round before anything happens, because an unmounted
  disk looks like an empty folder.
- **What the scan cannot see is left alone.** A missing entry means
  "deleted here", so anything the scan could not look at clearly is
  protected for the round, along with everything beneath it:
  - a `stat` that failed for any reason but "not found";
  - a folder it could not list;
  - a folder on another filesystem (a disk mounted inside the synced
    folder);
  - a symbolic link or special file.
- **Ignored paths are left alone on both sides,** even ones synced before
  their pattern was added, so ignoring a file never deletes it. Paths
  inside `.homedrive/` are never synced in either direction.
- **Downloads keep private folders private.** A downloaded file takes the
  permissions of the file it replaces, or else its folder's (without
  execute). New folders take their parent's.
- **A damaged state snapshot starts afresh,** without applying the log
  beside it: half a state could make files look deleted on the server.
- **Plain HTTP only to this machine.** `http://` is refused for anything
  but a loopback address, so the password and token never cross a
  network in the clear.
- **Mass-delete guard.** A round that would delete more than 50 files, or
  more than 10 that are over 20% of the synced files, performs none of
  those deletions until they are confirmed (`homedrive confirm`).
  Everything else in the round still runs.
- **Ransomware guard.** Changes to existing files are gathered and
  uploaded after the round has seen them all. Distinct files changed
  within an hour are counted, so a document saved every minute is one.
  More than 100, or more than 20 that are over 25% of the synced files,
  are held until confirmed. Each change whose new content looks random is
  also checked against the first 64 KiB of the old version, fetched with
  a Range request (`suspect`). It is suspicious if the old content was
  not random, or began with a known format's signature (zip, PDF, JPEG,
  PNG, MP4 and others) that the new content lacks. Ten suspicious files
  within an hour hold every change and every deletion in the folder, and
  raise an urgent notification. An edited photo stays a photo and an
  edited archive stays an archive, so ordinary work rarely trips it.
- **Confirmations are bounded.** `homedrive confirm` approves the numbers
  the last round held back, for an hour. A round with more held than
  were approved does none of them, so a confirmation forgotten or given
  in a hurry never approves a larger burst later.
- **Local damage (bit rot).** The engine re-reads synced files in the
  background, at a pace that covers every byte once in 14 days, saving up
  credit while idle and carrying a debt after a large file. A file whose
  size, mtime, inode and device are as recorded but whose SHA-256 is not
  changed without a write the filesystem could see, so the disk damaged
  it. It is read a second time first: a different answer means flaky
  hardware, which is reported and nothing replaced. Otherwise the server's
  copy is downloaded in its place (only if the server is at the synced
  version), and the damaged copy moves to `.homedrive/damaged/`, which
  never expires. `homedrive verify` checks everything at once.
- **One process per folder.** The engine holds an exclusive lock in the
  folder's state directory. Two at once would act on one folder from two
  views, and each would compact the state log the other is appending to.
  `homedrive status` reads the state without compacting it. `confirm` and
  `verify` write `request.json` for the daemon. Each round writes what
  it held back or could not do to `status.json` (`control`).
- **Nested and overlapping folders.** A folder inside a synced folder
  that has its own `.homedrive-root` is protected and reported, and the
  configuration refuses folders inside one another. Two folders syncing
  the same files from two places would turn each one's trash and staging
  into the other's changes.

**State.** Each folder has `state.snap`, checksummed and atomically
replaced, plus `log.<gen>`, append-only with checksummed records. Opening
compacts them into a new generation. Damage is logged and the damaged part
forgotten, which by the rules above costs only time.

**Executable files.** The scan reads the owner's execute bit, and the
state records each synced version's flag (the top bit of the kind byte,
so older state reads as not executable). A file whose stat is unchanged
but whose execute bit differs is a change: `chmod` moves no time. A
download sets the execute bits wherever the read bits are, or clears
them. Windows has no such bit; there the flag is carried, never changed.

**Restoring to plain files** (`restore`). `homedrive restore PATH --to DIR`
downloads the current files under PATH from the change feed's listing,
verifies each against its SHA-256 before it takes its name, and writes the
manifest beside DIR. DIR must be outside the synced folders and empty.
`homedrive check-files DIR MANIFEST` checks every file a manifest lists,
so files restored by the server's drill and copied to a computer can be
proved there.

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
- the missing-root, missing-marker and mass-delete guards, and the
  folder lock;
- ransomware: encryption in place and deletions held back while the other
  machine keeps good copies, a partial confirmation approving nothing,
  and a confirmed attack undone by a rewind on both machines;
- many ordinary changes held until confirmed, and one file saved many
  times never counted as many;
- a bit flipped on disk without changing the file's stat, found by
  `verify` and by the background check, repaired from the server with the
  damaged copy kept, and never uploaded;
- lost client state;
- a randomized run on two machines. It asserts the machines converge and
  that every content on disk when a sync saw it still exists somewhere: a
  file, a server version, a conflict copy, or a trash.

Also: the execute permission travelling both ways, `chmod` alone
included; and a client restore to plain files whose manifest equals the
server's own restore, checked by `check-files`, which catches a changed
and a missing file. `crates/hd-server/tests/admin.rs` restores a backup
copy of a store through the drill (executables executable, the manifest
in `sha256sum` format), compares it with a drive that has since moved,
changed and grown a file (clean), and with a backup missing a file or
holding forged content (both caught).

The randomized run was also checked once with `HD_E2E_SEEDS=60`.

**Healing the server.** Each round the client asks which of its current
versions the server can no longer read. It re-hashes its copy of each in
full, and if the copy is that exact version, uploads it again. The commit
changes nothing, but the missing chunks and manifest are written afresh.
Size and time are not trusted here, so local bit rot is never sent as a
repair.

**Notifications** (`notify`). The daemon turns each round's report into
notices: held deletions and changes, suspected ransomware, files repaired
from the server after local damage, conflicts, files that did not sync, a sync
stopped for over 30 minutes, a server restore, and the server's own
`GET /api/v1/status` problems (polled every 10 minutes). Lasting
conditions are shown at most once a day and again as soon as they
recur; events every time. A file left out of sync (skipped) for over an
hour is reported too, since nothing else would say it is not backed up.
On Windows notices are notification-area balloons through
`Shell_NotifyIconW` (`hd_sys::windows::notify`), from a hidden
message-only window on a thread of their own; struct sizes are checked
at compile time against Windows' published ones. On Linux they reach the desktop through
`org.freedesktop.Notifications.Notify` on the session bus. The client
speaks D-Bus itself, because shipped code starts no programs. It does the
SASL EXTERNAL handshake, `Hello`, one hand-marshalled call, and waits for
the reply. A test runs it against a stand-in bus and decodes every
argument. Everything is also logged.

## Exports and the admin socket (`hd-server`: `export`, `admin`)

**Exports.** `HD_EXPORTS=alice:Music=>music` keeps `HD_EXPORT_DIR/music/`
a plain-file copy of the current versions under alice's `Music`, for
programs that read files (music-server).
- It reconciles at start and after commits. A changed file is written
  from the verified store content, staged, fsynced and renamed, and a
  removed file is removed.
- Files the export did not write are never touched. A file is replaced or
  removed only if it still holds the content the export wrote (checked by
  SHA-256 at that moment); anything else in the way is left alone and
  reported. A file that already holds the wanted content is adopted.
- `HD_EXPORT_DIR/.homedrive-<name>` records the version and SHA-256 each
  file holds, so a restart rewrites nothing that is unchanged. A lost
  record costs a re-hash, not a rewrite.
- An export is derived: deleting it loses nothing, and it is rebuilt.

**The admin socket**, `<data>/admin.sock` (mode 0600), serves
`podman exec` while the server runs:
- `hd-server import` stores standard input as a version (the backup
  scripts' path in);
- `import-tree` loads a directory tree, with old versions named
  `<file>.v<unix seconds>` imported first and keeping their dates;
- `verify-tree` re-hashes every source file and compares it with the
  store;
- `fsck`, `gc`, `scrub` and `checkpoint` run through it whenever a server
  answers, so no maintenance needs the server stopped.

`import-tree` skips files whose current content is already stored, so it
resumes after an interruption. It never puts the source's copy over a
file changed through homedrive since the import (a current version whose
origin is not an import): such files are reported and left alone. Each
import names the version it expects to replace, so an edit that lands
while a file is being imported turns the import into a conflict copy.

## Windows (`hd-client` for `x86_64-pc-windows-gnu`)

The client and the crates it uses build for Windows. The server, the store
and their crates stay Unix-only. Each place the Windows build differs:
- **fsio** keeps its Unix half unchanged and adds a Windows half. NTFS
  journals metadata, so there is no directory fsync; `sync_all` is
  `FlushFileBuffers`. There are no permission bits. A file's identity
  check is its size and modification time, with hashing deciding anything
  that differs. Writes go through `seek_write`.
- **hd-sys** adds free space (`GetDiskFreeSpaceExW`) and a recursive
  change notification for the daemon (`watch::Watcher`, inotify on Linux).
  It gives OpenSSL the socket handle, and links the Windows system
  libraries a static OpenSSL needs.
- **Randomness** comes from OpenSSL's `RAND_bytes`.
- **Names.** On Windows and macOS, server paths that differ only in case,
  and on Windows names Windows forbids, are skipped and reported.
- The binary codec moved to `hd-chunk`, so the client no longer depends on
  the server's store.

The gate type-checks and lints the Windows client. `make windows` links it
in `tools/windows/Dockerfile`: mingw-w64 plus OpenSSL 3.5.9, built from
source checked against its published SHA-256.

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
