# Plan: `homedrive`, a first-party deduplicating file sync and storage server

> **This is the working plan for the whole project.** It was approved on
> 2026-10-27. Read it before starting work, update the Status table in
> the commit that finishes or starts a milestone, and add every decision
> made along the way to the Decision log at the bottom. Stop at the end of
> each milestone so the user can test.

## Status

| # | Milestone | State | Date | Commit / notes |
|---|---|---|---|---|
| M0 | Bootstrap | done | 2026-10-27 | First commit. `make test` and `make test-image` green |
| M1 | Chunker and chunk store | done | 2026-10-27 | `make test` and `make test-image` green |
| M2 | Journal, snapshot, namespace, crash tests | done | 2026-10-27 | `make test` green; crash suite in `crates/hd-store/tests/crash.rs` |
| M3 | Versions, trash, conflicts, retention, GC, scrub, fsck | done | 2026-10-27 | `make test` green; `tests/files.rs`, `tests/model.rs` |
| M4 | HTTP streaming, auth, users, devices, sync API | done | 2026-10-27 | `make test` and `make test-image` green; `crates/hd-server/tests/api.rs` |
| M5 | WebDAV subset and rclone interop | done | 2026-10-27 | `make test` green; real rclone in `tests/rclone.rs` |
| M6 | Web UI and admin page | done | 2026-10-27 | `make test` green; `crates/hd-server/tests/web.rs` |
| M7 | Linux client | done | 2026-10-27 | `make test` green; two-client E2E in `crates/hd-client/tests/sync.rs`, 60 random seeds clean |
| M8 | Exports, import, import-tree, verify-tree | done | 2026-10-27 | `make test` and `make test-image` green; `crates/hd-server/tests/admin.rs` |
| M9 | Release 0.1.0, Ansible Phase A, import on VM1 | in progress | 2026-10-29 | 0.1.6 ready to release (three data-loss reviews, with proof tests for client and server: kept copies, import-tree never replaces homedrive edits, restore manifests never overwritten, copy generations, retention clock, WebDAV COPY onto an ancestor); VM1 deploy and import pending |
| M10 | Consumer cutover | not started | | |
| M11 | Windows client | code done, untested on Windows | 2026-10-28 | `make windows` builds `dist/homedrive.exe`; the gate type-checks it |
| M12 | macOS client | not started | | |
| M13 | Retire the previous file service | not started | | |

## Context

homedrive is the homelab's file sync and local cloud storage service on VM1. It provides:
- file sync and storage for the user's devices;
- a backup sink for the homelab: service backups (vaultwarden, playbook_runner, music_server) land in it through a local import helper, and remote hosts and `scripts/backup_proxmox_config.sh` reach it as an rclone WebDAV remote;
- the music library source: music-server reads a read-only Music export.

It takes over these jobs from the homelab's previous file service. That migration is driven from `ansible_playbooks` and planned there. This repo only builds the features it needs: `import-tree` with old versions, `verify-tree`, `import`, exports and WebDAV.

It is a first-party Rust server and client, following the standing rules: no third-party crates, OpenSSL through hand-written FFI only, and music-server/playbook-runner as templates. **Data integrity and never losing a file come before every other goal.**

User decisions:
- **Clients:** a Linux sync daemon, plus Windows and macOS builds of the same client. Phones use WebDAV apps and the web UI. There is no native phone app.
- **Storage:** a content-defined chunk store (CAS) with SHA-256 IDs. Plain-file consumers move to the API or WebDAV. Music/ gets a read-only materialized export.
- **WebDAV:** yes, the subset that rclone and file-manager apps use.
- **Users:** several, defined in Ansible as a Vault list and passed in as a Podman secret.

Defaults chosen in this plan (easy to change): the name `homedrive` with crate prefix `hd-`, the hostname `drive.<domain>`, side-by-side rollout and then cutover, no compression, and no encryption at rest (the store sits on a local disk inside the homelab).

## Integrity principles (they bind every crate)

1. **Content is immutable and addressed by its hash.** A chunk file is never rewritten. Its name is the SHA-256 of its contents. Every read re-hashes the chunk, and a mismatch is an error that is never served.
2. **Durable before acknowledged.** Every write goes to a temp file, then `fsync(file)`, then `renameat2(RENAME_NOREPLACE)` (or `link`+`unlink`), then `fsync(dir)`. The client gets a 2xx only after the journal record is fdatasync'd.
3. **Nothing is overwritten or deleted directly.** An overwrite creates a new version. A delete moves the file to trash. A conflict keeps both copies. Only retention can drop a version, and it never drops the current version or anything still in trash.
4. **GC is mark-and-sweep, never refcounting**, with two grace stages: an unreferenced chunk moves to `chunks.trash/` after 48 h, and is unlinked 7 days later.
5. **End-to-end verification.** The client hashes each chunk and the whole file. The server re-hashes each chunk on receipt, and on commit recomputes the whole-file hash from the chunks. Downloads are verified before the atomic rename into place.
6. **Fail closed.** If the data dir's sentinel `store.id` is missing (an unmounted disk), the server refuses to start. A journal with corruption anywhere but a torn tail also stops startup, and `fsck` is required. Uploads are refused when free space is below a reserve (statvfs).
7. **The client never destroys local data on an assumption.** It deletes or overwrites a local file only when its current hash equals the last-synced hash, and even then the file goes to the client trash. A missing or empty sync root, or a mass delete over the threshold, pauses sync for confirmation.

## Repo bootstrap

- Create `/home/matthew/matt_dev/homedrive` with `git init` on branch `main`. Run `gh repo create MatthewDavidMiller/homedrive --private --source . --remote origin`. **The repo stays private for now**, at the user's request.
- The GHCR package `ghcr.io/matthewdavidmiller/homedrive` will be private too, so VM1 can't pull it anonymously the way it does the other two. At M9, the role needs a read-only pull credential: a fine-grained PAT with `read:packages` in Vault, written to a root-only `auth.json` and used as `podman pull --authfile`. The alternative is `podman save` on the workstation plus `podman load` on VM1. Pick one at M9, and check how `review_container_updates.sh` resolves digests for a private package.
- **The plan lives in the repo.** The work will take weeks, so the first commit adds this plan verbatim as `docs/PLAN.md`. A **Status** table at the top records each milestone as not started, in progress or done, with the date and commit. Decisions made along the way (the private-image pull method, chunk-size tuning, the memory figure) go into a "Decision log" section at the bottom. Every milestone commit updates the table, and later sessions start by reading `docs/PLAN.md`. `AGENTS.md` points to it.
- Copy the scaffold from **music-server**, renaming `ms`→`hd` and `MS_`→`HD_`:
  - the workspace `Cargo.toml` (lints, release profile with overflow checks), `clippy.toml`, `rustfmt.toml`, `rust-toolchain.toml`, `.cargo/config.toml`
  - `Makefile`, `Containerfile`, `tools/toolbox/Dockerfile`, `.githooks/pre-commit`, `scripts/*.sh`
  - `LICENSE`, `README.md`, `AGENTS.md`, `CLAUDE.md`, `docs/{DESIGN,USAGE,DEPLOYMENT}.md`
- `AGENTS.md` adds these non-negotiables:
  - the integrity principles above;
  - every file write goes through `hd-common::fsio` durable helpers (a `check-rust.sh` gate rejects `fs::write`, `File::create` and `fs::rename` outside `fsio`);
  - `remove_file` and `remove_dir_all` may appear only in `hd-store/src/gc.rs`, `hd-client/src/trash.rs` and tests (a gate enforces this);
  - never log file names at info level, or credentials at any level.
- The toolbox image adds `rclone`. It is a test-only tool for the WebDAV interop test and is not in the runtime image.

## Crates (`crates/hd-*`). Everything except `hd-sys` is `#![forbid(unsafe_code)]`.

| Crate | Source | Contents |
|---|---|---|
| `hd-sys` | `music-server/crates/ms-sys` + `rpi-omt-client/crates/omt-sys/src/ssl.rs` | libcrypto (sha256, hmac, random, ct_equal, cleanse) plus **new streaming `EVP_DigestInit_ex/Update/Final_ex`**. libssl client side for the sync client only. posix additions: `renameat2`, `fdatasync`, `statvfs`, `inotify_*`, `flock`. Windows and macOS FFI modules behind `cfg(target_os)`: `ReadDirectoryChangesW`, `MoveFileExW`, `FlushFileBuffers`; FSEvents (CoreServices) and `F_FULLFSYNC`. |
| `hd-crypto` | `ms-crypto` | sha256 one-shot and streaming `Hasher`, hmac, ct_equal, SecretBytes, token generation. |
| `hd-common` | `ms-common` | base64, buf, error, json, rand, timefmt, plus `fsio` extended with `write_durable_new` (NOREPLACE), `fsync_dir`, `read_exact_bounded` and a cross-platform `durable_rename`. Adds `pathname` for validated relative names: no `..`, NUL, `/` inside a component, or names over 255 bytes; a Windows-illegal-name check and an ASCII case-fold collision key. |
| `hd-chunk` (new) | — | A FastCDC chunker. The gear table is a fixed constant derived from SHA-256 of a seed, with a test that pins it. Sizes are min 256 KiB, average 1 MiB and max 4 MiB. Streaming over `Read`, it emits `(offset, len, sha256)`. Shared by the server and the client, so chunk boundaries always match. |
| `hd-store` (new) | — | The server storage engine. Details below. |
| `hd-http` | `ms-http` | Adds **streaming request bodies** (Content-Length and `Transfer-Encoding: chunked` decode), **keep-alive** with a per-connection request cap, WebDAV methods, the `Range` module (kept), and the `Depth`, `Destination` and `Overwrite` headers. Bodies go to a `Read` adapter and are never buffered whole. |
| `hd-dav` (new) | — | The WebDAV subset. |
| `hd-api` (new) | — | Sync protocol handlers and JSON types, shared with the client. |
| `hd-server` (bin) | `ms-web` | config, auth, sessions, CSRF, throttle, users sync, the web UI, admin, exports, and the admin Unix socket. |
| `hd-client` (bin) | new | The sync engine, watcher, CLI and daemon. |

### `hd-store`: on-disk layout (data dir on the dedicated disk)

```
store.id                        sentinel: random uuid + format version; must exist or the server refuses to start
chunks/ab/cd/<sha256hex>        immutable chunk: 16-byte header (magic HDC1, version, kind, len) + bytes
chunks.trash/<day>/<sha256hex>  GC stage 1
meta/journal.<seq>              append-only records: [len u32][kind][body][sha256(len‖kind‖body)]
meta/snapshot.<seq>             a checkpoint of the whole namespace state, sha256 trailer, written durably
meta/LOCK                       flock held by the running server (one writer)
uploads/<session>               in-progress chunk-ID lists, so GC treats those chunks as live
exports/                        (a separate volume) materialized plain-file views
```

- **Manifest:** an object in CAS with kind `manifest`. It is the ordered list of `(chunk_id, len)` plus the whole-file sha256 and size. Large-file manifests are chunked the same way, so the journal stays small and identical files share a manifest.
- **Namespace model** (per user, in memory, rebuilt from snapshot plus journal):
  - `path → Entry { file_id (stable across moves), kind, current: VersionId }`
  - `file_id → [Version { id, manifest, size, sha256, mtime, created, device, origin: upload|conflict|restore|import }]`
  - `trash: [TrashItem { file_id, original_path, deleted_at }]`
  - `seq: u64`, a monotonic per-user change cursor that drives the change feed.
- **Journal records:** `PutVersion`, `Mkdir`, `Move`, `Copy`, `Trash`, `Restore`, `Purge`, `RetentionDrop`, `DeviceAdd/Revoke`. Group commit uses one fdatasync per batch, and nothing is acknowledged before the fdatasync. A torn final record (bad length or hash at EOF) is truncated on startup and logged. Any other bad record stops startup.
- **Checkpoint:** every N records or 10 minutes, write `snapshot.<seq>` durably, then start `journal.<seq+1>`. Keep the last 3 snapshots and their journals; never delete the only good chain.
- **Conflicts:** a commit carries `base_version`. If the current version is different, the new content is stored as a sibling `name (conflict <device> <yyyy-mm-dd hhmm>).ext`, and the response reports it. Nothing is lost.
- **Retention** (configurable): keep every version for 30 days; then keep daily for 90 days, weekly for 1 year and monthly after that; trash items for 90 days. Retention only writes `RetentionDrop` and `Purge` records. GC frees the bytes later.
- **GC** (`gc.rs`): runs daily. It marks from every live version, every trash item, every upload session younger than 24 h, and every snapshot still on disk, then sweeps with the two grace stages. A dry-run mode is available.
- **Scrub:** a background thread re-hashes every chunk on a configurable cycle (default 30 days), throttled by MB/s. A bad chunk is moved to `chunks.quarantine/` and reported on the admin page and in `/healthz` detail. If any client still has the chunk, it can be re-uploaded through the normal "missing chunks" path, which heals the store automatically.
- **fsck** (`hd-server fsck [--repair-tail]`): replays the journal, then checks that every referenced manifest and chunk exists and hashes correctly, and that the whole-file hashes match. It is read-only unless a flag is given.

### Sync protocol (`hd-api`, JSON over HTTPS, `/api/v1`)

| Endpoint | Purpose |
|---|---|
| `POST /devices` (Basic auth with the user password) | Register a device and get a random 32-byte token. Only its sha256 is stored. |
| `GET /changes?since=<seq>&wait=30` | Change feed with long-poll. Returns entries after the cursor. A cursor that is too old gets `410`, and the client does a full listing. |
| `GET /tree?path=` | Full listing, used for the initial sync and for recovery. |
| `POST /chunks/missing` | Takes chunk IDs and returns the ones the server lacks. This is where dedup happens: only new chunks are sent. |
| `PUT /chunks/<id>` and `POST /chunks/batch` | The server re-hashes, then stores durably. Batching packs small chunks into one request. |
| `GET /chunks/<id>` | The client verifies the hash. |
| `POST /commit` | Takes `{path, base_version, size, mtime, sha256, chunks[]}` and returns `{version}` or `{conflict_path, version}`. |
| `POST /mkdir`, `/move`, `/copy`, `/trash`, `/restore` | Tree operations. |
| `GET /versions?path=`, `GET /trash` | History and trash. |

### WebDAV subset (`/dav/<user>/`)

- `OPTIONS`, `PROPFIND` (Depth 0 and 1; resourcetype, getcontentlength, getlastmodified, getetag = version id, getcontenttype), `GET`/`HEAD` with Range, `PUT`, `MKCOL`, `DELETE` (goes to trash), `MOVE`, `COPY` (reuses the manifest, so it costs nothing), and `PROPPATCH` (only for mtime, otherwise a 403 per property).
- `PUT` streams through the chunker into CAS and commits a new version. It honours `X-OC-Mtime`, so rclone keeps mtimes.
- `LOCK`/`UNLOCK` are non-enforcing class-2 stubs, so macOS Finder and the Windows client can write.
- Auth is Basic with per-device app tokens (recommended for rclone and phones) or the account password, with the throttle from `pr-web`.
- The rclone remote uses `vendor = other`.

### Server binary (`hd-server`)

- **Config:** environment variables only. `HD_LISTEN`, `HD_DATA_DIR`, `HD_EXPORT_DIR`, `HD_USERS_FILE`, `HD_TRUSTED_PROXIES`, `HD_SECURE_COOKIES`, `HD_MIN_FREE_GB`, `HD_MAX_FILE_GB`, `HD_RETENTION_*`, `HD_SCRUB_DAYS`, `HD_SCRUB_MBPS`, `HD_EXPORTS` (for example `matt:/Music=>music`).
- **Users:** follows music-server's users sync. The secret is `{"version":1,"users":[{name,password,admin}]}`, validated, with passwords kept in memory only. A removed user is disabled and their data is kept.
- **Web UI** (no JavaScript, works on phones): browse, upload (multipart, streamed), download, version history and restore, trash and restore, device tokens (create and revoke), and an admin status page (store size, dedup ratio, scrub and GC status, quarantine, free space, journal seq). Reuses the html, session and CSRF code from `ms-web`.
- **Exports:** after each commit under an export root, a worker materializes the file into `HD_EXPORT_DIR/<name>/`. It writes a temp file, verifies the hash, fsyncs and renames. Deletes and moves are mirrored. A full reconcile runs on startup. The export is a derived view, so it can always be rebuilt with `hd-server export --rebuild`.
- **Admin socket** (`<data>/admin.sock`, mode 0600) for `podman exec`:
  - `hd-server import --user U --dest path < file` is how the host's backup scripts store a file. It streams over the socket with the same verify path and prints the version id.
  - `hd-server import-tree --user U --src <dir> [--versions <dir>]` bulk-loads an existing plain directory tree, for example the one-time migration. It reads the source read-only. In the optional versions tree, a file named `<path>.v<unix-timestamp>` becomes an older version of `<path>`. It writes a report of every file with its sha256.
  - `hd-server verify-tree --user U --src …` re-hashes every source file and checks that it matches the store's current version. Cutover is blocked until this reports 0 mismatches and 0 missing.
- **Other subcommands:** `serve`, `fsck`, `gc [--dry-run]`, `scrub`, `checkpoint` (a consistent snapshot for borg), `check-users`, `healthcheck`, `version`.

### Client (`hd-client`): Linux first, then Windows and macOS

- **Config:** `~/.config/homedrive/config.json` with the server URL, the device token file (mode 0600) and folder pairs `{remote, local, ignore[]}`. State lives under the XDG data dir, one journal per pair, using the same journal and checksum format as the server's `meta/` (shared code in `hd-store::journal`).
- **Sync engine:** a three-way reconcile per path of (last-synced state, local scan, remote change feed):
  - **Upload:** hash while reading, then re-stat (size, mtime, inode). If anything changed, retry later, so a file that was being written is never uploaded torn. Then missing-chunks, upload, commit with `base_version`.
  - **Download:** fetch the chunks, verify each and the whole-file hash, write a temp file in the same dir, fsync, and re-check that the local target still matches the last-synced state (otherwise treat it as a conflict). Then a durable rename.
  - **Both changed:** upload the local copy (the server makes the conflict sibling), then download both. Both are kept.
  - **Remote delete:** delete locally only if the local hash equals the synced hash, and move it to the client trash (30 days), never unlink it.
  - **Guards:** sync stops if the sync root or its `.homedrive-root` sentinel is missing. Deleting more than 50 files or 20% in one round pauses until `homedrive confirm`. Case-fold or Windows-illegal name collisions are skipped and reported, never renamed silently. Symlinks are not followed and are reported.
- **Watching:**
  - Linux: inotify.
  - Windows: `ReadDirectoryChangesW`.
  - macOS: FSEvents.
  - A full rescan every 10 minutes as the source of truth. The watcher is only a hint.
- **TLS:** libssl FFI from `omt-sys/ssl.rs`. It verifies the hostname and trusts the built-in ISRG Root X1 and X2 (Let's Encrypt) by default, with a `ca_file` override.
- **CLI:** `homedrive login|daemon|sync --once|status|conflicts|confirm|trash|versions|restore`.
- **Running it:**
  - Linux: a systemd user unit.
  - macOS: a launchd agent plist.
  - Windows: a Task Scheduler logon task. There is no tray GUI at first.

## Container and deployment

- Official Alpine pinned by digest, a two-stage static musl build, uid 10001, `/var/lib/homedrive` (store) and `/srv/exports`, `EXPOSE 8080`, and a `HEALTHCHECK`. Memory is 1g to start, measured during the deploy milestone. `--read-only --cap-drop=ALL --no-new-privileges`.
- Traefik terminates TLS for `drive.<domain>` through the standard `proxy_config`. The server speaks plain HTTP on an internal network only.

## Ansible (`/home/matthew/matt_dev/ansible_playbooks`)

The deployment role, the migration from the previous file service, and that
service's retirement all live in `ansible_playbooks` and are planned there.
From this repo's side:
- **M9:** a `roles/homedrive` role runs the image on VM1 side by side with the previous service. It covers the network route, a store on a dedicated disk, the users secret, a backup of the store (`hd-server checkpoint`, then borg), and the `homedrive_import_path.sh` host helper. The image was private at first, so VM1 needed a pull credential (public since 0.1.5).
- **M10:** the homelab's consumers move over: service backups use the import helper, music-server uses the Music export, and rclone remotes and remote-host borg point at homedrive.
- **M13:** the previous service is retired on the Ansible side. Nothing changes in this repo.

## Milestones (each ends with `make test` green; stop at each for the user to test)

| # | Milestone |
|---|---|
| M0 | Bootstrap: scaffold, copied crates, streaming sha256, `/healthz` server, the image builds and goes healthy, repo pushed. |
| M1 | `hd-chunk` + the `hd-store` chunk layer: a pinned gear-table test, boundary stability under inserts and deletes, a durable write path, read-verify, and bit-flip detection. |
| M2 | Journal + snapshot + namespace model: **crash tests** that truncate the journal at every byte offset and inject a failure at every write/fsync/rename step (an `fsio` fault-injection shim). Recovery must always give a valid prefix state and never lose an acknowledged commit. |
| M3 | Versions, trash, conflicts, retention, GC, scrub and fsck. A randomized model test runs op sequences against an in-memory reference, then retention, then GC, and asserts every live and trashed version is still readable byte-for-byte. |
| M4 | `hd-http` streaming bodies and keep-alive, auth, users sync, devices, and the sync API, with loopback integration tests. |
| M5 | The WebDAV subset, plus an **rclone interop test** in the toolbox (copy, sync, check `--download`, mtime round-trip). |
| M6 | The web UI and admin page. |
| M7 | The Linux client: engine, inotify and CLI. An E2E test runs two clients and the server on loopback with randomized concurrent edits, deletes and moves, and asserts that every content hash ever written survives as a file, a version, a conflict copy or a trash item. |
| M8 | Exports, the admin socket `import`, `import-tree` (with old versions) and `verify-tree`. |
| M9 | Release 0.1.0, Ansible Phase A, deploy side by side, import, verify-tree with 0 mismatches, and measure memory. |
| M10 | Cut consumers over (backups, music export, rclone remotes, borg). Watch a week of daily backups land. |
| M11 | The Windows client (an x86_64-pc-windows-gnu cross build in the toolbox with mingw + static OpenSSL), and the Windows rename and fsync semantics. |
| M12 | The macOS client (built on a Mac, with FSEvents and `F_FULLFSYNC`). |
| M13 | Retire the previous file service (done in `ansible_playbooks`, check mode first). |

## Verification

- **Repo gate:** `make test` runs fmt, clippy pedantic, the lockfile with no `source =`, the unsafe and native-lib allowlists, the new fsio and remove gates, unit and crash-injection tests, the randomized model test, loopback integration and E2E tests, and the rclone interop test.
- **Image:** `make test-image` uses VM1's flags, waits for healthy, then does a WebDAV PUT/GET round trip and an API commit, and checks the refusal to start without `store.id`.
- **Ansible:** `scripts/test-local.sh` with the new role assertions.
- **On VM1:**
  - `import-tree`, then `verify-tree` (0 mismatches), `fsck` clean and `gc --dry-run` reviewed;
  - the Linux client syncs a folder both ways;
  - a deliberate conflict produces both copies;
  - a version restore works;
  - rclone from a remote host works;
  - music-server plays from the export;
  - a restore drill: restore the store from borg into a scratch dir and run `fsck` on it.


## Decision log

Newest last. Each entry says what was decided, why, and when.

- **2026-10-27, plan approval.** The user chose: a chunk CAS plus a
  materialized Music export; a WebDAV subset alongside our own sync API;
  multiple users from Ansible; a Linux client first, then Windows and
  macOS; phones through WebDAV and the web UI.
- **2026-10-27, repo private.** The user asked for the GitHub repo to stay
  private for now. The GHCR package will be private too, so VM1 needs a
  pull credential or a `podman load` (decide at M9).
- **2026-10-27, this file.** The user asked for the plan to live in the
  repo, because testing and finishing everything will take weeks.
- **2026-10-27, M0 crypto surface.** `hd-sys` and `hd-crypto` drop MD5,
  AES-GCM and the sealed master key that music-server carries, because
  nothing in homedrive encrypts at rest. They add streaming SHA-256. Web
  sessions will be HMAC-signed with a key held in memory (M6).
- **2026-10-27, binary names.** The server binary is `hd-server` and the
  client is `homedrive`.
- **2026-10-27, scope of this repo.** homedrive is a standalone project
  with its own repo. This plan describes what homedrive builds. The
  migration from the homelab's previous file service is planned and
  carried out in `ansible_playbooks`, and this repo doesn't name that
  service.
- **2026-10-27, M1 formats.** The gear table is derived from SHA-256 of
  `"homedrive/fastcdc/gear/v1"` || i, not listed. It is pinned by hash,
  and the cut points of a fixed input are pinned too, both reproduced by
  an independent Python implementation. Object files are a 16-byte `HDO1`
  header plus the bytes. Chunks and manifests live in separate
  directories, so the kind is a namespace and not part of the ID.
- **2026-10-27, M1 no-replace commit.** Objects are committed by
  hard-linking a staged, fsynced file into place rather than with
  `renameat2(RENAME_NOREPLACE)`. A link never replaces a name and works
  on every Linux filesystem, while NOREPLACE is unsupported on some (and
  its glibc/musl wrappers differ).
- **2026-10-27, M1 healing.** A corrupt object is quarantined, never
  deleted, and then reads as missing, so the normal "which chunks are
  missing" upload path writes a good copy.
- **2026-10-27, M1 init.** The server never creates a store on its own. A
  separate `hd-server init` does, and only in an empty directory, so an
  unmounted disk is refused rather than silently written to.
- **2026-10-27, M2 journal framing.** Each record carries its length and
  the length's complement under the checksum. Without the complement, a
  flipped length bit in the final record would read as a torn write, and
  recovery would cut off an acknowledged record.
- **2026-10-27, M2 one journal, global sequence.** The store has one
  journal and one sequence for all users. Each record names its user, and
  a user's change cursor is the global sequence number. That is simpler
  than per-user journals and is plenty for a homelab.
- **2026-10-27, M2 poisoning.** After any journal or checkpoint write
  failure the metadata refuses writes until restart, where recovery
  decides the true state. Reads keep working.
- **2026-10-27, M2 pruning rule.** A journal is deleted only when the next
  journal starts at or before the record after the oldest kept snapshot,
  not when its own first record is older. The second rule would delete a
  journal that kept receiving records after a failed checkpoint.
- **2026-10-27, M2 scope shift.** Manifests and whole-file put/get move to
  M3 with versions and conflicts, which use them.
- **2026-10-27, M3 GC safety.** GC protects in-flight uploads by object
  age (the 48 h grace period, from file mtimes) rather than by tracking
  upload sessions. A dedup race (a commit reusing an old unreferenced
  object during a collection) is closed by the GC gate and the touched
  set. A commit whose chunks GC has moved fails verification cleanly, and
  the client re-uploads them.
- **2026-10-27, M3 identical content.** A commit whose content equals the
  current version adds no version, even from a stale base, so there is
  nothing to conflict with.
- **2026-10-27, M3 maintenance runs offline for now.** fsck, gc, scrub and
  checkpoint are subcommands that open the store, so the server must be
  stopped. The server runs them on a schedule itself from M4, and the
  admin socket (M8) can trigger them while it runs.
- **2026-10-27, M4 device tokens.** The format is `hd1_<id>_<64 hex>`, and
  the journal stores only the SHA-256 of the secret. Tokens double as
  Basic-auth passwords for their own user, so rclone and phone apps never
  hold the account password.
- **2026-10-27, M4 format change before release.** Devices were added to
  the snapshot encoding and the operation set (codes 9 and 10). No store
  exists outside tests yet, so this stays format 1. After the first real
  deployment, any change like this needs a version bump.
- **2026-10-27, M4 cross-user chunk reads.** Any signed-in user can fetch
  a chunk by its hash. That is accepted for a homelab, because knowing a
  chunk's hash already means knowing its content (see DESIGN).
- **2026-10-27, M4 passwords in memory.** Passwords are kept as an HMAC
  under a per-process random key rather than in plaintext.
- **2026-10-27, M5 WebDAV mount.** The path is `/dav/<user>/` with the
  user segment required to match the signed-in user, and rclone uses
  `vendor = other`. Depth: infinity is refused, as RFC 4918 allows.
  PROPPATCH is accepted but not stored, and LOCK is not enforced. Both
  exist so Finder and Windows will write.
- **2026-10-27, M5 overwrite semantics.** An overwriting MOVE or COPY
  trashes the destination first, then acts. If the move then fails, the
  destination is restored. Two journal records, nothing lost either way.
- **2026-10-27, M6 web sessions.** The session key is random per process,
  not derived from a master key, because homedrive has no master key. A
  restart signs browsers out, and devices are unaffected.
- **2026-10-27, M6 restore semantics.** Restoring a version adds it as the
  newest version (origin `restore`), so the history only ever grows.
  Restoring a trash item to a taken path uses a "(restored <date>)" name
  instead of replacing anything.
- **2026-10-27, M7 trust store.** On Linux the client trusts the system CA
  store (or a configured `ca_file`) rather than built-in Let's Encrypt
  roots, so certificate rotation is the distribution's problem. Built-in
  roots remain the plan for Windows and macOS (M11, M12), where OpenSSL
  has no system store.
- **2026-10-27, M7 conflicts through the server.** "Keep both" is a commit
  with base `absent`, so the server names the conflict copy, and the
  client renames its file to match. One naming rule serves every client.
  After a conflict the client forgets S for the original name, so a stale
  mirror can never make it trash the other side's version.
- **2026-10-27, M7 watching.** The daemon rescans every 15 seconds and on
  inotify events. The scan is the truth, and missed or overflowed events
  only delay a sync.
- **2026-10-27, M7 mass-delete guard.** Only the deletions are held; the
  rest of the round proceeds, so one big deletion does not stall syncing.
- **2026-10-27, M7 password entry.** `homedrive login` reads the password
  from `HOMEDRIVE_PASSWORD` or a line of standard input, without turning
  off terminal echo (that needs termios bindings). This is a known rough
  edge to revisit.
- **2026-10-27, M8 export bookkeeping.** An export records the version each
  file holds in `HD_EXPORT_DIR/.homedrive-<name>` (outside the exported
  tree), and never deletes a file it did not write. Exports are derived,
  so `fsio::remove_derived_file` is their only deletion.
- **2026-10-27, M8 admin socket.** All admin commands go through one Unix
  socket in the data directory (0600, under a 0700 directory), so they work
  while the server runs and need no network exposure. `import-tree` and
  `verify-tree` run in the CLI process and talk to the server over it,
  which keeps long walks out of the server.
- **2026-10-27, M8 imported dates.** Old versions keep their
  `.v<seconds>` timestamps as creation times (`Provenance::created_ms`),
  so retention thins them by real age, not import age.
- **2026-10-28, M9 private image.** VM1 pulls the private image with a
  fine-grained read:packages token from Vault, written by standard_podman
  to a root-only auth file used only for pulls (user's choice). The role
  deploys only when the inventory sets `homedrive_deploy` and the image is
  locked, and it creates the store only when `homedrive_init_store` is set
  for one run.
- **2026-10-28, history rewrite.** At the user's request the first
  commit's message was reworded to drop a mention of the previous
  service, and main was force-pushed (the tree is unchanged).
- **2026-10-28, M11 approach.** The user asked for the Windows port
  without a Windows machine to test on. The gate type-checks and lints it.
  `make windows` cross-builds it with mingw and OpenSSL 3.5.9 (pinned by
  SHA-256, the same release the toolbox ships). Windows needs `--ca-file`,
  because OpenSSL there has no system store. Built-in roots are a later
  option.
- **2026-10-28, M12 deferred.** macOS needs a Mac to build and test.
- **2026-10-28, 0.1.0 released.** `ghcr.io/matthewdavidmiller/homedrive:0.1.0`,
  digest `sha256:b86e8738eb9c45f5709af4677cfb63166c7b1cbc4d5dc7f93f1d55d0749d9807`
  (the registry's digest; the local image digest differs, so pin only the
  one the registry reports). The ansible_playbooks review tool could not
  read a private image at all: the skopeo image ignores mounted
  credentials. It now passes the login file explicitly. The lock entry
  is reviewed and the runtime container tests start the locked image
  under the role's flags.
- **2026-10-28, local race guards.** The client no longer checks a file
  and then replaces or trashes it: it moves the file aside first, checks
  what it moved, and puts it back if it changed, so an editor's save at
  any moment survives. A stat recorded within 3 s of the file's last
  change is untrusted, so a same-size write in the same timestamp tick is
  not missed. Tests drive each window through an engine hook
  (`Engine::set_hook`). Others cover two machines syncing the same files
  at once and 32 simultaneous commits to one file on the server. The
  client's state format is unchanged; an untrusted time is stored as
  `i64::MIN`.
- **2026-10-28, integrity review.** These gaps were found and closed:
  - The sync client's remote deletes now carry a precondition (the
    version it saw, or "folder is empty"), checked under the commit lock,
    so a stale view can't trash another machine's new edit.
  - The store has a `history.id`, which backups omit and a restored store
    regenerates. Clients that see it change reset, so files committed
    after the backup are re-uploaded rather than lost to repeated version
    numbers.
  - The backup script archives `meta/` before the objects.
  - Exports replace or remove only files that still hold what they
    wrote.
  - A reference check runs after every scheduled GC, so missing objects
    are found without a manual fsck.
  - A test proves an interrupted WebDAV upload changes nothing.

  The client state snapshot is format 2, which adds the history; format 1
  is still read.
- **2026-10-28, client notifications.** The daemon notifies the desktop
  of whatever needs the user, using D-Bus spoken directly (no
  `notify-send`, since there are no subprocesses), and logs it too.
  - The server gained `GET /api/v1/status`, so clients can report damage
    in the store.
  - Windows notifications go to the log only, for now.
- **2026-10-28, hardware damage.** Defences against bit rot and failing
  disks:
  - Objects that fail to read twice are quarantined (renamed, kept). An
    unreadable existing copy no longer blocks storing a good one.
  - Scrub goes on past read errors, verifies metadata files, and repairs
    damaged ones by checkpointing from memory.
  - Damage is re-checked as soon as anything is quarantined.
  - Clients re-upload damaged current versions they hold at the exact
    hash (`GET /api/v1/damaged`).
  - `hd-server repair --from DIR` restores objects from any store copy or
    from the quarantine.
  - The ansible role adds `homedrive_repair.sh` and a weekly `borg
    check`.
  - SMART monitoring belongs on the Proxmox host, since VM1 sees only
    virtual disks.
- **2026-10-28, 0.1.1.** Released with the race guards, trash
  preconditions, history.id, client notifications and the hardware-damage
  safeguards, so the first VM1 deploy starts with them. Store formats are
  unchanged from 0.1.0 (history.id is new and made when missing); the
  client state snapshot is format 2.
- **2026-10-28, full review.** Fixed:
  - **Client data loss:**
    - a damaged state snapshot applied its log alone (half a state reads
      as server deletions);
    - a stat error, a newly ignored pattern, a nested mount, or a file
      swapped for a symlink each turned into deletions everywhere; such
      paths are now protected;
    - paths inside `.homedrive/` were mirrored into the client's own trash.
  - **Server data loss:** retention trusted a clock that had jumped ahead;
    it is now guarded, and validates each step under the commit lock.
  - **Leakage:**
    - downloads were always 0644 and folders 0755; they now inherit;
    - `http://` was accepted for any host;
    - `GET /chunks/<id>` served any user's chunk.
  - **Accepted:** `chunks/missing` is a cross-user existence oracle,
    inherent to cross-user dedup; acceptable only with trusted accounts.
- **2026-10-28, 0.1.2.** Released with the full-review fixes so the first
  VM1 deploy starts with them. Store and client state formats are
  unchanged from 0.1.1.
- **2026-10-28, client-side safeguards.** Added for races, client
  hardware, ransomware and accidental deletion:
  - **Rewind** (store, API, web UI, `homedrive rewind`): a folder back as
    it was at a time, by adding versions and restoring from the trash,
    never removing. This is the recovery path for ransomware and for
    mistakes across many files.
  - **Ransomware guard:** many changed files within an hour, or ten whose
    content turned random against the old version's first 64 KiB, are
    held until `homedrive confirm`; suspicion holds deletions too.
    Distinct files are counted, so autosaves do not trip it.
    Confirmations name counts and expire after an hour.
  - **Local bit rot:** a background re-read (every byte once in 14 days)
    finds content changed without a write, restores the server's copy,
    and keeps the damaged copy in `.homedrive/damaged/`. A second read
    must agree first. `homedrive verify` checks everything at once.
  - **Races:** an exclusive per-folder lock (before this, `homedrive
    status` or `sync` run beside the daemon compacted the state and
    deleted the log the daemon was appending to); `status` now reads
    without writing; `confirm` and `verify` reach the daemon through
    `request.json`.
  - **Overlap:** nested `.homedrive-root` folders are protected, and
    overlapping configured folders are refused.
  - Server-side alerts and quotas followed in 0.1.3 (below).
- **2026-10-28, alerts and quotas (0.1.3).**
  - **Unusual-activity alerts:** derived from the metadata (no new
    state but the dismissal times), so WebDAV and web UI writes are
    watched as well as the sync client's. Imports are excluded because
    the homelab's nightly backups replace many files. An alerted drive is
    held from retention until its owner dismisses the alert in a browser;
    device tokens cannot dismiss it.
  - **Quotas:** optional `quota_gb` per account, counting all versions
    and the trash at full size (deduplication is not credited, so one
    user's usage never depends on another's files). Recovery operations
    and admin imports are exempt. The ansible role passes `quota_gb`
    through and validates it.
  - **0.1.3** carries these and the client-side safeguards. Store formats
    are unchanged; the client state format is unchanged.
- **2026-10-28, quotas required.** `quota_gb` is required for every
  account, and the server refuses to start unless all quotas, the drives
  of removed accounts and the free-space reserve fit on the store's disk,
  so the drives can never fill it. Imports now count against the quota,
  streams of unknown length stop at it, and chunks uploaded ahead of a
  commit count too. Admins are warned when other data on the disk eats
  into the room the quotas promise.
- **2026-10-28, remaining data-loss gaps.**
  - `verify-tree` fails on skipped files: a file the import could not
    store exists only in the source, and retiring the source on a "clean"
    check would lose it. `--accept-skipped` after saving them elsewhere.
  - Files left out of sync for over an hour are notified; before, only
    errors were, and a symlink or an always-busy file was never backed up
    without anyone hearing.
  - Windows notifications through `Shell_NotifyIconW`. Built and linked
    in the cross toolchain, with struct sizes checked at compile time;
    not yet run on a real Windows machine.
  - The execute permission is synced, carried in a spare bit of existing
    record bytes so no format version changed.
  - Retention minimums of 7 days for `HD_KEEP_ALL_DAYS` and
    `HD_TRASH_DAYS`.
  - Backups report every run; failures, silence and failed imports reach
    administrators.
  - **Restore proof:** `restore-tree`, `restore-drill` and `drill-compare`
    on the server, `restore` and `check-files` on the client, and a weekly
    drill in the ansible role that restores the newest backup to plain
    files and compares it with the live drive.
  - **Off the server:** an administrator pulls a copy of the whole store
    to their own machine (`homedrive backup-store`, incremental, every
    object verified; or the admin page's tar download). Chosen over an
    append-only push to a second managed machine: no extra host, keys or
    passphrase to run, and the server can no more reach a pulled copy than
    an append-only one. The cost: an administrator's password or device
    token can now fetch every drive over the network.
  - Found on the way: `subtree("")` (the whole drive) matched nothing, so
    a whole-drive rewind did nothing and a whole-drive export was empty.
- **2026-10-28, optional encryption.** Copies stay unencrypted by
  default. `homedrive backup-store --encrypt`, a passphrase on the admin
  page's download, and `homedrive_borg_passphrase` for the local Borg
  repository encrypt them. Copies use scrypt and AES-256-GCM in 1 MiB
  authenticated segments, with keyed-hash file names so a copy reveals
  neither paths nor which content it holds; incremental copying still
  works because each object is sealed on its own. A lost passphrase loses
  the copy, by design.
- **2026-10-28, public prerelease.** The user made the repository and the
  GHCR package public. The documentation says plainly that homedrive is
  prerelease software that may have issues. VM1 now pulls the image
  anonymously, like the other first-party images, and the ansible role's
  registry credentials are gone.
- **2026-10-29, data-loss review.** Fixed:
  - the ansible restore drill emptied `<drill path>/store` without
    checking it, so a drill path above the store (`/srv/homedrive` for a
    store at `/srv/homedrive/store`) would have deleted the live store.
    The role now refuses overlapping store, backup, drill and export
    paths. The drill marks its scratch space and refuses any that
    overlaps the store or the repository, or that holds files it did not
    put there. A Borg repository on the store's own disk is reported as
    a failing backup;
  - a changed copy that could not go back into place stayed in the client
    trash and expired after 30 days; it now goes to `.homedrive/kept/`,
    which never expires;
  - re-running `import-tree` put the source's older copy over files
    edited through homedrive since; such files are now left alone and
    reported, and each import names the version it replaces;
  - restores wrote their manifest over an existing file; they now refuse
    an existing manifest before restoring anything.
- **2026-10-29, second data-loss review.** Fixed:
  - an administrator's copy replaced its metadata with the server's on
    every run and removed what the server had pruned, so it could never
    go back further than the server: a trash item purged by retention, or
    anything done to the server's metadata, left the copy on its next run.
    Each run now keeps the metadata it replaces as a generation
    (`history/`, `sealed-history/`), and the copy opens as of any of them
    (`--generation`);
  - the copy's metadata lengths were read after the checkpoint without
    the lock, so a journal could be copied part way through an append;
    they are now read under it;
  - retention's clock check ended at the first upload after the clock
    jumped ahead, or never began if the server started with the clock
    already wrong. Retention now keeps its own clock (`retention.clock`),
    which moves on at most twice the time the server has measured passing,
    and the administrators are told while it lags by more than two days;
  - a WebDAV COPY onto a folder holding the source trashed that folder,
    source and all, then copied nothing and answered 204. MOVE and COPY
    between paths that hold one another are now refused with 409.
- **2026-10-29, the two limits left by the second review.**
  - Durable writes committed with a hard link, which FAT and exFAT (most
    USB disks) cannot make, so a store copy, or a synced folder, on such a
    disk failed. Where a hard link fails, `fsio` now commits with a rename
    that refuses to replace (`renameat2(RENAME_NOREPLACE)` through
    `syscall(2)`, as musl has no wrapper; `MoveFileExW` without
    `MOVEFILE_REPLACE_EXISTING` on Windows). A test forces the fallback.
  - Generations were whole metadata sets, so the history grew by the
    store's metadata on every run. They are now listings over pieces kept
    once by SHA-256, cut content-defined near 64 KiB (the store's 1 MiB
    chunks shared too little of a snapshot), so a run adds about what
    changed. Nothing is pruned: thinning old generations could drop the
    very one from before an unnoticed incident.
- **2026-10-29, renames, attributes and repositories.**
  - Renames (over existing files, swaps, cycles, folder moves, and a
    rename racing each moment the engine acts) needed no change: a rename
    is a delete plus a new file under the existing rules. Two tests now
    prove it (150 seeds of the randomized one found nothing).
  - Extended attributes and ACLs were dropped from a file a download
    replaced, and the old file expired from the trash after 30 days with
    them. Downloads now carry them onto the new content (xattr(7) on
    Linux, alternate data streams on Windows), and a file whose
    attributes may hold data goes to `.homedrive/kept/` instead of the
    trash.
  - An ignore pattern matching a folder protected the files inside it
    only by a last-moment re-check; it now applies to everything below
    the folder, both ways.
  - Repositories: a busy repository (lock file, or changed within five
    seconds) is skipped for the round, lock files are never synced,
    objects go before refs, and a metadata file changed on both sides
    keeps every commit it named as a ref under `refs/homedrive/` rather
    than a conflict copy git would ignore and later prune.
- **2026-10-30, a proof of no data loss, and what writing it found.**
  - The client never moved a changed file to the trash, but "changed"
    meant a different size, mtime or inode. A program that writes a file
    in place and puts its time back (`touch -r`, `rsync -t`, exiftool's
    `-P`) left all three as they were. The edit was never uploaded, and a
    later download or remote delete sent it to the trash, which expires.
    Two fixes: a file goes to the trash only if its content is byte for
    byte the synced version (so the trash only ever holds what the
    server has), and the change time (`ctime`), which no program can set
    back, is part of a file's identity. Old state records lack it and are
    compared by content once.
  - A conflict copy's record and an adopted file's record were taken from
    a stat after the fact, which could hide a write made in between; both
    now use the stat from before the upload or hash.
  - `crates/hd-client/tests/no_data_loss.rs` runs every S/L/R case of the
    engine, every race at every moment it acts, with state kept and lost,
    and checks nothing is lost even with every trash item expired.
    `crates/hd-server/tests/no_data_loss.rs` does the same for every
    interface of the server. Both fail when the fixes are undone, and
    the server one when retention keeps nothing or a replacing WebDAV
    `MOVE` skips the trash. `check-rust.sh` now refuses dropping versions
    or purging the trash outside retention.
  - Left as is: on Windows, which has no change time through std, an
    edit that puts the time back is still unseen until its content is
    next read; it is kept, never lost.
