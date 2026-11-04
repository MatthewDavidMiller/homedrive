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
| M9 | Release 0.1.0, Ansible Phase A, import on VM1 | in progress | 2026-11-03 | 0.1.3 released as a prerelease (its digest is in the release notes), with a History page in the client; 0.1.2 cut the client's CPU and memory and fixed a write hidden in the change time's tick; the versions restarted at 0.1.0, see the 2026-11-02 entry in the Decision log; 0.1.2 is deployed on VM1, import pending (three data-loss reviews, with proof tests for client and server: kept copies, import-tree never replaces homedrive edits, restore manifests never overwritten, copy generations, retention clock, WebDAV COPY onto an ancestor); VM1 deploy and import pending |
| M10 | Consumer cutover | not started | | |
| M11 | Windows client | tested on Windows 11 and NTFS, user sign-off pending | 2026-11-01 | `make test-windows` runs 102 tests natively, including the no-data-loss proof; see the 2026-11-01 entry in the Decision log for what is still unverified |
| M12 | macOS client | dropped | 2026-11-01 | No Mac to build or test on; see the Decision log |
| M13 | Retire the previous file service | not started | | |
| M14 | Client GUI | done, user sign-off pending | 2026-11-03 | Wizard, folder picker, status page, a History page, removing folders, signing out, start at sign-in, and a tray icon; `crates/hd-client/tests/gui.rs` passes on Linux and Windows |

## Context

homedrive is the homelab's file sync and local cloud storage service on VM1. It provides:
- file sync and storage for the user's devices;
- a backup sink for the homelab: service backups (vaultwarden, playbook_runner, music_server) land in it through a local import helper, and remote hosts and `scripts/backup_proxmox_config.sh` reach it as an rclone WebDAV remote;
- the music library source: music-server reads a read-only Music export.

It takes over these jobs from the homelab's previous file service. That migration is driven from `ansible_playbooks` and planned there. This repo only builds the features it needs: `import-tree` with old versions, `verify-tree`, `import`, exports and WebDAV.

It is a first-party Rust server and client, following the standing rules: no third-party crates, OpenSSL through hand-written FFI only, and music-server/playbook-runner as templates. **Data integrity and never losing a file come before every other goal.**

User decisions:
- **Clients:** a Linux sync daemon, plus a Windows build of the same client. Phones use WebDAV apps and the web UI. There is no native phone app.
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
| `hd-sys` | `music-server/crates/ms-sys` + `rpi-omt-client/crates/omt-sys/src/ssl.rs` | libcrypto (sha256, hmac, random, ct_equal, cleanse) plus **new streaming `EVP_DigestInit_ex/Update/Final_ex`**. libssl client side for the sync client only. posix additions: `renameat2`, `fdatasync`, `statvfs`, `inotify_*`, `flock`. Windows FFI behind `cfg(target_os)`: `ReadDirectoryChangesW`, `MoveFileExW`, `FlushFileBuffers`. |
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
- `LOCK`/`UNLOCK` are non-enforcing class-2 stubs, so Windows and other clients that want them can write.
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

### Client (`hd-client`): Linux first, then Windows

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
  - A full rescan every 10 minutes as the source of truth. The watcher is only a hint.
- **TLS:** libssl FFI from `omt-sys/ssl.rs`. It verifies the hostname and trusts the built-in ISRG Root X1 and X2 (Let's Encrypt) by default, with a `ca_file` override.
- **CLI:** `homedrive login|daemon|sync --once|status|conflicts|confirm|trash|versions|restore`.
- **Running it:**
  - Linux: a systemd user unit.
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
| M12 | Dropped: macOS is not supported. |
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
- **2026-11-01, M11 tested on real Windows.** First run on Windows 11 and
  NTFS, from WSL on the user's desktop, with `homedrive.exe` against the
  Linux server and the client's suites run natively. The server library
  now builds for Windows (test use only; `admin` stays Unix-only and there
  is no server binary), so the end-to-end suites run there. `make
  test-windows` is the repeatable form, and the gate lints those tests.
  - Found and fixed, each with a test in `crates/hd-client/tests/windows.rs`
    that fails when the fix is undone:
    - Two server folders differing only in case merged into one local
      folder: collisions compared whole paths. They now cover every level.
    - `fold_key` folded ASCII only, so `RÉSUMÉ.txt` and `résumé.txt` were
      not seen as a collision and the second never arrived, silently. It
      now maps characters as NTFS does.
    - A local rename of letter case alone was reported as a collision on
      every round, so later edits never uploaded. The scan now adopts the
      server's spelling, including under protected paths. Decided: such a
      rename stays local, and other devices keep the old spelling. Moving
      it on the server would be a feature the engine does not have yet.
    - Local names Win32 rewrites (`trailing.`, `space `) were skipped with
      no report, because the stat found nothing and read as "gone". The
      scan now reports them before it stats. This was a silent gap in
      backups.
    - The raw Win32 calls took paths without the `\\\\?\\` form, so
      past 260 characters stream listing failed and every replaced file went
      to `.homedrive/kept`, which never expires.
    - An edit that keeps size and modification time stayed unsynced, the
      gap the previous entry left as is. `file_stamp` (`ChangeTime` and the
      file number) now gives Windows the checks Linux has. That entry no
      longer applies.
    - `schtasks /sc onlogon`, as `docs/USAGE.md` gave it, is refused for a
      normal user. It now gives a logon task that needs no elevation.
    - A missing `--ca-file` reported "No such process".
  - Passed as they were: locked files (fail, retry, nothing lost), read-only
    files, alternate data streams, reserved and forbidden names, junctions,
    invalid UTF-16 names, the sentinel, missing-root and mass-delete guards,
    daemon and watcher, the one-client lock, restore, and HTTPS (wrong CA,
    no CA and wrong hostname are all refused). `fsck` was clean afterwards.
  - Checked on the desktop, the same day: `test-notification` and the
    daemon's own mass-delete alert both appear as Windows notifications,
    captured from the screen, and the 70 held files stayed on the server.
    A logon task registers without elevation (`docs/USAGE.md`), runs the
    daemon with no window, and syncs. Toasts appear even though the
    account's `ToastEnabled` value reads 0.
  - Not verified: the logon trigger itself firing (the task was started
    by hand, to avoid signing the user out); a FAT or exFAT disk, where
    `rename_noreplace` is the fallback (tested on NTFS only); `hd-store`'s and `fsio`'s own tests,
    which stay Unix-only, though the client suites exercise both.
- **2026-11-01, macOS dropped; releases carry the clients.** There is no Mac
  to build or test on, so M12 is closed rather than deferred, and the code
  paths and fallbacks kept for other systems are gone. Clients are x86-64
  Linux and Windows. Each release now attaches both, static, with
  `SHA256SUMS`; `make linux` is the new build. They are built before
  anything is published, so a client that will not build stops the release.
  The server stays image-only.
- **2026-11-01, M14: the client GUI is a local web page.** The user asked for
  a full GUI with a wizard, and allowed a web one. A native GUI would need a
  large crate or hand-written Win32 and GTK. The daemon serves it on
  127.0.0.1, so one process syncs and reports, and `homedrive` with no
  arguments (a double-click on Windows) opens it. The ISRG roots are built
  in for Windows, as the original plan had it, since a wizard asking for a
  PEM file would stop most users. `--ca-file` remains for private CAs.
  - Removing a folder and signing out discard its sync state, so a local
    deletion cannot replay onto a server later, and signing out clears the
    folder list, so one server's state never meets another. Tests prove a
    deleted file returns rather than being deleted on the server, and that
    moving to an empty server deletes nothing.
  - The Windows tray and the Run entry were tested on a real desktop: the
    icon registered, its clicks and menu worked, and the command stored in
    the registry started the program. A Linux StatusNotifierItem was tested
    on a real bus with a GLib watcher.
  - Left as is: a console shows for about a second at each Windows start,
    since one .exe is also the command-line tool; a separate windowless
    program would remove it.
  - Not verified: a real sign-in; a real Linux panel, or the portal call that
    opens a browser there; how the tray icon looks; the wizard on a real
    HTTPS server.
- **2026-11-01, a wizard no browser could use.** 0.1.9 refused every form in
  every browser. `Referrer-Policy: no-referrer` makes a browser send
  `Origin: null` on a form, which the GUI refuses, and no test used a browser:
  Edge only rendered pages, and curl and the test client send no `Origin`.
  The policy is now `same-origin`, and a test pins it. Every form was then
  submitted by real Edge through the DevTools protocol, with the result
  checked, and the wizard run with the real Windows program. A GUI change
  needs that, not only HTTP tests.
- **2026-11-02, an unexplained crash in a large first sync.** 0.1.10 aborted
  at the end of a round on 285 GB being copied in, with hundreds of HTTP 429s.
  Not reproduced: output with no console, 429s, files written during a sync,
  and a status page polled hard each survived. A panic left no trace, so
  `crash.log` now keeps the message and its source location. 429s are waited
  out with backoff, except when signing in, where they mean wrong passwords.
  Traefik's limit stays. The crash itself is still open.
- **2026-11-02, the crash, and power cuts.** `crash.log` named the crash:
  `failed printing to stdout`. A daemon that left its console kept printing,
  and a failed print ends a Rust program; one failure in many prints, so the
  first test of this missed it. Output now goes to `daemon.log`, and a failed
  print or report ends nothing.
  - The crash tests left what a dying process leaves, with the system's cache
    intact. `faults::shadow` models a power cut instead: only what was fsynced
    survives. The server store and a client round are cut at every write.
    Removing any one fsync makes the tests fail, so they can tell. They found
    no loss, and one leak: a cut download left its staging file forever, now
    cleared after an hour.
  - On Windows a directory is now flushed after a rename. NTFS keeps a rename
    atomic but had no reason to have written it yet.
  - The model assumes fsync is honoured. A disk that lies, or a virtual disk
    with an unsafe cache mode, can break any of this, and no test here can
    show that. It is untested on Windows: the shadow needs Unix.
  - The page shows a round in progress, since the status file only says how
    the last one ended. It could show old errors as current, or old success.

- **2026-11-02, performance, with every safeguard kept.** `make bench` times a
  whole sync with real fsyncs. On this machine, for 20,000 4 KB files and a
  1 GiB file:

  | | Before | After |
  |---|---|---|
  | Upload small files | 64 files/s | 279 files/s |
  | Download small files | 183 files/s | 349 files/s |
  | Upload a 1 GiB file | 60 MB/s | 83 MB/s |
  | Upload a 4 KB edit of it | 9.7 s | 4.7 s |
  | Peak memory, client and server | not measured | 48 MB |

  At 100,000 files small uploads ran at 307 files/s, so the rate holds as a
  drive fills. The old cost grew with the drive; it was not measured at that
  size.
  - A quota check added up every version in the drive, three times per file.
    It is now a running count, compared with the sum in the model test and,
    since it is rebuilt from snapshots, in every comparison of live and
    recovered state. The change feed no longer copies what its page drops,
    and answers at once when nothing has been recorded.
  - The chunker zeroed and copied 4 MiB for every chunk, and for every small
    file. `send` read and hashed a large file a second time, and a new file
    was hashed once more before chunking. None of those passes checked
    anything the others did not: what a commit names is what was hashed, and
    the server hashes everything it receives.
  - **Batches.** Three requests per file met the proxy's limit of 100 a
    second at 33 files/s, and the disk's fsyncs one after another. New files
    of up to 1 MiB now go in one request, up to 64 files or 8 MiB, with the
    same checks and the reply only once everything is durable. This changes
    the API by adding one call; a new client falls back to the old calls on a
    server without it. Changes to existing files are not batched, so the
    mass-change and encryption checks still see them first.
  - **Group commit.** A batch appends and applies its records under the lock
    and flushes once. The durability promise is unchanged: nothing is
    answered, and no one can read a record, before the flush. If the flush
    fails the store stops accepting writes, as it does for any journal
    failure. Journal format unchanged.
  - **One durability rule relaxed, on purpose.** The client's state log is
    flushed every 256 records and at the end of a round, not at each record,
    which saves two of seven fsyncs per small file. Principle 7 never depended
    on it: state is a memory that can be lost, and the power-cut tests passed
    with this flush removed. A new test takes the state back to every moment
    of a mixed history. Files, the server journal, and object writes keep
    every fsync they had.
  - The daemon no longer scans every 15 seconds: a watcher wakes it, it asks
    the server for news (now cheap) every 15 seconds, and it scans at least
    every 5 minutes, since watchers can miss things. So a change a watcher
    misses can take up to 5 minutes to go up, where it took 15 seconds.
  - **Proof.** 14 deliberate breaks of the new code. 13 are caught, three of
    them only after this review added tests: bytes lost as the chunker's
    buffer moved, a file changing as it is read, and a chunk vanishing before
    a batch arrives. The one survivor drops the client's own check of a
    re-read chunk, which the server's check of the same hash still catches.
    Parallel storing runs on one thread under fault injection, which follows
    one thread, so power cuts are proved for the sequential path only; the
    threads run the same thread-safe calls that concurrent connections do.
  - **Then, downloads and Windows scans.** New files come down in batches
    too: 349 to 514 files/s, and the proxy's 100 requests a second no longer
    caps them. Each is checked and flushed as before, side by side, and takes
    its name the same way. Replacing a local file still goes alone. A Windows
    scan used two opens per file, and now uses one, with a test that every
    field matches, so an update does not re-hash a drive: an idle round of
    20,000 files went from 1.6 s to 1.0 s on NTFS. Reading the directory
    listing instead would be faster and was refused: NTFS updates those
    entries lazily, so a held-open or hard-linked file can look unchanged.
    6 more deliberate breaks of the new code: 5 caught; the survivor is
    `place` skipping its check for a file that appeared, which `commit_new`
    still refuses to replace.
  - Left alone, measured: a large upload is 82 MB/s here with client and
    server sharing a machine and most of the CPU going to hashes that are
    checks. Each side's share is well above a gigabit link, so a real upload
    is limited by the network and VM1's disk, and sending chunks side by side
    would add risk for nothing.

- **2026-11-02, performance, third pass.** `make bench` now splits CPU: of
  72 s uploading 20,000 small files, 2 s were in user code, so what was left
  was waiting for fsyncs. Filesystems serve fsyncs that wait together with
  one disk write, so storing a batch on 16 threads instead of 4 took small
  uploads from 278 to 726 files/s and small downloads from 508 to 660, at
  the cost of more system CPU. This disk is an SSD behind WSL; VM1's is not
  measured.
  - A commit verifies chunks four at a time; a 4 KB edit of 1 GiB went from
    4.7 s to 4.1 s. It still checks every chunk and the whole file.
  - A folder listing used to read everything beneath the folder while
    holding the metadata lock. It now steps over each child's contents.
  - The export worker went to the disk after any commit by anyone. It now
    goes when something under the export changed, and hourly regardless, so
    a damaged export copy can take up to an hour to be noticed, not until the
    next commit. It had no test of its own; it has one now.
  - **A small hole closed.** A writer that found an object already stored
    relied on it without knowing its name had been flushed, so a power cut
    just then could lose a chunk a commit had counted on. It now flushes the
    folder first. No test can time this; it adds one fsync when content is
    stored twice.
  - 7 more deliberate breaks, all caught.
  - Left alone on purpose: edits are not batched (they are few, and sit next
    to the ransomware checks), and `removed` still keeps every deleted path
    forever, which grows state and the change feed slowly. Pruning it needs a
    horizon for old cursors, and a client past it would have to start over.

- **2026-11-02, the versions and the history start again.** Nothing depended on
  either, so before anything real runs on it the project became one commit,
  released as 0.1.0, and the earlier tags, releases, and images were deleted.
  In the entries above, versions 0.1.0 to 0.1.13 are that earlier series, not
  this one. They are kept because the reasons in them still hold. Rolling back
  to any of them is no longer possible.

- **2026-11-02, the daemon runs in the background.** A sync should never cost a
  game a frame, so it now asks to come after everything else. Measured on
  NTFS with client and server sharing a process, and so both slowed, 5,000
  small files went from 156 to 63 files/s up and 609 to 184 down, and 256 MiB
  from 101 to 91 MB/s up and 220 to 108 down, on a quiet machine. That is the
  price: Windows limits background disk access even on an idle disk. It was
  accepted because daily syncs are small. Only the daemon does this, so a
  first sync run by hand with `homedrive sync` does not pay it.

- **2026-11-02, the client's own CPU and memory.** The passes above were about
  how fast a sync goes. This one is about what the daemon costs the rest of
  the time. `make bench` shares a process with the server, so
  `make bench-daemon` runs the real programs apart, with 50,000 small files:

  | | Before | After |
  |---|---|---|
  | Memory at rest | 30 MB | 20 MB |
  | Peak after a restart | 49 MB | 33 MB |
  | Peak with the GUI open | 61 MB | 33 MB |
  | CPU idle for 320 s, one full scan included | 0.61 s | 0.31 s |
  | Wake-ups in those 320 s | 1,391 | 457 |
  | CPU for a one-file edit | 1.11 s | 0.27 s |
  | CPU for the GUI open for 60 s | 0.80 s | 0.01 s |
  | Peak for 64 MiB of 256 KiB files and 256 MiB each way, from 7 MB | 23 MB | 15 MB |
  | CPU for a first sync of the 50,000 files | 4.07 s | 3.53 s |

  The peak of that first sync did not move: 54 MB, once.
  - On Linux every round was followed by a second scan just to find folders
    to watch. The round's own scan now does that, before the round's work,
    so a change during a long first sync wakes the daemon. It used to wait
    for the next full scan.
  - The GUI read and checked a folder's whole state every 5 seconds to show
    one number. A running folder now reports it. A stopped one is still read.
  - A round copied every path to compare them. Paths whose three sides agree
    are now counted and passed over. `settled` must therefore say yes only
    where `reconcile` does nothing; a test changes each field in turn.
    Background verification copied the rest of its list each round, and now
    takes one file at a time.
  - Maps grown a key at a time keep half-empty nodes. They are built whole on
    loading, and again after a quarter of the state has changed.
  - Nothing else about the state changed, and its format did not.
  - A large file's chunks were copied only to be dropped, and the client now
    reuses one buffer to re-read them. Downloads wrote 8 KiB at a time, a
    system call each, and now write what the connection's buffer holds.
    Batches were in memory twice each way, and now once. These change how
    bytes move, not any check: every hash is taken as before.
  - The folder threads woke twice a second and the health thread once, to
    look at a stop flag. They now sleep until a change, a poll, or a wake-up
    (a pipe on Linux, an event on Windows). What remains is the 15-second
    poll and the disk's own waits during a scan. A failing watcher used to
    spin until the next poll; it now waits.
  - Folders share one TLS context, which holds every trusted root, and the
    health check closes its connection between its 10-minute asks. The bench
    runs over plain HTTP, so neither is measured.
  - **Proof.** 22 deliberate breaks of the new code. 21 are caught, three of
    them only after a further round of tests. One of those gaps is older than
    this pass: nothing tested that a repository's objects go up before its refs.
    The survivor sends a chunk twice in a batch, which costs bytes and which
    the server accepts. `make test` passes. `make test-windows` passes but for the open item
    below. No figure above was measured on Windows.
  - `a_file_changing_as_it_is_read_waits_for_the_next_round` failed about four
    runs in five on Windows when run alone, on older builds too: a write of
    the same size in the same 15 ms tick looks like no write, which the rule
    on recent files covers. The test now writes in a later tick.
  - On Windows `every_case_of_the_sync_table_loses_nothing_with_state_kept`
    sometimes ended with the two machines holding different versions of a
    file, on builds from before this pass too. Found and fixed in the next
    entry.
  - Left alone: the first sync's peak (mostly the scan, the state and the
    round's lists at once), and keeping scans in a sorted list, which would
    save about 3 MB of the peak at this size. Sharing path strings between
    the two maps would save little and touch every use of them.

- **2026-11-02, a write hidden in the change time's tick, and Windows.**
  - **The bug.** A record was trusted once its modification time was a few
    seconds old; the change time was not held to that. A program that writes a
    file and puts the modification time back leaves only the change time
    moved, and within that clock's tick, 15 ms on NTFS, not even that. A file
    renamed a moment before (old modification time, new change time) and then
    written that way while the engine read it was committed from what was
    read, and recorded as in sync with what is now on disk. The new content
    stayed on this computer, never sent, until the background check took it
    for damage: kept, and replaced with the server's copy. A new test does it
    300 times: on NTFS 61 writes never reached the server; on Linux, whose
    clock ticks finer, none. Now a recent change time also means the content
    is compared next round, and none are missed. This was what
    `every_case_of_the_sync_table_loses_nothing_with_state_kept` kept hitting
    on Windows (its case `f15`: a rename onto the file, then such a write).
    Downloads are left out on purpose: giving one its name sets the change
    time to now, and holding them to it would read back everything
    downloaded. A write would have to land in that tick and put the time
    back; the background check would then find it and keep it.
  - Three tests built a damaged file's record by hand with the old
    modification time and a new change time, which no real record now has.
    The helper now records both.
  - **Windows, measured** with `make bench-windows`: the real client on
    NTFS, the server in WSL, 20,000 small files:

    | | Before | After |
    |---|---|---|
    | CPU idle for 320 s, one full scan included | 0.94 s | 0.27 s |
    | CPU for one file edited | 1.88 s | 0.27 s |
    | CPU for one file added | 2.81 s | 0.59 s |
    | CPU for the first sync | 6.55 s | 4.28 s |
    | Working set at rest | 20 MB | 1 MB |
    | Private memory at rest | not measured | 13 MB |
    | Peak working set | 32 MB | 30 MB |

    The working set is what is in memory now; trimming it moves pages out,
    and they come back when touched, so the private figure is the one to
    compare with Linux.
  - A scan asked for each file's facts by opening it. Windows 11 24H2 can
    answer by name, and a test holds that answer to the open's at every
    moment where they could differ (see DESIGN). Older Windows still opens.
  - Every round looked at every name and folder name for case collisions
    and names Windows cannot make, building maps of all of them. A round
    with nothing to do now skips that and reports what the last one found;
    one that adopts no spelling is found without the maps. Case folding of
    ASCII no longer goes a letter at a time.
  - One save signals several times. Each signal waiting after the settle
    started another round; the round's scan sees what they were about, so
    they are passed over.
  - The built-in CA file was written durably for every connection to the
    server; it is written only when it differs.
  - **Proof on Windows.** 11 deliberate breaks of this entry's code, run on
    NTFS: 9 caught, two of them after tests were added (a junction for the
    by-name look; a wait on a watched folder for the wake-up). Survivors:
    reusing the name answer while something could not be seen, which only
    risks reporting a name twice; and trusting a download's recent
    modification time, which needs a write within 15 ms of the download to
    show, and no test can time that. The no-data-loss and sync suites then ran 12 times in a row on
    NTFS: 24 runs, no failure. `make test-windows`: all 12 suites and the
    folder check pass, 147 tests.
  - **Microsoft Defender** removes some debug test programs
    (`Program:Win32/Contebrew.A!ml`, a machine-learning guess) at times
    as `make test-windows` copies them, and then those suites do not run;
    the script reports a failure, never a pass. Release
    builds of `homedrive.exe`, before and after this pass, scan clean. No
    exclusion was added; that is the user's decision.

- **2026-11-02, fewer copies.** A probe of each part of a round, counting
  allocations, found two more:
  - The chunker zeroed a 64 KiB buffer for every file, however small: 3.1 GB
    of the 4.6 GB allocated in a first sync of 50,000 small files. Its first
    buffer now fits the file; a file that grows is still read whole, and a
    test cuts streams with every wrong size hint against the right cuts.
  - A scan made a new path for every file it looked at. It now lends one
    path down the walk: a third fewer allocations in a scan.
  - The server stored each chunk of a WebDAV or web upload from a copy; it
    now stores it from the chunker's buffer.
  - With 50,000 files, `make bench-daemon`: a first sync went from 3.53 to
    2.84 s of client CPU. Idle wake-ups fell from 457 to 43 in 320 s, mostly
    from the previous entry's passing over waiting signals. The rest is
    unchanged: an idle round is now the kernel's stats of every file.
  - 3 deliberate breaks, all caught. `make test` and `make test-windows` pass.
  - Left alone: one map of paths for both sides of the state instead of two
    would save about a fifth of the state's memory (about 3 MB at 50,000
    files), but touches every rule the engine has; scans kept as a sorted
    list would save about 3 MB at the same size, once per scan.
- **2026-11-03, a scan as a sorted list.** A scan is made in one go and then
  only read, so it is now a list sorted once at the end, with the map's
  `get`, `contains_key` and order, instead of a map of half-full nodes. The
  rules that read it are unchanged.
  - The walk goes folder by folder, which is not path order (`a/x` comes
    before `a-b`), so the list is sorted when the walk ends. Unsorted, a
    lookup would miss files that exist, and a missed file looks deleted.
    A test scans real folders named to fall out of order and finds every
    path; another keeps the last of two entries for one path, as the map
    did. Only the first test catches the sort left out: the sync suites
    do not.
  - With 50,000 files, `make bench-daemon` against the previous entry: the
    peak of a first sync went from 53.4 to 48.8 MB, and of the 64 MiB
    upload from 38.9 to 34.2 MB, both baselines as in the previous run.
    CPU moved within noise.
  - 4 deliberate breaks, all caught. `make test` passes, and so does
    `make test-windows`, except that Defender quarantined the client's
    unit-test binary (threat 251873, a false positive seen before); those
    tests pass on Windows built as release.
- **2026-11-03, a History page in the client.** The page said only whether
  a folder was up to date, so there was no way to see whether something had
  synced recently.
  - Each round that changes something adds what it uploaded, downloaded,
    deleted here or on the server, kept as both copies, repaired or sent
    again to `history.jsonl` in the folder's state directory. A failed round
    is added with its reason, once rather than at every retry. It keeps the
    newest 1000 changes and names at most 200 a round, counting the rest.
  - It is a record for the user, not state: the engine never reads it to
    decide anything, a damaged line is passed over, and a failure to save
    it never fails a round.
  - Each folder card says when the folder was last checked and last
    changed, and links to the page. With no JavaScript the page cannot know
    the time zone, so times read as how long ago, with UTC on hover.
  - Checked in headless Edge on Windows against a real server: the Windows
    client recorded uploads, an edit, a download from WebDAV and a
    deletion, and both pages rendered in light and dark. `make test` passes.
