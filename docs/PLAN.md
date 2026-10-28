# Plan: `homedrive`, a first-party deduplicating file sync server to replace the previous file service

> **This is the working plan for the whole project.** It was approved on
> 2026-10-27. Read it before starting work, update the Status table in
> the commit that finishes or starts a milestone, and add every decision
> made along the way to the Decision log at the bottom. Stop at the end of
> each milestone so the user can test.

## Status

| # | Milestone | State | Date | Commit / notes |
|---|---|---|---|---|
| M0 | Bootstrap | done | 2026-10-27 | First commit. `make test` and `make test-image` green |
| M1 | Chunker and chunk store | not started | | |
| M2 | Journal, snapshot, namespace, crash tests | not started | | |
| M3 | Versions, trash, conflicts, retention, GC, scrub, fsck | not started | | |
| M4 | HTTP streaming, auth, users, devices, sync API | not started | | |
| M5 | WebDAV subset and rclone interop | not started | | |
| M6 | Web UI and admin page | not started | | |
| M7 | Linux client | not started | | |
| M8 | Exports, import, import-tree, verify-tree | not started | | |
| M9 | Release 0.1.0, Ansible Phase A, import on VM1 | not started | | |
| M10 | Consumer cutover | not started | | |
| M11 | Windows client | not started | | |
| M12 | macOS client | not started | | |
| M13 | Phase B: retire the previous file service | not started | | |

## Context

VM1 runs the previous file service (in `ansible_playbooks`) with Postgres and Redis. It is used for:
- file sync and storage for the user's devices;
- the backup sink for the whole homelab. The vaultwarden, playbook_runner and music_server backups write into `<old_path>/data/<user>/files/...` and then run the old rescan helper. Remote hosts and `scripts/backup_proxmox_config.sh` use the previous service's rclone WebDAV remote;
- the music library source. music-server reads `files/Music` read-only.

We replace it with a first-party Rust server and client, following the standing rules: no third-party crates, OpenSSL through hand-written FFI only, and music-server/playbook-runner as templates. **Data integrity and never losing a file come before every other goal.**

User decisions:
- **Clients:** a Linux sync daemon, plus Windows and macOS builds of the same client. Phones use WebDAV apps and the web UI. There is no native phone app.
- **Storage:** a content-defined chunk store (CAS) with SHA-256 IDs. Plain-file consumers move to the API or WebDAV. Music/ gets a read-only materialized export.
- **WebDAV:** yes, the subset that rclone and file-manager apps use.
- **Users:** several, defined in Ansible as a Vault list and passed in as a Podman secret.

Defaults chosen in this plan (easy to change): the name `homedrive` with crate prefix `hd-`, the hostname `drive.<domain>`, side-by-side rollout and then cutover, no compression, and no encryption at rest (the same as the previous file service today).

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
  - `hd-server import --user U --dest path < file` replaces the old rescan helper in the backup scripts. It streams over the socket with the same verify path and prints the version id.
  - `hd-server import-tree --user U --src /old/data/U/files [--versions /…/files_versions]` is the one-time migration. It reads the source read-only. The previous service's `.v<timestamp>` files become older versions. It writes a report of every file with its sha256.
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

**Phase A (side by side):**
- A new `roles/homedrive/`, modelled on `roles/music_server/`:
  - defaults: enabled, paths, uid/gid, users vault list, exports, memory, image, and network routes (pick a free /29 after `172.16.1.48/29`);
  - tasks: `container_network`, data and export dirs, the SELinux fcontext for the store path, Podman secrets, unit and script templates;
  - templates: the unit uses `RequiresMountsFor` on the store disk. The store goes on the previous service's disk under `<old_path>/../homedrive`, or on a new disk if free space is less than current usage, which is checked before import.
- `homedrive_import_path.sh` is the replacement helper with the same interface as the old rescan helper. It runs `podman exec -i homedrive hd-server import`.
- Wiring: the `vm1.yml` lock and image entries, `approved_container_images`, and `artifacts/containers.lock.yml` with `first_party: true`. Route dicts go in `reverse_proxy` defaults.
- A store backup script: run `hd-server checkpoint`, then borg the store dir. Chunks are immutable, so this is borg-friendly. The rclone offsite copy keeps the existing pattern.
- Tests: `tests/test_ansible_regressions.py`, `scripts/test_container_security.sh`, `test_shell_secret_env.sh`, `test_supply_chain_policy.sh`.

**Migration and cutover of consumers** (after `import-tree` plus `verify-tree` come back clean):
- vaultwarden, playbook_runner and music_server backups: replace the old rescan helper's call and the local DEST write with `homedrive_import_path.sh`.
- music_server: point `music_server_music_path` at the homedrive Music export.
- `standard_rclone` and `scripts/backup_proxmox_config.sh`: a `Homedrive:` WebDAV remote, with `*_backup_location` vars renamed.
- `roles/backup` (remote-host borg via SSHFS of the previous service's path): point it at the store dir plus a checkpoint.

**Phase B (retire the previous file service):**
- Move Postgres and Redis out of the previous service's role into a new `roles/postgres` (paperless still needs them, and its container network is renamed or kept for paperless).
- Delete the previous service's tasks, templates and lock entry. Add a retirement playbook, modelled on `retire_navidrome.yml`, which keeps the previous service's data dir unless a flag is given.
- Docs: architecture, ADR, variables, services, dr-restore, and `docs/guides/homedrive-migration.md`.

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
| M8 | Exports, the admin socket `import`, `import-tree` (with the previous service's versions) and `verify-tree`. |
| M9 | Release 0.1.0, Ansible Phase A, deploy side by side, import, verify-tree with 0 mismatches, and measure memory. |
| M10 | Cut consumers over (backups, music export, rclone remotes, borg). Watch a week of daily backups land. |
| M11 | The Windows client (an x86_64-pc-windows-gnu cross build in the toolbox with mingw + static OpenSSL), and the Windows rename and fsync semantics. |
| M12 | The macOS client (built on a Mac, with FSEvents and `F_FULLFSYNC`). |
| M13 | Phase B: retire the previous file service (check mode first) and split out Postgres and Redis. |

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
