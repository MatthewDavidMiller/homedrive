# Deployment

The image is `ghcr.io/matthewdavidmiller/homedrive`. It is private while
the repository is private, so VM1 needs a pull credential. The method is
decided at M9 and recorded in [PLAN.md](PLAN.md).

## Container

- Built from the official Alpine image, pinned by digest. The binary is
  fully static.
- Runs as uid 10001.
- The store lives on a volume at `/var/lib/homedrive`; exports go to
  `/srv/exports`.
- Listens on 8080 with plain HTTP, on an internal Podman network only.
  Traefik terminates TLS for `drive.<domain>`.
- `HEALTHCHECK` runs `hd-server healthcheck`.

VM1 runs it with:

```
--read-only --cap-drop=ALL --security-opt=no-new-privileges:true
--memory=1g --memory-swap=1g --pids-limit=200
--tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m
```

`make test-image` checks the image under exactly these flags.

## First start

The server refuses to start on a volume that is not a store. Create the
store once, on the empty volume, with the same mount:

```
podman run --rm <flags> -v <store>:/var/lib/homedrive <image> init
```

`init` refuses a non-empty directory and an existing store, so running it
again by mistake changes nothing. Never run it to "fix" a refusal to start:
that refusal usually means the store's disk is not mounted.

## Exports and imports

Mount a host directory at `/srv/exports` and set `HD_EXPORTS` to keep
plain-file copies there, for example `alice:Music=>music` for
music-server, which then mounts `<exports>/music` read-only.

Backup scripts store their archives with:

```
podman exec -i homedrive hd-server import --user alice --dest backups/x/archive.tar.gz < archive.tar.gz
```

## Backing up the store

Run `podman exec homedrive hd-server checkpoint`, then back up the store
directory with borg. Chunks and manifests never change once written, so
borg deduplicates them across runs. Two rules make a backup taken while
the server runs safe:
- **Archive `meta/` first**, as its own path before the rest of the
  store. An object is always stored before the journal record that names
  it, so a journal copied first never names an object the copy lacks.
- **Leave out `history.id`.** A restored store then starts a new history,
  and every sync client compares its files afresh instead of trusting what
  it saw of the history the restore went back on. If you restore by other
  means (a disk copy, a filesystem snapshot), delete `history.id` before
  starting the server.

A restore needs nothing else: run `hd-server fsck --deep` on it before
trusting it.

## Disk damage: bit rot and failing drives

What the server does on its own:
- **Every read is verified** against the object's SHA-256. Damage is
  never served: the request fails, and the object is quarantined
  (renamed, bytes kept) so it reads as missing.
- **A read the disk cannot complete** (an I/O error from a bad sector) is
  retried once, then treated the same way. A copy that cannot be read
  never blocks storing a good one in its place.
- **Scrub** re-reads every object every `HD_SCRUB_DAYS` (default 30),
  throttled to `HD_SCRUB_MBPS`. It carries on past unreadable objects and
  reports them. It also checks every metadata snapshot and journal, and
  repairs a damaged one by writing a fresh checkpoint from the verified
  state in memory.
- **A reference check** finds which files are affected, as soon as
  anything is quarantined, after each scrub and GC, and every 10 minutes
  while damage remains.
- **Sync clients heal it.** A client whose copy of a damaged file is that
  exact version (re-hashed in full first) uploads it again, and shows a
  notification saying so. Remaining damage, and a disk that cannot read
  some data, appear on the admin page, in `GET /api/v1/status`, and as a
  notification on every client.

What needs you: damage no client can heal (old versions, trash, files
only ever uploaded through WebDAV or the web). Repair it from any copy of
the store, such as a backup extracted to scratch space, however old:

```sh
hd-server repair --from /path/to/extracted/store   # server stopped, or via its socket
```

It reads every version in full, takes only copies that verify, and
exits 1 naming any version no source could repair. Without `--from` it
searches only `quarantine/`, which is enough when the disk once failed a
read it now completes. The ansible role installs `homedrive_repair.sh`,
which stops the server, runs the repair in a one-off container with the
copy mounted read-only, and starts the server again.

A disk that keeps producing errors is failing: replace it. Restore the
store from backup onto the new disk (see above), then run `repair`
against the old disk's store, read-only, to recover anything written
since the backup that it can still read.

## Ansible

The `roles/homedrive` role in `ansible_playbooks` is written at M9. See
PLAN.md for the Phase A and Phase B rollout.
