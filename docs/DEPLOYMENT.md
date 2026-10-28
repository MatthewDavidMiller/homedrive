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

## Ansible

The `roles/homedrive` role in `ansible_playbooks` is written at M9. See
PLAN.md for the Phase A and Phase B rollout.
