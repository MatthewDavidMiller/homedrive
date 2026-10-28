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

## Ansible

The `roles/homedrive` role in `ansible_playbooks` is written at M9. See
PLAN.md for the Phase A and Phase B rollout.
