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

## Ansible

The `roles/homedrive` role in `ansible_playbooks` is written at M9. See
PLAN.md for the Phase A and Phase B rollout.
