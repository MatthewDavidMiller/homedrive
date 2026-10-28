# Agent Instructions

Workflow instructions for coding agents working in this repository.

**Start every session by reading [docs/PLAN.md](docs/PLAN.md).** It is the
approved plan, and its Status table shows which milestone is in progress.
Update that table, and its Decision log, in the commit that changes either.
Stop at the end of each milestone so the user can test.

The architecture lives in [docs/DESIGN.md](docs/DESIGN.md).
[docs/USAGE.md](docs/USAGE.md) and [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)
describe the behaviour users and operators rely on. Update them with any
change to it.

## Non-Negotiables

- **Never lose a file.** Data integrity comes before every other goal,
  including speed, features and code size. The integrity principles in
  docs/PLAN.md bind every crate:
  - content is immutable and addressed by SHA-256, and verified on every
    read;
  - a write is durable before it is acknowledged;
  - nothing is overwritten or deleted directly; overwrites make versions,
    deletes go to trash, and conflicts keep both copies;
  - GC is mark-and-sweep with grace periods, never refcounting;
  - hashes are verified end to end;
  - the server fails closed on a missing sentinel or a corrupt journal;
  - the client never destroys local data on an assumption.
- **Durable writes go through `hd_common::fsio`.** `scripts/check-rust.sh`
  refuses `fs::write`, `File::create`, `fs::rename` and friends anywhere
  else in shipped code.
- **Only GC and the client trash delete.** `remove_file`, `remove_dir*` and
  `set_len` are allowed only in `hd-common/src/fsio.rs`,
  `hd-store/src/gc.rs` and `hd-client/src/trash.rs`. The gate enforces
  this.
- **No third-party crates.** `Cargo.lock` lists workspace members only, and
  `scripts/check-rust.sh` fails the build otherwise. Write what you need, or
  port it from the sibling `music-server`, `playbook-runner` and
  `rpi-omt-client` repositories, which follow the same rule.
- **OpenSSL is the only third-party library.** Never implement a
  cryptographic primitive. Bind OpenSSL's in `crates/hd-sys` and wrap it in
  `crates/hd-crypto`. libssl is for the sync client's TLS only; the server
  speaks plain HTTP behind Traefik.
- **No subprocesses.** Nothing in shipped code starts a program, and the
  gate checks this.
- **`unsafe` lives only in `hd-sys`.** Every other crate root carries
  `#![forbid(unsafe_code)]`, and the gate checks it.
- **Secrets never reach disk in plaintext, logs, or the UI.** Passwords
  live in memory only, loaded from the users file. Device tokens are
  stored as hashes. Never log file names at info level, or credentials at
  any level.
- **Every input is bounded.** `clippy.toml` refuses the unbounded std
  readers; use the bounded replacements in `hd-common`.
- **Formats are forever.** The chunker's gear table and size parameters,
  chunk and manifest IDs, and the journal and snapshot formats decide
  whether existing stores stay readable. Change them only with a version
  bump and a reader for the old version.
- **Images are pinned by digest.** Base images in `Containerfile` and
  `tools/toolbox/Dockerfile` are official images referenced by digest.

## Validation

Every gate runs inside the toolbox image; rootless Podman is the only host
prerequisite. Never install a toolchain or linter on the host to satisfy a
gate.

```bash
make install     # once per clone
make test        # the full pre-commit gate
make test-image  # before a release: the image under VM1's flags
```

Run `make test` before reporting a change complete. Never pass `--no-verify`
to `git commit`.

## Commits

Only commit when asked. Commit messages are a short imperative subject
followed by a body explaining what was wrong, what changed, and why, wrapped
at 72 columns, no emoji.
