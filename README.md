# homedrive

A first-party, deduplicating file sync and storage server, with a sync
client, written in Rust with no third-party crates. It replaces the previous file service
in the homelab (`ansible_playbooks`).

- **Never loses a file.** Content is immutable and addressed by SHA-256,
  every write is durable before it is acknowledged, and overwrites, deletes
  and conflicts all keep the old data.
- **Deduplicated.** Files are split into content-defined chunks and each
  chunk is stored once, across every version and every user.
- **Versioned.** Every change is a new version, with a trash and a
  retention policy.
- **Reachable.** A sync client for Linux (then Windows and macOS), a
  WebDAV subset for rclone and phone apps, and a web UI.

**Status:** early development. See [docs/PLAN.md](docs/PLAN.md) for the
plan and the milestone status.

## Documentation

| Document | Contents |
|---|---|
| [docs/PLAN.md](docs/PLAN.md) | The approved plan, milestone status, and decision log |
| [docs/DESIGN.md](docs/DESIGN.md) | Architecture and the integrity model |
| [docs/USAGE.md](docs/USAGE.md) | Running the server and the client |
| [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) | The container and VM1 deployment |
| [AGENTS.md](AGENTS.md) | Rules for anyone (or anything) changing the code |

## Building

Rootless Podman is the only prerequisite. Every gate runs in the toolbox
image.

```bash
make install     # build the toolbox and install the git hooks (once)
make test        # the full gate: lint, fmt, dependency graph, clippy, tests
make image       # build localhost/homedrive:dev
make test-image  # run the image under VM1's security flags
```

## License

MIT. See [LICENSE](LICENSE) and
[crates/hd-server/THIRD_PARTY_NOTICES.txt](crates/hd-server/THIRD_PARTY_NOTICES.txt).
