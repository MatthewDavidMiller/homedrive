# Usage

## Server

```text
hd-server [serve]      Run the server (the container's command); it
                       refuses to start unless HD_DATA_DIR is a store
hd-server init         Make HD_DATA_DIR a new, empty store (it must be
                       empty; this never adopts an existing tree)
hd-server healthcheck  Exit 0 when the local server answers /healthz
hd-server version      Print the version
```

Maintenance commands open the store themselves, so the server must be
stopped (the store admits one process at a time):

```text
hd-server fsck [--deep] [--repair-tail]
        Check that every live and trashed version can be read back. --deep
        reads and hashes every chunk. Exits non-zero on any problem and
        names the affected files. --repair-tail sets a damaged final
        journal record aside in quarantine/ (the store refuses to open
        otherwise).
hd-server gc [--dry-run]
        Collect unreferenced objects: 48 h grace, then 7 days in gc-trash/
        before deletion.
hd-server scrub        Re-verify every object and quarantine any damage
hd-server checkpoint   Write a metadata snapshot now
```

| Variable | Default | Meaning |
|---|---|---|
| `HD_LISTEN` | `127.0.0.1:8080` | Address the HTTP listener binds |
| `HD_DATA_DIR` | `/var/lib/homedrive` | The store |
| `HD_MIN_FREE_GB` | `1` | Free space below which the store refuses writes (0-100000) |

If `serve` says the data directory "has no store.id", check that the
store's disk is mounted before doing anything else. Run `init` only for a
brand-new store.

Later milestones add the store, the sync API, WebDAV, the web UI, the
maintenance commands (`fsck`, `gc`, `scrub`, `checkpoint`, `import`,
`import-tree`, `verify-tree`) and the `homedrive` client. Each is
documented here as it lands.
