# Usage

## Server

```text
hd-server [serve]      Run the server (the container's command)
hd-server healthcheck  Exit 0 when the local server answers /healthz
hd-server version      Print the version
```

| Variable | Default | Meaning |
|---|---|---|
| `HD_LISTEN` | `127.0.0.1:8080` | Address the HTTP listener binds |
| `HD_DATA_DIR` | `/var/lib/homedrive` | The store |

Later milestones add the store, the sync API, WebDAV, the web UI, the
maintenance commands (`fsck`, `gc`, `scrub`, `checkpoint`, `import`,
`import-tree`, `verify-tree`) and the `homedrive` client. Each is
documented here as it lands.
