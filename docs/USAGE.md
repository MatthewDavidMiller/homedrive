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
| `HD_USERS_FILE` | `/run/secrets/homedrive_users` | The accounts (see below) |
| `HD_TRUSTED_PROXIES` | unset | Proxy IPs whose `X-Forwarded-For` is believed |
| `HD_SECURE_COOKIES` | `true` | `false` only for plain-HTTP development |
| `HD_MIN_FREE_GB` | `1` | Free space below which the store refuses writes |
| `HD_MAX_FILE_GB` | `1024` | The largest file accepted |
| `HD_KEEP_ALL_DAYS` | `30` | Keep every old version this long, then thin |
| `HD_TRASH_DAYS` | `90` | Keep deleted files this long |
| `HD_MAINTENANCE_HOURS` | `24` | Retention and GC interval; `0` off |
| `HD_SCRUB_DAYS` | `30` | Full re-verification interval; `0` off |
| `HD_SCRUB_MBPS` | `50` | Scrub read rate ceiling |

The users file:

```json
{"version": 1, "users": [
  {"name": "alice", "password": "8 to 128 characters", "admin": true},
  {"name": "bob", "password": "another one"}
]}
```

Names are 1-64 characters from `A-Z a-z 0-9 . _ -`, there must be at least
one admin, and at most 50 accounts. Any problem refuses the whole file.
Removing someone stops them signing in, and their files stay.

**Devices.** Register one with the account password and keep the token it
returns. The token is shown only once:

```sh
curl -u alice -d '{"name":"laptop"}' https://drive.example/api/v1/devices
```

Use it as `Authorization: Bearer <token>`, or as the password for WebDAV
and rclone. Revoke one with `DELETE /api/v1/devices/<id>`.

## WebDAV and rclone

The WebDAV address is `https://drive.example/dav/<user>/`. Sign in with
your name and a device token. An rclone remote:

```ini
[homedrive]
type = webdav
url = https://drive.example/dav/alice
vendor = other
user = alice
pass = <the token, put through `rclone obscure`>
```

Deleting or overwriting through WebDAV is never final. Deleted files go
to the trash, and overwritten ones keep their old versions.

If `serve` says the data directory "has no store.id", check that the
store's disk is mounted before doing anything else. Run `init` only for a
brand-new store.

Later milestones add the store, the sync API, WebDAV, the web UI, the
maintenance commands (`fsck`, `gc`, `scrub`, `checkpoint`, `import`,
`import-tree`, `verify-tree`) and the `homedrive` client. Each is
documented here as it lands.
