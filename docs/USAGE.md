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

Commands for a running server, through its admin socket (inside the
container, with `podman exec`):

```text
hd-server import --user U --dest PATH [--absent] < FILE
        Store a file (the backup scripts use this)
hd-server import-tree --user U --src DIR [--dest PATH] [--versions DIR]
        Load a directory tree; files in --versions named <file>.v<unix
        seconds> become older versions. Prints "sha256 size path" lines.
        Re-running continues where it stopped.
hd-server verify-tree --user U --src DIR [--dest PATH]
        Re-hash every file under DIR and compare with what is stored;
        exits 1 on any difference. Do not trust an import until this is
        clean.
```

Maintenance commands go through the admin socket when the server is
running, and otherwise open the store themselves:

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
| `HD_EXPORT_DIR` | `/srv/exports` | Where exports are written |
| `HD_EXPORTS` | unset | `user:path=>name,...`: plain-file copies kept current (e.g. `alice:Music=>music`) |

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

## The sync client (Linux)

```sh
homedrive login --server https://drive.example --user alice   # asks for the password
homedrive add-folder ~/Drive                    # the whole drive
homedrive add-folder ~/Photos --remote Photos   # one folder of it
homedrive sync                                  # one round
homedrive daemon                                # keep syncing
homedrive status
```

To keep it running, install `contrib/systemd/homedrive.service` as a user
service; its comments say how.

The client never deletes or overwrites a local file without keeping the
old content:
- in the folder's `.homedrive/trash/` for 30 days;
- and on the server as a version or in its trash.

If the folder disappears (an unmounted disk) or loses its
`.homedrive-root` marker, the client stops and changes nothing. If a round
would delete unusually many files, it holds those deletions back until
you run `homedrive sync --confirm-deletes`. When two machines change the
same file, both copies are kept: yours becomes
`<name> (conflict <device> <date>).<ext>`.

## The web UI

Open `https://drive.example/` and sign in with your account password. It
covers files, history, trash, devices and, for admins, an admin page. It
uses no JavaScript and works on a phone. A server restart signs everyone
out.

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
