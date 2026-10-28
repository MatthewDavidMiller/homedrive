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
hd-server verify-tree --user U --src DIR [--dest PATH] [--accept-skipped]
        Re-hash every file under DIR and compare with what is stored;
        exits 1 on any difference, and on any file the import had to skip
        (a symbolic link, a special file, a name the drive cannot hold),
        which exists only in DIR. Do not trust an import, or retire its
        source, until this is clean. --accept-skipped passes with skipped
        files once you have saved them elsewhere.
hd-server drill-compare --user U --taken-ms T < MANIFEST
        Compare a restored backup's manifest with the live drive (the
        restore drill does this): every file the drive had at time T must
        be in it, by path or by content, and nothing unknown may be.
hd-server report-backup --kind K (--ok | --failed) [--message TEXT]
        Record a backup or drill run. A failure, or no success for two
        days (eight for "drill"), reaches the administrators.
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

Restoring, on a store the server is not using (a backup extracted with
`borg extract`, or with the server stopped):

```text
hd-server restore-tree --user U --to DIR [--path P] [--manifest FILE]
        Write U's current files (under P) to DIR as plain files, each
        verified against its SHA-256, executables executable, and a
        manifest in sha256sum format (default DIR.sha256). Never writes
        into a directory that has anything in it.
hd-server restore-drill --to DIR
        Read every version back (fsck --deep), then restore every drive
        to DIR/<user>/ with DIR/<user>.sha256, and print when the backup
        was taken (TAKEN_MS). Exits 1 on any problem.
```

**Proving the backups.** The deployment runs a weekly drill: it extracts
the newest backup, runs `restore-drill` on it, and `drill-compare`s each
manifest with the live drive, then reports the result
(`report-backup --kind drill`). The restored files are plain files with a
`sha256sum` manifest, so they can be copied to any computer and checked
there with `homedrive check-files` or `sha256sum -c`.

**Backups the administrators hear about.** The admin page lists each
backup kind's last success and failure. Administrators also get, in
`GET /api/v1/status` and so as sync-client notifications: a failed
backup or drill, one that has gone quiet, a failed import (how the other
services' backups land), and quotas that promise more than the disk has
free. A backup run elsewhere can report with an administrator's device
token: `POST /api/v1/backup-report {"kind","ok","message"}`.

**A copy off the server.** A backup on the server's own disks goes with
the server, and anyone with root there can delete it. So an administrator
keeps a copy of the whole store on their own machine, pulled from the
server, out of its reach:

```sh
homedrive backup-store /mnt/external/homedrive-copy   # first run: everything; then only what changed
homedrive store-copy-check /mnt/external/homedrive-copy
homedrive store-copy-restore /mnt/external/homedrive-copy --user alice --to ~/restored/alice
```

The Admin page's "Download the store (.tar)" gives the same copy as one
file. The copy is the store itself (every drive, with its history and
trash), so it can also repair the server's store (`hd-server repair --from
DIR`) or be served by a new server. Each copy is reported; after eight days
without one, the administrators are reminded. Anyone with an
administrator's password or device token can take one.

**Encrypted copies.** Copies are unencrypted unless you ask. To encrypt
one, start it in a new directory with `--encrypt`; you are asked for a
passphrase of at least 12 characters (or set `HOMEDRIVE_COPY_PASSPHRASE`),
and every later run needs it:

```sh
homedrive backup-store /mnt/external/sealed-copy --encrypt    # first run: choose the passphrase
homedrive backup-store /mnt/external/sealed-copy              # later runs ask for it
homedrive store-copy-check /mnt/external/sealed-copy          # every file authenticates, every object intact
homedrive store-copy-decrypt /mnt/external/sealed-copy --to /scratch/plain-copy
homedrive store-copy-restore /scratch/plain-copy --user alice --to ~/restored/alice
```

Every file of an encrypted copy is sealed with AES-256-GCM under keys
stretched from the passphrase with scrypt, and named by a keyed hash, so
the copy shows neither file names nor which content it holds (each file's
size stays visible). A changed, swapped or shortened file is refused.
Nothing is written in the clear while copying. The Admin page's download
takes a passphrase too; open it with `homedrive decrypt-file DOWNLOAD --to
copy.tar`, then unpack it with `tar`. Keep the passphrase somewhere other
than the copy: without it the copy cannot be read, by anyone.

| Variable | Default | Meaning |
|---|---|---|
| `HD_LISTEN` | `127.0.0.1:8080` | Address the HTTP listener binds |
| `HD_DATA_DIR` | `/var/lib/homedrive` | The store |
| `HD_USERS_FILE` | `/run/secrets/homedrive_users` | The accounts (see below) |
| `HD_TRUSTED_PROXIES` | unset | Proxy IPs whose `X-Forwarded-For` is believed |
| `HD_SECURE_COOKIES` | `true` | `false` only for plain-HTTP development |
| `HD_MIN_FREE_GB` | `1` | Free space below which the store refuses writes |
| `HD_MAX_FILE_GB` | `1024` | The largest file accepted |
| `HD_KEEP_ALL_DAYS` | `30` | Keep every old version this long, then thin (at least 7) |
| `HD_TRASH_DAYS` | `90` | Keep deleted files this long (at least 7) |
| `HD_MAINTENANCE_HOURS` | `24` | Retention and GC interval; `0` off |
| `HD_SCRUB_DAYS` | `30` | Full re-verification interval; `0` off |
| `HD_SCRUB_MBPS` | `50` | Scrub read rate ceiling |
| `HD_EXPORT_DIR` | `/srv/exports` | Where exports are written |
| `HD_EXPORTS` | unset | `user:path=>name,...`: plain-file copies kept current (e.g. `alice:Music=>music`) |
| `HD_ALERT_CHANGED` | `200` | Files changed in one hour that raise an unusual-activity alert |
| `HD_ALERT_DELETED` | `200` | Files deleted in one hour that raise one |
| `HD_ALERT_SUSPICIOUS` | `10` | Changes in one hour that look like encryption and raise one |

The users file:

```json
{"version": 1, "users": [
  {"name": "alice", "password": "8 to 128 characters", "admin": true, "quota_gb": 500},
  {"name": "bob", "password": "another one", "quota_gb": 200}
]}
```

Names are 1-64 characters from `A-Z a-z 0-9 . _ -`, every account needs a
`quota_gb`, there must be at least one admin, and at most 50 accounts. Any problem refuses the whole file.
Removing someone stops them signing in, and their files stay.

**Quotas.** `quota_gb` (required, whole GiB) limits what a drive holds,
counting every version of every file and the trash at full size. Storage
deduplicates, so the disk never holds more than the drives' totals, and
the server refuses to start if the quotas, plus what the drives of
removed accounts hold, plus `HD_MIN_FREE_GB`, add up to more than the
store's disk. The drives therefore can never fill it.

A drive at its quota refuses new content (507, with the reason), and its
owner's sync clients and web UI say so. Every route is held to it:
uploads of unknown length stop at the quota, chunks uploaded for a commit
not yet made count, and so do imports (`homedrive_import_path.sh`, a
backup into a full drive fails and says why). Nothing stored is touched.
Restores and rewinds are never refused: they reuse content already
stored, and are how a drive is recovered. Deleting files frees room only
once retention purges them from the trash, so the way out is a larger
quota.

If something else uses the store's disk, so that the drives' remaining
room exceeds the free space, admins are warned (log, admin page, and their
sync clients). The free-space reserve still stops writes before the disk
fills.

**Unusual activity.** Every five minutes the server looks at each drive's
last week: within any hour, more than `HD_ALERT_CHANGED` files changed in
place, more than `HD_ALERT_DELETED` deleted, or `HD_ALERT_SUSPICIOUS`
changes that look like encryption (the same test the sync client uses,
on the old and new content) raise an alert. This covers WebDAV and the
web UI, which have no client-side guard. Imports, restores, rewinds and
copies do not count, so the nightly backups do not set it off. The owner's
sync clients show it, the web UI shows a banner with the way to Rewind,
the admin page lists it, and the log has an `ALERT` line. Retention leaves
that drive alone (nothing thinned or purged) until the owner dismisses the
alert in the web UI. Only a signed-in browser can dismiss it, never a
device token that ransomware could have taken. Dismissals are kept in
`alerts-dismissed.json` in the data directory.

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
homedrive status                                # and what is held back
homedrive confirm                               # approve what is held back
homedrive verify                                # check every file now
homedrive rewind Docs --days 2                  # preview a rewind
homedrive rewind Docs --days 2 --apply          # and do it
homedrive restore Docs --to ~/restored/Docs     # plain files, verified, + a manifest
homedrive check-files ~/restored/Docs ~/restored/Docs.sha256
```

One process syncs a folder at a time. While the daemon runs, `sync`
leaves its folders alone, and `confirm` and `verify` leave a request the
daemon carries out on its next round.

To keep it running, install `contrib/systemd/homedrive.service` as a user
service; its comments say how.

The server address must be `https://`; `http://` is accepted only for a
server on the same computer. Adding an ignore pattern stops those files
syncing but never deletes them, here or on the server. A folder on
another disk mounted inside a synced folder, and anything the client
cannot read, are left alone and reported; sync such a disk as a folder of
its own.

File contents, modification times and the execute permission are synced.
Other permissions, extended attributes, ACLs and symbolic links are not.

The client never deletes or overwrites a local file without keeping the
old content:
- in the folder's `.homedrive/trash/` for 30 days;
- and on the server as a version or in its trash.

If the folder disappears (an unmounted disk) or loses its
`.homedrive-root` marker, the client stops and changes nothing. If a round
would delete unusually many files, it holds those deletions back until
you run `homedrive confirm`. When two machines change the same file, both
copies are kept: yours becomes `<name> (conflict <device> <date>).<ext>`.

**Ransomware.** Changes to many files within an hour (more than 100, or
more than 20 that are over a quarter of the folder) are held back until
you run `homedrive confirm`. So are changes that look like encryption:
a document whose content turns random, or a photo or archive that loses
its file signature. Ten of those within an hour hold back every change
and every deletion in the folder, and tell you, so the encrypted copies
never replace the good ones on the server or your other computers. One
file saved many times counts once. If encrypted copies did get through,
rewind the folder (below).

**Damage on this computer's disk.** The client re-reads synced files in
the background, about once every two weeks for each, and compares them
with what it synced. A file whose content changed although nothing wrote
to it (its size, time and inode are as they were) was damaged by the
disk. The server's copy takes its place, the damaged copy is kept in
`.homedrive/damaged/` (never deleted), and you are told. A file that
reads differently each time is left alone and reported: the disk or
memory may be failing. `homedrive verify` checks every file now.

**Rewind.** `homedrive rewind PATH --hours N` (or `--days N`) puts a folder
of the drive back as it was then, and so does Rewind at the bottom of
each folder in the web UI. It shows what it would do first; `--apply`, or
the web UI's second button, does it. Files changed since get their
earlier content back as a new version, and files deleted since come back
from the trash, beside any new file that took their name. Files made
since stay, and every version since stays in each file's history, so a
rewind is itself undone by another. Your computers then sync the result.
For a time more than 30 days back, a file gets the nearest version
retention kept. Files moved since stay where they were moved to.

**Notifications.** The daemon tells you, as a desktop notification, when
something needs you:
- deletions or changes held back, and the command that confirms them;
- changes that look like encryption (possible ransomware);
- files damaged on this computer's disk and repaired from the server;
- a conflict, and the name your copy was kept under;
- files that could not sync;
- a folder that has not synced for half an hour (an unmounted disk, a
  missing marker, an unreachable server);
- the server restored from a backup;
- damage the server reports in its store (checked every 10 minutes);
- files left out of sync for over an hour (a name the drive cannot hold,
  a symbolic link, a file that changes during every upload): they are not
  backed up. Fix or rename them, or add an ignore pattern to leave them
  out on purpose;
- for administrators: failed or silent backups and restore drills, and
  failed imports.

A lasting problem is shown again at most once a day. Everything shown is
also written to the daemon's log (`journalctl --user -u homedrive`).
Notifications go to the desktop's notification service over the D-Bus
session bus. If the daemon runs as a systemd user service, it already has
the bus. Check that notifications reach your desktop with
`homedrive test-notification`.

## The sync client on Windows

Build it with `make windows`, which writes `dist/homedrive.exe`: a single
file with OpenSSL linked in. It uses the same commands as on Linux:

```bat
homedrive.exe login --server https://drive.example --user alice --ca-file C:\path\to\cacert.pem
homedrive.exe add-folder C:\Users\alice\Drive
homedrive.exe sync
```

Configuration is in `%APPDATA%\homedrive`, and sync state is in
`%LOCALAPPDATA%\homedrive\state`. OpenSSL on Windows has no system
certificate store, so pass `--ca-file` with a PEM bundle that includes the
server's CA (for Let's Encrypt, the ISRG roots).

To run it at sign-in:

```bat
schtasks /create /tn homedrive /sc onlogon /tr "C:\Tools\homedrive.exe daemon"
```

Windows cannot hold two names that differ only in letter case, or names
like `CON` or ones containing `:`. Such server paths are skipped and
reported, never renamed.

On Windows the daemon's notifications appear as notification-area
balloons (toasts on Windows 10 and 11), and are also written to its log
(standard error). `homedrive.exe test-notification` shows one. Windows
has no execute permission: a file's executable flag is kept as it is on
the server when it is edited there.



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
to the trash, and overwritten ones keep their old versions. A folder
spoiled through any route can be put back as it was with Rewind (see the
sync client section).

If `serve` says the data directory "has no store.id", check that the
store's disk is mounted before doing anything else. Run `init` only for a
brand-new store.

Later milestones add the store, the sync API, WebDAV, the web UI, the
maintenance commands (`fsck`, `gc`, `scrub`, `checkpoint`, `import`,
`import-tree`, `verify-tree`) and the `homedrive` client. Each is
documented here as it lands.
