#!/bin/sh
# Sign a Windows executable with the personal code-signing key (run in WSL or
# the toolbox with ~/.config/code-signing mounted). Usage:
#
#   scripts/codesign.sh path/to/app.exe [description]
#
# The file is signed in place. A public timestamp is added so the signature
# stays valid after the certificate expires; set CODESIGN_NO_TIMESTAMP=1 to
# sign offline.
set -eu

file="${1:?usage: codesign.sh FILE [DESCRIPTION]}"
desc="${2:-$(basename "$file")}"
dir="${CODESIGN_DIR:-$HOME/.config/code-signing}"

[ -f "$dir/codesign.key" ] || { echo "no signing key in $dir (run scripts/make-codesign-cert.sh)" >&2; exit 1; }

set -- sign -certs "$dir/codesign.pem" -key "$dir/codesign.key" -h sha256 -n "$desc"
if [ -z "${CODESIGN_NO_TIMESTAMP:-}" ]; then
    set -- "$@" -ts "${CODESIGN_TSA:-http://timestamp.digicert.com}"
fi

tmp="$file.signing"
osslsigncode "$@" -in "$file" -out "$tmp"

# Prove the signature before it replaces the original: it must verify against
# our own certificate, and the timestamp against the system's public roots.
if ! osslsigncode verify -CAfile "$dir/codesign.pem" -in "$tmp" >/dev/null 2>&1; then
    # osslsigncode checks the signing chain against -CAfile only, so a failure
    # here is a real problem; show why.
    osslsigncode verify -CAfile "$dir/codesign.pem" -in "$tmp" >&2 || true
    rm -f "$tmp"
    echo "ERROR: the signature on $file did not verify" >&2
    exit 1
fi
mv "$tmp" "$file"
echo "signed $file"
