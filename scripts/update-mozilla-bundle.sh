#!/usr/bin/env bash
# Replaces internal/trustbundle/mozilla.pem with the current Mozilla TLS roots
# from https://curl.se/docs/caextract.html after checking the published SHA-256.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="$ROOT/internal/trustbundle/mozilla.pem"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

curl -fsS -o "$TMP/cacert.pem" https://curl.se/ca/cacert.pem
curl -fsS -o "$TMP/cacert.pem.sha256" https://curl.se/ca/cacert.pem.sha256
(cd "$TMP" && sha256sum -c --quiet cacert.pem.sha256)

cp "$TMP/cacert.pem" "$DEST"
grep -m1 'Certificate data from Mozilla' "$DEST"
echo "$(grep -c 'BEGIN CERTIFICATE' "$DEST") roots"
