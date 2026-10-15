#!/bin/sh
# Usage: CERTWATCH_TOKEN_FILE=/etc/certwatch/client.token ./certwatch-fetch.sh https://certwatch.example.com profile name /etc/tls [--private]
set -eu
umask 077
if [ "$#" -lt 4 ] || [ "$#" -gt 5 ]; then
  echo "Usage: CERTWATCH_TOKEN_FILE=... $0 https://certwatch-host profile cert-name destination [--private]" >&2
  exit 2
fi
base=${1%/}; profile=$2; name=$3; out=$4; mode=${5:-}
case "$base" in https://*) ;; *) echo 'HTTPS ist Pflicht' >&2; exit 2;; esac
case "$profile:$name" in *[!a-zA-Z0-9_.:-]*|*..*|*/*) echo 'Unzulässige Zertifikatskennung' >&2; exit 2;; esac
case "$mode" in ''|--private) ;; *) echo 'Unbekannte Option' >&2; exit 2;; esac
command -v curl >/dev/null || { echo 'curl fehlt' >&2; exit 2; }
command -v python3 >/dev/null || { echo 'python3 fehlt' >&2; exit 2; }
command -v openssl >/dev/null || { echo 'openssl fehlt' >&2; exit 2; }
if [ -n "${CERTWATCH_TOKEN_FILE:-}" ]; then
  [ -f "$CERTWATCH_TOKEN_FILE" ] || { echo 'Token-Datei fehlt' >&2; exit 2; }
  token=$(tr -d '\r\n' < "$CERTWATCH_TOKEN_FILE")
else
  token=${CERTWATCH_API_TOKEN:-}
fi
case "$token" in cw_*) ;; *) echo 'Kein gültiger CERTWATCH_TOKEN_FILE oder CERTWATCH_API_TOKEN' >&2; exit 2;; esac
case "$token" in *[!a-zA-Z0-9_-]*) echo 'Ungültige Token-Zeichen' >&2; exit 2;; esac
mkdir -p "$out"
chmod 700 "$out"
stage=$(mktemp -d "$out/.certwatch.XXXXXXXX")
trap 'rm -rf "$stage"' EXIT HUP INT TERM
# Send bearer token via curl's stdin configuration, not command line or URL.
fetch() { printf 'header = "Authorization: Bearer %s"\n' "$token" | curl -fsS --connect-timeout 10 --max-time 40 --proto '=https' --tlsv1.2 --config - -o "$1" "$2"; }
api="$base/api/v1/distribution/$profile/$name"
fetch "$stage/manifest.json" "$api/manifest"
version=$(python3 -c 'import json,sys; j=json.load(open(sys.argv[1])); assert j["profile"]==sys.argv[2] and j["certificate"]==sys.argv[3]; print(j["version"])' "$stage/manifest.json" "$profile" "$name")
case "$version" in *[!a-zA-Z0-9_-]*|'') echo 'Ungültige Version' >&2; exit 1;; esac
release_marker="$profile/$name@$version"
if [ -f "$out/.certwatch-version" ] && [ "$(cat "$out/.certwatch-version")" = "$release_marker" ] && [ -s "$out/fullchain.pem" ] && { [ "$mode" != '--private' ] || [ -s "$out/privkey.pem" ]; }; then
  echo "Unverändert: $profile/$name ($version)"
  exit 0
fi
for f in cert.pem chain.pem fullchain.pem; do
  fetch "$stage/$f" "$api/versions/$version/artifacts/$f"
done
openssl x509 -in "$stage/cert.pem" -noout -checkend 0 >/dev/null
openssl x509 -in "$stage/fullchain.pem" -noout -checkend 0 >/dev/null
leaf_fp=$(openssl x509 -in "$stage/cert.pem" -noout -fingerprint -sha256)
full_fp=$(openssl x509 -in "$stage/fullchain.pem" -noout -fingerprint -sha256)
[ "$leaf_fp" = "$full_fp" ] || { echo 'Leaf-Zertifikat unterscheidet sich von fullchain.pem' >&2; exit 1; }
python3 - "$stage/manifest.json" "$stage/fullchain.pem" <<'PY'
import hashlib,json,sys
meta=json.load(open(sys.argv[1]))
assert hashlib.sha256(open(sys.argv[2],'rb').read()).hexdigest()==meta['version_sha256'], 'fullchain checksum mismatch'
PY
if [ "$mode" = '--private' ]; then
  fetch "$stage/privkey.pem" "$api/versions/$version/artifacts/privkey.pem"
  cert_pub=$(openssl x509 -in "$stage/cert.pem" -pubkey -noout | openssl pkey -pubin -outform DER | openssl dgst -sha256)
  key_pub=$(openssl pkey -in "$stage/privkey.pem" -pubout -outform DER | openssl dgst -sha256)
  [ "$cert_pub" = "$key_pub" ] || { echo 'Privater Schlüssel passt nicht zum Zertifikat' >&2; exit 1; }
fi
# Atomic file replacement. Reload the local webserver only after this script succeeds.
for f in cert.pem chain.pem fullchain.pem; do
  chmod 600 "$stage/$f"
  mv -f "$stage/$f" "$out/$f"
done
if [ "$mode" = '--private' ]; then
  chmod 600 "$stage/privkey.pem"
  mv -f "$stage/privkey.pem" "$out/privkey.pem"
fi
printf '%s\n' "$release_marker" > "$stage/.certwatch-version"
mv -f "$stage/.certwatch-version" "$out/.certwatch-version"
echo "Aktualisiert: $profile/$name ($version)"
