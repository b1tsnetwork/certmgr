#!/bin/sh
# Generic/manual format fetcher. Example:
# CERTWATCH_TOKEN_FILE=/etc/certwatch/client.token ./certwatch-fetch-format.sh \
#   https://certwatch.example.org manual intranet-web /etc/certwatch/iis leaf-chain.pfx pfx-password.txt
set -eu
umask 077
if [ "$#" -lt 5 ]; then
  echo "Usage: CERTWATCH_TOKEN_FILE=... $0 https://server profile certificate destination artifact [artifact...]" >&2
  exit 2
fi
base=${1%/}; profile=$2; cert=$3; target=$4
shift 4
case "$base" in https://*) ;; *) echo "HTTPS required" >&2;exit 2;; esac
for word in "$profile" "$cert" "$@"; do
  case "$word" in ''|.*|*[!a-zA-Z0-9_.-]*|*..*) echo "Invalid identifier or artifact: $word" >&2;exit 2;; esac
done
command -v python3 >/dev/null && command -v curl >/dev/null || { echo "Requires python3 and curl" >&2;exit 2; }
if [ -n "${CERTWATCH_TOKEN_FILE:-}" ]; then
  token=$(tr -d '\r\n' < "$CERTWATCH_TOKEN_FILE")
else
  token=${CERTWATCH_API_TOKEN:-}
fi
case "$token" in cw_*) ;; *) echo "Missing API token" >&2;exit 2;; esac
case "$token" in *[!a-zA-Z0-9_-]*) echo "Invalid API token" >&2;exit 2;; esac
mkdir -p "$target"
chmod 700 "$target"
stage=$(mktemp -d "$target/.certwatch.XXXXXXXX")
trap 'rm -rf "$stage"' EXIT HUP INT TERM
fetch() { printf 'header = "Authorization: Bearer %s"\n' "$token" | curl -fsS --connect-timeout 10 --max-time 60 --proto '=https' --tlsv1.2 --config - -o "$1" "$2"; }
api="$base/api/v1/distribution/$profile/$cert"
fetch "$stage/manifest.json" "$api/manifest"
version=$(python3 -c 'import json,sys; j=json.load(open(sys.argv[1])); assert j["profile"]==sys.argv[2] and j["certificate"]==sys.argv[3]; print(j["version"])' "$stage/manifest.json" "$profile" "$cert")
case "$version" in ''|*[!a-zA-Z0-9_-]*) echo "Invalid version" >&2;exit 1;; esac
# Download only artifacts explicitly present in this token-scoped manifest.
for f in "$@"; do
  python3 - "$stage/manifest.json" "$f" <<'PY'
import json,sys
m=json.load(open(sys.argv[1]))
if sys.argv[2] not in m['artifacts']:
    raise SystemExit('File is not available for this token: '+sys.argv[2])
PY
  fetch "$stage/$f" "$api/versions/$version/artifacts/$f"
  python3 - "$stage/manifest.json" "$stage/$f" "$f" <<'PY'
import json,hashlib,sys,os
m=json.load(open(sys.argv[1])); fn=sys.argv[3]
known={a['name']:a for a in m.get('artifact_details',[])}
if fn in known:
    data=open(sys.argv[2],'rb').read()
    if hashlib.sha256(data).hexdigest()!=known[fn]['sha256'] or len(data)!=known[fn]['size']:
        raise SystemExit('SHA256 mismatch: '+fn)
PY
done
# Move after all artifacts were successfully retrieved and verified.
for f in "$@"; do chmod 600 "$stage/$f"; mv -f "$stage/$f" "$target/$f"; done
printf '%s\n' "$profile/$cert@$version" > "$stage/.certwatch-format-version"
mv -f "$stage/.certwatch-format-version" "$target/.certwatch-format-version"
echo "Downloaded $profile/$cert ($version): $*"
