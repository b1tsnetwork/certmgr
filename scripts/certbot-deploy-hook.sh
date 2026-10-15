#!/bin/sh
# Certbot ruft diesen Hook nur nach erfolgreicher Ausstellung/Erneuerung auf.
set -eu
: "${RENEWED_LINEAGE:?Certbot RENEWED_LINEAGE fehlt}"
: "${CERTWATCH_ACME_PROFILE:?ACME-Profil fehlt}"
case "$CERTWATCH_ACME_PROFILE" in ''|.|..|*[!a-zA-Z0-9_.-]*|.*) echo "Invalid profile" >&2; exit 1;; esac
name=$(basename "$RENEWED_LINEAGE")
case "$name" in ''|.|..|*[!a-zA-Z0-9_.-]*|.*) echo "Invalid cert name" >&2; exit 1;; esac
base="/handoff/$CERTWATCH_ACME_PROFILE/$name"
mkdir -p "/handoff/$CERTWATCH_ACME_PROFILE"
chgrp 65532 /handoff "/handoff/$CERTWATCH_ACME_PROFILE"
chmod 750 /handoff "/handoff/$CERTWATCH_ACME_PROFILE"
mkdir -p "$base/releases"
chgrp 65532 "$base" "$base/releases"
chmod 750 "$base" "$base/releases"
stage=$(mktemp -d "$base/releases/.incoming.XXXXXXXX")
trap 'rm -rf "$stage"' EXIT HUP INT TERM
for file in cert.pem chain.pem fullchain.pem privkey.pem; do
  cp "$RENEWED_LINEAGE/$file" "$stage/$file"
done
# Sidecar publishes to a read-only CertWatch mount. Only GID 65532 can
# read released artifacts; all other host/container users are denied.
chgrp 65532 "$stage" "$stage"/*.pem
chmod 750 "$stage"
chmod 640 "$stage"/*.pem
release="$(date +%Y%m%d%H%M%S)-$(basename "$stage" | sed 's/^.incoming.//')"
mv "$stage" "$base/releases/$release"
ln -s "releases/$release" "$base/.current-new-$$"
python -c 'import os,sys; os.replace(sys.argv[1], sys.argv[2])' "$base/.current-new-$$" "$base/current"
trap - EXIT HUP INT TERM
printf 'Exported %s to handoff\n' "$name"
