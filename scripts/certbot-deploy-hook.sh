#!/bin/sh
# Certbot ruft diesen Hook nur nach erfolgreicher Ausstellung/Erneuerung auf.
set -eu
: "${RENEWED_LINEAGE:?Certbot RENEWED_LINEAGE fehlt}"
: "${UCNG_ACME_PROFILE:?ACME-Profil fehlt}"
case "$UCNG_ACME_PROFILE" in ''|.|..|*[!a-zA-Z0-9_.-]*|.*) echo "Invalid profile" >&2; exit 1;; esac
name=$(basename "$RENEWED_LINEAGE")
case "$name" in ''|.|..|*[!a-zA-Z0-9_.-]*|.*) echo "Invalid cert name" >&2; exit 1;; esac
base="/handoff/$UCNG_ACME_PROFILE/$name"
mkdir -p "/handoff/$UCNG_ACME_PROFILE"
chown 10001:10001 "/handoff/$UCNG_ACME_PROFILE"
chmod 700 "/handoff/$UCNG_ACME_PROFILE"
mkdir -p "$base/releases"
# Go-Container läuft als UID/GID 10001. Andere Benutzer sollen keinen Zugriff erhalten.
chown 10001:10001 /handoff "$base" "$base/releases"
chmod 700 /handoff "$base" "$base/releases"
stage=$(mktemp -d "$base/releases/.incoming.XXXXXXXX")
trap 'rm -rf "$stage"' EXIT HUP INT TERM
for file in cert.pem chain.pem fullchain.pem privkey.pem; do
  cp "$RENEWED_LINEAGE/$file" "$stage/$file"
done
chown -R 10001:10001 "$stage"
chmod 700 "$stage"
chmod 600 "$stage"/*.pem
release="$(date +%Y%m%d%H%M%S)-$(basename "$stage" | sed 's/^.incoming.//')"
mv "$stage" "$base/releases/$release"
ln -s "releases/$release" "$base/.current-new-$$"
mv -fT "$base/.current-new-$$" "$base/current"
trap - EXIT HUP INT TERM
printf 'Exported %s to handoff\n' "$name"
