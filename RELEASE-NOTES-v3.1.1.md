# UCNG Certificate Manager v3.1.1 – Docker-Volume Berechtigungen

- Behoben: `mkdir /data/certificates: permission denied` auf neuen oder alten root-eigenen `cert-data` Docker-Volumes.
- Neuer einmaliger Container `cert-data-init` richtet Besitzer UID/GID `10001:10001` für das persistente Volume ein.
- Webdienst bleibt unverändert mit eingeschränkten Rechten (UID 10001, Read-only-Root-Dateisystem, keine Linux-Capabilities).
- Dockerfile setzt die Besitzrechte an `/data` zusätzlich für neue Volumes.
- Keine Änderungen am Schema, Master-Key, Token-Modell oder API. Bestehende Zertifikatsdaten bleiben erhalten.
- Bitte nur `docker compose up -d` nutzen, nicht `docker compose down -v`.
