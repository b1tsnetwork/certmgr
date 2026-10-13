# Version 3.1 – GitHub Container Registry

- `.github/workflows/docker-images.yml` erstellt zwei GHCR-Images für AMD64/ARM64.
- Go-Tests/Race-Detector, `go vet`, Python-Worker-Tests und Hook-Syntaxprüfung vor Veröffentlichung.
- Push auf `main`/`master`, Versionstags `v*` sowie manueller Workflow-Start veröffentlichen; PRs bauen ohne Push.
- `Dockerfile.certbot`: Worker-Logik direkt im Image statt Host-Skript-Mounts.
- `.dockerignore` verhindert, dass lokale Secrets und Zertifikatsdaten in den Build-Kontext gelangen.
- Compose unterstützt weiterhin lokale Builds sowie Registry-Deployments über `CERTMANAGER_IMAGE` / `CERTBOT_IMAGE`.
- Keine Änderungen an gespeichertem Zertifikatsarchiv und API-Schnittstellen.
