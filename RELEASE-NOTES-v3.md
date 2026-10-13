# UCNG Certificate Manager · Release 3

## Neu

- ACME-Profile als eigenständige CMS-Datensätze: HTTPS-Directory-URL, Label, Kontakt-E-Mail, DNS-01-Verfahren, Dateipfade für Cloudflare-Credentials bzw. DNS-Automatisierungs-Hooks, interne CA-Bundles und optionale EAB-ENV-Referenzen.
- Jedem Zertifikat lässt sich über ein Dropdown ein ACME-Profil zuordnen. Konfiguriert der Nutzer kein Profil, bleibt der bewährte manuelle Import möglich.
- Zwei vorausgefüllte Profile für Let's Encrypt Produktion und Staging bei Erstinstallation. Eigene interne CAs können zusätzlich angelegt werden.
- Separater Certbot-Worker im bestehenden Compose-Stack (`docker compose --profile acme up -d --build`), der alle konfigurierten Zertifikate pro Profil isoliert ausstellt/erneuert. Getrennte Certbot-Konfigurationen und Handoff-Verzeichnisse vermeiden Profilüberschneidungen.
- Login mit beliebig vielen per `USERS_JSON` in `.env` definierten Nutzern, ohne separate User-Datenbank. V2-Einzel-Admin weiterhin kompatibel.
- `APP_SECRET` (32+ Zeichen) aus `.env` ersetzt separate Master-Key-Datei bei Neuinstallationen; für V2-Daten kann der alte Base64-Schlüssel unverändert als `MASTER_KEY` übernommen werden.
- Öffentliche Downloadoberfläche `/public` und `/public/{name}`. Öffentliche Zertifikatsartefakte sind anonym per API abrufbar; private Dateien/Passwörter bleiben tokenpflichtig.
- Go- und Python-Tests für Profile, Login, öffentliche und private Downloads sowie Profiltrennung.

## Vor einer produktiven Aktualisierung

1. `/data`, alte Master-Key-Datei und Certbot-Volumes sichern.
2. V2-Vault benötigt identischen Schlüssel: bisherigen Base64-Wert direkt in `MASTER_KEY` setzen. Neue Vaults können `APP_SECRET` nutzen. Ein Wechsel ohne Re-Encryption entschlüsselt alte Daten nicht.
3. In `.env` ein oder mehrere Benutzer in `USERS_JSON` setzen; vorherigen `ADMIN_USER` / `ADMIN_PASSWORD` nur behalten, falls `USERS_JSON` nicht genutzt wird.
4. Profile und Credentials konfigurieren, Zertifikaten Profile zuweisen.
5. Certbot-Worker explizit aktivieren; er wird ohne Compose-Profil `acme` nicht gestartet.
6. DNS-Provider und interne ACME-CA separat in einer Staging-Umgebung prüfen. Docker-Laufzeit und echte Ausstellung sind in der lokalen Testumgebung nicht verifizierbar.
7. Alle API-Tokens, Firewall-/Reverse-Proxy-Regeln und Produktionsinstallationsskripte vor dem Rollout testen.

Weitere Einzelheiten unter [README.md](README.md).
