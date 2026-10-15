# CertWatch – TLS/PKI-Monitoring mit optionalem ACME/Certbot-Sidecar

CertWatch überwacht TLS-Ziele regelmäßig und zeigt die vollständige verifizierte Zertifikatskette mit Server-, Intermediate- und Root-Zertifikaten, ihren Ablaufdaten, Fingerprints und Ampelstatus. Interne Root-CAs werden per PEM importiert, systemweite Roots lassen sich je Ziel ein-/ausschalten.

**Neu in v2.6 – Systeminventar und Abhängigkeiten:** Im WebUI können eigenständige **Systeme** (Server oder Applikationen) mit Name, IP-Adresse, Dokumentationslink und Beschreibung angelegt werden. Zertifikate aus TLS-Monitoring, ACME oder manuellem Import können einem oder mehreren Systemen zugewiesen werden. Unter **Abhängigkeiten** gibt es einen anklickbaren Graphen aus System- bzw. Zertifikatsperspektive, ohne JavaScript und ohne Formular-Reload. Zugriffsrechte: Viewer lesen, Editor und Admin bearbeiten. **Migrationshinweis:** Die `state.json` wird beim Upgrade von Version 2 auf Version 3 migriert. Bisherige Freitextwerte des Felds „Server / Hostsystem“ werden automatisch in Systemobjekte übertragen und den TLS-Zielen zugeordnet. Vor dem Update unbedingt `state.json` sichern; v2.5 kann die neue Datei anschließend nicht mehr lesen. Mehr dazu in `RELEASE-NOTES-v2.6.md`.

**Neu in v2.5:** Ein interaktiver Zertifikats-Downloadbereich für angemeldete Benutzer einschließlich Viewer, unabhängig von API-Tokens; öffentliche und private Artefakte werden separat angeboten. Die API-Tokenverwaltung unterstützt jetzt bis zu 50 gezielt ausgewählte Zertifikate pro Token. Unversionierte API-Endpunkte folgen weiter automatisch dem neuesten Release, auch nach einer Rotation des Private Keys. ACME-Zertifikate werden bei konfiguriertem Vault-Schlüssel zusätzlich in DER/PFX/P12/PKCS#7/PKCS#8 konvertiert und verschlüsselt versionsweise zwischengespeichert. **Neu in v2.4:** manueller Zertifikatsimport (PEM und PFX/P12), Konvertierung in PEM/DER/PFX/PKCS#7/PKCS#8, verschlüsselter Vault, versionierte APIs und generische Shell-/PowerShell-Clients. **Neu in v2.3:** zentraler Zertifikatsabruf (Public-PEM und optional Private-Key) über eine authentifizierte REST-API, WebUI-Tokenverwaltung sowie Bash-/PowerShell-Clients. Die Ausgabe erfolgt aus unveränderlichen ACME-Releases. **Neu in v2.2:** kein automatischer Refresh auf der ACME-Formularseite. **Neu in v2.1:** RFC2136/TSIG als dritte ACME-DNS-01-Methode. DNS-Server-IP und Port können direkt im Admin-WebUI angegeben werden; das TSIG-Secret verbleibt ausschließlich im Worker. Alle Funktionen aus v2 (responsives Inventar, Mehrbenutzerverwaltung, optionaler Sidecar, Docker/GitHub Actions/Dependabot) bleiben erhalten.

## Architektur und Sicherheitsgrenzen

```text
┌───────────────────────────┐          ┌───────────────────────────┐
│  CertWatch (Go + WebUI)   │          │ Certbot-Sidecar [acme]    │
│  Scheduler, TLS-Prüfung   │          │ DNS-01, ACME, EAB        │
│  Benutzer, Roots, Ziele   │          │ Private DNS-Credentials  │
│  state.json               │          │ Zertifikat + Private Key │
└────────────┬──────────────┘          └─────────────┬─────────────┘
             │  öffentlicher ACME-Katalog (read-only) ──►│
             │◄───────────── Status-JSON (read-only) ────│
             │                                           │
             └── keine direkte Abhängigkeit vom Worker ──┘
```

- **Monitoring ist immer eigenständig.** Der Certbot-Worker startet *nur* mit Docker-Compose-Profil `acme` und arbeitet unabhängig vom 15-Sekunden-Überwachungsscheduler.
- **Zwei Bedingungen für aktives ACME:** In `.env` muss `ACME_ENABLED=true` stehen **und** das Compose-Profil `acme` gestartet werden. Mit `ACME_ENABLED=false` enthält der Worker-Katalog keine verwalteten Zertifikate und die ACME-UI ist schreibgeschützt.
- **DNS-/EAB-Credentials** bleiben ausschließlich im Certbot-Worker; der Go-Container erhält sie nie. **Neu in v2.3:** Der Go-Container bekommt einen **schreibgeschützten** Mount des ACME-Handoff-Volumes, damit Client-Downloads möglich sind. Darin liegen die ausgestellten **PEM-Zertifikate UND PRIVATE KEYS** als Dateien mit Gruppe 65532 und Modus 0640 (Verzeichnisse 0750). Der Go-Prozess kann diese Schlüssel daher lesen. Das ist eine **bewusste Erweiterung der Vertrauensgrenze** gegenüber v2.2! Bei einem kompromittierten Go-Prozess könnten die Schlüssel unabhängig von API-Rechten gelesen werden. Nur in einem ausreichend abgesicherten Netz einsetzen.
- Der Certbot-Worker vergleicht die gewünschten Lineages periodisch mit Certbot, fordert bei Bedarf neue Zertifikate an und veröffentlicht sie atomar über den Deploy-Hook. Bestehende Lineages werden auch dann nachpubliziert, wenn gerade keine Erneuerung ansteht. Die Go-API erlaubt Downloads mit **Bearer-Tokens für ein oder mehrere gezielt gewählte Zertifikate**; Public und Private sind getrennte Berechtigungen, der Private-Key-Download bleibt **standardmäßig deaktiviert**.
- **Wichtig:** Die Sidecar-ACME-Funktion bedeutet nicht automatisch, dass Zertifikate auf überwachten Webservern installiert werden. Für die tatsächliche Bereitstellung werden passende externe Installations-/Deploy-Prozesse benötigt; hierzu kann das `certbot_handoff`-Volume angebunden werden. CertWatch zeigt weiterhin die *tatsächlich am TLS-Endpunkt präsentierte* Kette und nicht nur ausgestellte Zertifikate.

## Systeme und Abhängigkeiten (v2.6)

**Systeminventar:** Unter **Systeme** kannst du Server oder Applikationen mit Namen, optionaler IPv4-/IPv6-Adresse, Beschreibung und einem Link zur internen Dokumentation anlegen. Ein System ist ein eigenständiges Objekt mit stabiler ID. In der Systemmaske können mehrere Zertifikate zugeordnet werden – **TLS-Überwachungsziele**, **manuell importierte Zertifikate** und **ACME-Lineages**. Ebenso können die Systeme direkt unter der Zertifikats-Zuordnungsseite ausgewählt werden (Ziel-Detail → „Abhängigkeiten“, manueller Import → Zertifikat → „Systemzuordnungen“, ACME → Zertifikat → „Systemzuordnungen“).

**Abhängigkeitsansicht:** Menü **Abhängigkeiten** (`/dependencies`). Ein Systemknoten zeigt die verwendeten Zertifikate; ein Zertifikatsknoten zeigt die betroffenen Systeme. Über einen Klick auf den jeweiligen Knoten wird die Blickrichtung gewechselt. Die Anzeige ist rein lesend, ohne automatisches Reload und auch auf mobilen Bildschirmen nutzbar. Eine Zuordnung bedeutet, dass die Verwendung im Inventar **dokumentiert** ist, nicht dass CertWatch die Installation selbst erkennt oder ein Zertifikat auf dem System verteilt.

**Rechte:** Viewer können alle Zuordnungen und Systemdetails lesen, Editor und Admin sie ändern. Das hat keinen Einfluss auf die bestehenden API-Tokens und gibt keinerlei zusätzliche Rechte auf private Schlüssel.

**Update v2.5 → v2.6:** Alte Daten und Secrets zuerst sichern (`state.json`, Vault-Schlüssel, Zertifikatsvolumes); den vorhandenen `.env`- und Compose-Volume-Namen beibehalten. Dann das neue Projekt verwenden und mit `docker compose up -d --build` (oder optional `docker compose --profile acme up -d --build`) starten. Bei Start übernimmt die Migration einmalig die bisherigen Freitextfelder und schreibt die Datenversion 3. Zurückwechseln auf v2.5 ist ohne Wiederherstellen des Backups nicht vorgesehen.

## Schnellstart ohne ACME

Erforderlich: **Go 1.23+** oder Docker + Docker Compose. Produktiv nur hinter einem HTTPS-Reverse-Proxy veröffentlichen; die mitgelieferte Compose-Datei bindet ausschließlich an `127.0.0.1:8080`.

### Docker

```bash
cp .env.example .env
# In .env: ADMIN_PASSWORD mit einem langen zufälligen Passwort ändern
# ACME_ENABLED bleibt false
docker compose up -d --build
```

**WebUI:** `http://127.0.0.1:8080` – Benutzername: `admin`, Passwort: Wert von `ADMIN_PASSWORD` beim **ersten** Start. Passwörter nach dem Erststart über das WebUI verwalten; das Bootstrap-Passwort wird nicht zum Zurücksetzen bestehender Benutzer verwendet.

### Ohne Docker

```bash
ADMIN_PASSWORD='ein-langes-zufaelliges-Admin-Passwort' go run .
```

Standard: `127.0.0.1:8080`, Daten: `./data/state.json`. Optionen:

```bash
go run . -listen 127.0.0.1:8089 -data /var/lib/certwatch/state.json
```

## Zentraler Zertifikatsabruf: Clients (v2.3)

**Für ACME-Zertifikate**, die im Menü **ACME / Certbot → Verwaltete Zertifikate** angelegt und vom Sidecar erfolgreich ausgestellt wurden, gibt es jetzt die Admin-Seite **Zertifikatsabruf**.

- `cert.pem` – End-Entity-/Serverzertifikat (öffentlich)
- `chain.pem` – Intermediate-Zertifikatskette (öffentlich)
- `fullchain.pem` – Serverzertifikat + Intermediate-Zertifikate (öffentlich)
- `privkey.pem` – zugehöriger privater Schlüssel (**nur bei ausdrücklicher Freigabe**)

ACME kann weiterhin vollständig **deaktiviert** sein; die normale TLS-Überwachung ist davon unabhängig. Für den zentralen Abruf müssen Zertifikate entweder **vom optionalen Sidecar veröffentlicht** oder **über den manuellen Import** in den verschlüsselten Vault geladen sein. Reine überwachte Websites besitzen keine bei CertWatch gespeicherten privaten Schlüssel; sie können nicht als private Artefakte ausgegeben werden.

### Aktivierung und Migration von v2.2

1. Wie üblich vor dem Upgrade die `state.json` und das Certbot-Volume sichern. Das neue Feld `distribution_tokens` ist rückwärtskompatibel zum bisherigen v2-Datenformat; eine Datenmigration ist nicht nötig.
2. Die aktualisierte `compose.yaml` bindet das Volume `certbot_handoff` zusätzlich **schreibgeschützt** in den Go-Container ein und konfiguriert `CERTWATCH_HANDOFF_PATH=/app/handoff`.
3. In `.env` kann man optional den Private-Key-Abruf aktivieren: `CERTWATCH_PRIVATE_EXPORT_ENABLED=true` (Standard `false`). **Dies ermöglicht noch keinen unauthentifizierten Download:** zusätzlich ist immer ein expliziter Public+Private-Token erforderlich.
4. Beide Dienste starten: `docker compose --profile acme up -d --build`. Einmalig vorhandene Zertifikate in den Handoff übernehmen: `docker compose --profile acme run --rm certbot --once`.
5. Im WebUI als Admin unter **Zertifikatsabruf** ein oder mehrere Zertifikate anhaken, eine Token-Bezeichnung, 30/90/365 Tage und optional „Private-Key-Download“ festlegen. Den **nur einmal angezeigten** `cw_...`-Token auf dem Client sicher speichern.

**Security:** CertWatch selbst läuft in Compose an `127.0.0.1:8080` mit reinem HTTP. Clients dürfen **nur über einen vorgeschalteten HTTPS-Reverse-Proxy** zugreifen, der keine `Authorization`-Header protokolliert oder an fremde Dienste weitergibt. Die Shell-/PowerShell-Clients verweigern unverschlüsseltes HTTP. Die Zertifikatsprüfung des HTTPS-Proxys darf nicht ausgeschaltet werden; interne Roots müssen im Client-Truststore installiert sein. Zugangstokens niemals in URLs, Git-Repositories, Crontabs oder Kommandoargumenten hinterlegen. Kein Token erlaubt Zugriffe auf nicht ausdrücklich ausgewählte ACME-Profile/Zertifikate; jedes Token läuft ab und ist durch den Admin sofort widerrufbar. Tokens werden **nur gehasht** persistiert. Bei Änderung von Profil, SANs, aktiviertem Status oder Löschung einer ACME-Lineage wird diese Berechtigung aus den Tokens entfernt. Bei einem Mehrfach-Token bleiben die übrigen ausgewählten Zertifikate erreichbar. Eine normale Erneuerung oder ein Key-Rollover mit gleichbleibender Zertifikats-ID widerruft Tokens nicht.

### API für eigene Clients

Alle Requests benötigen `Authorization: Bearer cw_...`; Cookies reichen nicht. Beispiel für Profil `internal` und Lineage `web-prod`:

```text
GET /api/v1/distribution/internal/web-prod/manifest
GET /api/v1/distribution/internal/web-prod/artifacts/fullchain.pem
GET /api/v1/distribution/internal/web-prod/artifacts/privkey.pem
GET /api/v1/distribution/internal/web-prod/versions/<version>/artifacts/cert.pem
GET /api/v1/distribution/internal/web-prod/versions/<version>/artifacts/chain.pem
GET /api/v1/distribution/internal/web-prod/versions/<version>/artifacts/fullchain.pem
GET /api/v1/distribution/internal/web-prod/versions/<version>/artifacts/privkey.pem
```

Das JSON-Manifest enthält `profile`, `certificate`, `version`, `version_sha256`, `dns_names`, `not_after` und die erlaubten `artifacts`. **Versionierte URLs** sorgen dafür, dass ein Client Schlüssel und Zertifikatskette aus demselben unveränderlichen Release erhält – auch während einer neuen Certbot-Erneuerung. `ETag` wird unterstützt. Die Dateien werden nicht in der WebUI gerendert; der Token wird nie in eine URL aufgenommen.

### Linux / POSIX-Shell

Voraussetzung: `curl`, `python3`, `openssl`. Auf dem Client:

```sh
sudo install -m 0700 -d /etc/certwatch /etc/certwatch/tls
sudo sh -c 'umask 077; cat > /etc/certwatch/client.token'  # Token hineinkopieren, Strg+D
sudo chmod 600 /etc/certwatch/client.token
sudo CERTWATCH_TOKEN_FILE=/etc/certwatch/client.token sh ./clients/certwatch-fetch.sh \
  https://certwatch.example.org internal web-prod /etc/certwatch/tls --private
```

Ohne `--private` lädt der Client nur die öffentlichen Zertifikate. Unveränderte Versionen werden übersprungen. Bei erfolgreichem Update den jeweiligen Dienst **separat nach der Prüfung neu laden**, beispielsweise per Cron/systemd-Timer als regelmäßiger Job und anschließendem `nginx -t && systemctl reload nginx`. Die Beispielskripte starten **nicht eigenständig** fremde Services neu. Dateien erhalten restriktive Berechtigungen; eine geschützte Installation/Schlüsselablage auf dem Zielserver ist Pflicht.

### Windows / PowerShell 7.4+

```powershell
./clients/CertWatch-Fetch.ps1 `
  -BaseUrl https://certwatch.example.org `
  -Profile internal -Certificate web-prod `
  -Destination C:\certwatch\tls `
  -TokenFile C:\certwatch\secrets\client.token `
  -IncludePrivateKey
```

Für den Privatmodus ist zusätzlich `openssl` erforderlich. Das Skript setzt Windows-Dateizugriffe des Zielordners restriktiv auf die ausführende Identität. Zusätzliche Zugriffsrechte für Windows-Dienste müssen gezielt erteilt werden. Ein geplanter Task mit einem dedizierten Dienstkonto kann den Abruf regelmäßig ausführen; der Dienst-Restart erfolgt danach gesondert.

**Hinweise:** Die ACME-Handoff-Ausgabe umfasst PEM. Über den manuellen Import (v2.4) stehen zusätzlich PFX/P12 und weitere Formate zur Verfügung. Ältere ACME-Releases bleiben bislang im Handoff-Volume liegen; der Betrieb muss Aufbewahrung/Löschung gemäß eigener Sicherheitsrichtlinie regeln. Das System ist ein zentraler **Artefaktabruf**, kein Remote-Code-Ausführungsdienst und keine automatische ACME-Installation auf Clients.

## Benutzer und Migration

Unter **Benutzer** (nur für Administratoren) lassen sich beliebig viele Benutzer mit individuellem Passwort anlegen, ihre Rollen ändern, Passwörter zurücksetzen und Konten löschen. Rollen:

| Rolle | Berechtigungen |
| --- | --- |
| Admin | Alles, einschließlich Benutzer, Globaleinstellungen, ACME-Profile |
| Editor | Ziele, Root-CAs und ACME-Zertifikatszuordnungen verwalten; kein Zugriff auf Benutzerverwaltung |
| Viewer | Status/Details lesen und eigenes Passwort ändern, keine Konfigurationsänderungen |

Alle Passwörter werden lokal mit individuell gesalzenem PBKDF2-HMAC-SHA256 gespeichert. Session-Cookies sind `HttpOnly` und `SameSite=Strict`; CSRF-Token schützen verändernde Aktionen. Hinter einem HTTPS-Reverse-Proxy müssen sichere Cookie-Verbindungen gewährleistet sein. Für mehreren Instanzen ist derzeit keine gemeinsame Sessionverwaltung vorhanden.

**Bestehende v1-Daten:** Beim ersten Start mit v1 `state.json` wird der bisherige Administrator automatisch als Benutzer `admin` in das v2-Datenformat übertragen, mit **unverändert gültigem Passwort**. Vor Updates immer die bestehende `state.json` sichern. **Downgrade** auf das alte Programm wird nicht unterstützt. Migration benötigt Schreibzugriff auf das Datenverzeichnis.

## Monitoring / Verwaltungsinformationen

**Website hinzufügen**: Anzeigename, `https://`-/`tls://`-URL, SNI, Prüfintervall (1–10080 Minuten), Ampelschwellen, System- und eigene Root-CAs. Zusätzliche Angaben: Server, Zertifikatsformate, Umgebung, Owner, Notizen und beliebige `Schlüssel=Wert`-Felder. Optional kann ein ACME-Lineage-Name einem Ziel zugeordnet werden. Dies ist eine *dokumentarische Verknüpfung*, keine automatische Zertifikatsauslieferung. Die Felder werden in der Detailansicht in responsiven Inventar-Kacheln ausgegeben.

Ampelstatus: Grün (OK), Gelb (Warnschwelle), Rot (kritisch, abgelaufen oder TLS-/Hostname-/Vertrauensfehler). Die Zertifikatskette wird inklusive eigener Stammzertifikate analysiert; nicht verfügbare Intermediate/Roots werden nicht als erfolgreich validiert ausgegeben. Sonderfall: OCSP/CRL-Widerrufsstatus und automatischer AIA-Intermediate-Download werden **nicht** geprüft. Es findet kein HTTP-Aufruf der eigentlichen Website statt.

## ACME: optionaler Sidecar

```bash
cp .env.example .env
# ADMIN_PASSWORD ersetzen und ACME_ENABLED=true setzen
mkdir -p certbot-credentials acme-hooks acme-ca

docker compose --profile acme up -d --build
# Optionaler Einzeldurchlauf:
docker compose --profile acme run --rm certbot --once
# Ausgabe:
docker compose logs -f certbot
```

`Dockerfile.acme` baut den Certbot-Worker mit Cloudflare- und RFC2136-DNS-Plugins. Der Worker prüft alle aktivierten Zertifikate bei Start und standardmäßig alle **12 Stunden** (`ACME_RUN_INTERVAL=43200`, mindestens 3600). Zertifikate werden je ACME-Profil in eigenen Certbot-Config-/Work-/Log-Unterverzeichnissen gehalten. Bei neuen Zertifikaten meldet der Deploy-Hook die Zertifikatsdateien unter dem Worker-Volume `certbot_handoff`.

1. Als Admin unter **ACME / Certbot** ein Profil anlegen: z. B. ID `le-staging`, ACME-Directory `https://acme-staging-v02.api.letsencrypt.org/directory`, Kontakt-E-Mail und DNS-01-Methode.
2. Bei Cloudflare eine Credentials-Datei lokal speichern und im Profil **nur** den Containerpfad `/run/secrets/cloudflare.ini` hinterlegen:

   ```bash
   printf 'dns_cloudflare_api_token = %s\n' 'TOKEN_AUS_SECRET_STORE' > certbot-credentials/cloudflare.ini
   chmod 600 certbot-credentials/cloudflare.ini
   ```

3. Für andere DNS-Provider unter `acme-hooks/` **eigene ausführbare DNS-Auth-/Cleanup-Hooks** bereitstellen; im Profil z. B. `/hooks/auth.sh` und `/hooks/cleanup.sh` verwenden. Für interne ACME-Directory-URLs optional das CA-Zertifikat unter `acme-ca/` ablegen (im Profil `/run/acme-ca/interne-root.pem`). EAB wird über **Umgebungsvariablen ausschließlich des Workers** geladen (`ACME_INTERNAL_KID`, `ACME_INTERNAL_HMAC` in `.env`), deren **Namen** im Profil zu hinterlegen sind.
4. Als Admin/Editor ein Zertifikat mit eindeutigem Lineage-Namen, ausgewähltem Profil und DNS-SANs (`www.example.com, *.example.com`) registrieren. Der Worker prüft es beim nächsten Durchlauf. Ein Zertifikat im Certbot-Katalog kann unter **Website bearbeiten → ACME-Zuordnung** einer überwachten URL zugeordnet werden.
5. Nur für einen Test ACME Staging verwenden – es ist öffentlich **nicht** vertrauenswürdig. Für Produktion separates Profil mit Let's Encrypt Production Directory einrichten.

**Keine Zugangsdaten** in `.env.example`, Git oder das WebUI kopieren. `.env`, `certbot-credentials`, `acme-hooks` und `acme-ca` sind aus Git und Docker-Build-Kontext ausgeschlossen. Bei Nutzung eigener Hooks als ausführbare Skripte deren Inhalt und Berechtigungen vorher prüfen. Cloudflare-Token auf die erforderliche DNS-Zone beschränken.

### Interner DNS-Server: RFC2136/TSIG statt DNS-Hooks (v2.1)

Für interne ACME-Umgebungen mit einem autoritativen DNS-Server, der **RFC2136 Dynamic Updates** unterstützt (z. B. ein entsprechend konfigurierter BIND-Server), entfällt ein eigener Auth-/Cleanup-Hook. Der Certbot-Worker erstellt und entfernt `_acme-challenge.<name>`-TXT-Records über das RFC2136-Plugin. Dazu braucht er Schreibberechtigung in der zuständigen DNS-Zone; **nur die IP eines DNS-Resolvers reicht nicht**. Der TSIG-Schlüssel sollte ausschließlich TXT-Updates für `_acme-challenge` in der betreffenden Zone erlauben.

1. Auf dem autoritativen DNS-Server TSIG-Key und eine eingeschränkte Update-Policy einrichten. RFC2136/TSIG muss für den Sidecar erreichbar sein (UDP/TCP Port 53 bzw. der eingestellte Port).
2. Lokal eine Datei `certbot-credentials/rfc2136.ini` erstellen, **ohne** DNS-Server-IP oder Port. Beispiel (Platzhalter durch einen echten TSIG-Key ersetzen):

   ```ini
   dns_rfc2136_name = certwatch-acme.
   dns_rfc2136_secret = TSIG_SECRET_AUS_SECRET_STORE
   dns_rfc2136_algorithm = HMAC-SHA256
   # optional: dns_rfc2136_sign_query = true
   ```

   ```bash
   chmod 600 certbot-credentials/rfc2136.ini
   ```

3. Im WebUI unter **ACME / Certbot → ACME-Profil hinzufügen** die Methode **„Direkter DNS-Server (RFC2136 / TSIG)“** wählen und folgende Felder eintragen:

   | Feld | Beispiel |
   | --- | --- |
   | ACME-Directory | `https://acme.internal.example/directory` |
   | DNS-01-Verfahren | `rfc2136` |
   | DNS-Server-IP | `10.20.30.53` |
   | DNS-Port | `53` (leer: Standard 53) |
   | Credentials-Datei | `/run/secrets/rfc2136.ini` |
   | Wartezeit vor ACME-Prüfung | `60` Sekunden (leer: Standard 60) |
   | CA-Bundle (optional) | `/run/acme-ca/internal-ca.pem` |

4. ACME-Zertifikat registrieren und den Worker mit `docker compose --profile acme up -d --build` aktivieren.

**Sicherheitsgrenze:** Der Go-Webserver speichert nur DNS-IP, Port und Dateipfad. Der TSIG-Key wird nicht in der Go-Datenbank gespeichert. Der Worker generiert aus Server-IP und der auf den Worker gemounteten TSIG-Datei eine `0600`-Credentials-Datei in seinem eigenen privaten Certbot-Datenvolume. Die Quelldatei ist ebenfalls auf `0600` zu setzen. Der ACME-Server muss die TXT-Daten **selbst** abfragen können.

**DNS-Abfragen ohne Updates:** Für die reine Namensauflösung des Certbot-Containers (z. B. `acme.internal.example`) kann zusätzlich ein interner Resolver eingestellt werden, **unabhängig von der RFC2136-Konfiguration**. Eine lokale Datei `compose.override.yaml` könnte z. B. so aussehen:

   ```yaml
   services:
     certbot:
       dns:
         - 10.20.30.53
   ```

Dieser Resolver wird für den Container verwendet und ersetzt **nicht** die Berechtigung, ACME-TXT-Einträge auf dem autoritativen DNS-Server zu erzeugen. Falls der interne ACME-Server eine andere DNS-Sicht nutzt (Split DNS), muss er die `_acme-challenge`-Einträge aus seiner eigenen Sicht ebenfalls erreichen können. Ein öffentlicher ACME-Anbieter wie Let's Encrypt validiert aus seiner Infrastruktur und kann privat gehaltene TXT-Einträge in internen, nicht öffentlich auflösbaren Zonen nicht abrufen. Für rein private DNS-Namen daher einen internen ACME-Dienst verwenden.

Wenn der DNS-Server keine passenden RFC2136-Updates zulässt, die vorhandene Methode **„Eigene DNS-Hooks“** verwenden (z. B. für proprietäre API oder Windows-DNS-spezifische Update-Mechanismen). RFC2136 funktioniert nicht automatisch mit jedem DNS-Server.

### Ergebnis-/Statusanzeige

Die Statusdatei in `acme_status` enthält nur Name, Profil, Ergebnis, Ablaufdatum und Zeitstempel. Der Worker schreibt sie nach einem Durchlauf. Erneuerungen sind von den in CertWatch beobachteten Endpunkten getrennt – erst nach Deployment des Zertifikats am Ziel ändert sich der Monitoring-Status.

## GitHub Container Registry (GHCR)

`/.github/workflows/docker-images.yml`:
- bei Pull Requests: Go-Tests mit Race-Detector, `go vet`, Python-Syntaxcheck und Multiarch-Docker-Build **ohne Push**;
- bei Push auf `main`, Git-Tags `v*` oder manueller Auslösung: Docker-Images für `linux/amd64` und `linux/arm64` nach GHCR **pushen**;
- Haupt-Image: `ghcr.io/<owner>/<repository>:latest`, Sidecar: `ghcr.io/<owner>/<repository>-acme:latest`;
- Git-Tags verwenden semantische Version-Tags zusätzlich; `latest` wird nur vom Branch `main` gebaut.

Beachte: Im GitHub-Repository unter **Actions → General** entsprechende Workflow-Berechtigungen sowie Paketveröffentlichung via `GITHUB_TOKEN` zulassen. Zum Verwenden der veröffentlichten Images `.env` ergänzen:

```dotenv
CERTWATCH_IMAGE=ghcr.io/owner/repo:latest
CERTWATCH_ACME_IMAGE=ghcr.io/owner/repo-acme:latest
```

`docker compose pull` für vorhandene Images statt `--build` verwenden. `/.github/dependabot.yml` prüft wöchentlich GitHub-Actions, Docker-Basisimages und Go-Module. Vor Veröffentlichung alle Tests prüfen.

## Wartung, Test, Datensicherung

```bash
go test -race ./...
go vet ./...
python3 -m py_compile scripts/certbot-runner.py
python3 -m unittest discover -s scripts -p "test_*.py" -v
```

Sichern: Go-Datenvolume `certwatch_data` (einschließlich verschlüsselter manueller Zertifikatsversionen), gegebenenfalls den unveränderten Vault-Key **separat**, für ACME `certbot_config`, `certbot_handoff` und bei Bedarf Worker-Logs sowie die Secrets aus dem Secret Store. Die ACME-Statusdatei und der öffentliche Katalog können wiederhergestellt werden; Zertifikats-Private-Keys und ACME-Accountdaten **nicht**. Bei Restore die Dateirechte erhalten. Reverse Proxy benötigt HTTPS, TLS, geeignete Zugangskontrolle und Sicherung gegen unberechtigten öffentlichen Zugriff. Multi-Replica-Betrieb ist nicht unterstützt.

## Lizenz / Credits der importierten ACME-Komponente

Die Worker-Skripte `scripts/certbot-runner.py` und `scripts/certbot-deploy-hook.sh` stammen aus dem mitgelieferten **UCNG Certificate Manager** und wurden für das isolierte Sidecar-/Status-Konzept angepasst. Der Ursprungscode wurde unter **GNU AGPL v3** geliefert. Siehe `third_party/ucng/LICENSE` und `third_party/ucng/NOTICE.md`. Vor Veröffentlichung des kombinierten Images/Projekts die Lizenzpflichten (insbesondere Quellcodebereitstellung) beachten.

Der tokenbasierte Public-PEM-/Private-PEM-Abruf sowie der manuelle Zertifikatsimport mit Formatkonvertierung sind **umgesetzt**. Noch nicht implementiert sind die automatische Konvertierung von ACME-Releases in PFX/P12, das Abrufen von Private Keys aus reinen Monitoring-TLS-Endpunkten sowie automatische Webserver-Restarts/Deployments. Die Installation übernimmt weiterhin der jeweilige Client.

### Formularseiten / automatische Aktualisierung (v2.2)

Das Dashboard und die reine Zertifikatsdetailansicht aktualisieren sich weiterhin alle 30 Sekunden. **Die ACME-Seite lädt nicht mehr automatisch neu**, damit beim Bearbeiten eines ACME-Profils oder beim Registrieren eines Zertifikats keine ungespeicherten Eingaben verloren gehen. Zum Abfragen eines neuen Worker-Status gibt es dort **„Ansicht aktualisieren“**; ein manuelles Neuladen verwirft ungespeicherte Eingaben. Auch Benutzerverwaltung, Einstellungen, Stammzertifikate und Zielbearbeitung werden nicht automatisch neu geladen. Die Zertifikatsprüfungen im Hintergrund sind davon nicht betroffen.

## v2.4 – Manueller Zertifikatsimport und Konvertierung (UCNG-Komponente)

Das manuelle Verwalten von Zertifikaten aus dem ursprünglichen UCNG-Certmanager wurde für CertWatch wieder ergänzt. Die **Überwachung funktioniert weiterhin ohne ACME und ohne Vault**. Der Menüpunkt **Manueller Import** ist nur für Admins erreichbar. Die Artefakte liegen separat unter `/app/data/certificates/` und werden nicht im ACME-Handoff gespeichert. Der Certbot-Sidecar ist **nicht** nötig, um Zertifikate manuell zu importieren oder auszuliefern.

### Upgrade und Aktivierung

Bestehende `state.json` und Compose-Volumes **vorher sichern**. Ein Upgrade von v2.3 benötigt keine Datenmigration und lässt bestehende ACME-Tokens und Zielkonfigurationen bestehen. Für den neuen manuellen Import benötigst du zusätzlich einen **dauerhaft unveränderten** 32-Byte AES-256-GCM-Vault-Key:

```bash
cp .env.example .env # nur für neue Installationen; bestehende .env NICHT überschreiben
openssl rand -base64 32
```

Die erzeugte Base64-Zeichenfolge als `CERTWATCH_VAULT_KEY` in die bestehende `.env` eintragen und sicher getrennt sichern (Zugriffsrechte 0600). `docker compose up -d --build certwatch` startet ausschließlich den Go-Dienst. Für Produktion lässt sich statt der Umgebungsvariable auch `CERTWATCH_VAULT_KEY_FILE` nutzen: ein gemountetes Secret mit genau diesem Base64-Schlüssel. **Schlüsselverlust macht alle manuellen Zertifikatsversionen dauerhaft unlesbar.** Den Key nicht ins Git oder ins Docker-Image aufnehmen. Für Zertifikate und Private Keys ist ein Backup von **Daten-Volume und Vault-Key** nötig; den Key getrennt vom Backup aufbewahren.

OpenSSL wird im CertWatch-Laufzeitimage mitgeliefert (Go selbst benötigt keine externen Libraries). Die OpenSSL-Konvertierung verwendet kurzlebige Klartextdateien ausschließlich unter `/tmp`, das im mitgelieferten Docker-Compose auf `tmpfs` liegt. Bei `go run .` außerhalb von Docker muss das eigene `TMPDIR` für diese sensiblen Dateien ebenfalls auf einem angemessen geschützten tmpfs liegen. Die temporären Dateien werden anschließend gelöscht. Dateiuploads sind auf 8 MiB insgesamt und 2 MiB pro Datei beschränkt.

### Import im Admin-WebUI

1. Unter **Manueller Import** eine neue Zertifikats-ID (`intranet-web`) und einen Anzeigenamen angeben.
2. Entweder **Leaf-Zertifikat** + **Private Key** als PEM hochladen (optional geordnete Intermediate-Kette und Root-CA), **oder** eine bereits vorhandene `.pfx`/`.p12`-Datei samt Importpasswort.
3. Speichern: Schlüsselpaar, aktuelle Zertifikatsgültigkeit und die Signaturen in der angegebenen Zertifikatskette werden geprüft. Aus einer PFX-Datei wird die Zertifikatskette anhand der Signaturen sortiert. Die Prüfung einer CA-Signatur bedeutet nicht automatisch, dass die Root-CA vertrauenswürdig ist.
4. Unter derselben ID kann später eine erneuerte Datei hochgeladen werden. Es entsteht eine **neue, unveränderliche Version**. Bestehende Token behalten ihren Scope; aktuelle Clients sehen die neue Version.
5. Unter **Zertifikatsabruf** ein Public-Token oder einen explizit für Private Keys berechtigten Token für `manual/intranet-web` ausstellen.

Bei einem manuellen Upload wird **nichts** automatisch an andere Webserver verteilt. Clients können die Artefakte via API abrufen und nach eigener Prüfung installieren bzw. Dienste neu laden. Ein Import öffentlicher Zertifikate ganz ohne privaten Schlüssel (Public-only-Archivierung) ist hier noch nicht vorgesehen.

### Erzeugte Ausgabeformate

Die genauen Artefakte hängen davon ab, ob Intermediate- und Root-Zertifikate vorhanden sind. Eine Übersicht findet sich direkt im Menü **Manueller Import** und im Token-spezifischen API-Manifest.

| Öffentliche Artefakte (Public-Token) | Geschützte Artefakte (Private-Token und Opt-in) |
| --- | --- |
| `cert.pem`, `leaf.pem`, `leaf.crt`, `leaf.cer`, `leaf.der`, `leaf-base64.cer` | `privkey.pem`, `private-key.pem` |
| `fullchain.pem`, `fullchain.crt`, `chain.pem`, einzelne Intermediate-PEM/DER | `key-leaf.pem`, `key-fullchain.pem`, optional mit Root |
| `public-key.pem`, `public-key.der`, `public.key` | `leaf-only.pfx` und `.p12`; mit Intermediates `leaf-chain.pfx`/`.p12` |
| Optional `root-ca.pem`/`.der`, `ca-bundle.pem`, `fullchain-with-root.pem` | Optional `leaf-fullchain-with-root.pfx`/`.p12` |
| PKCS#7 `.p7b` / `.pkcs7.pem`, Zertifikatsinformationen | PKCS#8 verschlüsselt PEM/DER; PFX-Passwortdatei `pfx-password.txt` |

PFX/P12 wird **mit einem zufällig erzeugten Passwort** pro Zertifikatsversion verschlüsselt. `pfx-password.txt` ist ebenfalls geschützt. Der Private-Key-Export erfordert global `CERTWATCH_PRIVATE_EXPORT_ENABLED=true` **und** einen passenden Private-Token. Standardmäßig ist er ausgeschaltet. PKCS#8-Schlüssel **ohne Passwort** sind ausschließlich bei explizitem `CERTWATCH_EXPORT_UNENCRYPTED_KEYS=true` erzeugbar und ebenfalls geschützt; dieses zusätzliche unsichere Format wird nicht standardmäßig erzeugt. Für ältere PKCS#12-Consumer kann außerdem `CERTWATCH_LEGACY_PFX=true` eingestellt werden; die alten Verschlüsselungsalgorithmen sind schwächer und sollten nur bei tatsächlichem Bedarf aktiviert werden.

### Generische API für manuell importierte Zertifikate

Wie bei ACME sind alle Endpunkte authentifiziert und auf ein Zertifikat beschränkt:

```text
GET /api/v1/distribution/manual/intranet-web/manifest
GET /api/v1/distribution/manual/intranet-web/artifacts/leaf.der
GET /api/v1/distribution/manual/intranet-web/artifacts/leaf-chain.pfx
GET /api/v1/distribution/manual/intranet-web/artifacts/pfx-password.txt
GET /api/v1/distribution/manual/intranet-web/versions/{version}/artifacts/{filename}
Authorization: Bearer cw_...
```

Das Manifest enthält `source=manual`, `artifacts`, `artifact_details` (Dateinamen, Größen, SHA-256 und Schutzklassifikation) und die unveränderliche `version`. Private Dateien erscheinen **nicht** in einem Public-Manifest. Verwende ausschließlich HTTPS, verwalte API-Tokens im Secret Store und gib keine Tokens/Passwörter in URLs oder Logs weiter.

Die bisherigen PEM-Clients (`clients/certwatch-fetch.sh`, `clients/CertWatch-Fetch.ps1`) funktionieren mit `-Profile manual` bzw. `manual` auch für PEM-Aliase. Für **beliebige Formate** gibt es zusätzlich:

**Linux / POSIX Shell:**

```bash
CERTWATCH_TOKEN_FILE=/etc/certwatch/client.token sh clients/certwatch-fetch-format.sh \
  https://certwatch.example.org manual intranet-web /etc/certwatch/export \
  leaf-only.pfx pfx-password.txt
```

**Windows / PowerShell 7.4+:**

```powershell
./clients/CertWatch-FetchFormat.ps1 `
  -BaseUrl https://certwatch.example.org `
  -Profile manual -Certificate intranet-web `
  -Destination C:\certwatch\tls `
  -TokenFile C:\certwatch\client.token `
  -Artifacts @('leaf-only.pfx','pfx-password.txt')
```

Die Clients laden aus einer einzelnen Version herunter und prüfen Hashes, falls im Manifest enthalten. Sie installieren **keine** Zertifikate im lokalen System und starten keine Dienste neu. Zugriffsrechte des Ablageortes für PFX/Private Keys bleiben Aufgabe des Client-Administrators. Für Anwendungen, die nicht mehrere Dateien atomar wechseln können, ist ein separates Release-Verzeichnis mit anschließendem atomarem Symlink-/Junction-Wechsel empfehlenswert.

**Lizenz:** Teile des Konverters und des verschlüsselten Vaults basieren auf dem bereitgestellten UCNG-Certmanager-Quellcode unter AGPL-3.0. Lizenz und Hinweise liegen unter `third_party/ucng/`. Beachte AGPL-Pflichten bei der Weitergabe und beim Bereitstellen des Webdienstes.


## Interaktiver Zertifikatsdownload (v2.5)

In der linken Navigation steht für **alle angemeldeten Benutzer (Admin, Editor, Viewer)** der Bereich **„Zertifikate herunterladen“** (`GET /downloads`) bereit:

1. Ein Zertifikat aus dem manuellen Import oder einem aktiven ACME-Profil auswählen.
2. Die angezeigte Veröffentlichungsversion kontrollieren.
3. Dateien nach **Öffentliche Formate** und **Private Formate** getrennt herunterladen. Es werden die jeweils verfügbaren PEM/CRT/CER/DER/PKCS#7/PKCS#8/PFX/P12-Varianten und die PFX-Passwortdatei angeboten.
4. Bei einer Erneuerung die Detailseite erneut öffnen: Sie zeigt stets die aktuell veröffentlichte Version. Alle Downloadlinks derselben Seite sind **fest auf die angezeigte Version** begrenzt, damit kein gemischtes Zertifikat-Schlüssel-Paar entsteht.

**Der Browserbereich ist unabhängig von der API:** Er benötigt einen gültigen Cookie-Login und **akzeptiert keine API-Tokens**. Das API-Flag `CERTWATCH_PRIVATE_EXPORT_ENABLED` schränkt weiterhin ausschließlich private **API-Downloads** ein. Ein Viewer darf auf ausdrücklichen Wunsch auch über die Browseroberfläche private Schlüssel und PFX-Passwörter herunterladen. Dies ist eine **bewusste Sicherheitsentscheidung**: Ein kompromittierter Viewer-Account kann Schlüssel aller veröffentlichten Zertifikate exportieren. Deshalb nur über HTTPS betreiben, Viewer-Konten vertrauenswürdigen Personen geben und bei Bedarf getrennte WebUI-Instanzen oder Netzsegmentierung nutzen. Browserdownloads verwenden `Cache-Control: no-store, private` und `Content-Disposition: attachment`; es werden keine Schlüssel im HTML angezeigt.

**Formatkonvertierung für ACME:** Die vier ursprünglichen Certbot-PEM-Dateien sind auch ohne Vault erreichbar. Für die übrigen Formate muss `CERTWATCH_VAULT_KEY` gesetzt sein, wie bereits beim manuellen Import. Beim ersten Aufruf eines neuen ACME-Releases erzeugt OpenSSL dessen Formate in einem temporären Verzeichnis und speichert sie verschlüsselt in einem vom manuellen Import separierten Vault-Cache. Die PFX-Passwortdatei wird versionsweise zusammen mit dem PFX gespeichert und bleibt bei Folgeabrufen stabil. Der Docker-Container verwendet `/tmp` als `tmpfs`; außerhalb von Docker muss das temporäre Verzeichnis entsprechend geschützt werden. Die ACME-PEM-Ausgabe des Sidecars bleibt der unveränderte Ursprung.

### Mehrfach-Zertifikate pro API-Zugang

Unter **„Zertifikatsabruf“** (Admin) lassen sich nun durch Checkboxen mehrere Zertifikate für einen Token auswählen (maximal 50). Die öffentliche/private Berechtigung gilt für die gesamte Auswahl. Bestehende Einzelzertifikat-Tokens aus v2.3/v2.4 funktionieren unverändert und erfordern keine Migration. Der Token kann in mehreren unabhängigen Client-Jobs verwendet werden:

```sh
# Beide Jobs lesen denselben sicher aufbewahrten Token, aber unterschiedliche Zertifikate.
CERTWATCH_TOKEN_FILE=/etc/certwatch/client.token sh clients/certwatch-fetch.sh \
  https://certwatch.example.org internal nginx-prod /etc/certwatch/nginx --private
CERTWATCH_TOKEN_FILE=/etc/certwatch/client.token sh clients/certwatch-fetch.sh \
  https://certwatch.example.org internal api-prod /etc/certwatch/api --private
```

Unversionierte `.../manifest`-Aufrufe liefern **immer die neueste veröffentlichte Version**, inklusive neuer Private Keys. Nach dem Lesen des Manifests sollen Clients die Versionspfade `/versions/{version}/artifacts/{file}` verwenden. Dadurch stammen Zertifikat, Kette, PFX und Key immer aus **derselben** Generation. Verwende einen regelmäßigen Cronjob, systemd-Timer oder Task Scheduler und aktualisiere den Dienst erst nach vollständigem, geprüftem Download.

**Migration von v2.4:** Bestehende `state.json`, verschlüsselte Zertifikate und API-Tokens sind weiterhin verwendbar. Vorher `state.json`, `certificates/`, ACME-Handoff und `CERTWATCH_VAULT_KEY` sichern; den Vault-Key niemals neu erzeugen, wenn bestehende Zertifikate entschlüsselt werden sollen. GitHub-Workflows, Docker-Dateien und ACME-Sidecar sind unverändert enthalten.
