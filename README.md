# UCNG Certificate Manager v3.1.2

Zentrale Zertifikatsverwaltung in Go: mehrere Wildcard-Zertifikate, ACME-Profile (Let's Encrypt / Staging / interne ACME), Dienste-Inventar mit Format-Checkboxen, direkten Datei-Uploads (Key/CRT/CA), passwortgeschütztes Web-CMS für mehrere Benutzer, öffentliche Zertifikatsdownloads und tokenpflichtiger Abruf von Private Keys/PFX.

**Architektur:** Ein Go-Webdienst + **ein** optionaler isolierter Certbot-Worker. Der Worker liest die Profil- und Zertifikatszuordnungen regelmäßig aus dem gemeinsam genutzten Katalog; pro ACME-Profil werden separate Certbot-Konfigurations-, Arbeits- und Log-Verzeichnisse verwendet. Der Go-Dienst hat keinen direkten Zugriff auf DNS-/ACME-Zugangsdaten oder auf das ausführbare Certbot. Für jeden Dienst können die freigegebenen Dateien einzeln festgelegt werden.

## 1. Schnellstart mit zwei Web-Benutzern

Benötigt: Go 1.23+ und OpenSSL **oder** Docker Compose. TLS-Reverse-Proxy für Produktion empfohlen.

```bash
cp .env.example .env
```

Ändere in `.env` mindestens diese Einträge:

```dotenv
APP_SECRET=EIN-ZUFÄLLIGES-LANGES-GEHEIMNIS-MINDESTENS-32-ZEICHEN
USERS_JSON={"admin":"MeinLangesPasswortFuerDenAdmin123!","technik":"MeinAnderesLangesPasswort456!"}
COOKIE_SECURE=true
```

- `APP_SECRET` dient zur **AES-256-GCM-Verschlüsselung der Zertifikatsdateien auf dem Server**; es ist **keine Master-Key-Datei mehr nötig**. Es muss bei jedem Neustart identisch bleiben und gesichert werden. Eine Änderung führt dazu, dass alte Dateien nicht mehr entschlüsselt werden können. Es sollte zufällig mit hoher Entropie erzeugt werden, z. B. `openssl rand -hex 32` (64 Zeichen).
- `USERS_JSON` ist die vollständige Benutzerliste als JSON-Objekt. Jeder Name benötigt ein eigenes Passwort mit mindestens 12 Zeichen. Nach einer Änderung Container neu erstellen/starten; es gibt bewusst **keine zusätzliche Benutzer-Datenbank**. Die Anmeldung per Session-Cookie mit CSRF-Schutz bleibt erhalten.
- Vorhandenes `ADMIN_USER` + `ADMIN_PASSWORD` bleibt als Alternative gültig, **wenn `USERS_JSON` nicht gesetzt** ist.
- Die `.env` gehört **nicht** ins Repository, und sollte auf dem Host nur vom Administrator gelesen werden. Für Produktion ist ein Secret-Store sicherer als Klartext in ENV.
- Hinter HTTPS muss `COOKIE_SECURE=true` gesetzt bleiben. **Nur** bei lokalen HTTP-Tests `COOKIE_SECURE=false` verwenden.

### Docker Compose

```bash
docker compose up -d --build
```

**Berechtigungen des Daten-Volumes (v3.1.1):** Vor dem Webdienst läuft
`cert-data-init` als einmaliger Init-Container. Dieser Container benötigt nur
`CHOWN`, `DAC_OVERRIDE` und `FOWNER`, hat **kein Netzwerk** und korrigiert die
Eigentümerschaft des Docker-Volumes `cert-data` auf UID/GID `10001:10001`.
Der Webdienst bleibt mit `USER 10001:10001`, `read_only: true` und
`cap_drop: [ALL]` abgesichert. Das funktioniert auch mit Volumes aus v3.1:
**bestehende Zertifikate und Schlüssel werden nicht gelöscht.**

Wenn du nur die neue `compose.yml` einspielst, reicht:

```bash
docker compose up -d certmanager
# optional mit Certbot-Worker:
docker compose --profile acme up -d
```

Falls die Fehlermeldung `mkdir /data/certificates: permission denied` schon
aufgetreten ist und du die Compose-Datei noch nicht aktualisieren kannst,
führe einmalig folgenden Befehl im Projektverzeichnis aus:

```bash
docker compose run --rm --no-deps --user 0 \
  --cap-add CHOWN --cap-add DAC_OVERRIDE --cap-add FOWNER \
  --entrypoint sh certmanager \
  -c 'chown -R 10001:10001 /data && chmod 0700 /data'
```

**Kein `docker compose down -v` ausführen:** Das würde die gespeicherten
Zertifikate, Tokens und den Katalog entfernen. Bei NFS-/CIFS-Bind-Mounts mit
Root-Squash muss die UID/GID `10001` auf dem Storage-Server Schreibrechte
bekommen; in diesem Fall kann der Init-Container `chown` nicht erzwingen.

Es läuft zunächst **nur der Go-Dienst** auf `127.0.0.1:8089`. Anmeldung über `/admin/login`, öffentlicher Bereich unter `/public`. Vor dem Zugriff über das Netzwerk einen HTTPS-Reverse-Proxy konfigurieren. Für reine lokale Tests kann alternativ gelten: `go run .` mit zuvor exportierten Variablen aus der `.env` (Go lädt `.env` nicht automatisch).

## 1a. Manueller Upload: Key und CRT direkt im Browser (v3.1.2)

Kein Einhängen und Umbenennen von Dateien im Handoff-Verzeichnis mehr nötig:

1. Im Webinterface anmelden (`/admin/login`).
2. Ein bestehendes Zertifikat aus der Übersicht öffnen oder ein neues anlegen.
3. Unter **Zertifikatsdaten** das Profil **Manuell / Web-Upload** auswählen und sicherstellen, dass die erwarteten DNS-Namen (SAN) korrekt eingetragen sind. Änderungen ggf. speichern.
4. Im Abschnitt **Key und Zertifikat hochladen** die Dateien auswählen:

   | Feld | Pflicht | Beispiel |
   |---|---|---|
   | **Privater Schlüssel** | Ja | `_.cert.pem` oder `privkey.pem`, unverschlüsseltes PKCS#8-/RSA-/EC-PEM |
   | **Leaf-Zertifikat** | Ja | `_cert.crt`, `cert.pem` oder `fullchain.pem` |
   | **Intermediate CAs** | Nein | Eine oder mehrere `.crt`-/`.pem`-/`.der`-/`.cer`-Dateien, in Signaturreihenfolge |
   | **Root CA** | Nein | `USERTrustRSACertificationAuthority.crt` |

5. Auf **Dateien hochladen und konvertieren** klicken. Die Anwendung verifiziert die Zuordnung zwischen Private Key und Leaf-Zertifikat, erwartete SANs, Zeitgültigkeit und die mitgelieferte Kette; danach werden die bisherigen Formate (PEM, DER, PFX/P12, PKCS#7, PKCS#8 und Bundles) erzeugt und als **neue verschlüsselte Zertifikatsversion** gespeichert. Die Dienst-Checkboxen und API-Endpunkte funktionieren unverändert.

**Wichtig:** Zertifikate werden sowohl als PEM als auch als DER akzeptiert, die Private-Key-Datei **derzeit nur unverschlüsselt als PEM**. Eine PEM-Fullchain im Feld „Leaf“ wird automatisch in Leaf und Intermediates aufgeteilt. Die Root-CA wird nicht automatisch aus dem Internet heruntergeladen. Maximal **12 MiB pro Upload** und **4 MiB pro Datei**. Der Browser muss über **HTTPS** auf die Anwendung zugreifen; Private Keys sind vertraulich.

**Manuelle und automatische Zertifikate nicht vermischen:** Ist ein ACME-Profil aktiviert, steht der Upload erst nach Umstellung auf „Manuell / Web-Upload“ zur Verfügung. Sobald ein manueller Upload erfolgt ist, verhindert `source: manual` im Katalog, dass der alte Legacy-Handoff-Importer das neue Zertifikat alle fünf Minuten überschreibt. Für die spätere Rückkehr zum ACME-Betrieb das gewünschte ACME-Profil im Zertifikat auswählen und speichern. Bestehende Token und Dienstzuordnungen bleiben dabei erhalten.

**Upgrade von v3.1.1:** Projektdateien bzw. Docker-Image aktualisieren, das vorhandene `/data`-Volume und die bisherige `.env` **weiterverwenden**. Kein neues `APP_SECRET` und kein neues `MASTER_KEY` generieren. Nur die Webanwendung muss für diese Erweiterung neu gebaut werden:

```bash
docker compose build certmanager
docker compose up -d --no-deps certmanager
```

Bei Nutzung von GHCR muss zunächst der neue Stand über GitHub Actions gebaut und veröffentlicht werden; danach das neue Image-Tag in `CERTMANAGER_IMAGE` konfigurieren und mit `docker compose pull certmanager && docker compose up -d --no-deps certmanager` aktualisieren. Die GitHub-Actions-Datei ist weiterhin vorhanden.

## 2. ACME-Profile im Webinterface

Die frische Installation enthält zwei vorbereitete Profile:

| Profil-ID | ACME-Directory-URL | Typ |
|---|---|---|
| `letsencrypt` | `https://acme-v02.api.letsencrypt.org/directory` | Produktiv |
| `letsencrypt-staging` | `https://acme-staging-v02.api.letsencrypt.org/directory` | Test |

Eine **Kontakt-E-Mail** muss vor der ersten Ausstellung pro Profil eingetragen werden. Auf aktualisierten v2-Installationen, die schon eine `catalog.json` haben, können die Profile im UI angelegt werden; bestehende Einträge werden nicht überschrieben.

Für eine interne CA über **Admin → ACME-Profile → Neues Profil** beispielsweise:

| Feld | Wert |
|---|---|
| Profil-ID | `interne-acme` |
| Bezeichnung | `Interne PKI` |
| Directory-URL | `https://pki.intern.example/acme/directory` |
| E-Mail | `pki@example.com` |
| Methode | `manual-dns-hooks` oder `cloudflare` |
| DNS-Auth-Hook | `/hooks/dns-auth.sh` (nur bei Hooks) |
| DNS-Cleanup-Hook | `/hooks/dns-cleanup.sh` |
| CA-Bundle | `/run/acme-ca/internal-ca.pem` (falls nötig) |
| EAB-KID-ENV | `ACME_INTERNAL_KID` (optional) |
| EAB-HMAC-ENV | `ACME_INTERNAL_HMAC` (optional) |

**Es werden keine API-Schlüssel oder EAB-Geheimnisse in der Web-Datenbank gespeichert.** Es werden nur Credentials-Dateipfade bzw. Namen von Worker-ENV-Variablen konfiguriert. ACME-Directory-Adressen müssen HTTPS verwenden. Um die ACME-CA eines bereits verwendeten Profils zu wechseln, ein neues Profil erstellen und das Zertifikat diesem zuordnen; Zertifikate werden pro Profil strikt getrennt verarbeitet.

### DNS-01 einrichten

Für Cloudflare DNS liegt die Credentials-Datei auf dem Host beispielsweise unter:

```bash
mkdir -p certbot-credentials
printf 'dns_cloudflare_api_token = %s\n' 'DEIN-EINGESCHRAENKTER-CLOUDFLARE-TOKEN' > certbot-credentials/cloudflare.ini
chmod 600 certbot-credentials/cloudflare.ini
```

Sie wird als `/run/secrets/cloudflare.ini` **nur im Certbot-Container** eingebunden. Dem Token möglichst nur `Zone:DNS:Edit` für die benötigte DNS-Zone gewähren. Für weitere DNS-Provider können automatisch arbeitende Auth-/Cleanup-Hooks verwendet werden (im Ordner `acme-hooks/`, nur lesbar nach `/hooks/` gemountet). Ein interner ACME-Server ist **nicht automatisch gleichbedeutend mit internem DNS**: Die DNS-01-Hooks müssen die vom internen CA-Server abgefragten `_acme-challenge`-TXT-Records tatsächlich setzen und anschließend entfernen. Für beliebige DNS-Provider wird noch kein vorgefertigtes Hook-Skript mitgeliefert – das ist installationsabhängig.

Falls die interne ACME-HTTPS-Verbindung einer privaten CA vertraut, deren PEM-Datei nach `acme-ca/internal-ca.pem` ablegen. Der Worker setzt dann `REQUESTS_CA_BUNDLE`, aber nur für genau dieses Profil.

Für EAB kann die `.env` enthalten:

```dotenv
ACME_INTERNAL_KID=dein-key-identifier
ACME_INTERNAL_HMAC=dein-hmac-base64url
```

Die oben angegebenen Variablennamen werden über `compose.yml` explizit in den Certbot-Worker weitergereicht. Weitere individuelle EAB-Sets müssen in der Compose-Worker-Umgebung ergänzt werden.

### Zertifikat registrieren und Worker starten

Im CMS `Admin → Zertifikate → Zertifikat registrieren`:

- **Certbot-Name:** `wildcard-example-com` (eindeutige Lineage-ID)
- **SANs:** `*.example.com, example.com`
- **ACME-Profil:** `letsencrypt`, `letsencrypt-staging` oder `interne-acme`

Bei einem bestehenden Zertifikat lässt sich das Profil in dessen Detailansicht ändern. Anschließend:

```bash
docker compose --profile acme up -d --build
# Einmaligen Durchlauf anstoßen (optional):
docker compose --profile acme run --rm --entrypoint python certbot /opt/ucng/certbot-runner.py --once
# Worker-Logs:
docker compose logs -f certbot
```

Der Worker prüft alle aktivierten, einem Profil zugewiesenen Zertifikate beim Start und danach alle 12 Stunden (`ACME_RUN_INTERVAL=43200`); Certbot ermittelt, ob eine Ausstellung/Erneuerung erforderlich ist. Nach erfolgreichem Certbot-Lauf veröffentlicht der Deploy-Hook einen atomaren Satz in `/handoff/<profil>/<zertifikat>/current`. Der Go-Dienst prüft und importiert diese Quelle normalerweise innerhalb von fünf Minuten (`POLL_INTERVAL`). Die Ausgabeformat-Erzeugung und verschlüsselte Versionsablage bleiben unverändert.

**Wichtig:** Staging-Zertifikate sind nicht öffentlich vertrauenswürdig und dürfen nicht unbeabsichtigt auf Produktionsservern installiert werden. Bereits importierte ältere Versionen bleiben beim Wechsel des Profils im Vault abrufbar, bis ein neues Zertifikat erfolgreich importiert wurde; für einen harten Wechsel Zertifikatzugang bis dahin deaktivieren und Tokens prüfen.

## 3. Dienste und Ausgabeformate

Über die Zertifikatsdetailseite beliebig viele Dienste anlegen, beispielsweise:

- `IIS-Web01` (Hostname `web01.intern`): `leaf-chain.pfx`, `leaf.der`
- `Apache-Web02` (Hostname `web02.intern`): `fullchain.pem`, `private-key.pem`
- `Proxy-03` (Nginx): `fullchain.pem`, `private-key.pem`

Alle verfügbaren Formate lassen sich pro Dienst über **Checkboxen** auswählen. Für jeden Dienst einen eigenen Token mit minimalen Rechten ausstellen. Zertifikats-API und dienstspezifische API verwenden versionierte Pfade; die beiden Berechtigungstypen sind getrennt.

```text
GET /api/v1/services/{service_id}
GET /api/v1/services/{service_id}/versions/{version}/artifacts/{datei}
Authorization: Bearer ucng_...
```

PowerShell-Skript: `scripts/Install-CentralCertificate.ps1` (Windows PowerShell 5.1 / PowerShell 7+, IIS und PEM-Export für Apache).

## 4. Öffentliche Dateien ohne Anmeldung

Öffentliche Zertifikate sind im Browser über diese URLs erreichbar:

```text
GET /public
GET /public/{certbot-name}
GET /api/v1/certificates
GET /api/v1/certificates/{certbot-name}
GET /api/v1/certificates/{certbot-name}/artifacts/fullchain.pem
GET /api/v1/certificates/{certbot-name}/artifacts/leaf.der
GET /api/v1/certificates/{certbot-name}/artifacts/leaf-chain.p7b
```

Für öffentliches Material **kein Login und keinen Token** nötig. In der öffentlichen Browseroberfläche werden ausschließlich als nicht-privat gekennzeichnete Artefakte angezeigt; auch die API schützt PFX, P12, private-key.pem, kombinierte Key-PEMs und PFX-Passwörter weiterhin mit Bearer-Token und Private-Key-Recht. Die Dienstinventare/Hosts sind öffentlich **nicht** sichtbar. Für öffentlich zugängliche Deployments Zugriff auf private Endpunkte zusätzlich per HTTPS, Netzwerksegmentierung und getrennten Diensten beschränken.

## 5. Upgrade von v2

**Vorher `/data`, `tokens.json` und den bisherigen Master-Key sichern.** Bestehende verschlüsselte Artefakte wurden mit dem alten Base64-Schlüssel geschrieben. Damit sie lesbar bleiben, bei v3 **anstelle** des neuen `APP_SECRET` den bisherigen Key als ENV setzen:

```dotenv
MASTER_KEY=DEIN-ALTER-BASE64-MASTER-KEY-AUS-master-key.b64
USERS_JSON={"admin":"LangesAdminPasswort...","ops":"AnderesLangesPasswort..."}
```

Die frühere `MASTER_KEY_FILE`-Umgebungsvariable wird für direkte Migration in `go run` ebenfalls noch unterstützt, ist aber bei Docker Compose nicht mehr verdrahtet. **Nicht** automatisch von dem alten Key auf `APP_SECRET` wechseln – die alten Daten wären sonst nicht mehr entschlüsselbar. Für komplett neue Installationen reicht `APP_SECRET` und es wird keine Key-Datei benötigt. Gleiche `/data`-Volume weiterverwenden; `catalog.json`, Dienstzuordnungen und bestehende Tokens bleiben erhalten. Bestehende v2-Zertifikate besitzen zunächst kein ACME-Profil (Legacy-Import unter `/handoff/{name}`), bis ihnen im CMS eines zugewiesen wird.

## 6. Sicherheit / Betrieb

- Der Go-Container hat keinen Netzwerkzugriff auf Certbot-Secrets, kein Certbot-Binary und keine Docker-Socket-Mounts; er liest nur atomisch bereitgestellte PEM-Dateien aus dem schreibgeschützten Handoff-Volume.
- Zertifikats- und Schlüsselartefakte werden mit AES-256-GCM verschlüsselt gespeichert. Umgebungswerte und Tokens sicher sichern/rotieren. Die Master-Key-/APP_SECRET-Änderung ist **keine** Passwort-Rotation ohne Re-Encryption.
- Web-Logins verwenden eigene Session-Cookies (12 Stunden), CSRF-Token, Origin-Prüfung und IP-basiertes Login-Limit. Alle angemeldeten Benutzer können momentan Profile, Zertifikate, Dienste und Tokens verwalten (**keine Rollen/RBAC**).
- Das Webinterface muss über HTTPS bereitgestellt werden. Der Compose-Port wird bewusst nur an `127.0.0.1` gebunden; einen TLS-Reverse-Proxy separat betreiben. `COOKIE_SECURE=true` beibehalten.
- Profile sollten immer getrennte Lineage-IDs verwenden; die Anwendung erzwingt keine DNS-Zonenautorisierung. Die administrativen Benutzer sind vertrauenswürdig. Vermeide öffentlich erreichbare interne ACME-URLs, ungeschützte DNS-Hooks oder unnötige Tokenrechte.
- Certbot setzt `/etc/letsencrypt`, `/var/lib/letsencrypt` und `/var/log/letsencrypt` pro Profil ein. TLS-Zertifikate aus einer internen CA benötigen auf den Clients ihren eigenen Vertrauensanker. Root-Zertifikate werden nicht automatisch aus ACME mitgeliefert. Optional `roots/<certbot-name>.pem` für die Go-Konvertierung bereitstellen.
- Vertrauliche `.env`, `certbot-credentials/`, `acme-ca/` und Certbot-Datenvolumes nicht ins Git einchecken. Backups regelmäßig mit Wiederherstellungstest durchführen.

### Tests

```bash
go test ./...
go test -race ./...
go vet ./...
python -m unittest discover -s scripts -p '*test*.py'
```

Automatisiert getestet werden die Go-CMS-APIs, Login, Profile, Katalog, Upload von PEM-/DER-Zertifikaten und Private Keys, ungültige Uploads, Formatkonvertierung und Zugriffskontrollen. Eine **echte ACME-Ausstellung, Certbot-Docker-Laufzeit, DNS-Provider-Anbindung und produktiver IIS-Deploy** benötigen einen Staging-Test in deiner Infrastruktur.


## 7. Docker-Images mit GitHub Actions (GHCR)

Der Workflow `.github/workflows/docker-images.yml` baut und veröffentlicht zwei Images:

- `ghcr.io/<OWNER>/<REPO>-app` – Go-Weboberfläche mit API
- `ghcr.io/<OWNER>/<REPO>-certbot` – Certbot-Worker mit DNS-Cloudflare-Plugin und den eingebauten Skripten

Das Suffix wird an den **GitHub-Reponamen** angehängt. Bei `firma/ucng-certmanager`
sind das z. B. `ghcr.io/firma/ucng-certmanager-app` und
`ghcr.io/firma/ucng-certmanager-certbot`.

### Auslöser / Tags

| Auslöser | Aktion | Tags |
|---|---|---|
| Pull Request | Beide Images bauen, Tests ausführen, **kein Push** | – |
| Push auf `main` / `master` | Tests, Build und Push beider Images | `latest`, Branchname, `sha-<commit>` |
| Git-Tag `v1.2.3` | Tests, Build und Push beider Images | `1.2.3`, `1.2`, `sha-<commit>` |
| GitHub Actions → `Run workflow` | Tests, Build und Push (ausgewählter Ref) | Ref-abhängig |

Beide Images werden für `linux/amd64` und `linux/arm64` gebaut. GitHub Actions
benutzt den automatisch bereitgestellten `GITHUB_TOKEN`; ein eigener Registry-Token
wird nicht benötigt. Das Workflow-Job-Recht `packages: write` erlaubt das
Veröffentlichen. Für Repository- bzw. Organisationsregeln muss das Veröffentlichen
von Packages ggf. separat erlaubt werden. Bei privaten Packages müssen sich
Deployments vor dem Pull bei GHCR anmelden; bei öffentlichen Packages ist das
nicht erforderlich.

### Release bauen

```bash
git tag v3.1.0
git push origin v3.1.0
```

Die Images werden anschließend als `:3.1.0` veröffentlicht. Ein Commit auf `main`
aktualisiert dagegen `:latest` (Achtung: sich ändernder Tag). Für produktive
Deployments lieber die Versionsnummer oder den Image-Digest verwenden.

### Mit veröffentlichten Images starten

Nach dem ersten erfolgreichen Workflow-Lauf z. B. folgende Variablen in `.env`
eintragen (Owner und Repo-Namen durch die tatsächlichen, kleingeschriebenen
Namen ersetzen):

```dotenv
CERTMANAGER_IMAGE=ghcr.io/firma/ucng-certmanager-app:3.1.0
CERTBOT_IMAGE=ghcr.io/firma/ucng-certmanager-certbot:3.1.0
```

Anschließend:

```bash
docker compose --profile acme pull
docker compose --profile acme up -d --no-build
```

Für **lokale Builds** die beiden `*_IMAGE`-Variablen weglassen und stattdessen
`docker compose --profile acme up -d --build` aufrufen. Das normale Compose-Setup
bleibt so unverändert benutzbar. Die Images enthalten **keine** `.env`, Tokens,
ACME-Zugangsdaten oder private Schlüssel; diese kommen erst beim Deployment über
Environment/Volumes hinzu. Für das Deployment mit Compose sind die lokal
bereitgestellten `certbot-credentials/`, `acme-ca/`, `acme-hooks/` und `roots/`
Verzeichnisse ggf. weiterhin notwendig.

**Wichtig:** GHCR veröffentlicht Container-Images, deployt sie aber nicht und
führt keine ACME-Zertifikatsausstellung durch. Dafür bleibt die laufende
Certbot-Worker-Instanz mit ihren DNS-01-Credentials zuständig.
