# CertWatch v2.6 – Systeminventar und Abhängigkeitsansicht

## Neu

- **Systemobjekte** für Server und Applikationen mit Name, optionaler IPv4-/IPv6-Adresse, Beschreibung und sicher validiertem HTTP(S)-Dokumentationslink. Eigene IDs verhindern Probleme beim Umbenennen.
- **Viele-zu-viele-Zuordnungen** zwischen Systemen und Zertifikaten. Ein Zertifikat darf mehreren Systemen zugewiesen sein, jedes System beliebig vielen Zertifikaten.
- **Alle drei Zertifikatstypen:** TLS-Überwachungsziele, ACME-Lineages und manuell importierte Zertifikate. Die Zuordnungen sind für alle einheitlich.
- **Grafische Abhängigkeiten** in beide Richtungen (System → Zertifikate; Zertifikat → Systeme). Fokus und Richtung lassen sich durch Klick auf die Knoten ändern. Funktioniert ohne clientseitiges JavaScript oder automatische Seiten-Reloads.
- **Zuweisung aus mehreren Ansichten:** beim Bearbeiten des Systems; beim Bearbeiten eines TLS-Ziels; auf der separaten Zuordnungsseite eines ACME-, manuellen oder TLS-Zertifikats.
- **Rollen:** Viewer dürfen Inventar und Graph lesen. Editor/Admin dürfen Systeme und Zuordnungen bearbeiten.
- **Konsistenz:** Beim Löschen eines Zertifikats oder Systems werden dessen Verknüpfungen entfernt, ohne fremde Einträge zu löschen.

## Datenmigration

Beim ersten Start mit dem bisherigen `state.json`-Format (`version: 2`) migriert CertWatch nach `version: 3`. Die bisherigen Freitextwerte unter **Server / Hostsystem** in TLS-Überwachungszielen werden in Systemobjekte des Typs „Server“ umgewandelt und diesen TLS-Zielen zugeordnet. Identische Namen (Groß-/Kleinschreibung ignoriert) werden nur einmal angelegt. Die bisherigen Freitextwerte bleiben zur Nachvollziehbarkeit in der bestehenden JSON-Datei erhalten, sind aber nicht mehr editierbar.

**Vor dem Upgrade unbedingt `state.json` sichern.** Ein Downgrade auf v2.5 kann die neue Datenversion nicht lesen. Alle bisherigen Benutzer, ACME-Profile, Importzertifikate, API-Tokens und Docker-Volumes bleiben bestehen. Das optional aktivierte ACME-Sidecar benötigt keine neue Konfiguration.

## Navigation

- **Systeme:** `/systems` – Übersicht; `/systems/new` – System anlegen.
- **Systemdetails:** `/systems/{id}` – Stammdaten und Liste der verwendeten Zertifikate.
- **Abhängigkeiten:** `/dependencies` – grafische, anklickbare Ansicht; `?system={id}` oder `?certificate=manual:intranet-web` für eine konkrete Perspektive.
- **Zertifikatssicht:** `/dependencies/certificates/{target|acme|manual}/{id}` – Liste verwendender Systeme und Zuweisung per Checkbox.

## Grenzen

Die Grafik zeigt **manuell dokumentierte Zuordnungen**, keine automatisch erkannte tatsächliche Installation eines Zertifikats auf einem Server. Zertifikats- und TLS-Status werden weiterhin durch die bestehenden Prüfungen ermittelt. Systemzuordnungen haben **keinen Einfluss auf Client-API-Tokens**, enthalten keine privaten Schlüssel und führen keine automatischen Deployments aus.

## Verifikation

`go test ./...`, `go test -race ./...` und `go vet ./...` prüfen das neue Datenmodell, Migration, Rollen und Zuordnungen sowie die bisherigen CertWatch-Funktionen. Die Templates wurden auch im Browser gerendert, einschließlich Mobilansicht ohne horizontalen Überlauf. Docker-/GHCR-Builds wurden in der Entwicklungsumgebung nicht ausgeführt.
