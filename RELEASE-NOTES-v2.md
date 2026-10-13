# UCNG Certificate Manager · Release 2

## Neu

- Beliebig viele Zertifikate über `/admin` registrieren, deaktivieren, bearbeiten und entfernen.
- Pro Zertifikat beliebig viele Dienste verwalten, einschließlich Host, Umgebung, Produkttyp und Freitextnotiz.
- Ausgabeformate über gruppierte Checkboxen je Dienst einzeln auswählen.
- Dienst-Tokens, die nur auf den jeweiligen Dienst und dessen freigegebene Dateien zugreifen dürfen.
- Dienst-Manifeste mit versionierten Download-URLs und SHA256-Prüfsummen.
- PowerShell-Client mit `-ServiceID` und generischem `-Target Files` zum Export der ausgewählten Formate.
- Persistenter CMS-Katalog `/data/catalog.json` mit Übernahme bestehender CERT_NAMES / CERT_SAN_RULES beim ersten Start.

## Achtung beim Upgrade

1. `/data`, `MASTER_KEY_FILE`, Certbot-/Handoff-Volumes sichern.
2. Neue Anwendung mit demselben Datenspeicher und Master-Key starten.
3. Ersteinmalig wird der bestehende Satz aus `CERT_NAMES` / `CERT_SAN_RULES` in `catalog.json` übernommen.
4. Neue Zertifikate anschließend in der Oberfläche anlegen; die Zertifikatsausstellung mittels Certbot/DNS-01 bleibt ein separater Schritt.
5. Für jeden Dienst ein separates Secret-/Token-Paar erzeugen und den PowerShell-Client mit `-ServiceID` ausführen.
6. Vor einer produktiven Nutzung IIS-/Apache-Rollout und Security-Härtung im Staging testen.

Die vollständige Dokumentation inklusive API-Beispiele steht in `README.md`.
