# UCNG Certificate Manager v3.1.2 – manueller Browser-Upload

- Uploadformular pro Zertifikat: privater PEM-Schlüssel, Leaf-Zertifikat, mehrere Intermediates und optionale Root CA.
- `.crt`, `.cer`, `.der` und `.pem` für X.509-Zertifikate, PEM-Fullchains sowie RSA/EC/PKCS#8-Private Keys in unverschlüsseltem PEM.
- Nach erfolgreich geprüftem Upload direkte Konvertierung durch die vorhandene Go/OpenSSL-Pipeline und Veröffentlichung als verschlüsselte Version im Vault. Keine neuen Daten-Volumes oder Upload-Mounts erforderlich.
- Upload nur mit Administrator-Session, Same-Origin-Prüfung und CSRF; Limit 12 MiB gesamt und 4 MiB pro Datei. Upload-Daten werden ohne persistente Klartext-Uploads verarbeitet; Scratch liegt unter Docker auf tmpfs.
- Manuell hochgeladene Zertifikate bekommen im bestehenden Katalog `source: manual`, damit der Legacy-Importer sie nicht später überschreibt. ACME-betreute Zertifikate bleiben durch ihren Worker verwaltet; Profilwechsel weiterhin im Webinterface.
- Neue Integrationstests für Browser-Upload, DER, PEM-Fullchain, Formate, SANs, abweichende Schlüssel, Login, CSRF, übergroße Dateien sowie Schutz vor Legacy-Overwrite.
- Vorhandene `.env`, Master-Key, Volumes, Dienste, API-Tokens, Certbot-Profile und GHCR-Workflow bleiben kompatibel.

**Hinweis:** Der private Schlüssel muss derzeit als **unverschlüsseltes PEM** vorliegen; er wird weder öffentlich ausgeliefert noch unverschlüsselt dauerhaft gespeichert. In der Dokumentation ist HTTPS für den Web-Upload verpflichtend beschrieben.
