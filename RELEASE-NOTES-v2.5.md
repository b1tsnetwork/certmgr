# CertWatch v2.5 – Browser-Downloads & Multi-Certificate API

- Neuer Menüpunkt **Zertifikate herunterladen** für Admin, Editor und Viewer, **ohne API-Token**. Interaktive Auswahl, Version, öffentliche und vertrauliche Formate, direkte Datei-Downloads.
- Vertrauliche Zertifikatsschlüssel und PFX/P12-Dateien sind bewusst auch für Viewer zugänglich. WebUI ausschließlich über HTTPS und mit vertrauenswürdigen Benutzern verwenden.
- ACME-PEM-Zertifikate werden bei vorhandenem `CERTWATCH_VAULT_KEY` in das vollständige Formatset konvertiert; generierte Formate werden **verschlüsselt und versionsweise** in einem separaten Cache gespeichert. Die vier ursprünglichen PEM-Dateien bleiben immer verfügbar.
- Admin kann einen API-Token für **bis zu 50 Zertifikate** anlegen. Authentifizierung und Berechtigung bleiben je Zertifikat und Public/Private geprüft.
- Vorhandene Einzelzertifikat-Tokens funktionieren ohne Migration weiter.
- Entfernte/deaktivierte/umgehängte Lineages verlieren gezielt ihren Token-Scope; andere Token-Scopes bleiben bestehen.
- Normale ACME-Erneuerung und neuer Private Key erfordern **keine neuen API-Tokens**. Das Manifest liefert die jeweils neueste Version; versionierte Download-Endpunkte verhindern Mischungen zwischen Releases.
- Tests für Login/Viewer, private Formate, URL-Sicherheit, altes Tokenformat, Mehrfach-Token, Token-Revoke, Cert-Key-Rotation sowie verschlüsselte ACME-Konvertierung.

**Hinweis:** ACME-PFX-Konvertierung erfordert den bereits aus v2.4 bekannten Vault-Key und OpenSSL. Die ursprüngliche TLS-Überwachung und der optionale Sidecar bleiben unverändert.
