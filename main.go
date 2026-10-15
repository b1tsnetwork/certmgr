package main

import (
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:8080", "HTTP-Listen-Adresse (für externen Zugriff TLS-Reverse-Proxy verwenden)")
	data := flag.String("data", "./data/state.json", "Datei für die persistente JSON-Datenbank")
	flag.Parse()
	app, err := newApp(filepath.Clean(*data), os.Getenv("ADMIN_PASSWORD"))
	if err != nil {
		log.Fatalf("Start nicht möglich: %v", err)
	}
	app.acmeCatalogPath = os.Getenv("ACME_CATALOG_PATH")
	app.acmeStatusPath = os.Getenv("ACME_STATUS_PATH")
	app.acmeEnabled = os.Getenv("ACME_ENABLED") == "true"
	app.handoffPath = os.Getenv("CERTWATCH_HANDOFF_PATH")
	app.privateExportEnabled = os.Getenv("CERTWATCH_PRIVATE_EXPORT_ENABLED") == "true"
	// Key must be persisted outside the app data volume, e.g. a Docker secret.
	// If absent, existing manual certificates stay registered but cannot be decrypted.
	keyStr := strings.TrimSpace(os.Getenv("CERTWATCH_VAULT_KEY"))
	if file := os.Getenv("CERTWATCH_VAULT_KEY_FILE"); file != "" {
		if keyStr != "" {
			log.Fatal("CERTWATCH_VAULT_KEY und CERTWATCH_VAULT_KEY_FILE nicht gleichzeitig setzen")
		}
		b, err := os.ReadFile(file)
		if err != nil {
			log.Fatalf("Vault-Key-Datei: %v", err)
		}
		keyStr = strings.TrimSpace(string(b))
	}
	if keyStr != "" {
		key, err := base64.StdEncoding.DecodeString(keyStr)
		if err != nil || len(key) != 32 {
			log.Fatal("CERTWATCH_VAULT_KEY muss exakt 32 Byte Base64-kodiert enthalten")
		}
		app.manualVault, err = newVault(filepath.Dir(*data), key)
		if err != nil {
			log.Fatalf("Vault konnte nicht geöffnet werden: %v", err)
		}
	}
	app.mu.Lock()
	if err := app.exportACMECatalogLocked(); err != nil {
		log.Fatalf("ACME-Katalog nicht schreibbar: %v", err)
	}
	app.mu.Unlock()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go app.scheduler(ctx)
	server := &http.Server{Addr: *listen, Handler: app.routes(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 90 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 1 << 20}
	go func() {
		log.Printf("CertWatch auf http://%s gestartet (Daten: %s)", *listen, *data)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("HTTP-Serverfehler: %v", err)
			stop()
		}
	}()
	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("Shutdown: %v", err)
	}
}
