package main

import (
	"bytes"
	"encoding/pem"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestManualGenericShellClientHTTPS(t *testing.T) {
	for _, n := range []string{"curl", "python3", "openssl", "sh"} {
		if _, err := exec.LookPath(n); err != nil {
			t.Skipf("%s missing", n)
		}
	}
	app, cert, key := manualFixture(t)
	if result := manualUpload(t, app, cert, key); result.Code != 303 {
		t.Fatalf("upload failed %d", result.Code)
	}
	scopedToken(app, "cw_private_manual", true)
	server := httptest.NewTLSServer(app.routes())
	defer server.Close()
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "received")
	args := []string{"clients/certwatch-fetch-format.sh", server.URL, "manual", "myserver", target, "leaf-only.pfx", "pfx-password.txt", "leaf.der"}
	cmd := exec.Command("sh", args...)
	cmd.Env = append(os.Environ(), "CERTWATCH_API_TOKEN=cw_private_manual", "CURL_CA_BUNDLE="+ca)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("generic shell client: %v output: %s", err, output)
	}
	if !strings.Contains(string(output), "Downloaded") {
		t.Fatalf("missing update: %s", output)
	}
	for _, filename := range []string{"leaf-only.pfx", "pfx-password.txt", "leaf.der"} {
		got, err := os.ReadFile(filepath.Join(target, filename))
		if err != nil {
			t.Fatal(err)
		}
		original, _, err := app.manualRead("myserver", "", filename)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, original) {
			t.Fatalf("format %s did not match", filename)
		}
	}
}
func TestManualHTMLPageRendersAndHasNoRefresh(t *testing.T) {
	app, _, _ := manualFixture(t)
	cookie, _ := manualSession(t, app)
	req := httptest.NewRequest("GET", "/manual", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	app.routes().ServeHTTP(rr, req)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "PFX/P12-Datei") || !strings.Contains(rr.Body.String(), "Manueller Zertifikatsimport") {
		t.Fatalf("page not rendered: %d %s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), `http-equiv="refresh"`) {
		t.Fatal("manual upload form auto refreshes")
	}
}
