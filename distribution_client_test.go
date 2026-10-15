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
	"time"
)

// End-to-end test against an actual HTTPS listener and real curl/openssl client.
func TestShellDistributionClientHTTPS(t *testing.T) {
	for _, binary := range []string{"curl", "openssl", "python3", "sh"} {
		if _, err := exec.LookPath(binary); err != nil {
			t.Skipf("%s missing", binary)
		}
	}
	app, cert, key, _ := setupDistributionTest(t)
	createAPIKeyForTest(t, app, "cw_client_test", true, time.Now().Add(time.Hour))
	server := httptest.NewTLSServer(app.routes())
	defer server.Close()
	work := t.TempDir()
	ca := filepath.Join(work, "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(work, "dest")
	args := []string{"clients/certwatch-fetch.sh", server.URL, "internal", "test", output, "--private"}
	cmd := exec.Command("sh", args...)
	cmd.Dir = "."
	cmd.Env = append(os.Environ(), "CERTWATCH_API_TOKEN=cw_client_test", "CURL_CA_BUNDLE="+ca)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("client failed: %v\n%s", err, out)
	}
	for file, want := range map[string][]byte{"cert.pem": cert, "fullchain.pem": cert, "privkey.pem": key} {
		got, err := os.ReadFile(filepath.Join(output, file))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s mismatch", file)
		}
	}
	cmd = exec.Command("sh", args...)
	cmd.Env = append(os.Environ(), "CERTWATCH_API_TOKEN=cw_client_test", "CURL_CA_BUNDLE="+ca)
	out, err = cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "Unverändert") {
		t.Fatalf("second run err=%v output=%s", err, out)
	}
}
