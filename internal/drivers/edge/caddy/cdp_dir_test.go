package caddy

// cdp_dir_test.go covers the M-A5/M-A6 helpers: the cdp directory signature and
// the Caddyfile admin-address reader that feeds the opt-in --probe upgrade. The
// reader must return only what the file (or Caddy's documented default) declares
// — never a guess — and name WHY a config is unprobeable (admin off, unix socket).

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSniffCDPDir(t *testing.T) {
	dir := t.TempDir()
	if SniffCDPDir(dir) {
		t.Error("empty dir must not match the cdp signature")
	}
	if err := os.WriteFile(filepath.Join(dir, "Caddyfile.autosave"), []byte("a.example.com {\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !SniffCDPDir(dir) {
		t.Error("dir with Caddyfile.autosave must match")
	}
	if CDPAutosavePath(dir) != filepath.Join(dir, "Caddyfile.autosave") {
		t.Error("CDPAutosavePath must point at the autosave file")
	}
	// The signature is a REGULAR file, not a subdirectory of that name.
	sub := t.TempDir()
	if err := os.Mkdir(filepath.Join(sub, "Caddyfile.autosave"), 0o755); err != nil {
		t.Fatal(err)
	}
	if SniffCDPDir(sub) {
		t.Error("a DIRECTORY named Caddyfile.autosave must not match")
	}
}

func TestAdminAddressFromCaddyfile(t *testing.T) {
	cases := []struct {
		name       string
		content    string
		wantURL    string
		wantReason bool
	}{
		{"no global block: documented default", "a.example.com {\n\treverse_proxy 10.0.0.1:80\n}\n", "http://localhost:2019", false},
		{"global block without admin: default", "{\n\temail ops@example.com\n}\na.example.com {\n}\n", "http://localhost:2019", false},
		{"declared host:port", "{\n\tadmin 127.0.0.1:2020\n}\na.example.com {\n}\n", "http://127.0.0.1:2020", false},
		{"declared bare :port", "{\n\tadmin :2021\n}\na.example.com {\n}\n", "http://localhost:2021", false},
		{"declared with scheme", "{\n\tadmin http://10.0.0.9:2019\n}\na.example.com {\n}\n", "http://10.0.0.9:2019", false},
		{"admin off: unprobeable, named", "{\n\tadmin off\n}\na.example.com {\n}\n", "", true},
		{"unix socket: unprobeable, named", "{\n\tadmin unix//run/caddy.sock\n}\na.example.com {\n}\n", "", true},
	}
	for _, tc := range cases {
		url, reason := AdminAddressFromCaddyfile([]byte(tc.content))
		if url != tc.wantURL {
			t.Errorf("%s: url = %q, want %q", tc.name, url, tc.wantURL)
		}
		if (reason != "") != tc.wantReason {
			t.Errorf("%s: reason = %q, wantReason %v", tc.name, reason, tc.wantReason)
		}
	}
}
