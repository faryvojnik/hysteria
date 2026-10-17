package cmd

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/apernet/hysteria/core/v2/server"
	"go.uber.org/zap"
)

// testPSK — a valid 32-byte ss2022 key, deterministic per seed.
func testPSK(seed string) string {
	key := sha256.Sum256([]byte(seed))
	return base64.StdEncoding.EncodeToString(key[:])
}

// funnelFile writes a userOutboundsFile-shaped doc with one entry per authID.
func funnelFile(t *testing.T, path, addr string, authIDs ...string) {
	t.Helper()
	entries := ""
	for i, id := range authIDs {
		if i > 0 {
			entries += ","
		}
		entries += fmt.Sprintf(`%q:{"type":"shadowsocks2022","addr":%q,`+
			`"method":"2022-blake3-aes-256-gcm","password":"%s:%s"}`, id, addr, testPSK("server"), testPSK(id))
	}
	if err := os.WriteFile(path, []byte(`{"outbounds":{`+entries+`}}`), 0o644); err != nil {
		t.Fatal(err)
	}
}

func assertBlocked(t *testing.T, ob server.Outbound, authID string) {
	t.Helper()
	if ob != rejectOutbound {
		t.Fatalf("authID %q: outbound = %v, want reject", authID, ob)
	}
}

func TestUserOutboundsFile(t *testing.T) {
	logger = zap.NewNop()
	path := filepath.Join(t.TempDir(), "funnel.json")
	funnelFile(t, path, "127.0.0.1:39000", "42", "43")
	f := &userOutboundsFile{path: path}

	for _, id := range []string{"42", "43"} {
		if ob := f.outboundFor(id); ob == nil || ob == rejectOutbound {
			t.Fatalf("authID %q: outbound = %v, want a real outbound", id, ob)
		}
	}
	// Absent from an otherwise healthy file is blocked too - no fallback to the general outbound.
	assertBlocked(t, f.outboundFor("999"), "999")

	// A new subscriber is picked up on the rewrite, without a restart.
	funnelFile(t, path, "127.0.0.1:39000", "42", "43", "999")
	if ob := f.outboundFor("999"); ob == rejectOutbound {
		t.Fatal("authID 999 still blocked after the file gained it")
	}
}

func TestUserOutboundsFileFailsClosed(t *testing.T) {
	logger = zap.NewNop()
	dir := t.TempDir()
	for _, tc := range []struct {
		name    string
		content string
	}{
		{"malformed json", `{"outbounds":`},
		{"unknown entry type", `{"outbounds":{"42":{"type":"socks5","addr":"127.0.0.1:1080"}}}`},
		{"bad entry method", `{"outbounds":{"42":{"type":"shadowsocks2022","addr":"127.0.0.1:39000","method":"aes-256-gcm","password":"x"}}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, tc.name+".json")
			if err := os.WriteFile(path, []byte(tc.content), 0o644); err != nil {
				t.Fatal(err)
			}
			f := &userOutboundsFile{path: path}
			assertBlocked(t, f.outboundFor("42"), "42")
		})
	}

	f := &userOutboundsFile{path: filepath.Join(dir, "missing.json")}
	assertBlocked(t, f.outboundFor("42"), "42")
}

func TestUserOutboundsFileConflictsWithUserOutbounds(t *testing.T) {
	c := &serverConfig{
		UserOutbounds:     map[string]string{"42": "default"},
		UserOutboundsFile: "funnel.json",
	}
	err := c.fillOutboundConfig(&server.Config{})
	cErr, ok := err.(configError)
	if !ok || cErr.Field != "userOutboundsFile" {
		t.Fatalf("err = %v, want configError{Field: userOutboundsFile}", err)
	}
}
