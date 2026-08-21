package outbounds

import (
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func ss2022TestPSK(t *testing.T) string {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(key)
}

func TestShadowsocks2022OutboundMultiUserPassword(t *testing.T) {
	password := ss2022TestPSK(t) + ":" + ss2022TestPSK(t)
	ob, err := NewShadowsocks2022Outbound("127.0.0.1:39000", "2022-blake3-aes-256-gcm", password)
	if err != nil {
		t.Fatal(err)
	}
	ss, ok := ob.(*shadowsocks2022Outbound)
	if !ok {
		t.Fatalf("outbound type = %T, want *shadowsocks2022Outbound", ob)
	}
	if ss.Addr != "127.0.0.1:39000" {
		t.Fatalf("Addr = %q, want 127.0.0.1:39000", ss.Addr)
	}
	if ss.Method.Name() != "2022-blake3-aes-256-gcm" {
		t.Fatalf("method = %q, want 2022-blake3-aes-256-gcm", ss.Method.Name())
	}
}

func TestShadowsocks2022OutboundRejectsBadConfig(t *testing.T) {
	psk := ss2022TestPSK(t)
	for _, tc := range []struct {
		name             string
		addr             string
		method, password string
	}{
		{"empty method", "127.0.0.1:39000", "", psk},
		{"unknown method", "127.0.0.1:39000", "aes-256-gcm", psk},
		{"empty addr", "", "2022-blake3-aes-256-gcm", psk},
		{"empty password", "127.0.0.1:39000", "2022-blake3-aes-256-gcm", ""},
		// chacha has no multi-user form, so "serverPSK:userPSK" must not build
		{"multi-user chacha", "127.0.0.1:39000", "2022-blake3-chacha20-poly1305", psk + ":" + psk},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewShadowsocks2022Outbound(tc.addr, tc.method, tc.password); err == nil {
				t.Fatal("expected an error, got none")
			}
		})
	}
}
