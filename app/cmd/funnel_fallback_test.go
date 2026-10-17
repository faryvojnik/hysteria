package cmd

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"

	"github.com/apernet/hysteria/app/v2/internal/utils"
	"github.com/apernet/hysteria/core/v2/server"
	"github.com/apernet/hysteria/extras/v2/outbounds"
	"github.com/apernet/hysteria/extras/v2/outbounds/acl/v2geo"
)

func listenTCP(t *testing.T, addr string) *net.TCPListener {
	t.Helper()
	l, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l.(*net.TCPListener)
}

// closedAddr is a loopback address nothing listens on: the funnel with xray down.
func closedAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return addr
}

// jnBlockGeoSite writes a geosite.dat whose JN-BLOCK holds only full:localhost.
func jnBlockGeoSite(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "geosite.dat")
	bs, err := proto.Marshal(&v2geo.GeoSiteList{Entry: []*v2geo.GeoSite{{
		CountryCode: "JN-BLOCK",
		Domain:      []*v2geo.Domain{{Type: v2geo.Domain_Full, Value: "localhost"}},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, bs, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// testFallback is the exit's fallback chain built by hand: Resolver(ACL(direct)) + the bare ACL.
func testFallback(t *testing.T) *funnelFallback {
	t.Helper()
	acl, err := outbounds.NewACLEngineFromString("reject(geosite:jn-block)",
		[]outbounds.OutboundEntry{{Name: "direct", Outbound: outbounds.NewDirectOutboundSimple(outbounds.DirectOutboundModeAuto)}},
		&utils.GeoLoader{GeoSiteFilename: jnBlockGeoSite(t)})
	if err != nil {
		t.Fatal(err)
	}
	return &funnelFallback{fallback: outbounds.NewSystemResolver(acl), routeOnly: acl}
}

func testSS2022(t *testing.T, addr string) outbounds.PluggableOutbound {
	t.Helper()
	ob, err := outbounds.NewShadowsocks2022Outbound(addr, "2022-blake3-aes-256-gcm", testPSK("server")+":"+testPSK("42"))
	if err != nil {
		t.Fatal(err)
	}
	return ob
}

func addrEx(t *testing.T, addr string) *outbounds.AddrEx {
	t.Helper()
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	return &outbounds.AddrEx{Host: host, Port: uint16(p)}
}

// TestFunnelFallbackTCP drives the config path the exit renders: userOutboundsFile + fallback + jn-block ACL.
func TestFunnelFallbackTCP(t *testing.T) {
	logger = zap.NewNop()
	funnelAddr := closedAddr(t)
	funnelPath := filepath.Join(t.TempDir(), "funnel.json")
	funnelFile(t, funnelPath, funnelAddr, "42")
	c := &serverConfig{
		UserOutboundsFile:         funnelPath,
		UserOutboundsFileFallback: true,
		ACL:                       serverConfigACL{Inline: []string{"reject(geosite:jn-block)"}, GeoSite: jnBlockGeoSite(t)},
	}
	var hy server.Config
	if err := c.fillOutboundConfig(&hy); err != nil {
		t.Fatal(err)
	}
	ob := hy.OutboundForAuthID("42")
	target := listenTCP(t, "127.0.0.1:0").Addr().String()

	conn, err := ob.TCP(target)
	if err != nil {
		t.Fatalf("funnel refused: want the direct fallback, got %v", err)
	}
	if _, err := conn.Write(append(btHandshake, make([]byte, 48)...)); !errors.Is(err, errBitTorrent) {
		t.Fatalf("BitTorrent handshake on the fallback: err = %v, want errBitTorrent", err)
	}
	_, port, _ := net.SplitHostPort(target)
	if _, err := ob.TCP(net.JoinHostPort("localhost", port)); err == nil {
		t.Fatal("jn-block domain passed the fallback")
	}
	assertBlocked(t, hy.OutboundForAuthID("999"), "999")

	funnel := listenTCP(t, funnelAddr)
	conn, err = ob.TCP(target)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	_ = funnel.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := funnel.Accept(); err != nil {
		t.Fatalf("funnel back up but not dialed: %v", err)
	}

	if err := (&serverConfig{UserOutboundsFileFallback: true}).fillOutboundConfig(&hy); err == nil {
		t.Fatal("userOutboundsFileFallback without userOutboundsFile accepted")
	}
}

// A funnel that accepts and then drops the connection is xray's answer, not a dead funnel: no fallback.
func TestFunnelFallbackNotOnRemoteFailure(t *testing.T) {
	logger = zap.NewNop()
	funnel := listenTCP(t, "127.0.0.1:0")
	go func() {
		for {
			c, err := funnel.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	target := listenTCP(t, "127.0.0.1:0")
	f := testFallback(t)
	ob := f.wrap(testSS2022(t, funnel.Addr().String()))

	conn, err := ob.TCP(addrEx(t, target.Addr().String()))
	if err == nil {
		_, err = io.ReadAll(conn)
		if err == nil {
			err = io.EOF
		}
		_ = conn.Close()
	}
	if err == nil || f.down.Load() {
		t.Fatalf("funnel accepted then closed: err = %v, down = %v; want an error and no fallback", err, f.down.Load())
	}
	_ = target.SetDeadline(time.Now().Add(300 * time.Millisecond))
	if c, err := target.Accept(); err == nil {
		_ = c.Close()
		t.Fatal("target dialed directly although the funnel answered")
	}
}

// clientHello returns the first TLS record a client sends for serverName.
func clientHello(t *testing.T, serverName string) []byte {
	t.Helper()
	cli, srv := net.Pipe()
	defer srv.Close()
	go func() {
		_ = tls.Client(cli, &tls.Config{ServerName: serverName}).Handshake()
		_ = cli.Close()
	}()
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(srv, hdr); err != nil {
		t.Fatal(err)
	}
	body := make([]byte, int(hdr[3])<<8|int(hdr[4]))
	if _, err := io.ReadFull(srv, body); err != nil {
		t.Fatal(err)
	}
	return append(hdr, body...)
}

// Fallback streams to an IP on 80/443 are routed by the sniffed name and dialed at the client's IP.
func TestFunnelFallbackSniffTCP(t *testing.T) {
	logger = zap.NewNop()
	f := testFallback(t)
	target := listenTCP(t, "127.0.0.1:0")
	reqAddr := addrEx(t, target.Addr().String())

	// Split across two writes: the dial waits for the whole ClientHello.
	blocked := clientHello(t, "localhost")
	c := newSniffConn(f, reqAddr)
	if _, err := c.Write(blocked[:10]); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(blocked[10:]); err == nil {
		t.Fatal("ClientHello for a jn-block name passed the fallback")
	}
	_ = c.Close()

	allowed := clientHello(t, "example.test")
	c = newSniffConn(f, reqAddr)
	if _, err := c.Write(allowed); err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = target.SetDeadline(time.Now().Add(2 * time.Second))
	got, err := target.Accept()
	if err != nil {
		t.Fatalf("allowed name not dialed at the client's IP: %v", err)
	}
	defer got.Close()
	buf := make([]byte, len(allowed))
	_ = got.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(got, buf); err != nil || string(buf) != string(allowed) {
		t.Fatalf("held ClientHello not replayed: %v", err)
	}

	// Nothing sniffable within the timeout: dial the IP as is.
	c = newSniffConn(f, reqAddr)
	defer c.Close()
	if c.RemoteAddr() == nil {
		t.Fatal("silent stream not dialed after the sniff timeout")
	}
}

// pipeOutbound hands out one end of a net.Pipe: a remote that never reads stalls every write.
type pipeOutbound struct{ conn net.Conn }

func (o pipeOutbound) TCP(*outbounds.AddrEx) (net.Conn, error)          { return o.conn, nil }
func (o pipeOutbound) UDP(*outbounds.AddrEx) (outbounds.UDPConn, error) { return nil, io.EOF }
func (o pipeOutbound) CheckUDP(*outbounds.AddrEx) error                 { return nil }

// The core closes a stream whose Write is stuck on a remote that never reads; Close must not wait for it.
func TestSniffConnCloseUnblocksWrite(t *testing.T) {
	cli, srv := net.Pipe()
	defer srv.Close()
	ob := pipeOutbound{cli}
	c := newSniffConn(&funnelFallback{fallback: ob, routeOnly: ob}, &outbounds.AddrEx{Host: "192.0.2.1", Port: 443})
	if c.RemoteAddr() == nil { // decided by the sniff timeout
		t.Fatal("not dialed")
	}
	wrote := make(chan error, 1)
	go func() { _, err := c.Write([]byte("x")); wrote <- err }()
	time.Sleep(50 * time.Millisecond)
	closed := make(chan struct{})
	go func() { _ = c.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("Close blocked behind a stuck Write")
	}
	select {
	case <-wrote:
	case <-time.After(2 * time.Second):
		t.Fatal("stuck Write not released by Close")
	}
}

func TestSniffHost(t *testing.T) {
	for _, tc := range []struct {
		b    string
		host string
		done bool
	}{
		{"GET / HTTP/1.1\r\nHost: localhost:80\r\n\r\n", "localhost", true},
		{"GET / HTTP/1.1\r\nHost: local", "", false},
		{"SSH-2.0-OpenSSH\r\n", "", true},
		{"\x16\x03\x01\x02", "", false},
	} {
		if host, done := sniffHost([]byte(tc.b)); host != tc.host || done != tc.done {
			t.Errorf("sniffHost(%q) = %q, %v; want %q, %v", tc.b, host, done, tc.host, tc.done)
		}
	}
}

func TestFunnelFallbackUDP(t *testing.T) {
	logger = zap.NewNop()
	funnelAddr := closedAddr(t)
	f := testFallback(t)
	ob := f.wrap(testSS2022(t, funnelAddr))
	target, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	tAddr := addrEx(t, target.LocalAddr().String())

	// The funnel UDP socket opens with xray down; the refusal only surfaces on use.
	conn, err := ob.UDP(tAddr)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := conn.(*funnelUDPConn); !ok {
		t.Fatalf("funnel up: UDP conn = %T, want the funnel", conn)
	}
	_, _ = conn.WriteTo([]byte("x"), tAddr)
	done := make(chan error, 1)
	go func() { _, _, err := conn.ReadFrom(make([]byte, 2048)); done <- err }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("no ECONNREFUSED from the dead funnel")
	}
	_ = conn.Close()
	if !f.down.Load() {
		t.Fatal("refused funnel UDP did not flag the funnel down")
	}

	conn, err = ob.UDP(tAddr)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := conn.(*fallbackUDPConn); !ok {
		t.Fatalf("funnel down: UDP conn = %T, want the fallback", conn)
	}
	syn := make([]byte, 20)
	syn[0] = 0x41
	_, _ = conn.WriteTo(syn, tAddr)
	_, _ = conn.WriteTo([]byte("hello"), tAddr)
	_ = target.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	n, _, err := target.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "hello" {
		t.Fatalf("first datagram at target = %q, %v; want hello (uTP SYN dropped)", buf[:n], err)
	}
	_ = conn.Close()

	listenTCP(t, funnelAddr)
	tc, err := ob.TCP(tAddr)
	if err != nil {
		t.Fatal(err)
	}
	_ = tc.Close()
	if f.down.Load() {
		t.Fatal("good TCP funnel dial did not clear the flag")
	}
}

// recordUDPConn records what reaches the real socket.
type recordUDPConn struct{ sent int }

func (c *recordUDPConn) ReadFrom([]byte) (int, *outbounds.AddrEx, error) { return 0, nil, io.EOF }
func (c *recordUDPConn) WriteTo(b []byte, _ *outbounds.AddrEx) (int, error) {
	c.sent++
	return len(b), nil
}
func (c *recordUDPConn) Close() error { return nil }

// quicInitial captures the first datagram a QUIC client sends for serverName. X25519 only: a post-quantum
// key share spreads the ClientHello over two Initials, which the sniffer (like upstream's) can't read.
func quicInitial(t *testing.T, serverName string) []byte {
	t.Helper()
	l, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_, _ = quic.DialAddr(ctx, l.LocalAddr().String(), &tls.Config{
			ServerName: serverName, NextProtos: []string{"h3"}, CurvePreferences: []tls.CurveID{tls.X25519},
		}, nil)
	}()
	_ = l.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 2048)
	n, _, err := l.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	return buf[:n]
}

func TestFunnelFallbackSniffQUIC(t *testing.T) {
	f := testFallback(t)
	rec := &recordUDPConn{}
	c := &fallbackUDPConn{UDPConn: rec, f: f}
	dst := &outbounds.AddrEx{Host: "192.0.2.1", Port: 443}
	_, _ = c.WriteTo(quicInitial(t, "localhost"), dst)
	if rec.sent != 0 {
		t.Fatal("QUIC Initial for a jn-block name passed the fallback")
	}
	_, _ = c.WriteTo(quicInitial(t, "example.test"), dst)
	if rec.sent != 1 {
		t.Fatal("QUIC Initial for an allowed name dropped")
	}
}

func TestIsUTPSyn(t *testing.T) {
	syn := make([]byte, 20)
	syn[0] = 0x41
	withExt := append(append([]byte{}, syn...), 0, 4, 1, 2, 3, 4)
	withExt[1] = 1
	for _, tc := range []struct {
		b    []byte
		want bool
	}{
		{syn, true},
		{withExt, true},
		{append(append([]byte{}, syn...), 'x'), false}, // payload: not a SYN
		{withExt[:len(withExt)-1], false},              // truncated extension
		{[]byte("hello"), false},
		{append([]byte{0x01}, syn[1:]...), false}, // ST_DATA
	} {
		if got := isUTPSyn(tc.b); got != tc.want {
			t.Errorf("isUTPSyn(%x) = %v, want %v", tc.b, got, tc.want)
		}
	}
}
