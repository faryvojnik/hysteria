package cmd

import (
	"bufio"
	"bytes"
	"errors"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	utls "github.com/refraction-networking/utls"
	"go.uber.org/zap"

	"github.com/apernet/hysteria/extras/v2/outbounds"
	"github.com/apernet/hysteria/extras/v2/sniff"
)

const (
	funnelFallbackWarnEvery = time.Minute
	fallbackSniffTimeout    = 300 * time.Millisecond
	fallbackSniffMaxBytes   = 16 * 1024
)

var (
	errBitTorrent = errors.New("bittorrent blocked")
	// btHandshake opens every plaintext BitTorrent peer connection (BEP 3).
	btHandshake = []byte("\x13BitTorrent protocol")
)

// funnelFallback: a stream whose xray funnel can't be dialed goes to the general outbound, where the
// exit's xray blocks are replicated (jn-block via the ACL, bittorrent by first bytes below).
// One instance serves every entry: they all dial the same funnel inbound.
type funnelFallback struct {
	fallback outbounds.PluggableOutbound // Resolver(ACL(...)), for targets the client sent as a domain
	// routeOnly is the ACL without the resolver: a sniffed name picks the rule, the client's IP is dialed,
	// like xray's routeOnly sniffing.
	routeOnly outbounds.PluggableOutbound
	// down: set by a TCP dial error or a refused UDP funnel socket, cleared by the next good TCP dial.
	// A UDP funnel dial never fails (connectionless), so UDP sessions follow this flag instead.
	down     atomic.Bool
	lastWarn atomic.Int64
}

func (f *funnelFallback) wrap(funnel outbounds.PluggableOutbound) outbounds.PluggableOutbound {
	return &funnelFallbackOutbound{funnelFallback: f, funnel: funnel}
}

func (f *funnelFallback) markDown(err error) {
	f.down.Store(true)
	now, last := time.Now().UnixNano(), f.lastWarn.Load()
	if now-last >= int64(funnelFallbackWarnEvery) && f.lastWarn.CompareAndSwap(last, now) {
		logger.Warn("user outbound funnel unreachable, falling back to the general outbound", zap.Error(err))
	}
}

// dialTCP dials the fallback; host is the sniffed name of an IP target, "" when there is none.
func (f *funnelFallback) dialTCP(reqAddr *outbounds.AddrEx, host string) (net.Conn, error) {
	ob := f.fallback
	if host != "" {
		reqAddr = &outbounds.AddrEx{Host: host, Port: reqAddr.Port, ResolveInfo: ipResolveInfo(reqAddr.Host)}
		ob = f.routeOnly
	}
	conn, err := ob.TCP(reqAddr)
	if err != nil {
		return nil, err
	}
	return &btGuardConn{Conn: conn}, nil
}

func ipResolveInfo(host string) *outbounds.ResolveInfo {
	ip := net.ParseIP(host)
	if ip4 := ip.To4(); ip4 != nil {
		return &outbounds.ResolveInfo{IPv4: ip4}
	}
	return &outbounds.ResolveInfo{IPv6: ip}
}

func isDialError(err error) bool {
	var opErr *net.OpError
	return errors.As(err, &opErr) && opErr.Op == "dial"
}

type funnelFallbackOutbound struct {
	*funnelFallback
	funnel outbounds.PluggableOutbound
}

func (o *funnelFallbackOutbound) TCP(reqAddr *outbounds.AddrEx) (net.Conn, error) {
	conn, err := o.funnel.TCP(reqAddr)
	if err == nil {
		o.down.Store(false)
		return conn, nil
	}
	if !isDialError(err) {
		return nil, err
	}
	o.markDown(err)
	if net.ParseIP(reqAddr.Host) != nil && (reqAddr.Port == 80 || reqAddr.Port == 443) {
		return newSniffConn(o.funnelFallback, reqAddr), nil
	}
	return o.dialTCP(reqAddr, "")
}

func (o *funnelFallbackOutbound) UDP(reqAddr *outbounds.AddrEx) (outbounds.UDPConn, error) {
	if !o.down.Load() {
		conn, err := o.funnel.UDP(reqAddr)
		if err == nil {
			return &funnelUDPConn{UDPConn: conn, f: o.funnelFallback}, nil
		}
		if !isDialError(err) {
			return nil, err
		}
		o.markDown(err)
	}
	conn, err := o.fallback.UDP(reqAddr)
	if err != nil {
		return nil, err
	}
	return &fallbackUDPConn{UDPConn: conn, f: o.funnelFallback}, nil
}

// ponytail: picks by the flag, not by the session's conn: a fallback session still open when the funnel
// recovers gets later destinations unchecked by the ACL; revisit-after: never
func (o *funnelFallbackOutbound) CheckUDP(reqAddr *outbounds.AddrEx) error {
	if o.down.Load() {
		return o.fallback.CheckUDP(reqAddr)
	}
	return o.funnel.CheckUDP(reqAddr)
}

// funnelUDPConn flags the funnel down once its socket reports ICMP port unreachable (xray gone).
type funnelUDPConn struct {
	outbounds.UDPConn
	f *funnelFallback
}

func (c *funnelUDPConn) ReadFrom(b []byte) (int, *outbounds.AddrEx, error) {
	n, addr, err := c.UDPConn.ReadFrom(b)
	c.check(err)
	return n, addr, err
}

func (c *funnelUDPConn) WriteTo(b []byte, addr *outbounds.AddrEx) (int, error) {
	n, err := c.UDPConn.WriteTo(b, addr)
	c.check(err)
	return n, err
}

func (c *funnelUDPConn) check(err error) {
	if errors.Is(err, syscall.ECONNREFUSED) {
		c.f.markDown(err)
	}
}

// sniffConn holds the dial of a fallback stream to an IP on 80/443 until the client's first bytes name
// the host (TLS SNI / HTTP Host) or fallbackSniffTimeout passes, so the jn-block ACL can match it.
type sniffConn struct {
	f       *funnelFallback
	reqAddr *outbounds.AddrEx
	timer   *time.Timer
	ready   chan struct{} // closed after the dial and the replay; err is final from then on
	err     error

	mu      sync.Mutex // never held across a dial or a write, so Close can always cut a stuck stream
	decided bool
	closed  bool
	pre     []byte
	conn    net.Conn
}

func newSniffConn(f *funnelFallback, reqAddr *outbounds.AddrEx) *sniffConn {
	c := &sniffConn{f: f, reqAddr: reqAddr, ready: make(chan struct{})}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.timer = time.AfterFunc(fallbackSniffTimeout, func() {
		c.mu.Lock()
		if c.decided {
			c.mu.Unlock()
			return
		}
		pre := c.claim()
		c.mu.Unlock()
		c.decide("", pre)
	})
	return c
}

// claim makes the caller the one that decides; c.mu held, c.decided false.
func (c *sniffConn) claim() []byte {
	c.decided = true
	c.timer.Stop()
	pre := c.pre
	c.pre = nil
	return pre
}

// decide dials with what was sniffed and replays the held bytes; called once, without c.mu.
func (c *sniffConn) decide(host string, pre []byte) {
	conn, err := c.f.dialTCP(c.reqAddr, host)
	c.mu.Lock()
	if err == nil && c.closed {
		_ = conn.Close()
		conn, err = nil, net.ErrClosed
	}
	c.conn = conn
	c.mu.Unlock()
	if err == nil && len(pre) > 0 {
		if _, err = conn.Write(pre); err != nil {
			_ = conn.Close()
		}
	}
	c.err = err
	close(c.ready)
}

func (c *sniffConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	if !c.decided {
		c.pre = append(c.pre, b...)
		host, done := sniffHost(c.pre)
		if !done && len(c.pre) < fallbackSniffMaxBytes {
			c.mu.Unlock()
			return len(b), nil
		}
		pre := c.claim()
		c.mu.Unlock()
		if c.decide(host, pre); c.err != nil {
			return 0, c.err
		}
		return len(b), nil
	}
	c.mu.Unlock()
	<-c.ready
	if c.err != nil {
		return 0, c.err
	}
	return c.conn.Write(b)
}

func (c *sniffConn) Read(b []byte) (int, error) {
	<-c.ready
	if c.err != nil {
		return 0, c.err
	}
	return c.conn.Read(b)
}

func (c *sniffConn) Close() error {
	c.mu.Lock()
	c.closed = true
	if !c.decided {
		c.decided = true
		c.timer.Stop()
		c.err = net.ErrClosed
		close(c.ready)
	}
	conn := c.conn
	c.mu.Unlock()
	if conn != nil {
		return conn.Close()
	}
	return nil
}

func (c *sniffConn) LocalAddr() net.Addr {
	if <-c.ready; c.conn != nil {
		return c.conn.LocalAddr()
	}
	return nil
}

func (c *sniffConn) RemoteAddr() net.Addr {
	if <-c.ready; c.conn != nil {
		return c.conn.RemoteAddr()
	}
	return nil
}

func (c *sniffConn) SetDeadline(t time.Time) error {
	if <-c.ready; c.conn != nil {
		return c.conn.SetDeadline(t)
	}
	return c.err
}

func (c *sniffConn) SetReadDeadline(t time.Time) error {
	if <-c.ready; c.conn != nil {
		return c.conn.SetReadDeadline(t)
	}
	return c.err
}

func (c *sniffConn) SetWriteDeadline(t time.Time) error {
	if <-c.ready; c.conn != nil {
		return c.conn.SetWriteDeadline(t)
	}
	return c.err
}

// sniffHost reads the TLS SNI or HTTP Host off a stream's first bytes; done=false wants more bytes.
// Same formats as extras/sniff, which can only read the client stream itself, not bytes already written.
func sniffHost(b []byte) (host string, done bool) {
	if len(b) < 5 {
		return "", false
	}
	if b[0] == 0x16 && b[1] == 0x03 { // TLS handshake record
		n := 5 + (int(b[3])<<8 | int(b[4]))
		if len(b) < n {
			return "", false
		}
		if ch := utls.UnmarshalClientHello(b[5:n]); ch != nil {
			return ch.ServerName, true
		}
		return "", true
	}
	notUpper := func(r rune) bool { return r < 'A' || r > 'Z' }
	if i := bytes.IndexByte(b, ' '); i < 3 || bytes.ContainsFunc(b[:i], notUpper) {
		return "", true // not an HTTP request line
	}
	end := bytes.Index(b, []byte("\r\n\r\n"))
	if end < 0 {
		return "", false
	}
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(b[:end+4])))
	if err != nil {
		return "", true
	}
	if h, _, err := net.SplitHostPort(req.Host); err == nil {
		return h, true
	}
	return req.Host, true
}

// btGuardConn closes a fallback connection whose first client write is a BitTorrent handshake.
// Write comes from one copy goroutine, so checked needs no lock.
type btGuardConn struct {
	net.Conn
	checked bool
}

func (c *btGuardConn) Write(b []byte) (int, error) {
	if !c.checked {
		c.checked = true
		if bytes.HasPrefix(b, btHandshake) {
			_ = c.Conn.Close()
			return 0, errBitTorrent
		}
	}
	return c.Conn.Write(b)
}

// fallbackUDPConn drops uTP connection openers and QUIC Initials whose SNI the ACL rejects.
type fallbackUDPConn struct {
	outbounds.UDPConn
	f *funnelFallback
}

func (c *fallbackUDPConn) WriteTo(b []byte, addr *outbounds.AddrEx) (int, error) {
	if isUTPSyn(b) || c.quicRejected(b, addr) {
		return len(b), nil
	}
	return c.UDPConn.WriteTo(b, addr)
}

func (c *fallbackUDPConn) quicRejected(b []byte, addr *outbounds.AddrEx) bool {
	if addr.Port != 443 || net.ParseIP(addr.Host) == nil {
		return false
	}
	orig := addr.String()
	sniffed := orig
	if (&sniff.Sniffer{}).UDP(b, &sniffed) != nil || sniffed == orig {
		return false
	}
	host, _, _ := net.SplitHostPort(sniffed)
	named := &outbounds.AddrEx{Host: host, Port: addr.Port, ResolveInfo: ipResolveInfo(addr.Host)}
	return c.f.routeOnly.CheckUDP(named) != nil
}

// isUTPSyn matches a uTP ST_SYN (BEP 29): type 4 + version 1, a 20-byte header, then the extension
// chain and no payload. The exact length keeps random first bytes (DNS ids, QUIC) from matching.
func isUTPSyn(b []byte) bool {
	if len(b) < 20 || b[0] != 0x41 {
		return false
	}
	ext, i := b[1], 20
	for ext != 0 {
		if ext != 1 && ext != 2 || i+2 > len(b) {
			return false
		}
		ext, i = b[i], i+2+int(b[i+1])
	}
	return i == len(b)
}
