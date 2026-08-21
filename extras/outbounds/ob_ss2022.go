package outbounds

import (
	"errors"
	"fmt"
	"net"
	"slices"

	shadowsocks "github.com/sagernet/sing-shadowsocks"
	"github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// shadowsocks2022Outbound connects to the target through a Shadowsocks 2022 server.
// Both TCP and UDP carry the user identity in-band (multi-user "serverPSK:userPSK"),
// so one server port serves all users. Ignores ResolveInfo, sends Host as-is.
type shadowsocks2022Outbound struct {
	Dialer *net.Dialer
	Addr   string
	Method shadowsocks.Method
}

func NewShadowsocks2022Outbound(addr, method, password string) (PluggableOutbound, error) {
	if addr == "" {
		return nil, errors.New("empty Shadowsocks 2022 address")
	}
	// Unknown/empty ciphers do not fail in NewWithPassword - they yield a half-built
	// Method that only panics later, on the first connection.
	if !slices.Contains(shadowaead_2022.List, method) {
		return nil, fmt.Errorf("unsupported Shadowsocks 2022 method: %q", method)
	}
	m, err := shadowaead_2022.NewWithPassword(method, password, nil)
	if err != nil {
		return nil, err
	}
	return &shadowsocks2022Outbound{
		Dialer: &net.Dialer{
			Timeout: defaultDialerTimeout,
		},
		Addr:   addr,
		Method: m,
	}, nil
}

func (o *shadowsocks2022Outbound) TCP(reqAddr *AddrEx) (net.Conn, error) {
	conn, err := o.Dialer.Dial("tcp", o.Addr)
	if err != nil {
		return nil, err
	}
	sConn, err := o.Method.DialConn(conn, M.ParseSocksaddrHostPort(reqAddr.Host, reqAddr.Port))
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return sConn, nil
}

func (o *shadowsocks2022Outbound) CheckUDP(reqAddr *AddrEx) error {
	return nil
}

func (o *shadowsocks2022Outbound) UDP(reqAddr *AddrEx) (UDPConn, error) {
	conn, err := o.Dialer.Dial("udp", o.Addr)
	if err != nil {
		return nil, err
	}
	return &shadowsocks2022UDPConn{conn: o.Method.DialPacketConn(conn)}, nil
}

type shadowsocks2022UDPConn struct {
	conn N.NetPacketConn
}

func (c *shadowsocks2022UDPConn) ReadFrom(b []byte) (int, *AddrEx, error) {
	n, addr, err := c.conn.ReadFrom(b)
	if err != nil {
		return 0, nil, err
	}
	sAddr := M.SocksaddrFromNet(addr)
	return n, &AddrEx{Host: sAddr.AddrString(), Port: sAddr.Port}, nil
}

func (c *shadowsocks2022UDPConn) WriteTo(b []byte, addr *AddrEx) (int, error) {
	return c.conn.WriteTo(b, M.ParseSocksaddrHostPort(addr.Host, addr.Port))
}

func (c *shadowsocks2022UDPConn) Close() error {
	return c.conn.Close()
}
