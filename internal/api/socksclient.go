package api

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

// socks5Connect performs a SOCKS5 CONNECT to the given target through
// the SOCKS5 proxy at proxyAddr. Returns the connected TCP connection.
func socks5Connect(ctx context.Context, proxyAddr, targetHost string, targetPort int) (net.Conn, error) {
	d := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("socks5 dial proxy: %w", err)
	}

	// SOCKS5 handshake: no auth (0x05 version, 0x01 number of methods, 0x00 no auth)
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5 handshake write: %w", err)
	}
	var buf [2]byte
	if _, err := io.ReadFull(conn, buf[:]); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5 handshake read: %w", err)
	}
	if buf[0] != 0x05 || buf[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("socks5 handshake rejected: method=%d", buf[1])
	}

	// CONNECT request (domain name type: 0x03)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(targetPort))
	req := append([]byte{0x05, 0x01, 0x00, 0x03, byte(len(targetHost))}, []byte(targetHost)...)
	req = append(req, portBytes...)
	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5 connect write: %w", err)
	}

	// Read response header (first 4 bytes: version, reply, reserved, address type)
	resp := make([]byte, 4)
	if _, err := io.ReadFull(conn, resp); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5 connect response header: %w", err)
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("socks5 connect rejected: reply_code=%d", resp[1])
	}

	// Read remaining response based on address type
	addrType := resp[3]
	switch addrType {
	case 0x01: // IPv4 – 4 bytes addr + 2 bytes port
		extra := make([]byte, 6)
		if _, err := io.ReadFull(conn, extra); err != nil {
			conn.Close()
			return nil, fmt.Errorf("socks5 read ipv4 addr: %w", err)
		}
	case 0x03: // Domain name – 1 byte len + N bytes name + 2 bytes port
		var dlen [1]byte
		if _, err := io.ReadFull(conn, dlen[:]); err != nil {
			conn.Close()
			return nil, fmt.Errorf("socks5 read domain len: %w", err)
		}
		extra := make([]byte, int(dlen[0])+2)
		if _, err := io.ReadFull(conn, extra); err != nil {
			conn.Close()
			return nil, fmt.Errorf("socks5 read domain addr: %w", err)
		}
	case 0x04: // IPv6 – 16 bytes addr + 2 bytes port
		extra := make([]byte, 18)
		if _, err := io.ReadFull(conn, extra); err != nil {
			conn.Close()
			return nil, fmt.Errorf("socks5 read ipv6 addr: %w", err)
		}
	default:
		conn.Close()
		return nil, fmt.Errorf("socks5 unsupported address type: %d", addrType)
	}

	return conn, nil
}
