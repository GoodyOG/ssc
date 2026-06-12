// Package socks5 implements a local SOCKS5 proxy (RFC 1928 + RFC 1929 USER/PASS).
// The server listens on a TCP port and forwards connections through a custom dialer
// (typically the SSH tunnel's DialTCP function).
package socks5

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"time"
)

const (
	socks5Version = 0x05
	cmdConnect    = 0x01

	addrIPv4   = 0x01
	addrDomain = 0x03
	addrIPv6   = 0x04

	repSuccess         = 0x00
	repGeneralFailure  = 0x01
	repNotAllowed      = 0x02
	repNetUnreachable  = 0x03
	repHostUnreachable = 0x04
	repConnRefused     = 0x05
	repTTLExpired      = 0x06
	repCmdNotSupported = 0x07
	repAddrNotSupported = 0x08

	// Auth methods
	authNone     = 0x00
	authPassword = 0x02
	authNoAcceptable = 0xFF

	// RFC 1929 sub-negotiation
	authVersion = 0x01

	// Deadlines
	handshakeTimeout = 30 * time.Second
)

// Dialer is called by the SOCKS5 server to establish an outbound connection
// through the tunnel.
type Dialer func(ctx context.Context, network, addr string) (net.Conn, error)

// Server is a SOCKS5 proxy that listens on a TCP address and forwards connections
// through a user-provided dialer.
type Server struct {
	addr   string
	dialer Dialer
}

// NewServer creates a SOCKS5 server.
func NewServer(addr string, dialer Dialer) *Server {
	return &Server{addr: addr, dialer: dialer}
}

// Serve listens and accepts connections until the context is canceled.
func (s *Server) Serve(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("socks5 listen %s: %w", s.addr, err)
	}
	log.Printf("[socks5] listening on %s", s.addr)
	go func() { <-ctx.Done(); _ = ln.Close() }()

	for {
		c, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				return fmt.Errorf("socks5 accept: %w", err)
			}
		}
		go s.handle(ctx, c)
	}
}

// Addr returns the server's listening address.
func (s *Server) Addr() string { return s.addr }

func (s *Server) handle(ctx context.Context, c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(handshakeTimeout))

	// RFC 1928: Method negotiation
	target, err := s.handshake(c)
	if err != nil {
		return
	}

	_ = c.SetDeadline(time.Time{})

	// Establish connection through tunnel
	remote, err := s.dialer(ctx, "tcp", target)
	if err != nil {
		_ = reply(c, repHostUnreachable)
		return
	}
	defer remote.Close()

	_ = reply(c, repSuccess)

	// Bidirectional copy (timeout removed — pipeBoth handles it)
	if err := pipe(c, remote, 128*1024, 120*time.Second); err != nil {
		log.Printf("[socks5] pipe error for %s: %v", target, err)
	}
}

// handshake performs RFC 1928 method negotiation, optionally followed by
// RFC 1929 username/password authentication.
func (s *Server) handshake(c net.Conn) (string, error) {
	buf := make([]byte, 262)

	// Read version + number of methods
	if _, err := io.ReadFull(c, buf[:2]); err != nil {
		return "", err
	}
	if buf[0] != socks5Version {
		return "", fmt.Errorf("unsupported socks version %d", buf[0])
	}
	nmethods := int(buf[1])
	if nmethods < 1 || nmethods > 255 {
		return "", errors.New("invalid methods length")
	}

	// Read methods list
	if _, err := io.ReadFull(c, buf[:nmethods]); err != nil {
		return "", err
	}

	// Check which auth method the client wants
	wantsAuth := false
	for _, m := range buf[:nmethods] {
		if m == authPassword {
			wantsAuth = true
			break
		}
	}

	if wantsAuth {
		// Request username/password auth
		if _, err := c.Write([]byte{0x05, authPassword}); err != nil {
			return "", err
		}
		// RFC 1929: sub-negotiation
		// VER (1) | ULEN (1) | UNAME (ULEN) | PLEN (1) | PASSWD (PLEN)
		if _, err := io.ReadFull(c, buf[:2]); err != nil {
			return "", err
		}
		if buf[0] != authVersion {
			return "", fmt.Errorf("unsupported user/pass version %d", buf[0])
		}
		ulen := int(buf[1])
		if ulen <= 0 || ulen > 255 {
			return "", errors.New("invalid username length")
		}
		if _, err := io.ReadFull(c, buf[:ulen]); err != nil {
			return "", err
		}
		// PLEN is 1 byte (NOT 2!)
		if _, err := io.ReadFull(c, buf[:1]); err != nil {
			return "", err
		}
		plen := int(buf[0])
		if plen < 0 || plen > 255 {
			return "", errors.New("invalid password length")
		}
		if plen > 0 {
			if _, err := io.ReadFull(c, buf[:plen]); err != nil {
				return "", err
			}
		}
		// Accept any credentials (tunnel access control is at the SSH layer)
		if _, err := c.Write([]byte{authVersion, 0x00}); err != nil {
			return "", err
		}
	} else {
		// NO AUTH REQUIRED
		if _, err := c.Write([]byte{0x05, authNone}); err != nil {
			return "", err
		}
	}

	// Read CONNECT request
	if _, err := io.ReadFull(c, buf[:4]); err != nil {
		return "", err
	}
	if buf[0] != socks5Version {
		return "", fmt.Errorf("bad request version %d", buf[0])
	}
	if buf[1] != cmdConnect {
		_ = reply(c, repCmdNotSupported)
		return "", fmt.Errorf("unsupported command %d", buf[1])
	}

	// Read destination address
	var host string
	atyp := buf[3]
	switch atyp {
	case addrIPv4:
		if _, err := io.ReadFull(c, buf[:4]); err != nil {
			return "", err
		}
		host = net.IPv4(buf[0], buf[1], buf[2], buf[3]).String()
	case addrDomain:
		if _, err := io.ReadFull(c, buf[:1]); err != nil {
			return "", err
		}
		l := int(buf[0])
		if l <= 0 {
			return "", errors.New("empty domain")
		}
		if _, err := io.ReadFull(c, buf[:l]); err != nil {
			return "", err
		}
		host = string(buf[:l])
	case addrIPv6:
		if _, err := io.ReadFull(c, buf[:16]); err != nil {
			return "", err
		}
		host = net.IP(buf[:16]).String()
	default:
		_ = reply(c, repAddrNotSupported)
		return "", fmt.Errorf("unsupported address type %d", atyp)
	}

	// Read port
	if _, err := io.ReadFull(c, buf[:2]); err != nil {
		return "", err
	}
	port := int(buf[0])<<8 | int(buf[1])

	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}

// reply sends a SOCKS5 reply.
func reply(c net.Conn, rep byte) error {
	_, err := c.Write([]byte{0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	return err
}

// pipe copies data bidirectionally with an idle timeout.
func pipe(a, b net.Conn, bufSize int, idleTimeout time.Duration) error {
	done := make(chan error, 2)
	activity := make(chan struct{}, 2)

	closeBoth := func() {
		_ = a.Close()
		_ = b.Close()
	}

	pump := func(dst, src net.Conn) {
		buf := make([]byte, bufSize)
		for {
			n, err := src.Read(buf)
			if n > 0 {
				select {
				case activity <- struct{}{}:
				default:
				}
				if _, werr := dst.Write(buf[:n]); werr != nil {
					done <- werr
					return
				}
			}
			if err != nil {
				done <- nil
				return
			}
		}
	}

	go pump(b, a)
	go pump(a, b)

	timer := time.NewTimer(idleTimeout)
	defer timer.Stop()

	for {
		select {
		case <-activity:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(idleTimeout)
		case <-done:
			grace := time.NewTimer(400 * time.Millisecond)
			select {
			case <-done:
			case <-grace.C:
			}
			grace.Stop()
			closeBoth()
			return nil
		case <-timer.C:
			closeBoth()
			return errors.New("idle timeout")
		}
	}
}
