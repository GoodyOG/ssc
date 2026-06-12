package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/GoodyOG/SSHCustom_Magisk/internal/tunnel"
)

// serveDNSForward runs a UDP listener that proxies DNS queries as TCP DNS
// (RFC 1035 §4.2.2: 2-byte length prefix + payload) through the SSH tunnel.
func serveDNSForward(ctx context.Context, listenAddr, upstream string, curClient func() *tunnel.Client) error {
	udpAddr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return fmt.Errorf("resolve udp: %w", err)
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("listen udp: %w", err)
	}
	log.Printf("[dns-forward] listening on %s, upstream=%s (via SSH)", listenAddr, upstream)
	go func() { <-ctx.Done(); _ = conn.Close() }()
	defer conn.Close()

	buf := make([]byte, 1500)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return fmt.Errorf("read udp: %w", err)
		}
		if n < 12 {
			continue
		}
		query := make([]byte, n)
		copy(query, buf[:n])
		go forwardOneDNSQuery(ctx, conn, src, query, upstream, curClient)
	}
}

func forwardOneDNSQuery(ctx context.Context, listener *net.UDPConn, src *net.UDPAddr, query []byte, upstream string, curClient func() *tunnel.Client) {
	c := curClient()
	if c == nil {
		for i := 0; i < 4 && c == nil; i++ {
			select {
			case <-ctx.Done():
				return
			case <-time.After(500 * time.Millisecond):
			}
			c = curClient()
		}
	}
	if c == nil {
		return
	}
	dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tcp, err := c.DialTCP(dialCtx, "tcp", upstream)
	if err != nil {
		return
	}
	defer tcp.Close()
	_ = tcp.SetDeadline(time.Now().Add(5 * time.Second))

	frame := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(query)))
	copy(frame[2:], query)
	if _, err := tcp.Write(frame); err != nil {
		return
	}
	var lenHdr [2]byte
	if _, err := io.ReadFull(tcp, lenHdr[:]); err != nil {
		return
	}
	respLen := int(binary.BigEndian.Uint16(lenHdr[:]))
	if respLen < 12 || respLen > 65535 {
		return
	}
	resp := make([]byte, respLen)
	if _, err := io.ReadFull(tcp, resp); err != nil {
		return
	}
	_, _ = listener.WriteToUDP(resp, src)
}
