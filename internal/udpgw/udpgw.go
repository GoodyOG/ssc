//go:build linux
//
// Package udpgw implements the BadVPN UDPGW client for tunneling UDP traffic
// through an SSH connection. It follows the same protocol used by HTTP Injector
// and HTTP Custom: a single persistent TCP connection to the SSH server's udpgw
// port carries multiplexed UDP flows as framed messages.
//
// Protocol (BadVPN UDPGW wire format v1, original BadVPN by Ambrov):
//
// SEND frame (client → server):
//   [1B flags] [2B conid BE] [2B data_len BE] ([4B addr BE] [2B port BE]) [payload]
//   flags:
//     0x00 = no address info (use previously learned addr for this conid)
//     0x01 = HAS_ADDR (address fields present before payload)
//   conid: connection ID (big endian)
//   data_len: payload length (big endian, NOT including addr/port)
//   addr: destination IPv4 (big endian, only if HAS_ADDR)
//   port: destination port (big endian, only if HAS_ADDR)
//   payload: UDP payload data
//
// RECV frame (server → client):
//   [2B conid BE] [2B data_len BE] [payload]
//
// Architecture:
//  1. A local UDP listener on 0.0.0.0:7300 with IP_TRANSPARENT + IP_PKTINFO +
//     IP_RECVORIGDSTADDR receives TPROXY-captured and REDIRECT-captured UDP packets.
//  2. IP_RECVORIGDSTADDR recovers the original destination IP + port (after DNAT).
//     IP_PKTINFO provides the destination IP as fallback.
//  3. Each unique source address gets a connection ID (conid).
//  4. Outbound packets are framed with the original destination and written to
//     the persistent TCP connection to the SSH server's udpgw port.
//  5. A reader goroutine reads framed responses and dispatches them back to
//     the original UDP source address.
//  6. Idle conid mappings expire after 2 minutes and are garbage-collected.
package udpgw

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"sync"
	"time"

	"syscall"
)

const (
	// Default listen port on the device for UDP TPROXY/REDIRECT capture.
	DefaultPort = 7300

	// Max UDP payload size (often 1472, but we allow up to 4096 for safety).
	maxPayload = 4096

	// Idle conid timeout.
	idleTimeout = 2 * time.Minute

	// Janitor sweep interval.
	janitorInterval = 30 * time.Second

	// Max frame buffer size (header + addr + payload).
	maxFrameSize = 8192

	// IP_PKTINFO control message type — not exported by Go's syscall package.
	ipPktInfo = 8

	// IP_RECVORIGDSTADDR — recovers original dst after DNAT/REDIRECT.
	// Defined as SOL_IP option 20 in Linux kernel (include/net/netfilter/ipv4/nf_reject.h).
	ipOrigDstAddr = 20

	// SEND frame header size without address: flags(1) + conid(2) + data_len(2)
	sendHeaderSize = 5

	// Address size for IPv4: addr(4) + port(2)
	addrSize = 6

	// Full SEND frame header with address: sendHeaderSize + addrSize
	sendHeaderWithAddrSize = sendHeaderSize + addrSize

	// RECV frame header size: conid(2) + data_len(2)
	recvHeaderSize = 4
)

// Dialer dials a TCP connection (typically through the SSH tunnel)
// to the server's UDPGW port.
type Dialer func(ctx context.Context, network, addr string) (net.Conn, error)

// Server manages the UDPGW tunnel.
type Server struct {
	cfg    Config
	dialer Dialer

	mu       sync.Mutex
	conn     net.Conn
	conidSeq uint16
	srcByID  map[uint16]*udpSource
	idleByID map[uint16]time.Time

	ctx    context.Context
	cancel context.CancelFunc
}

// Config configures the local UDPGW listener.
type Config struct {
	ListenAddr string // "0.0.0.0:7300" or similar
}

type udpSource struct {
	addr *net.UDPAddr
}

// NewServer creates a new UDPGW server.
func NewServer(cfg Config, dialer Dialer) *Server {
	ctx, cancel := context.WithCancel(context.Background())
	return &Server{
		cfg:      cfg,
		dialer:   dialer,
		srcByID:  make(map[uint16]*udpSource),
		idleByID: make(map[uint16]time.Time),
		ctx:      ctx,
		cancel:   cancel,
	}
}

// Serve runs the UDPGW server: listens locally, connects to the server's
// UDPGW via the SSH tunnel, and forwards bi-directionally.
// Automatically reconnects the TCP leg on disconnection with exponential backoff.
func (s *Server) Serve(ctx context.Context, serverUDPGWAddr string) error {
	addr := s.cfg.ListenAddr
	if addr == "" {
		addr = fmt.Sprintf(":%d", DefaultPort)
	}
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return fmt.Errorf("udpgw: resolve listen addr: %w", err)
	}

	conn, err := listenUDPTransparent(udpAddr)
	if err != nil {
		return fmt.Errorf("udpgw: listen udp: %w", err)
	}
	defer conn.Close()
	log.Printf("[udpgw] listening on %s (IP_TRANSPARENT + IP_PKTINFO + IP_RECVORIGDSTADDR)", addr)

	// Start application-level keepalive and janitor loops (once, not per reconnect).
	go s.keepalive(s.ctx)
	go s.janitor()

	// Persistent TCP connection to server's badvpn-udpgw with reconnect
	backoff := 1 * time.Second
	const maxBackoff = 30 * time.Second

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		tcpConn, err := s.dialer(ctx, "tcp", serverUDPGWAddr)
		if err != nil {
			log.Printf("[udpgw] dial server udpgw %s failed: %v (retry in %v)", serverUDPGWAddr, err, backoff)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
				backoff = time.Duration(math.Min(float64(backoff*2), float64(maxBackoff)))
				continue
			}
		}
		backoff = 1 * time.Second // reset on successful connect

		log.Printf("[udpgw] connected to server udpgw at %s", serverUDPGWAddr)

		s.mu.Lock()
		s.conn = tcpConn
		s.mu.Unlock()

		// Enable TCP keepalive on the UDPGW tunnel connection
		if tcp, ok := tcpConn.(*net.TCPConn); ok {
			_ = tcp.SetKeepAlive(true)
			_ = tcp.SetKeepAlivePeriod(15 * time.Second)
		}

		// Run forwarder until error
		err = s.runForwarder(ctx, conn, tcpConn)

		s.mu.Lock()
		s.conn = nil
		s.mu.Unlock()

		tcpConn.Close()

		if ctx.Err() != nil {
			return ctx.Err()
		}

		log.Printf("[udpgw] disconnected from server (will reconnect in %v): %v", backoff, err)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
			backoff = time.Duration(math.Min(float64(backoff*2), float64(maxBackoff)))
		}
	}
}

// runForwarder runs the forward and read loops until one fails.
func (s *Server) runForwarder(ctx context.Context, udpConn *net.UDPConn, tcpConn net.Conn) error {
	done := make(chan error, 2)

	go func() {
		done <- s.readLoop(ctx, udpConn, tcpConn)
	}()
	go func() {
		done <- s.forwardLoop(ctx, udpConn, tcpConn)
	}()

	return <-done
}

// Shutdown stops the server gracefully.
func (s *Server) Shutdown() {
	s.cancel()
}

// ── Transparent UDP listener ────────────────────────────────────────────────

func listenUDPTransparent(addr *net.UDPAddr) (*net.UDPConn, error) {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var ctrlErr error
			err := c.Control(func(fd uintptr) {
				// IP_TRANSPARENT (SOL_IP, 19) — accept packets with non-local dest IPs
				if e := syscall.SetsockoptInt(int(fd), syscall.SOL_IP, 19, 1); e != nil {
					ctrlErr = fmt.Errorf("setsockopt IP_TRANSPARENT: %w", e)
					return
				}
				// IP_PKTINFO (SOL_IP, 8) — receive destination IP in control message
				if e := syscall.SetsockoptInt(int(fd), syscall.SOL_IP, ipPktInfo, 1); e != nil {
					ctrlErr = fmt.Errorf("setsockopt IP_PKTINFO: %w", e)
					return
				}
				// IP_RECVORIGDSTADDR (SOL_IP, 20) — receive original dest after DNAT/REDIRECT
				// This gives us the real destination IP + port even after REDIRECT rewrites it
				if e := syscall.SetsockoptInt(int(fd), syscall.SOL_IP, ipOrigDstAddr, 1); e != nil {
					log.Printf("[udpgw] IP_RECVORIGDSTADDR not available (kernel may not support it): %v", e)
				}
				if e := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); e != nil {
					ctrlErr = fmt.Errorf("setsockopt SO_REUSEADDR: %w", e)
					return
				}
			})
			if ctrlErr != nil {
				return ctrlErr
			}
			return err
		},
	}
	raw, err := lc.ListenPacket(context.Background(), "udp", addr.String())
	if err != nil {
		return nil, err
	}
	return raw.(*net.UDPConn), nil
}

// ── Forward loop (local → server) ───────────────────────────────────────────

func (s *Server) forwardLoop(ctx context.Context, udpConn *net.UDPConn, tcpConn net.Conn) error {
	buf := make([]byte, maxPayload)
	oob := make([]byte, 256)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		_ = udpConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, oobn, _, src, err := udpConn.ReadMsgUDP(buf, oob)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return fmt.Errorf("udpgw: read udp: %w", err)
		}
		if n < 1 {
			continue
		}

		// Recover original destination from control message
		// IP_RECVORIGDSTADDR gives full (IP + port) even after REDIRECT
		// IP_PKTINFO gives IP only (works with TPROXY, port is the TPROXY port)
		dst := extractDstFromPktInfo(oob[:oobn], src)
		if dst == nil {
			// Fallback: use source as destination (last resort, won't work for routing)
			dst = src
		}

		conid := s.allocateConid(src, dst)

		frame := encodeFrame(conid, dst, buf[:n])
		s.mu.Lock()
		conn := s.conn
		s.mu.Unlock()
		if conn == nil {
			continue
		}
		_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err := conn.Write(frame); err != nil {
			log.Printf("[udpgw] write frame conid=%d: %v", conid, err)
			return fmt.Errorf("udpgw: write frame: %w", err)
		}

		s.mu.Lock()
		s.idleByID[conid] = time.Now()
		s.mu.Unlock()
	}
}

// ── Read loop (server → local) ──────────────────────────────────────────────

func (s *Server) readLoop(ctx context.Context, udpConn *net.UDPConn, tcpConn net.Conn) error {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[udpgw] read loop panic recovered: %v", r)
		}
	}()
	buf := make([]byte, maxFrameSize)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		_ = tcpConn.SetReadDeadline(time.Now().Add(65 * time.Second))
		_, err := io.ReadFull(tcpConn, buf[:recvHeaderSize])
		if err != nil {
			if ctx.Err() == nil {
				log.Printf("[udpgw] read header: %v", err)
			}
			return err
		}

		conid := binary.BigEndian.Uint16(buf[:2])
		datalen := int(binary.BigEndian.Uint16(buf[2:4]))

		if datalen <= 0 || datalen > maxFrameSize {
			return fmt.Errorf("invalid frame conid=%d len=%d", conid, datalen)
		}

		_, err = io.ReadFull(tcpConn, buf[:datalen])
		if err != nil {
			if ctx.Err() == nil {
				log.Printf("[udpgw] read payload conid=%d: %v", conid, err)
			}
			return err
		}

		s.mu.Lock()
		src, ok := s.srcByID[conid]
		if ok {
			s.idleByID[conid] = time.Now()
		}
		s.mu.Unlock()

		if !ok || src == nil {
			continue
		}

		_, _ = udpConn.WriteToUDP(buf[:datalen], src.addr)
	}
}

// ── Conid management ────────────────────────────────────────────────────────

func (s *Server) allocateConid(src *net.UDPAddr, dst *net.UDPAddr) uint16 {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Reuse existing conid if source matches
	for id, existing := range s.srcByID {
		if existing != nil && existing.addr != nil &&
			existing.addr.IP.Equal(src.IP) && existing.addr.Port == src.Port {
			s.idleByID[id] = time.Now()
			return id
		}
	}

	s.conidSeq++
	if s.conidSeq == 0 {
		s.conidSeq = 1
	}
	conid := s.conidSeq

	s.srcByID[conid] = &udpSource{addr: src}
	s.idleByID[conid] = time.Now()

	return conid
}

// ── Frame encoding ──────────────────────────────────────────────────────────

// encodeFrame builds a BadVPN UDPGW SEND frame with the original destination address.
// Format:
//   [1B flags=0x01(HAS_ADDR)] [2B conid BE] [2B data_len BE] [4B addr BE] [2B port BE] [payload]
//
// Address is always included so that badvpn-udpgw knows where to forward each packet,
// and so that REDIRECT-captured traffic (where the original dest port is not the listener port)
// is correctly forwarded.
func encodeFrame(conid uint16, addr *net.UDPAddr, payload []byte) []byte {
	frame := make([]byte, sendHeaderWithAddrSize+len(payload))
	frame[0] = 0x01 // flags: HAS_ADDR
	binary.BigEndian.PutUint16(frame[1:3], conid)
	binary.BigEndian.PutUint16(frame[3:5], uint16(len(payload)))
	// Destination IPv4 address (BE)
	if addr != nil && addr.IP != nil {
		ip4 := addr.IP.To4()
		if ip4 != nil {
			copy(frame[5:9], ip4)
		}
	}
	// Destination port (BE)
	if addr != nil {
		binary.BigEndian.PutUint16(frame[9:11], uint16(addr.Port))
	}
	copy(frame[11:], payload)
	return frame
}

// ── IP_PKTINFO / IP_RECVORIGDSTADDR extraction ──────────────────────────────

// extractDstFromPktInfo recovers the original UDP destination after TPROXY or REDIRECT.
//
// Priority:
//  1. IP_RECVORIGDSTADDR (SOL_IP, 20) — returns full (IP + port) from conntrack.
//     Works with both TPROXY and REDIRECT on kernels with nf_conntrack.
//  2. IP_PKTINFO (SOL_IP, 8) — returns destination IP only (port is unreliable,
//     will fall back to src.Port for TPROXY traffic).
func extractDstFromPktInfo(oob []byte, src *net.UDPAddr) *net.UDPAddr {
	msgs, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return nil
	}
	for _, msg := range msgs {
		if msg.Header.Level != syscall.SOL_IP {
			continue
		}

		// IP_RECVORIGDSTADDR: struct sockaddr_in { sa_family(2B), port(2B BE), addr(4B), zero(8B) }
		if msg.Header.Type == ipOrigDstAddr && len(msg.Data) >= 8 {
			port := int(binary.BigEndian.Uint16(msg.Data[2:4]))
			ip := net.IPv4(msg.Data[4], msg.Data[5], msg.Data[6], msg.Data[7])
			return &net.UDPAddr{IP: ip, Port: port}
		}

		// IP_PKTINFO: struct in_pktinfo { ifindex(4B), spec_dst(4B), addr(4B) }
		if msg.Header.Type == ipPktInfo && len(msg.Data) >= 12 {
			dstIP := net.IPv4(msg.Data[8], msg.Data[9], msg.Data[10], msg.Data[11])
			// Port not available from IP_PKTINFO; use src.Port as fallback.
			// For TPROXY traffic the original destination port is the same as
			// what the app sent. For REDIRECT traffic the port was changed to
			// the listener port, so this fallback will be wrong.
			return &net.UDPAddr{IP: dstIP, Port: src.Port}
		}
	}
	return nil
}

// ── Janitor ─────────────────────────────────────────────────────────────────

func (s *Server) janitor() {
	ticker := time.NewTicker(janitorInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.mu.Lock()
			now := time.Now()
			for conid, lastSeen := range s.idleByID {
				if now.Sub(lastSeen) > idleTimeout {
					delete(s.srcByID, conid)
					delete(s.idleByID, conid)
				}
			}
			s.mu.Unlock()
		}
	}
}

// ── Keepalive ──────────────────────────────────────────────────────────────

// keepalive sends periodic frames to prevent badvpn-udpgw's idle timeout
// (default 20 seconds). We send a SEND frame with HAS_ADDR pointing to a
// real public destination (1.1.1.1:53, Cloudflare DNS) so badvpn accepts
// the frame and successfully creates the upstream socket. We use a reserved
// conid (0xFFFF) and a dummy 1-byte payload. Any DNS response is silently
// discarded since we have no real source for that conid.
//
// Why a real address: badvpn-udpgw requires a valid destination to create
// the upstream UDP socket. Port 0 / 127.0.0.1 destinations fail the socket
// creation, which closes the connection instead of resetting the timer.
func (s *Server) keepalive(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	const keepaliveConid = 0xFFFF

	// 1.1.1.1:53 in network byte order
	// 1.1.1.1 = 01 01 01 01
	// port 53 = 00 35
	kaFrame := make([]byte, 12)
	kaFrame[0] = 0x01 // HAS_ADDR
	binary.BigEndian.PutUint16(kaFrame[1:3], keepaliveConid)
	binary.BigEndian.PutUint16(kaFrame[3:5], 1) // data_len = 1
	kaFrame[5] = 1  // 1.1.1.1
	kaFrame[6] = 1
	kaFrame[7] = 1
	kaFrame[8] = 1
	kaFrame[9] = 0  // port 53 BE
	kaFrame[10] = 53
	kaFrame[11] = 0 // 1 dummy payload byte

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.mu.Lock()
			conn := s.conn
			s.mu.Unlock()
			if conn == nil {
				continue
			}

			_ = conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
			if _, err := conn.Write(kaFrame); err != nil {
				log.Printf("[udpgw] keepalive write error: %v", err)
				continue
			}
		}
	}
}

type Stats struct {
	ActiveFlows int
}

func (s *Server) GetStats() Stats {
	s.mu.Lock()
	n := len(s.srcByID)
	s.mu.Unlock()
	return Stats{ActiveFlows: n}
}
