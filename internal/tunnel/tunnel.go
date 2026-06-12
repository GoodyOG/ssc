// Package tunnel manages the single-connection SSH engine: keepalive,
// stream retry, and the reconnection loop.
package tunnel

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"sync/atomic"
	"time"

	xssh "golang.org/x/crypto/ssh"
)

// Client wraps an authenticated SSH client with an in-flight stream counter
// and a keepalive goroutine that detects dead links.
type Client struct {
	ssh    *xssh.Client
	ctx    context.Context
	cancel context.CancelFunc
	active int32
}

// NewClient creates a tunnel client with background keepalive.
func NewClient(parent context.Context, sc *xssh.Client, keepaliveSec int) *Client {
	ctx, cancel := context.WithCancel(parent)
	c := &Client{ssh: sc, ctx: ctx, cancel: cancel}
	go c.keepAlive(keepaliveSec)
	return c
}

func (c *Client) keepAlive(sec int) {
	if sec <= 0 {
		sec = 15
	}
	t := time.NewTicker(time.Duration(sec) * time.Second)
	defer t.Stop()
	missed := 0
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-t.C:
			done := make(chan error, 1)
			go func() {
				_, _, err := c.ssh.SendRequest("keepalive@openssh.com", true, nil)
				done <- err
			}()
			select {
			case err := <-done:
				if err != nil {
					missed++
					if missed >= 3 {
						_ = c.ssh.Close()
						return
					}
				} else {
					missed = 0
				}
			case <-time.After(5 * time.Second):
				missed++
				if missed >= 3 {
					_ = c.ssh.Close()
					return
				}
			}
		}
	}
}

// DialTCP opens an on-demand direct-tcpip channel through the SSH server.
func (c *Client) DialTCP(ctx context.Context, network, addr string) (net.Conn, error) {
	return c.ssh.DialContext(ctx, network, addr)
}

func (c *Client) Add()        { atomic.AddInt32(&c.active, 1) }
func (c *Client) Remove()     { atomic.AddInt32(&c.active, -1) }
func (c *Client) Active() int { return int(atomic.LoadInt32(&c.active)) }
func (c *Client) Close()      { c.cancel(); _ = c.ssh.Close() }
func (c *Client) Wait() error { return c.ssh.Wait() }

// ── Stream retry ────────────────────────────────────────────────────────────
// Dropbear/OpenSSH have short internal connect timeouts (3-10s). A single
// stream timeout doesn't mean the SSH session is dead — retrying usually
// succeeds on the next attempt.

// DialStreamWithRetry opens a direct-tcpip channel with up to 2 automatic
// retries for transient server-side failures.
func DialStreamWithRetry(ctx context.Context, cl *Client, target string) (net.Conn, error) {
	remote, err := cl.DialTCP(ctx, "tcp", target)
	if err == nil {
		return remote, nil
	}
	if !isStreamRetryable(err) {
		return nil, err
	}
	for attempt := 1; attempt <= 2; attempt++ {
		time.Sleep(time.Duration(attempt*300) * time.Millisecond)
		remote, err = cl.DialTCP(ctx, "tcp", target)
		if err == nil {
			log.Printf("[tunnel] stream retry %d succeeded for %s", attempt, target)
			return remote, nil
		}
		if !isStreamRetryable(err) {
			return nil, err
		}
	}
	return nil, err
}

func isStreamRetryable(err error) bool {
	s := err.Error()
	return strings.Contains(s, "connect failed") ||
		strings.Contains(s, "Connection refused") ||
		strings.Contains(s, "Connection timed out") ||
		strings.Contains(s, "Temporary failure in name resolution") ||
		strings.Contains(s, "no route to host")
}

// ── Transport error counting (circuit breaker) ──────────────────────────────
// When too many transport errors accumulate, the tunnel health check
// force-disconnects to get a fresh SSH session.

var TransportErrorCount atomic.Int64

// IsTransportError returns true if the error indicates a dying SSH session.
func IsTransportError(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "bad record mac") ||
		strings.Contains(s, "error decoding message") ||
		strings.Contains(s, "use of closed network connection") ||
		strings.Contains(s, "eof") ||
		strings.Contains(s, "packet too large") ||
		strings.Contains(s, "invalid packet length")
}

// ── Connection classification ───────────────────────────────────────────────

// ClassifyDisconnect categorizes an SSH Wait() error.
func ClassifyDisconnect(err error) string {
	if err == nil {
		return "clean close"
	}
	s := err.Error()
	switch {
	case strings.Contains(s, "EOF") || strings.Contains(s, "eof"):
		return "remote closed (SSH server)"
	case strings.Contains(s, "timeout") || strings.Contains(s, "i/o timeout"):
		return "network timeout"
	case strings.Contains(s, "reset") || strings.Contains(s, "broken pipe"):
		return "network reset"
	case strings.Contains(s, "use of closed network connection"):
		return "keepalive timeout (connection dead)"
	case strings.Contains(s, "unexpected packet") || strings.Contains(s, "bad record mac"):
		return "transport corruption"
	default:
		return s
	}
}

// ── Buffered I/O ────────────────────────────────────────────────────────────

const (
	DefaultCopyBufferSize = 128 * 1024
	MaxCopyBufferSize     = 512 * 1024
)

// NormalizeBufferSize clamps and aligns the copy buffer size.
func NormalizeBufferSize(n int) int {
	if n <= 0 {
		n = DefaultCopyBufferSize
	}
	if n < 32*1024 {
		n = 32 * 1024
	}
	if n > MaxCopyBufferSize {
		n = MaxCopyBufferSize
	}
	q := 32 * 1024
	return ((n + q - 1) / q) * q
}

// PipeBoth copies data bidirectionally between two connections with idle timeout.
func PipeBoth(a, b net.Conn, bufSize int, idleTimeout time.Duration) {
	bufSize = NormalizeBufferSize(bufSize)
	if idleTimeout <= 0 {
		idleTimeout = 120 * time.Second
	}
	done := make(chan struct{}, 2)
	activity := make(chan struct{}, 2)
	closeBoth := func() {
		if tc, ok := a.(*net.TCPConn); ok {
			_ = tc.SetDeadline(time.Now().Add(3 * time.Second))
			_ = tc.CloseWrite()
		}
		if tc, ok := b.(*net.TCPConn); ok {
			_ = tc.SetDeadline(time.Now().Add(3 * time.Second))
			_ = tc.CloseWrite()
		}
		_ = a.Close()
		_ = b.Close()
	}

	pump := func(dst, src net.Conn) {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, bufSize)
		for {
			n, err := src.Read(buf)
			if n > 0 {
				select {
				case activity <- struct{}{}:
				default:
				}
				if _, werr := writeAll(dst, buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
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
			return
		case <-timer.C:
			closeBoth()
			return
		}
	}
}

func writeAll(w net.Conn, b []byte) (int, error) {
	total := 0
	for len(b) > 0 {
		n, err := w.Write(b)
		if n > 0 {
			total += n
			b = b[n:]
		}
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, fmt.Errorf("short write")
		}
	}
	return total, nil
}

// ── Delay ───────────────────────────────────────────────────────────────────

// NextDelay implements exponential backoff with a cap.
func NextDelay(cur, base, max time.Duration) time.Duration {
	if cur <= 0 {
		return base
	}
	cur *= 2
	if cur > max {
		return max
	}
	return cur
}
