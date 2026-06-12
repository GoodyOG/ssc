// Package transport handles the SSH connection setup: DNS resolution, TCP dial,
// HTTP CONNECT proxy, TLS wrapping, payload injection, and SSH handshake.
// Supports 4 modes: direct, http_proxy, tls_sni, http_proxy_tls_sni.
package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/GoodyOG/SSHCustom_Magisk/internal/config"
	"github.com/GoodyOG/SSHCustom_Magisk/internal/dnsx"
	xssh "golang.org/x/crypto/ssh"
)

// Result holds the outcome of a transport probe / connection attempt.
type Result struct {
	Banner         string
	Statuses       []int
	Preview        string
	ResolvedDial   string
	ResolverMethod string
	ResolvedIPs    []string
}

// DialContext establishes a transport connection and performs SSH authentication.
// Returns the authenticated SSH client and transport probe result.
func DialContext(ctx context.Context, cfg config.Config, p config.Profile) (*xssh.Client, Result, error) {
	conn, res, err := openPreparedConn(ctx, cfg, p)
	if err != nil {
		return nil, res, err
	}

	pass := p.SSH.Password
	if pass == "" {
		pass = p.SSH.Username // fallback for legacy profiles
	}

	timeout := time.Duration(config.SecondsDefault(cfg.Performance.ConnectTimeoutSec, 20)) * time.Second
	sshCfg := &xssh.ClientConfig{
		User: p.SSH.Username,
		Auth: []xssh.AuthMethod{
			xssh.Password(pass),
			xssh.KeyboardInteractive(func(user, instruction string, questions []string, echos []bool) ([]string, error) {
				answers := make([]string, len(questions))
				for i := range answers {
					answers[i] = pass
				}
				return answers, nil
			}),
		},
		HostKeyCallback: xssh.InsecureIgnoreHostKey(),
		Timeout:         timeout,
		Config: xssh.Config{
			KeyExchanges: []string{"curve25519-sha256", "curve25519-sha256@libssh.org", "ecdh-sha2-nistp256", "diffie-hellman-group14-sha256", "diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha256"},
			Ciphers:      []string{"chacha20-poly1305@openssh.com", "aes128-ctr", "aes192-ctr", "aes256-ctr"},
			MACs:         []string{"hmac-sha1", "hmac-sha2-256"},
		},
	}

	addr := net.JoinHostPort(p.SSH.Host, strconv.Itoa(p.SSH.Port))
	sshConn, chans, reqs, err := xssh.NewClientConn(conn, addr, sshCfg)
	if err != nil {
		conn.Close()
		return nil, res, fmt.Errorf("ssh auth/handshake failed: %w", err)
	}
	return xssh.NewClient(sshConn, chans, reqs), res, nil
}

// openPreparedConn establishes the transport chain: TCP dial → HTTP CONNECT →
// TLS → payload → ready for SSH handshake.
func openPreparedConn(ctx context.Context, cfg config.Config, p config.Profile) (net.Conn, Result, error) {
	timeout := time.Duration(config.SecondsDefault(cfg.Performance.ConnectTimeoutSec, 20)) * time.Second
	readTimeout := time.Duration(config.SecondsDefault(cfg.Performance.ConnectTimeoutSec, 6)) * time.Second

	dialHost, dialPort, err := dialEndpoint(p)
	if err != nil {
		return nil, Result{}, err
	}

	base, resolved, method, resolvedIPs, err := dialTCPResolved(ctx, cfg, dialHost, dialPort, dialFallbackIPs(p, dialHost))
	res := Result{ResolvedDial: resolved, ResolverMethod: method, ResolvedIPs: resolvedIPs}
	if err != nil {
		return nil, res, fmt.Errorf("tcp dial failed: %w", err)
	}

	conn := base

	// HTTP CONNECT proxy
	if UsesHTTPProxy(p) && strings.EqualFold(p.Transport.HTTPProxy.ConnectMethod, "connect") {
		if err := httpCONNECT(conn, p, readTimeout); err != nil {
			conn.Close()
			return nil, Result{}, err
		}
	}
	// TLS wrapping
	if UsesTLS(p) {
		tlsCfg := p.Transport.TLS
		if tlsCfg == nil {
			conn.Close()
			return nil, Result{}, errors.New("tls mode selected but tls config is missing")
		}
		sni := tlsCfg.ServerName
		if sni == "" {
			sni = p.SSH.Host
		}
		log.Printf("[transport] tls handshake sni=%s insecure=%v", sni, tlsCfg.InsecureSkipVerify)
		tc := tls.Client(conn, &tls.Config{
			ServerName:         sni,
			InsecureSkipVerify: tlsCfg.InsecureSkipVerify,
			NextProtos:         tlsCfg.ALPN,
			MinVersion:         tls.VersionTLS10,
		})
		hctx, cancel := context.WithTimeout(ctx, timeout)
		err := tc.HandshakeContext(hctx)
		cancel()
		if err != nil {
			conn.Close()
			return nil, Result{}, fmt.Errorf("tls handshake failed: %w", err)
		}
		cs := tc.ConnectionState()
		log.Printf("[transport] tls complete version=%s cipher=%s", tlsVersionName(cs.Version), tls.CipherSuiteName(cs.CipherSuite))
		conn = tc
	}

	// Payload injection
	var all []byte
	if p.Transport.Payload.Enabled {
		payload := RenderPayload(p.Transport.Payload.Template, p)
		log.Printf("[transport] sending payload timing=%s bytes=%d", p.Transport.Payload.SendTiming, len(payload))
		if _, err := io.WriteString(conn, payload); err != nil {
			conn.Close()
			return nil, Result{}, fmt.Errorf("payload write failed: %w", err)
		}
		if p.Transport.Payload.ReadResponse {
			buf, err := readProbe(conn, readTimeout)
			if err != nil {
				conn.Close()
				return nil, Result{}, fmt.Errorf("payload response read failed: %w", err)
			}
			all = append(all, buf...)
		}
	}

	statuses := ExtractHTTPStatuses(string(all))
	if len(statuses) > 0 && !AllowedStatuses(statuses, p.Transport.Payload.AllowStatuses) {
		conn.Close()
		return nil, Result{Statuses: statuses, Preview: preview(all)}, fmt.Errorf("http status not allowed: %v", statuses)
	}
	banner := ExtractSSHBanner(string(all))
	idx := bytes.Index(all, []byte("SSH-"))
	if p.Transport.Payload.Enabled && p.Transport.Payload.ReadResponse {
		if banner != "" && idx >= 0 {
			conn = &prefixConn{Conn: conn, prefix: bytes.NewReader(all[idx:])}
		} else if len(statuses) > 0 {
			log.Printf("[transport] payload response statuses=%v; waiting for SSH banner", statuses)
			for _, s := range statuses {
				if s == 302 || s == 301 || s == 503 {
					dnsx.EvictHost(p.SSH.Host)
					if p.Transport.HTTPProxy != nil {
						dnsx.EvictHost(p.Transport.HTTPProxy.Host)
					}
					log.Printf("[transport] payload got %d from CDN — DNS cache evicted", s)
					break
				}
			}
		} else {
			conn.Close()
			return nil, Result{Statuses: statuses, Preview: preview(all)}, fmt.Errorf("transport did not expose SSH banner")
		}
	}
	res.Banner = banner
	res.Statuses = statuses
	res.Preview = preview(all)
	return conn, res, nil
}

// ── Dial helpers ────────────────────────────────────────────────────────────

func dialEndpoint(p config.Profile) (string, int, error) {
	host := p.SSH.Host
	port := p.SSH.Port
	if UsesHTTPProxy(p) {
		if p.Transport.HTTPProxy == nil {
			return "", 0, errors.New("http_proxy mode but http_proxy config missing")
		}
		host = p.Transport.HTTPProxy.Host
		port = p.Transport.HTTPProxy.Port
	}
	if host == "" || port <= 0 {
		return "", 0, fmt.Errorf("invalid dial endpoint %q:%d", host, port)
	}
	return host, port, nil
}

func dialFallbackIPs(p config.Profile, host string) []string {
	var out []string
	if strings.EqualFold(host, p.SSH.Host) {
		out = append(out, p.SSH.FallbackIPs...)
	}
	if p.Transport.HTTPProxy != nil && strings.EqualFold(host, p.Transport.HTTPProxy.Host) {
		out = append(out, p.Transport.HTTPProxy.FallbackIPs...)
	}
	return dnsx.SanitizeIPv4List(out)
}

func dialTCPResolved(ctx context.Context, cfg config.Config, host string, port int, fallbackIPs []string) (net.Conn, string, string, []string, error) {
	portStr := strconv.Itoa(port)

	if ip := net.ParseIP(host); ip != nil {
		addr := net.JoinHostPort(host, portStr)
		d := baseDialer(cfg)
		c, err := d.DialContext(ctx, "tcp", addr)
		return c, addr, "literal_ip", []string{ip.String()}, err
	}

	dnsMode := NormalizeDNSMode(cfg.DNS.Mode)
	if dnsMode != "device" {
		ips, method := dnsx.ResolveHost(ctx, dnsCfg(cfg), host)
		if len(ips) > 0 {
			ips = dnsx.RotateIPs(ips)
			var lastErr error
			for _, ip := range ips {
				ipAddr := net.JoinHostPort(ip, portStr)
				d := baseDialer(cfg)
				c, err := d.DialContext(ctx, "tcp", ipAddr)
				if err == nil {
					return c, ipAddr, method, ips, nil
				}
				lastErr = err
			}
			log.Printf("[transport] configured DNS resolved host=%s but all dials failed: %v", host, lastErr)
		}
	}

	// System DNS fallback
	addr := net.JoinHostPort(host, portStr)
	d := baseDialer(cfg)
	if d.Timeout <= 0 || d.Timeout > 10*time.Second {
		d.Timeout = 10 * time.Second
	}
	c, err := d.DialContext(ctx, "tcp", addr)
	if err == nil {
		return c, addr, "device_system_dns", nil, nil
	}

	// Shell DNS fallback
	ips, method := dnsx.ResolveHost(ctx, dnsCfg(cfg), host)
	if len(ips) == 0 && len(fallbackIPs) > 0 {
		for _, ip := range dnsx.RotateIPs(fallbackIPs) {
			ipAddr := net.JoinHostPort(ip, portStr)
			d := baseDialer(cfg)
			if c, cerr := d.DialContext(ctx, "tcp", ipAddr); cerr == nil {
				return c, ipAddr, "profile_fallback_ip", fallbackIPs, nil
			}
		}
	}
	if len(ips) == 0 {
		return nil, addr, "dns_failed", nil, err
	}
	for _, ip := range dnsx.RotateIPs(ips) {
		ipAddr := net.JoinHostPort(ip, portStr)
		d := baseDialer(cfg)
		c, cerr := d.DialContext(ctx, "tcp", ipAddr)
		if cerr == nil {
			return c, ipAddr, method, ips, nil
		}
	}
	return nil, addr, method, ips, err
}

func baseDialer(cfg config.Config) net.Dialer {
	timeout := time.Duration(config.SecondsDefault(cfg.Performance.ConnectTimeoutSec, 20)) * time.Second
	keepAlive := time.Duration(config.SecondsDefault(cfg.Performance.KeepAliveSec, 30)) * time.Second
	return net.Dialer{Timeout: timeout, KeepAlive: keepAlive}
}

func dnsCfg(cfg config.Config) dnsx.Config {
	return dnsx.Config{
		Mode:       dnsx.Mode(NormalizeDNSMode(cfg.DNS.Mode)),
		Servers:    cfg.DNS.Servers,
		TimeoutSec: cfg.DNS.TimeoutSec,
	}
}

// ── HTTP CONNECT ────────────────────────────────────────────────────────────

func httpCONNECT(conn net.Conn, p config.Profile, timeout time.Duration) error {
	target := net.JoinHostPort(p.SSH.Host, strconv.Itoa(p.SSH.Port))
	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Connection: Keep-Alive\r\n\r\n", target, target)
	if _, err := io.WriteString(conn, req); err != nil {
		return fmt.Errorf("http CONNECT write failed: %w", err)
	}
	data, err := readSome(conn, timeout, 4096)
	if err != nil {
		return fmt.Errorf("http CONNECT response read failed: %w", err)
	}
	statuses := ExtractHTTPStatuses(string(data))
	if len(statuses) == 0 {
		return fmt.Errorf("http CONNECT response had no status")
	}
	if statuses[0] < 200 || statuses[0] > 299 {
		return fmt.Errorf("http CONNECT failed with status %d", statuses[0])
	}
	return nil
}

// ── Payload rendering ───────────────────────────────────────────────────────

func RenderPayload(t string, p config.Profile) string {
	repl := map[string]string{
		"[crlf]":       "\r\n",
		"[lf]":         "\n",
		"[host]":       p.SSH.Host,
		"[port]":       strconv.Itoa(p.SSH.Port),
		"[ssh_host]":   p.SSH.Host,
		"[ssh_port]":   strconv.Itoa(p.SSH.Port),
		"[sni]":        "",
		"[proxy_host]": "",
		"[proxy_port]": "",
	}
	if p.Transport.TLS != nil {
		repl["[sni]"] = p.Transport.TLS.ServerName
	}
	if p.Transport.HTTPProxy != nil {
		repl["[proxy_host]"] = p.Transport.HTTPProxy.Host
		repl["[proxy_port]"] = strconv.Itoa(p.Transport.HTTPProxy.Port)
	}
	out := t
	for k, v := range repl {
		out = strings.ReplaceAll(out, k, v)
	}
	return out
}

// ── I/O helpers ─────────────────────────────────────────────────────────────

type prefixConn struct {
	net.Conn
	prefix *bytes.Reader
}

func (c *prefixConn) Read(p []byte) (int, error) {
	if c.prefix != nil && c.prefix.Len() > 0 {
		return c.prefix.Read(p)
	}
	return c.Conn.Read(p)
}

func readProbe(conn net.Conn, timeout time.Duration) ([]byte, error) {
	maxBytes := 64 * 1024
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	defer conn.SetReadDeadline(time.Time{})
	var out bytes.Buffer
	tmp := make([]byte, 2048)
	for out.Len() < maxBytes {
		n, err := conn.Read(tmp)
		if n > 0 {
			out.Write(tmp[:n])
			if strings.Contains(out.String(), "SSH-") {
				return out.Bytes(), nil
			}
		}
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				break
			}
			if errors.Is(err, io.EOF) {
				break
			}
			return out.Bytes(), err
		}
	}
	if out.Len() == 0 {
		return nil, errors.New("no bytes received before timeout")
	}
	return out.Bytes(), nil
}

func readSome(conn net.Conn, timeout time.Duration, max int) ([]byte, error) {
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	defer conn.SetReadDeadline(time.Time{})
	buf := make([]byte, max)
	n, err := conn.Read(buf)
	if n > 0 {
		return buf[:n], nil
	}
	if err != nil {
		return nil, err
	}
	return nil, errors.New("empty response")
}

// ── String parsers ──────────────────────────────────────────────────────────

func ExtractHTTPStatuses(s string) []int {
	var out []int
	for _, line := range strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "HTTP/") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			if n, err := strconv.Atoi(parts[1]); err == nil {
				out = append(out, n)
			}
		}
	}
	return out
}

func ExtractSSHBanner(s string) string {
	idx := strings.Index(s, "SSH-")
	if idx < 0 {
		return ""
	}
	tail := s[idx:]
	for _, sep := range []string{"\r\n", "\n"} {
		if j := strings.Index(tail, sep); j >= 0 {
			return strings.TrimSpace(tail[:j])
		}
	}
	if len(tail) > 120 {
		tail = tail[:120]
	}
	return strings.TrimSpace(tail)
}

func AllowedStatuses(got, allowed []int) bool {
	if len(got) == 0 || len(allowed) == 0 {
		return true
	}
	set := map[int]bool{}
	for _, n := range allowed {
		set[n] = true
	}
	for _, n := range got {
		if !set[n] {
			return false
		}
	}
	return true
}

// ── Mode helpers ────────────────────────────────────────────────────────────

func NormalizeMode(mode string) string {
	switch strings.TrimSpace(strings.ToLower(mode)) {
	case "direct", "ssh", "ssh_payload", "ssh+pl":
		return "direct"
	case "http_proxy", "ssh_http_proxy", "ssh+http", "ssh+http_proxy", "ssh+pl+http":
		return "http_proxy"
	case "tls_sni", "sni", "ssh+sni", "ssh+pl+sni":
		return "tls_sni"
	case "http_proxy_tls_sni", "http_tls", "ssh+http+sni", "ssh+pl+http+sni":
		return "http_proxy_tls_sni"
	default:
		return ""
	}
}

func NormalizeDNSMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", "system", "device", "default":
		return "device"
	case "google", "cloudflare", "custom":
		return strings.ToLower(strings.TrimSpace(mode))
	default:
		return "device"
	}
}

func UsesHTTPProxy(p config.Profile) bool {
	return p.Transport.Mode == "http_proxy" || p.Transport.Mode == "http_proxy_tls_sni" || contains(p.Transport.Chain, "http_proxy")
}

func UsesTLS(p config.Profile) bool {
	return p.Transport.Mode == "tls_sni" || p.Transport.Mode == "http_proxy_tls_sni" || contains(p.Transport.Chain, "tls")
}

func contains(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

func preview(b []byte) string {
	s := string(b)
	s = strings.ReplaceAll(s, "\r", "\\r")
	s = strings.ReplaceAll(s, "\n", "\\n")
	if len(s) > 500 {
		s = s[:500] + "..."
	}
	return s
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLSv1.0"
	case tls.VersionTLS11:
		return "TLSv1.1"
	case tls.VersionTLS12:
		return "TLSv1.2"
	case tls.VersionTLS13:
		return "TLSv1.3"
	default:
		return fmt.Sprintf("0x%x", v)
	}
}
