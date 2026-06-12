package main

import (
	"context"
	"log"
	"net"
	"strconv"
	"time"

	"github.com/GoodyOG/SSHCustom_Magisk/internal/api"
	"github.com/GoodyOG/SSHCustom_Magisk/internal/config"
	"github.com/GoodyOG/SSHCustom_Magisk/internal/tunnel"
)

// maxTransparentConns limits the number of simultaneous transparent proxy
// connections to prevent resource exhaustion under heavy load.
const maxTransparentConns = 2048

// transparentSem is a weighted semaphore that limits concurrent transparent connections.
var transparentSem = make(chan struct{}, maxTransparentConns)

// serveTransparentTCP listens for REDIRECT-d TCP connections and forwards them
// through the SSH tunnel. Uses SO_ORIGINAL_DST to recover the original destination.
func serveTransparentTCP(ctx context.Context, cfg config.Config, curClient func() *tunnel.Client, state *api.State) error {
	addr := transparentAddr(cfg)

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("[transparent] listen %s: %v", addr, err)
		state.Set(func() { state.TransparentRunning = false })
		return err
	}
	state.Set(func() { state.TransparentRunning = true; state.TransparentAddr = addr })
	log.Printf("[transparent] listening on %s (REDIRECT)", addr)

	go func() { <-ctx.Done(); _ = ln.Close() }()

	for {
		c, err := ln.Accept()
		if err != nil {
			state.Set(func() { state.TransparentRunning = false })
			return nil
		}
		go handleTransparentConn(ctx, c, cfg, curClient)
	}
}

func handleTransparentConn(ctx context.Context, c net.Conn, cfg config.Config, curClient func() *tunnel.Client) {
	defer c.Close()

	// Acquire semaphore slot — if full, drop connection gracefully
	select {
	case transparentSem <- struct{}{}:
		defer func() { <-transparentSem }()
	default:
		log.Printf("[transparent] connection limit reached (%d), dropping", maxTransparentConns)
		return
	}

	tcp, ok := c.(*net.TCPConn)
	if !ok { return }

	target, err := originalDst(tcp)
	if err != nil { return }

	if isLocalTarget(target, cfg) { return }

	_ = tcp.SetNoDelay(true)
	_ = tcp.SetKeepAlive(true)
	_ = tcp.SetKeepAlivePeriod(60 * time.Second)

	cl := curClient()
	if cl == nil { return }

	remote, err := tunnel.DialStreamWithRetry(ctx, cl, target)
	if err != nil {
		if tunnel.IsTransportError(err) { tunnel.TransportErrorCount.Add(1) }
		log.Printf("[transparent] failed %s: %v", target, err)
		return
	}
	defer remote.Close()

	cl = curClient()
	if cl == nil { return }
	cl.Add()
	defer cl.Remove()

	bufSize := config.SecondsDefault(cfg.Performance.BufferSize, 128*1024)
	if bufSize < 32*1024 { bufSize = 128 * 1024 }
	idleTimeout := time.Duration(config.SecondsDefault(cfg.Performance.StreamIdleTimeoutSec, 120)) * time.Second
	tunnel.PipeBoth(c, remote, bufSize, idleTimeout)
}

func isLocalTarget(target string, cfg config.Config) bool {
	h, p, err := net.SplitHostPort(target)
	if err != nil { return true }
	ip := net.ParseIP(h)
	if ip == nil { return false }
	port, _ := strconv.Atoi(p)
	for _, p := range []int{cfg.API.Port, cfg.LocalProxy.SocksPort, cfg.TransparentProxy.TCPPort} {
		if p > 0 && port == p { return true }
	}
	return ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast()
}
