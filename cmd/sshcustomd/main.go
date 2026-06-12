// SSHCustom-Magisk daemon — transparent SSH tunnel proxy using REDIRECT + TPROXY.
//
// Architecture:
//   - internal/config     — types, load/save, normalize
//   - internal/transport  — SSH dial chain (DNS→TCP→CONNECT→TLS→payload→SSH)
//   - internal/tunnel     — single-connection SSH engine, keepalive, stream retry
//   - internal/socks5     — local SOCKS5 proxy (RFC 1928 + RFC 1929)
//   - internal/iptables   — REDIRECT (local) + TPROXY (hotspot) + DNS + leak prevention
//   - internal/udpgw      — BadVPN UDPGW client (disabled by default)
//   - internal/dnsx       — Android-aware DNS resolver
//   - internal/api        — HTTP API + SSE + WebUI
//   - internal/metrics    — /proc CPU/memory sampling
package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/GoodyOG/SSHCustom_Magisk/internal/api"
	"github.com/GoodyOG/SSHCustom_Magisk/internal/config"
	"github.com/GoodyOG/SSHCustom_Magisk/internal/dnsx"
	"github.com/GoodyOG/SSHCustom_Magisk/internal/iptables"
	"github.com/GoodyOG/SSHCustom_Magisk/internal/metrics"
	"github.com/GoodyOG/SSHCustom_Magisk/internal/socks5"
	"github.com/GoodyOG/SSHCustom_Magisk/internal/transport"
	"github.com/GoodyOG/SSHCustom_Magisk/internal/tunnel"
	"github.com/GoodyOG/SSHCustom_Magisk/internal/version"
)

const (
	dnsForwardPort  = 5353
	dnsUpstream     = "8.8.8.8:53"
)

func main() {
	debug.SetGCPercent(100)
	if os.Getenv("GOMEMLIMIT") == "" {
		debug.SetMemoryLimit(96 * 1024 * 1024)
	}
	mp := runtime.NumCPU()
	if mp > 8 { mp = 8 }
	if mp < 1 { mp = 1 }
	runtime.GOMAXPROCS(mp)

	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "sshcustomd %s\nusage: sshcustomd {run|version|validate|iptables-dump|probe}\n", version.Version)
		os.Exit(2)
	}
	switch os.Args[1] {
	case "version":
		fmt.Println(version.Version)
	case "run":
		run(os.Args[2:])
	case "validate":
		validateCmd(os.Args[2:])
	case "iptables-dump":
		fmt.Print(iptables.Dump())
	case "probe":
		probeCmd(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		os.Exit(2)
	}
}

func validateCmd(args []string) {
	cfgPath := flagArg(args, "-c", "config.json")
	pfPath := flagArg(args, "-p", "profiles.json")
	_, err := config.LoadConfig(cfgPath)
	if err != nil { fatal(err) }
	pf, err := config.LoadProfiles(pfPath)
	if err != nil { fatal(err) }
	sp := pf.SelectedProfile()
	if sp == nil { fatal(fmt.Errorf("no profile found")) }
	if sp.SSH.Host == "" || sp.SSH.Port <= 0 { fatal(fmt.Errorf("invalid ssh host/port")) }
	if len(sp.Transport.Chain) == 0 { fatal(fmt.Errorf("empty transport chain")) }
	fmt.Println("config OK")
}

func probeCmd(args []string) {
	cfgPath := flagArg(args, "-c", "config.json")
	pfPath := flagArg(args, "-p", "profiles.json")
	cfg, err := config.LoadConfig(cfgPath)
	if err != nil { fatal(err) }
	pf, err := config.LoadProfiles(pfPath)
	if err != nil { fatal(err) }
	sp := pf.SelectedProfile()
	if sp == nil { fatal(fmt.Errorf("no selected profile")) }
	fmt.Println("[probe] Connecting to test SSH + payload...")
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	_, res, err := transport.DialContext(ctx, cfg, *sp)
	if err != nil {
		fmt.Printf("banner: %s\n", res.Banner)
		fmt.Printf("statuses: %v\n", res.Statuses)
		fmt.Printf("resolved: %s\n", res.ResolvedDial)
		fatal(err)
	}
	fmt.Printf("banner: %s\n", res.Banner)
	fmt.Printf("statuses: %v\n", res.Statuses)
	fmt.Printf("resolved: %s (%s)\n", res.ResolvedDial, res.ResolverMethod)
	fmt.Printf("ips: %v\n", res.ResolvedIPs)
	fmt.Println("probe OK — SSH server reachable and responding")
}

func fatal(err error) { fmt.Fprintln(os.Stderr, "error:", err); os.Exit(1) }
func flagArg(args []string, flag, def string) string {
	for i := 0; i < len(args)-1; i++ {
		if args[i] == flag { return args[i+1] }
	}
	return def
}
func hasFlag(args []string, flag string) bool {
	for _, a := range args { if a == flag { return true } }
	return false
}

// ── Run ────────────────────────────────────────────────────────────────────

func run(args []string) {
	cfgPath := flagArg(args, "-c", "/data/adb/sshcustom/config.json")
	pfPath := flagArg(args, "-p", "/data/adb/sshcustom/profiles.json")
	workDir := flagArg(args, "-w", "/data/adb/sshcustom")
	idleMode := hasFlag(args, "--idle")

	runDir := filepath.Join(workDir, "run")
	logFile, err := setupLogger(filepath.Join(runDir, "core.log"))
	if err != nil { fatal(err) }
	defer logFile.Close()
	_ = os.MkdirAll(runDir, 0755)

	cfg, err := config.LoadConfig(cfgPath)
	if err != nil { log.Fatal(err) }
	// Apply configurable memory limit (overrides the 96MB default in main())
	if cfg.Performance.MemoryLimitMB > 0 {
		debug.SetMemoryLimit(int64(cfg.Performance.MemoryLimitMB) * 1024 * 1024)
		log.Printf("[daemon] memory limit set to %d MB from config", cfg.Performance.MemoryLimitMB)
	}
	pf, err := config.LoadProfiles(pfPath)
	if err != nil { log.Fatal(err) }
	sp := pf.SelectedProfile()
	if sp == nil && !idleMode { log.Fatal("no selected profile") }

	ri := routeInfo()

	state := &api.State{
		StartedAt:          time.Now(),
		Version:            version.Version,
		GOOS:               runtime.GOOS,
		GOARCH:             runtime.GOARCH,
		WorkDir:            workDir,
		ConfigPath:         cfgPath,
		ProfilesPath:       pfPath,
		Running:            !idleMode,
		NetworkOnline:      ri.Online,
		Interface:          ri.Iface,
		Gateway:            ri.Gw,
		SourceIP:           ri.Src,
		HotspotEnabled:     cfg.Hotspot.Enabled,
		SocksEnabled:       cfg.LocalProxy.SocksEnabled,
		SocksAddr:          socksAddr(cfg),
		TransparentEnabled: cfg.TransparentProxy.Enabled,
		TransparentAddr:    transparentAddr(cfg),
		DNSMode:            cfg.DNS.Mode,
		DNSServers:         append([]string(nil), cfg.DNS.Servers...),
	}
	if idleMode { state.State = "IDLE" } else { state.State = "STARTING" }
	if sp != nil {
		state.SelectedProfile = sp.Name
		state.SelectedMode = sp.Transport.Mode
		state.TransportChain = strings.Join(sp.Transport.Chain, " -> ")
		state.PayloadEnabled = sp.Transport.Payload.Enabled
	}

	log.Printf("SSHCustom daemon %s starting (idle=%v)", version.Version, idleMode)
	if sp != nil {
		log.Printf("profile=%q mode=%s ssh=%s:%d", sp.Name, sp.Transport.Mode, sp.SSH.Host, sp.SSH.Port)
	}

	apiPort := cfg.API.Port; if apiPort <= 0 { apiPort = 9190 }
	apiSrv := api.NewServer(api.APIConfig{
		Host: cfg.API.Host, Port: apiPort, WorkDir: workDir,
		ConfigPath: cfgPath, ProfilesPath: pfPath,
	}, state)
	state.APIAddr = apiSrv.Addr()

	if err := apiSrv.LoadConfig(); err != nil { log.Printf("[api] load config: %v", err) }
	if err := apiSrv.Start(); err != nil { log.Printf("[api] start: %v", err) }

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go startMetricsSampler(ctx, state)

	// ── Tunnel lifecycle ───────────────────────────────────────
	var (
		tunnelCancel   context.CancelFunc
		tunnelDone     chan struct{}
		tunnelRunning  atomic.Bool
		explicitStop   atomic.Bool
		restartBackoff time.Duration
		sshClient      atomic.Pointer[tunnel.Client]
		listenerCancel context.CancelFunc
		iptablesUp     bool
		socksSrv       *socks5.Server
		lifecycleMu    sync.Mutex
	)

	setModDesc := func(status string) {
		path := "/data/adb/modules/sshcustom/module.prop"
		data, err := os.ReadFile(path)
		if err != nil { return }
		lines := strings.Split(string(data), "\n")
		var desc string
		switch status {
		case "running": desc = "description=[*] SSHCustom-Magisk - running"
		case "standby": desc = "description=[~] SSHCustom-Magisk - standby"
		default:        desc = "description=[ ] SSHCustom-Magisk - disconnected"
		}
		for i, line := range lines {
			if strings.HasPrefix(line, "description=") { lines[i] = desc; break }
		}
		_ = os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0644)
	}

	var startTunnel func()
	var stopTunnel func()

	startTunnel = func() {
		lifecycleMu.Lock()
		defer lifecycleMu.Unlock()
		if tunnelRunning.Load() { return }

		apiSrv.ReloadProfiles()
		pf := apiSrv.GetProfiles()
		sp := pf.SelectedProfile()
		if sp == nil {
			state.Set(func() { state.LastError = "no selected profile"; state.LastEvent = "no profile selected" })
			return
		}
		cfg := apiSrv.GetConfig()

		tunnelRunning.Store(true)
		explicitStop.Store(false)
		restartBackoff = 0
		done := make(chan struct{})
		tunnelDone = done
		tunnelCtx, tcancel := context.WithCancel(ctx)
		tunnelCancel = tcancel

		spCopy := *sp
		cfgCopy := cfg

		state.Set(func() {
			state.Running = true; state.State = "STARTING"; state.TunnelStartedAt = time.Now()
			state.SelectedProfile = sp.Name; state.SelectedMode = sp.Transport.Mode
			state.TransportChain = strings.Join(sp.Transport.Chain, " -> ")
			state.PayloadEnabled = sp.Transport.Payload.Enabled
			state.LastEvent = "tunnel starting"; state.LastError = ""
		})
		setModDesc("running")

		go func() {
			defer close(done)
			defer func() {
				if r := recover(); r != nil { log.Printf("[tunnel] panic: %v", r) }
			}()

			tunnelLoop(tunnelCtx, &cfgCopy, spCopy, state, &sshClient,
				&listenerCancel, &iptablesUp, &socksSrv)

			if explicitStop.Load() || ctx.Err() != nil {
				tunnelRunning.Store(false)
				state.Set(func() {
					state.Running = false; state.Connected = false
					state.TunnelStartedAt = time.Time{}
					if state.State != "IDLE" { state.State = "IDLE"; state.LastEvent = "tunnel stopped" }
				})
				setModDesc("disconnected")
				return
			}

			tunnelRunning.Store(false)
			if restartBackoff <= 0 { restartBackoff = 2 * time.Second }
			delay := restartBackoff
			restartBackoff *= 2
			if restartBackoff > 60*time.Second { restartBackoff = 60 * time.Second }
			log.Printf("[tunnel] auto-restart in %v", delay)
			select {
			case <-ctx.Done():
			case <-time.After(delay):
			}
			if ctx.Err() == nil && !explicitStop.Load() { startTunnel() }
		}()
	}

	stopTunnel = func() {
		lifecycleMu.Lock()
		defer lifecycleMu.Unlock()
		if !tunnelRunning.Load() { return }
		explicitStop.Store(true)
		if tunnelCancel != nil { tunnelCancel() }
		sshClient.Store(nil)
		if tunnelDone != nil {
			select { case <-tunnelDone: case <-time.After(5 * time.Second): }
		}
		// Shell-based cleanup (belt and suspenders)
		netClean := filepath.Join(workDir, "net_clean.sh")
		if _, err := os.Stat(netClean); err == nil { _ = exec.Command("/system/bin/sh", netClean).Run() }
		state.Set(func() {
			state.Running = false; state.Connected = false; state.State = "IDLE"
			state.LastEvent = "tunnel stopped and rules cleaned"; state.LastError = ""
			state.TunnelStartedAt = time.Time{}; state.PoolSize = 0; state.PoolHealthy = 0; state.PoolStreams = 0
		})
		setModDesc("disconnected")
		log.Printf("[tunnel] stopped")
	}

	apiSrv.SetControlHandler(func(action string) {
		switch action {
		case "start":   go startTunnel()
		case "stop":    go stopTunnel()
		case "restart": go func() { stopTunnel(); time.Sleep(500*time.Millisecond); startTunnel() }()
		}
	})

	if !idleMode { startTunnel() } else { log.Printf("idle mode — WebUI at http://127.0.0.1:%d", apiPort); setModDesc("disconnected") }

	go func() {
		ch, cleanup := state.Subscribe()
		defer cleanup()
		last := ""
		for {
			select {
			case <-ctx.Done(): return
			case <-ch:
				var status string
				snap := state.Snapshot()
				if c, _ := snap["connected"].(bool); c { status = "running"
				} else if r, _ := snap["running"].(bool); r { status = "running"
				} else { status = "disconnected" }
				if status != last { last = status; setModDesc(status) }
			}
		}
	}()

	log.Printf("[daemon] ready")
	<-ctx.Done()
	log.Printf("[daemon] shutdown")
	_ = apiSrv.Shutdown()
	state.Set(func() { state.State = "STOPPED"; state.Running = false })
	log.Printf("[daemon] stopped")
}

// ── Tunnel loop ────────────────────────────────────────────────────────────

func tunnelLoop(
	ctx context.Context,
	cfg *config.Config,
	sp config.Profile,
	state *api.State,
	clientPtr *atomic.Pointer[tunnel.Client],
	listenerCancel *context.CancelFunc,
	iptablesUp *bool,
	socksSrv **socks5.Server,
) {
	const baseDelay = 1 * time.Second
	const maxDelay = 30 * time.Second

	curClient := func() *tunnel.Client { return clientPtr.Load() }

	teardown := func() {
		if *listenerCancel != nil { (*listenerCancel)(); *listenerCancel = nil }
		if *iptablesUp { _ = iptables.Cleanup(iptablesCfg(*cfg)); *iptablesUp = false }
		clientPtr.Store(nil)
	}
	defer teardown()

	var delay time.Duration
	for {
		select {
		case <-ctx.Done(): return
		case <-time.After(delay):
		}

		ri := routeInfo()
		state.Set(func() {
			state.NetworkOnline = ri.Online; state.Interface = ri.Iface
			state.Gateway = ri.Gw; state.SourceIP = ri.Src
		})
		if !ri.Online {
			state.Set(func() { state.State = "PAUSED_NO_NETWORK"; state.Connected = false; state.LastEvent = "network offline" })
			delay = 5 * time.Second; continue
		}

		state.Set(func() { state.State = "CONNECTING_SSH"; state.LastEvent = "connecting"; state.LastError = "" })
		log.Printf("[tunnel] connecting %s:%d mode=%s", sp.SSH.Host, sp.SSH.Port, sp.Transport.Mode)

		client, res, err := transport.DialContext(ctx, *cfg, sp)
		if err != nil {
			state.Set(func() {
				state.State = "RETRY_BACKOFF"; state.Connected = false; state.LastError = err.Error()
				state.LastEvent = "SSH auth failed"; state.RemoteBanner = res.Banner
				state.HTTPStatuses = res.Statuses; state.ResolvedDial = res.ResolvedDial
				state.ResolverMethod = res.ResolverMethod; state.ResolvedIPs = res.ResolvedIPs
			})
			log.Printf("[tunnel] connect failed: %v", err)
			// Evict DNS cache when backoff exceeds 8s (4+ consecutive failures)
			// This forces re-resolution against a potentially different CDN IP.
			if delay >= 8*time.Second {
				dnsx.EvictHost(sp.SSH.Host)
				if sp.Transport.HTTPProxy != nil {
					dnsx.EvictHost(sp.Transport.HTTPProxy.Host)
				}
				log.Printf("[tunnel] DNS cache evicted for %s after repeated failures", sp.SSH.Host)
			}
			delay = tunnel.NextDelay(delay, baseDelay, maxDelay); continue
		}

		delay = baseDelay
		keepalive := config.SecondsDefault(cfg.Performance.KeepAliveSec, 15)
		tc := tunnel.NewClient(ctx, client, keepalive)
		clientPtr.Store(tc)
		state.Set(func() {
			state.State = "CONNECTED"; state.Connected = true; state.SSHAuthenticated = true; state.TransportReady = true
			state.LastError = ""; state.LastEvent = "SSH connected; SOCKS5 + transparent TCP + DNS active"
			state.RemoteBanner = res.Banner; state.HTTPStatuses = res.Statuses
			state.ResolvedDial = res.ResolvedDial; state.ResolverMethod = res.ResolverMethod; state.ResolvedIPs = res.ResolvedIPs
			state.PoolSize = 1; state.PoolHealthy = 1; state.PoolStreams = 0
		})
		log.Printf("[tunnel] connected: banner=%q", res.Banner)

		if *listenerCancel == nil {
			lctx, lcancel := context.WithCancel(ctx)
			*listenerCancel = lcancel
			startListeners(lctx, cfg, sp, curClient, state, socksSrv)
			time.Sleep(150 * time.Millisecond)

			if cfg.TransparentProxy.Enabled {
				if err := iptables.Apply(iptablesCfg(*cfg), res.ResolvedIPs); err != nil {
					log.Printf("[tunnel] iptables apply failed: %v", err)
					state.Set(func() { state.TransparentApplied = false; state.LastError = "iptables: " + err.Error() })
				} else {
					*iptablesUp = true
					state.Set(func() { state.TransparentApplied = true; state.HotspotRunning = cfg.Hotspot.Enabled && cfg.Hotspot.TCP })
					// Log iptables diagnostic for debugging
					iptables.LogRules("SSHC", cfg.TransparentProxy.TCPPort)
				}
			}
		}

		healthTicker := time.NewTicker(2 * time.Second)
		waitDone := make(chan error, 1)
		var waitErr error
		go func() { waitDone <- tc.Wait() }()
	wait:
		for {
			select {
			case <-ctx.Done():
				healthTicker.Stop(); tc.Close(); clientPtr.Store(nil); return
			case waitErr = <-waitDone:
				break wait
			case <-healthTicker.C:
				streams := tc.Active()
				maxStreams := cfg.Performance.MaxStreamsPerSSH
				if maxStreams <= 0 { maxStreams = 256 }
				if streams >= maxStreams*4/5 { log.Printf("[tunnel] high stream usage: %d/%d", streams, maxStreams) }
				te := tunnel.TransportErrorCount.Swap(0)
				if te >= 5 {
					log.Printf("[tunnel] %d transport errors; forcing reconnect", te)
					tc.Close(); clientPtr.Store(nil); healthTicker.Stop()
					waitErr = fmt.Errorf("forced reconnect after %d transport errors", te); break wait
				}
				state.Set(func() { state.PoolStreams = streams; state.PoolMaxStreams = maxStreams })
			}
		}
		healthTicker.Stop()

		reason := tunnel.ClassifyDisconnect(waitErr)
		tc.Close(); clientPtr.Store(nil)
		state.Set(func() {
			state.State = "RECONNECTING"; state.Connected = false; state.SSHAuthenticated = false; state.TransportReady = false
			state.PoolHealthy = 0; state.PoolReconnecting = 1; state.PoolStreams = 0
			state.LastEvent = "SSH connection lost; reconnecting"
		})
		log.Printf("[tunnel] connection lost (%s) — reconnecting", reason)
		delay = baseDelay
	}
}

// ── Listeners ──────────────────────────────────────────────────────────────

func startListeners(
	ctx context.Context,
	cfg *config.Config,
	sp config.Profile,
	curClient func() *tunnel.Client,
	state *api.State,
	socksSrv **socks5.Server,
) {
	// SOCKS5
	if cfg.LocalProxy.SocksEnabled {
		addr := socksAddr(*cfg)
		s := socks5.NewServer(addr, func(ctx context.Context, _, target string) (net.Conn, error) {
			cl := curClient()
			if cl == nil { return nil, fmt.Errorf("tunnel not connected") }
			return tunnel.DialStreamWithRetry(ctx, cl, target)
		})
		*socksSrv = s
		go func() {
			state.Set(func() { state.SocksRunning = true; state.SocksAddr = addr })
			if err := s.Serve(ctx); err != nil { log.Printf("[socks5] %v", err) }
			state.Set(func() { state.SocksRunning = false })
		}()
	}

	// Transparent TCP (REDIRECT listener — plain TCP, SO_ORIGINAL_DST)
	if cfg.TransparentProxy.Enabled {
		go func() {
			if err := serveTransparentTCP(ctx, *cfg, curClient, state); err != nil {
				log.Printf("[transparent] %v", err)
			}
		}()
	}

	// DNS forwarder (only if enabled in config)
	if cfg.DNS.Enabled {
		go func() {
			listenAddr := fmt.Sprintf("127.0.0.1:%d", dnsForwardPort)
			if err := serveDNSForward(ctx, listenAddr, dnsUpstream, curClient); err != nil {
				log.Printf("[dns-forward] %v", err)
			}
		}()
	} else {
		log.Printf("[dns-forward] disabled (dns.enabled=false)")
	}

	// UDPGW is removed completely, UDP is no longer tunneled.
}

// ── Config helpers ─────────────────────────────────────────────────────────

func socksAddr(cfg config.Config) string {
	host, port := cfg.LocalProxy.SocksHost, cfg.LocalProxy.SocksPort
	if host == "" { host = "127.0.0.1" }
	if port <= 0 { port = 1080 }
	return fmt.Sprintf("%s:%d", host, port)
}

func transparentAddr(cfg config.Config) string {
	port := cfg.TransparentProxy.TCPPort
	if port <= 0 { port = 10810 }
	return fmt.Sprintf("0.0.0.0:%d", port)
}

func iptablesCfg(cfg config.Config) iptables.Config {
	return iptables.Config{
		ChainsPrefix: cfg.TransparentProxy.ChainsPrefix,
		TCPPort: cfg.TransparentProxy.TCPPort,
		APIPort: cfg.API.Port, SocksPort: cfg.LocalProxy.SocksPort,
		DNSForwardPort: dnsForwardPort,
		DNSHijack:      cfg.DNS.Enabled && cfg.DNS.Hijack,
		Hotspot:        cfg.Hotspot.Enabled && cfg.Hotspot.TCP,
		HotspotDNS:     cfg.Hotspot.Enabled && cfg.Hotspot.DNS,
		HotspotIfaces:  cfg.Hotspot.Interfaces,
	}
}

// ── Metrics ─────────────────────────────────────────────────────────────────

func startMetricsSampler(ctx context.Context, st *api.State) {
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()
	sampler := &metrics.Sampler{}
	apply := func(snap metrics.Snapshot) {
		st.Set(func() {
			st.CPUPercent = snap.CPUPercent; st.MemoryRSSBytes = snap.MemoryRSSBytes
			st.MemoryRSSMB = snap.MemoryRSSMB; st.SystemMemTotalBytes = snap.SystemMemTotal
			st.SystemMemAvailBytes = snap.SystemMemAvail; st.SystemMemUsedPct = snap.SystemMemUsedPct
			st.Goroutines = snap.Goroutines
		})
	}
	apply(sampler.Sample())
	for { select { case <-ctx.Done(): return; case <-ticker.C: apply(sampler.Sample()) } }
}

func setupLogger(logPath string) (*os.File, error) {
	_ = os.MkdirAll(filepath.Dir(logPath), 0755)
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil { return nil, err }
	log.SetOutput(f)
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)
	return f, nil
}
