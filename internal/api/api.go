// Package api provides the HTTP control server for the SSHCustom daemon:
// REST endpoints, SSE event stream, WebUI serving, and CORS middleware.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/GoodyOG/SSHCustom_Magisk/internal/apiv1"
	"github.com/GoodyOG/SSHCustom_Magisk/internal/config"
	"github.com/GoodyOG/SSHCustom_Magisk/internal/transport"
	"github.com/GoodyOG/SSHCustom_Magisk/internal/webui"
)

// State exposes runtime state for the API handlers to read and write.
// This is a flat structure that the API package fully owns.
type State struct {
	mu    sync.RWMutex
	subsMu sync.Mutex
	subs  []chan struct{}

	// Fields
	StartedAt           time.Time `json:"started_at"`
	TunnelStartedAt     time.Time `json:"tunnel_started_at"`
	State               string    `json:"state"`
	Running             bool      `json:"running"`
	Connected           bool      `json:"connected"`
	SSHAuthenticated    bool      `json:"ssh_authenticated"`
	TransportReady      bool      `json:"transport_ready"`
	Phase               string    `json:"phase"`
	Version             string    `json:"version"`
	GOOS                string    `json:"goos"`
	GOARCH              string    `json:"goarch"`
	WorkDir             string    `json:"work_dir"`
	ConfigPath          string    `json:"config_path"`
	ProfilesPath        string    `json:"profiles_path"`
	SelectedProfile     string    `json:"selected_profile"`
	SelectedMode        string    `json:"selected_mode"`
	TransportChain      string    `json:"transport_chain"`
	PayloadEnabled      bool      `json:"payload_enabled"`
	LastError           string    `json:"last_error"`
	LastEvent           string    `json:"last_event"`
	Attempt             int       `json:"attempt"`
	NetworkOnline       bool      `json:"network_online"`
	DefaultRoute        string    `json:"default_route"`
	Interface           string    `json:"interface"`
	Gateway             string    `json:"gateway"`
	SourceIP            string    `json:"source_ip"`
	HotspotEnabled      bool      `json:"hotspot_enabled"`
	SocksEnabled        bool      `json:"socks_enabled"`
	SocksAddr           string    `json:"socks_addr"`
	SocksRunning        bool      `json:"socks_running"`
	TransparentEnabled  bool      `json:"transparent_enabled"`
	TransparentAddr     string    `json:"transparent_addr"`
	TransparentRunning  bool      `json:"transparent_running"`
	TransparentApplied  bool      `json:"transparent_applied"`
	HotspotRunning      bool      `json:"hotspot_running"`
	UDPGWRunning        bool      `json:"udpgw_running"`
	UDPGWActiveFlows    int       `json:"udpgw_active_flows"`
	CPUPercent          float64   `json:"cpu_percent"`
	MemoryRSSBytes      uint64    `json:"memory_rss_bytes"`
	MemoryRSSMB         float64   `json:"memory_rss_mb"`
	SystemMemTotalBytes uint64    `json:"system_mem_total_bytes"`
	SystemMemAvailBytes uint64    `json:"system_mem_available_bytes"`
	SystemMemUsedPct    float64   `json:"system_mem_used_percent"`
	Goroutines          int       `json:"goroutines"`
	RemoteBanner        string    `json:"remote_banner"`
	HTTPStatuses        []int     `json:"http_statuses"`
	APIAddr             string    `json:"api_addr"`
	ResolvedDial        string    `json:"resolved_dial"`
	ResolverMethod      string    `json:"resolver_method"`
	ResolvedIPs         []string  `json:"resolved_ips"`
	DNSMode             string    `json:"dns_mode"`
	DNSServers          []string  `json:"dns_servers"`
	PoolSize            int       `json:"pool_size"`
	PoolHealthy         int       `json:"pool_healthy"`
	PoolReconnecting    int       `json:"pool_reconnecting"`
	PoolStreams         int       `json:"pool_streams"`
	PoolMaxStreams      int       `json:"pool_max_streams"`
	PoolLastError       string    `json:"pool_last_error"`
	Note                string    `json:"note"`
}

// Set atomically updates state and broadcasts to SSE subscribers.
func (s *State) Set(fn func()) {
	s.mu.Lock()
	fn()
	s.mu.Unlock()
	s.broadcast()
}

// Subscribe returns a channel that receives a notification on every state change.
func (s *State) Subscribe() (<-chan struct{}, func()) {
	ch := make(chan struct{}, 1)
	s.subsMu.Lock()
	s.subs = append(s.subs, ch)
	s.subsMu.Unlock()
	cleanup := func() {
		s.subsMu.Lock()
		defer s.subsMu.Unlock()
		for i, c := range s.subs {
			if c == ch {
				s.subs = append(s.subs[:i], s.subs[i+1:]...)
				break
			}
		}
	}
	return ch, cleanup
}

func (s *State) broadcast() {
	s.subsMu.Lock()
	defer s.subsMu.Unlock()
	for _, ch := range s.subs {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

// Snapshot returns a map copy of state for JSON serialization.
func (s *State) Snapshot() map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	uptime := int64(0)
	if !s.StartedAt.IsZero() {
		uptime = int64(time.Since(s.StartedAt).Seconds())
	}
	tunnelUptime := int64(0)
	if !s.TunnelStartedAt.IsZero() && s.Running {
		tunnelUptime = int64(time.Since(s.TunnelStartedAt).Seconds())
	}
	return map[string]any{
		"started_at":              s.StartedAt.Format(time.RFC3339),
		"uptime_seconds":          uptime,
		"tunnel_uptime_seconds":   tunnelUptime,
		"state":                   s.State,
		"running":                 s.Running,
		"connected":               s.Connected,
		"ssh_authenticated":       s.SSHAuthenticated,
		"transport_ready":         s.TransportReady,
		"phase":                   s.Phase,
		"version":                 s.Version,
		"goos":                    s.GOOS,
		"goarch":                  s.GOARCH,
		"work_dir":                s.WorkDir,
		"config_path":             s.ConfigPath,
		"profiles_path":           s.ProfilesPath,
		"selected_profile":        s.SelectedProfile,
		"selected_mode":           s.SelectedMode,
		"transport_chain":         s.TransportChain,
		"payload_enabled":         s.PayloadEnabled,
		"last_error":              s.LastError,
		"last_event":              s.LastEvent,
		"attempt":                 s.Attempt,
		"network_online":          s.NetworkOnline,
		"default_route":           s.DefaultRoute,
		"interface":               s.Interface,
		"gateway":                 s.Gateway,
		"source_ip":               s.SourceIP,
		"hotspot_enabled":         s.HotspotEnabled,
		"api_addr":                s.APIAddr,
		"resolved_dial":           s.ResolvedDial,
		"resolver_method":         s.ResolverMethod,
		"resolved_ips":            s.ResolvedIPs,
		"dns_mode":                s.DNSMode,
		"dns_servers":             s.DNSServers,
		"pool_size":               s.PoolSize,
		"pool_healthy":            s.PoolHealthy,
		"pool_reconnecting":       s.PoolReconnecting,
		"pool_streams":            s.PoolStreams,
		"pool_max_streams":        s.PoolMaxStreams,
		"pool_last_error":         s.PoolLastError,
		"socks_enabled":           s.SocksEnabled,
		"socks_addr":              s.SocksAddr,
		"socks_running":           s.SocksRunning,
		"transparent_enabled":     s.TransparentEnabled,
		"transparent_addr":        s.TransparentAddr,
		"transparent_running":     s.TransparentRunning,
		"transparent_applied":     s.TransparentApplied,
		"hotspot_running":         s.HotspotRunning,
		"udpgw_running":           s.UDPGWRunning,
		"udpgw_active_flows":      s.UDPGWActiveFlows,
		"cpu_percent":             s.CPUPercent,
		"memory_rss_bytes":        s.MemoryRSSBytes,
		"memory_rss_mb":           s.MemoryRSSMB,
		"system_mem_used_percent": s.SystemMemUsedPct,
		"remote_banner":           s.RemoteBanner,
		"http_statuses":           s.HTTPStatuses,
		"note":                    s.Note,
	}
}

// RouteInfo holds the current network route state.
type RouteInfo struct {
	Online bool
	Raw    string
	Iface  string
	Gw     string
	Src    string
}

// ControlHandler is called when the WebUI sends a start/stop/restart command.
type ControlHandler func(action string)

// Server is the HTTP API + WebUI server.
type Server struct {
	mux    *http.ServeMux
	http   *http.Server
	addr   string
	state  *State
	cfg    atomic.Pointer[config.Config]
	pf     atomic.Pointer[config.ProfilesFile]

	cfgPath    string
	pfPath     string
	workDir    string
	runDir     string

	controlHandler atomic.Pointer[ControlHandler]

	cfgMu sync.RWMutex
	profMu sync.Mutex
}

// Config holds the initialization parameters for the API server.
type APIConfig struct {
	Host        string
	Port        int
	WorkDir     string
	ConfigPath  string
	ProfilesPath string
}

// NewServer creates the API server (doesn't start listening yet).
func NewServer(apiCfg APIConfig, state *State) *Server {
	s := &Server{
		mux:     http.NewServeMux(),
		state:   state,
		cfgPath: apiCfg.ConfigPath,
		pfPath:  apiCfg.ProfilesPath,
		workDir: apiCfg.WorkDir,
		runDir:  filepath.Join(apiCfg.WorkDir, "run"),
		addr:    net.JoinHostPort(apiCfg.Host, strconv.Itoa(apiCfg.Port)),
	}

	s.registerRoutes()
	return s
}

// LoadConfig reads config and profiles from disk and stores them.
func (s *Server) LoadConfig() error {
	cfg, err := config.LoadConfig(s.cfgPath)
	if err != nil {
		return err
	}
	s.cfg.Store(&cfg)

	pf, err := config.LoadProfiles(s.pfPath)
	if err != nil {
		return err
	}
	s.pf.Store(&pf)
	return nil
}

// Start begins listening on the configured address.
func (s *Server) Start() error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("api listen %s: %w", s.addr, err)
	}
	s.http = &http.Server{
		Handler:           withCORS(s.mux),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    64 * 1024,
	}
	s.http.SetKeepAlivesEnabled(true)
	go func() {
		log.Printf("[api] listening on http://%s", s.addr)
		if err := s.http.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("[api] serve error: %v", err)
		}
	}()
	return nil
}

// Shutdown gracefully stops the HTTP server.
func (s *Server) Shutdown() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return s.http.Shutdown(ctx)
}

// Addr returns the server's listening address.
func (s *Server) Addr() string { return s.addr }

// ── Config/profile access from outside ─────────────────────────────────────

func (s *Server) GetConfig() config.Config {
	p := s.cfg.Load()
	if p == nil {
		return config.DefaultConfig()
	}
	return *p
}

func (s *Server) UpdateConfig(cfg config.Config) error {
	if err := config.SaveConfig(s.cfgPath, cfg); err != nil {
		return err
	}
	s.cfg.Store(&cfg)
	return nil
}

func (s *Server) GetProfiles() config.ProfilesFile {
	p := s.pf.Load()
	if p == nil {
		return config.ProfilesFile{}
	}
	return *p
}

func (s *Server) SaveProfiles(pf config.ProfilesFile) error {
	if err := config.SaveProfiles(s.pfPath, pf); err != nil {
		return err
	}
	s.pf.Store(&pf)
	return nil
}

func (s *Server) ReloadProfiles() (config.ProfilesFile, error) {
	pf, err := config.LoadProfiles(s.pfPath)
	if err != nil {
		return pf, err
	}
	s.pf.Store(&pf)
	return pf, nil
}

// State returns the state object.
func (s *Server) State() *State { return s.state }

// ── Route registration ─────────────────────────────────────────────────────

func (s *Server) registerRoutes() {
	// Health
	s.mux.HandleFunc("/api/v1/health", s.handleHealth)
	// Latency probe
	s.mux.HandleFunc("/api/v1/latency", s.handleLatency)
	// Status
	s.mux.HandleFunc("/api/v1/status", s.handleStatus)
	// Diagnostics
	s.mux.HandleFunc("/api/v1/diagnostics", s.handleDiagnostics)
	// Config
	s.mux.HandleFunc("/api/v1/config", s.handleConfig)
	// Profiles
	s.mux.HandleFunc("/api/v1/profiles", s.handleProfiles)
	s.mux.HandleFunc("/api/v1/profile/current", s.handleProfileCurrent)
	s.mux.HandleFunc("/api/v1/profile/select", s.handleProfileSelect)
	s.mux.HandleFunc("/api/v1/profile/delete", s.handleProfileDelete)
	s.mux.HandleFunc("/api/v1/profile/save", s.handleProfileSave)
	// Control (start/stop/restart tunnel)
	s.mux.HandleFunc("/api/v1/control", s.handleControl)
	// Logs
	s.mux.HandleFunc("/api/v1/logs/", s.handleLogs)
	// Autostart
	s.mux.HandleFunc("/api/v1/autostart", s.handleAutostart)
	// Public IP
	s.mux.HandleFunc("/api/v1/network/public-ip", s.handlePublicIP)
	// Test UDP — sends a test packet to verify the MOUT + TPROXY pipeline
	s.mux.HandleFunc("/api/v1/test/udp", s.handleTestUDP)
	// UDP counters — diagnostic for verifying MARK + TPROXY pipeline
	s.mux.HandleFunc("/api/v1/diagnostics/udp", s.handleUDPCounters)
	// SSE events
	s.mux.HandleFunc("/api/v1/events", s.handleEvents)
	// Captive portal bypass
	s.mux.HandleFunc("/generate_204", s.handleCaptivePortal)
	s.mux.HandleFunc("/captive/generate_204", s.handleCaptivePortal)
	// WebUI
	s.mux.Handle("/", webui.Handler(s.workDir))
}

// ── Handlers ───────────────────────────────────────────────────────────────

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeV1OK(w, apiv1.HealthResponse{Status: "ok", Version: s.state.Version})
}

func (s *Server) handleLatency(w http.ResponseWriter, r *http.Request) {
	snap := s.state.Snapshot()
	running, _ := snap["running"].(bool)
	connected, _ := snap["connected"].(bool)
	if !running || !connected {
		writeV1OK(w, map[string]any{
			"latency_ms": -1,
			"target":     "",
			"error":      "tunnel not connected",
			"checked_at": time.Now().Format(time.RFC3339),
		})
		return
	}

	socksAddr, _ := snap["socks_addr"].(string)
	if socksAddr == "" {
		socksAddr = "127.0.0.1:1080"
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	start := time.Now()
	conn, err := socks5Connect(ctx, socksAddr, "google.com", 80)
	if err != nil {
		// fallback: try connecting to 1.1.1.1:80
		conn, err = socks5Connect(ctx, socksAddr, "1.1.1.1", 80)
		if err != nil {
			writeV1OK(w, map[string]any{
				"latency_ms": -1,
				"target":     "unreachable",
				"error":      err.Error(),
				"checked_at": time.Now().Format(time.RFC3339),
			})
			return
		}
	}
	conn.Close()
	latency := time.Since(start)

	writeV1OK(w, map[string]any{
		"latency_ms": latency.Milliseconds(),
		"target":     "google.com:80",
		"checked_at": time.Now().Format(time.RFC3339),
	})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	cfg := s.GetConfig()
	writeV1OK(w, map[string]any{
		"runtime":      s.state.Snapshot(),
		"config":       configSummary(cfg),
		"capabilities": apiCapabilities(cfg),
		"paths": map[string]string{
			"work_dir":      s.workDir,
			"config_path":   s.cfgPath,
			"profiles_path": s.pfPath,
			"run_dir":       s.runDir,
			"webroot":       filepath.Join(s.workDir, "webroot"),
		},
	})
}

func (s *Server) handleDiagnostics(w http.ResponseWriter, r *http.Request) {
	cfg := s.GetConfig()
	snap := s.state.Snapshot()
	writeV1OK(w, apiv1.DiagnosticsResponse{
		Runtime: snap,
		Config:  configSummary(cfg),
		Pool: map[string]any{
			"size":          snap["pool_size"],
			"healthy":       snap["pool_healthy"],
			"reconnecting":  snap["pool_reconnecting"],
			"streams":       snap["pool_streams"],
			"max_streams":   snap["pool_max_streams"],
			"last_error":    snap["pool_last_error"],
			"capacity_hint": fmt.Sprintf("%v/%v healthy, %v active streams", snap["pool_healthy"], snap["pool_size"], snap["pool_streams"]),
		},
		Route: map[string]any{
			"online":        snap["network_online"],
			"interface":     snap["interface"],
			"gateway":       snap["gateway"],
			"source_ip":     snap["source_ip"],
			"default_route": snap["default_route"],
		},
		Performance: map[string]any{
			"cpu_percent":             snap["cpu_percent"],
			"memory_rss_mb":           snap["memory_rss_mb"],
			"goroutines":              snap["goroutines"],
			"copy_buffer_size":        cfg.Performance.BufferSize,
			"connect_timeout_seconds": config.SecondsDefault(cfg.Performance.ConnectTimeoutSec, 20),
			"keepalive_seconds":       config.SecondsDefault(cfg.Performance.KeepAliveSec, 15),
			"max_streams_per_ssh":     cfg.Performance.MaxStreamsPerSSH,
		},
	})
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeV1OK(w, s.GetConfig())
	case http.MethodPost, http.MethodPatch:
		var req apiv1.ConfigPatchRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeV1Error(w, http.StatusBadRequest, err)
			return
		}
		// Apply patch
		next := s.GetConfig()
		if req.DNS != nil {
			next.DNS.Mode = transport.NormalizeDNSMode(req.DNS.Mode)
			if req.DNS.TimeoutSeconds > 0 {
				next.DNS.TimeoutSec = req.DNS.TimeoutSeconds
			}
			if next.DNS.Mode == "custom" {
				next.DNS.Servers = req.DNS.Servers
			}
		}
		if req.Hotspot != nil {
			if req.Hotspot.Enabled != nil {
				next.Hotspot.Enabled = *req.Hotspot.Enabled
			}
			if req.Hotspot.TCP != nil {
				next.Hotspot.TCP = *req.Hotspot.TCP
			}
		}
		if err := s.UpdateConfig(next); err != nil {
			writeV1Error(w, http.StatusInternalServerError, err)
			return
		}
		writeV1OK(w, apiv1.ConfigUpdateResponse{Config: next, Restart: req.Restart})
	default:
		writeV1Error(w, http.StatusMethodNotAllowed, errors.New("GET, POST, or PATCH required"))
	}
}

func (s *Server) handleProfiles(w http.ResponseWriter, r *http.Request) {
	pf, err := s.ReloadProfiles()
	if err != nil {
		writeV1Error(w, http.StatusInternalServerError, err)
		return
	}
	writeV1OK(w, pf)
}

func (s *Server) handleProfileCurrent(w http.ResponseWriter, r *http.Request) {
	pf, _ := s.ReloadProfiles()
	sp := pf.SelectedProfile()
	if sp == nil {
		writeV1Error(w, http.StatusNotFound, errors.New("no selected profile"))
		return
	}
	writeV1OK(w, sp)
}

func (s *Server) handleProfileSelect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeV1Error(w, http.StatusMethodNotAllowed, errors.New("POST required"))
		return
	}
	var req struct {
		SelectedID string `json:"selected_id"`
		Restart    bool   `json:"restart"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeV1Error(w, http.StatusBadRequest, err)
		return
	}
	pf, err := s.ReloadProfiles()
	if err == nil {
		err = pf.SelectByID(req.SelectedID)
	}
	if err == nil {
		err = s.SaveProfiles(pf)
	}
	if err != nil {
		writeV1Error(w, http.StatusBadRequest, err)
		return
	}
	writeV1OK(w, map[string]any{"selected_id": req.SelectedID, "restart": req.Restart})
}

func (s *Server) handleProfileDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeV1Error(w, http.StatusMethodNotAllowed, errors.New("POST required"))
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeV1Error(w, http.StatusBadRequest, err)
		return
	}
	pf, err := s.ReloadProfiles()
	if err == nil {
		err = pf.DeleteProfile(req.ID)
	}
	if err == nil {
		err = s.SaveProfiles(pf)
	}
	if err != nil {
		writeV1Error(w, http.StatusBadRequest, err)
		return
	}
	writeV1OK(w, map[string]any{"deleted": req.ID})
}

func (s *Server) handleProfileSave(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeV1Error(w, http.StatusMethodNotAllowed, errors.New("POST required"))
		return
	}
	var req config.SaveProfileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeV1Error(w, http.StatusBadRequest, err)
		return
	}
	pf, err := s.ReloadProfiles()
	if err == nil {
		err = upsertProfile(&pf, req)
	}
	if err == nil {
		err = s.SaveProfiles(pf)
	}
	if err != nil {
		writeV1Error(w, http.StatusBadRequest, err)
		return
	}
	writeV1OK(w, map[string]any{"selected_id": req.ID, "restart": req.Restart})
}

// SetControlHandler registers a callback for WebUI start/stop/restart commands.
func (s *Server) SetControlHandler(h ControlHandler) {
	s.controlHandler.Store(&h)
}

func (s *Server) handleControl(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeV1Error(w, http.StatusMethodNotAllowed, errors.New("POST required"))
		return
	}
	var req struct {
		Action string `json:"action"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeV1Error(w, http.StatusBadRequest, err)
		return
	}
	action := strings.TrimSpace(strings.ToLower(req.Action))
	// Dispatch to registered handler
	h := s.controlHandler.Load()
	if h != nil {
		(*h)(action)
	}
	writeV1OK(w, map[string]any{"action": action, "status": "acknowledged"})
}

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	// Extract log name from path: /api/v1/logs/{name}[/clear]
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/logs/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		writeV1Error(w, http.StatusBadRequest, errors.New("log name required"))
		return
	}
	name := parts[0]

	// Clear endpoint: POST /api/v1/logs/{name}/clear
	if len(parts) == 2 && parts[1] == "clear" {
		if r.Method != http.MethodPost {
			writeV1Error(w, http.StatusMethodNotAllowed, errors.New("POST required"))
			return
		}
		path := filepath.Join(s.runDir, name+".log")
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
		if err != nil {
			writeV1Error(w, http.StatusInternalServerError, err)
			return
		}
		_ = f.Close()
		writeV1OK(w, map[string]any{"cleared": name})
		return
	}

	// Read log
	path := filepath.Join(s.runDir, name+".log")
	serveLogFile(w, path)
}

func (s *Server) handleAutostart(w http.ResponseWriter, r *http.Request) {
	marker := filepath.Join(s.runDir, "autostart")
	switch r.Method {
	case http.MethodGet:
		_, err := os.Stat(marker)
		writeV1OK(w, map[string]any{"enabled": err == nil})
	case http.MethodPost, http.MethodPut:
		var req struct {
			Enabled bool `json:"enabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeV1Error(w, http.StatusBadRequest, err)
			return
		}
		if req.Enabled {
			_ = os.WriteFile(marker, []byte("1\n"), 0644)
		} else {
			_ = os.Remove(marker)
		}
		writeV1OK(w, map[string]any{"enabled": req.Enabled})
	default:
		writeV1Error(w, http.StatusMethodNotAllowed, errors.New("GET, POST, or PUT required"))
	}
}

func (s *Server) handlePublicIP(w http.ResponseWriter, r *http.Request) {
	snap := s.state.Snapshot()
	running, _ := snap["running"].(bool)
	connected, _ := snap["connected"].(bool)
	if !running || !connected {
		writeV1OK(w, map[string]any{
			"tunnel": map[string]any{
				"ok":         false,
				"ip":         "",
				"error":      "tunnel not connected",
				"checked_at": time.Now().Format(time.RFC3339),
			},
		})
		return
	}

	socksAddr, _ := snap["socks_addr"].(string)
	if socksAddr == "" {
		socksAddr = "127.0.0.1:1080"
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	start := time.Now()
	conn, err := socks5Connect(ctx, socksAddr, "api.ipify.org", 80)
	if err != nil {
		writeV1OK(w, map[string]any{
			"tunnel": map[string]any{
				"ok":         false,
				"ip":         "",
				"error":      err.Error(),
				"checked_at": time.Now().Format(time.RFC3339),
			},
		})
		return
	}
	defer conn.Close()
	dialLatency := time.Since(start)

	// Send HTTP GET
	req := "GET /?format=json HTTP/1.1\r\nHost: api.ipify.org\r\nConnection: close\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		writeV1OK(w, map[string]any{
			"tunnel": map[string]any{
				"ok":         false,
				"ip":         "",
				"error":      err.Error(),
				"checked_at": time.Now().Format(time.RFC3339),
			},
		})
		return
	}

	// Read response
	resp := make([]byte, 4096)
	n, err := conn.Read(resp)
	if err != nil && err.Error() != "EOF" {
		writeV1OK(w, map[string]any{
			"tunnel": map[string]any{
				"ok":         false,
				"ip":         "",
				"error":      err.Error(),
				"checked_at": time.Now().Format(time.RFC3339),
			},
		})
		return
	}
	body := string(resp[:n])

	// Extract IP from JSON body
	ip := extractIPFromHTTP(body)

	writeV1OK(w, map[string]any{
		"tunnel": map[string]any{
			"ok":         true,
			"ip":         ip,
			"latency_ms": dialLatency.Milliseconds(),
			"checked_at": time.Now().Format(time.RFC3339),
		},
	})
}

// extractIPFromHTTP parses the IP from an HTTP response body containing
// JSON like {"ip":"1.2.3.4"}. It skips HTTP headers to find the JSON body.
func extractIPFromHTTP(body string) string {
	// Find the start of JSON body (after headers: \r\n\r\n)
	idx := strings.Index(body, "\r\n\r\n")
	if idx >= 0 {
		body = body[idx+4:]
	}
	// Find {"ip":"x.x.x.x"} pattern
	idx = strings.Index(body, `"ip":"`)
	if idx < 0 {
		return ""
	}
	idx += 6 // skip past "ip":"
	end := strings.Index(body[idx:], `"`)
	if end < 0 {
		return ""
	}
	return body[idx : idx+end]
}

// handleTestUDP sends a test UDP packet to a public server (1.1.1.1:53 by
// default) so the user can verify the MOUT chain + TPROXY pipeline is
// working. After calling this, the SSHC_MOUT MARK rule and SSHC_PRE TPROXY
// rule packet counts should increase.
func (s *Server) handleTestUDP(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("target")
	if target == "" {
		target = "1.1.1.1:53"
	}
	addr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		writeV1Error(w, http.StatusBadRequest, err)
		return
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		writeV1OK(w, map[string]any{
			"ok": false,
			"error": err.Error(),
			"target": target,
		})
		return
	}
	defer conn.Close()
	// Send 5 packets spaced 100ms apart for reliability
	for i := 0; i < 5; i++ {
		_, _ = conn.Write([]byte("SSHC-UDP-TEST"))
		time.Sleep(100 * time.Millisecond)
	}
	writeV1OK(w, map[string]any{
		"ok": true,
		"target": target,
		"packets_sent": 5,
		"note": "Check log for [iptables] === SSHC_MOUT chain === to see if MARK counter increased. Then check UDP Flows counter — it should be > 0 if pipeline works.",
	})
}

// handleUDPCounters returns the iptables packet/byte counters for the MOUT,
// PRE, and OUT chains so the user can verify whether UDP packets are being
// marked and TPROXY'd. This is the definitive way to debug UDP capture.
func (s *Server) handleUDPCounters(w http.ResponseWriter, r *http.Request) {
	result := map[string]any{}

	mout, err := exec.Command("iptables", "-w", "10", "-t", "mangle", "-L", "SSHC_MOUT", "-n", "-v").Output()
	if err == nil {
		result["ssch_mout"] = string(mout)
	} else {
		result["ssch_mout_error"] = err.Error()
	}
	pre, err := exec.Command("iptables", "-w", "10", "-t", "mangle", "-L", "SSHC_PRE", "-n", "-v").Output()
	if err == nil {
		result["ssch_pre"] = string(pre)
	}
	out, err := exec.Command("iptables", "-w", "10", "-t", "mangle", "-L", "OUTPUT", "-n", "-v", "--line-numbers").Output()
	if err == nil {
		result["mangle_output"] = string(out)
	}
	rule, err := exec.Command("ip", "rule", "show").Output()
	if err == nil {
		result["ip_rule"] = string(rule)
	}
	route, err := exec.Command("ip", "route", "show", "table", "100").Output()
	if err == nil {
		result["ip_route_table_100"] = string(route)
	}
	writeV1OK(w, result)
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeV1Error(w, http.StatusInternalServerError, errors.New("streaming unsupported"))
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache, no-transform")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	send := func(event string, payload any) bool {
		data, err := json.Marshal(payload)
		if err != nil {
			return false
		}
		if event != "" {
			if _, err := fmt.Fprintf(w, "event: %s\n", event); err != nil {
				return false
			}
		}
		if _, err := fmt.Fprintf(w, "data: %s\n\n", data); err != nil {
			return false
		}
		flusher.Flush()
		return true
	}

	statusPayload := func() map[string]any {
		cfg := s.GetConfig()
		return map[string]any{
			"runtime":      s.state.Snapshot(),
			"config":       configSummary(cfg),
			"capabilities": apiCapabilities(cfg),
			"paths": map[string]string{
				"work_dir":      s.workDir,
				"config_path":   s.cfgPath,
				"profiles_path": s.pfPath,
				"run_dir":       s.runDir,
				"webroot":       filepath.Join(s.workDir, "webroot"),
			},
		}
	}

	if !send("status", statusPayload()) {
		return
	}

	ch, cleanup := s.state.Subscribe()
	defer cleanup()

	heartbeat := time.NewTicker(25 * time.Second)
	defer heartbeat.Stop()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ch:
			if !send("status", statusPayload()) {
				return
			}
		case <-heartbeat.C:
			if _, err := w.Write([]byte(": ping\n\n")); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

func (s *Server) handleCaptivePortal(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

// ── Profile upsert helper ──────────────────────────────────────────────────

func upsertProfile(pf *config.ProfilesFile, req config.SaveProfileRequest) error {
	req.ID = strings.TrimSpace(req.ID)
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		req.Name = "SSHCustom Profile"
	}

	creatingNew := req.ID == ""
	if req.ID == "" {
		req.ID = config.UniqueProfileID(pf, config.Slugify(req.Name))
	}
	if strings.TrimSpace(req.SSH.Host) == "" {
		return errors.New("SSH host is required")
	}
	if req.SSH.Port <= 0 || req.SSH.Port > 65535 {
		return errors.New("SSH port must be 1-65535")
	}
	if strings.TrimSpace(req.SSH.Username) == "" {
		return errors.New("SSH username is required")
	}

	mode := transport.NormalizeMode(req.Transport.Mode)
	if mode == "" {
		return errors.New("invalid transport mode")
	}

	// Find existing or build new
	idx := -1
	if !creatingNew {
		for i, p := range pf.Profiles {
			if p.ID == req.ID {
				idx = i
				break
			}
		}
	}

	oldPassword := ""
	if idx >= 0 {
		oldPassword = pf.Profiles[idx].SSH.Password
	}
	if req.SSH.Password == "" {
		req.SSH.Password = oldPassword
	}
	if req.SSH.AuthType == "" {
		req.SSH.AuthType = "password"
	}

	profile := config.Profile{ID: req.ID, Name: req.Name, SSH: req.SSH}
	profile.Transport = buildTransport(mode, req.Transport.Payload, req.Transport.HTTPProxy, req.Transport.TLS, profile.SSH)

	if idx >= 0 {
		pf.Profiles[idx] = profile
	} else {
		pf.Profiles = append(pf.Profiles, profile)
	}
	if req.Select || pf.SelectedID == "" || pf.SelectedID == req.ID {
		_ = pf.SelectByID(req.ID)
	}
	return nil
}

func buildTransport(mode string, payload config.PayloadCfg, hp *config.HTTPProxyCfg, tlsCfg *config.TLSCfg, ssh config.SSH) config.Transport {
	if payload.SendTiming == "" {
		switch mode {
		case "http_proxy":
			payload.SendTiming = "after_proxy_socket_before_ssh"
		case "tls_sni", "http_proxy_tls_sni":
			payload.SendTiming = "after_tls_before_ssh"
		default:
			payload.SendTiming = "before_ssh"
		}
	}
	if len(payload.AllowStatuses) == 0 {
		payload.AllowStatuses = []int{101, 200, 204, 302}
	}

	chain := []string{"tcp"}
	var outHP *config.HTTPProxyCfg
	var outTLS *config.TLSCfg

	if mode == "http_proxy" || mode == "http_proxy_tls_sni" {
		proxy := config.HTTPProxyCfg{Host: ssh.Host, Port: ssh.Port, ConnectMethod: "socket"}
		if hp != nil {
			proxy = *hp
		}
		if proxy.Host == "" {
			proxy.Host = ssh.Host
		}
		if proxy.Port <= 0 {
			proxy.Port = ssh.Port
		}
		if proxy.ConnectMethod == "" {
			proxy.ConnectMethod = "socket"
		}
		if mode == "http_proxy_tls_sni" && proxy.Port == 80 {
			proxy.Port = 443
		}
		outHP = &proxy
		chain = append(chain, "http_proxy")
	}
	if mode == "tls_sni" || mode == "http_proxy_tls_sni" {
		tc := config.TLSCfg{Enabled: true, ServerName: ssh.Host, InsecureSkipVerify: true, ALPN: []string{"http/1.1"}}
		if tlsCfg != nil {
			tc = *tlsCfg
		}
		if tc.ServerName == "" {
			tc.ServerName = ssh.Host
		}
		if len(tc.ALPN) == 0 {
			tc.ALPN = []string{"http/1.1"}
		}
		tc.Enabled = true
		outTLS = &tc
		chain = append(chain, "tls")
	}
	if payload.Enabled {
		chain = append(chain, "payload")
	}
	chain = append(chain, "ssh")

	return config.Transport{Mode: mode, Chain: chain, HTTPProxy: outHP, TLS: outTLS, Payload: payload}
}

// ── JSON response helpers ──────────────────────────────────────────────────

func writeV1OK(w http.ResponseWriter, data any) {
	writeJSON(w, apiv1.Envelope{APIVersion: apiv1.Version, OK: true, Data: data})
}

func writeV1Error(w http.ResponseWriter, code int, err error) {
	w.WriteHeader(code)
	writeJSON(w, apiv1.Envelope{APIVersion: apiv1.Version, OK: false, Error: err.Error()})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

// ── Config summary / capabilities ─────────────────────────────────────────

func configSummary(cfg config.Config) map[string]any {
	return map[string]any{
		"api": map[string]any{
			"host": cfg.API.Host,
			"port": cfg.API.Port,
		},
		"dns": map[string]any{
			"mode":            cfg.DNS.Mode,
			"servers":         cfg.DNS.Servers,
			"timeout_seconds": cfg.DNS.TimeoutSec,
		},
		"hotspot": map[string]any{
			"enabled":    cfg.Hotspot.Enabled,
			"tcp":        cfg.Hotspot.TCP,
			"dns":        cfg.Hotspot.DNS,
			"interfaces": cfg.Hotspot.Interfaces,
		},
		"local_proxy": map[string]any{
			"socks_enabled": cfg.LocalProxy.SocksEnabled,
			"socks_host":    cfg.LocalProxy.SocksHost,
			"socks_port":    cfg.LocalProxy.SocksPort,
		},
		"transparent_proxy": map[string]any{
			"enabled":       cfg.TransparentProxy.Enabled,
			"tcp_port":      cfg.TransparentProxy.TCPPort,
			"udp_port":      cfg.TransparentProxy.UDPPort,
			"chains_prefix": cfg.TransparentProxy.ChainsPrefix,
		},
	}
}

func apiCapabilities(cfg config.Config) []apiv1.Capability {
	return []apiv1.Capability{
		{Name: "tproxy_tcp", Enabled: cfg.TransparentProxy.Enabled, Description: "TPROXY-based transparent TCP tunneling"},
		{Name: "tproxy_udp", Enabled: cfg.TransparentProxy.Enabled, Description: "TPROXY-based UDP tunneling via BadVPN UDPGW"},
		{Name: "hotspot_tcp", Enabled: cfg.Hotspot.Enabled && cfg.Hotspot.TCP, Description: "TCP sharing for tethered clients"},
		{Name: "hotspot_udp", Enabled: cfg.Hotspot.Enabled, Description: "UDP sharing for tethered clients"},
		{Name: "socks5", Enabled: cfg.LocalProxy.SocksEnabled, Description: "local SOCKS5 proxy (RFC 1928 + RFC 1929)"},
		{Name: "quic_block", Enabled: cfg.TransparentProxy.Enabled, Description: "drops UDP 443/80 so QUIC apps fall back to TCP"},
		{Name: "ipv6_disable", Enabled: cfg.TransparentProxy.Enabled, Description: "disables IPv6 while active to prevent leaks"},
		{Name: "captive_portal_bypass", Enabled: cfg.TransparentProxy.Enabled, Description: "localhost 204 server for captive portal bypass"},
		{Name: "ssh_payload_injection", Enabled: cfg.Transport.PayloadIsCore, Description: "inject HTTP payload before SSH handshake"},
		{Name: "udpgw", Enabled: true, Description: "BadVPN UDPGW wire protocol on port " + strconv.Itoa(cfg.TransparentProxy.UDPPort)},
	}
}

// ── Log serving ────────────────────────────────────────────────────────────

func serveLogFile(w http.ResponseWriter, path string) {
	const maxRead = 65536
	stat, err := os.Stat(path)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	f, err := os.Open(path)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer f.Close()

	var b []byte
	if stat.Size() > maxRead {
		offset := stat.Size() - maxRead
		_, _ = f.Seek(offset, io.SeekStart)
		b = make([]byte, maxRead)
		_, err = io.ReadFull(f, b)
		if err != nil && err != io.EOF {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		b, err = io.ReadAll(f)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write(b)
}

// ── CORS ───────────────────────────────────────────────────────────────────

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
