// Package config holds the daemon's configuration and profile types,
// plus helpers for loading, saving, normalizing, and validating.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// ── Config ─────────────────────────────────────────────────────────────────

type Config struct {
	Module struct {
		Name        string `json:"name"`
		WorkDir     string `json:"work_dir"`
		LogDir      string `json:"log_dir"`
		ManualStart bool   `json:"manual_start"`
	} `json:"module"`
	API struct {
		Enabled bool   `json:"enabled"`
		Host    string `json:"host"`
		Port    int    `json:"port"`
	} `json:"api"`
	DNS struct {
		Enabled    bool     `json:"enabled"`
		Mode       string   `json:"mode"`
		Hijack     bool     `json:"hijack"`
		DoH        bool     `json:"doh"`
		Servers    []string `json:"servers"`
		TimeoutSec int      `json:"timeout_seconds"`
		Note       string   `json:"note"`
	} `json:"dns"`
	Transport struct {
		SupportedModes []string `json:"supported_modes"`
		PayloadIsCore  bool     `json:"payload_is_core_feature"`
	} `json:"transport"`
	LocalProxy struct {
		SocksEnabled bool   `json:"socks_enabled"`
		SocksHost    string `json:"socks_host"`
		SocksPort    int    `json:"socks_port"`
	} `json:"local_proxy"`
	TransparentProxy struct {
		Enabled         bool   `json:"enabled"`
		TCPPort         int    `json:"tcp_port"`
		ChainsPrefix    string `json:"chains_prefix"`
		ApplyAfterSSH   bool   `json:"apply_after_ssh_connected"`
	} `json:"transparent_proxy"`
	Hotspot struct {
		Enabled    bool     `json:"enabled"`
		TCP        bool     `json:"tcp"`
		DNS        bool     `json:"dns"`
		Interfaces []string `json:"interfaces"`
	} `json:"hotspot"`
	Performance struct {
		BufferSize          int  `json:"buffer_size"`
		ConnectTimeoutSec   int  `json:"connect_timeout_seconds"`
		KeepAliveSec        int  `json:"keepalive_seconds"`
		SSHPoolSize         int  `json:"ssh_pool_size"`
		MaxStreamsPerSSH    int  `json:"max_streams_per_ssh"`
		StreamIdleTimeoutSec int  `json:"stream_idle_timeout_seconds"`
		VerboseTransparentLogs bool `json:"verbose_transparent_logs"`
		MemoryLimitMB       int  `json:"memory_limit_mb"`
	} `json:"performance"`
}

// DefaultConfig returns a config with sensible defaults for a new install.
func DefaultConfig() Config {
	var cfg Config
	cfg.Module.Name = "SSHCustom-Magisk"
	cfg.Module.WorkDir = "/data/adb/sshcustom"
	cfg.Module.LogDir = "/data/adb/sshcustom/run"
	cfg.Module.ManualStart = true
	cfg.API.Enabled = true
	cfg.API.Host = "127.0.0.1"
	cfg.API.Port = 9190
	cfg.DNS.Mode = "device"
	cfg.DNS.TimeoutSec = 4
	cfg.Transport.SupportedModes = []string{"direct", "http_proxy", "tls_sni", "http_proxy_tls_sni"}
	cfg.Transport.PayloadIsCore = true
	cfg.LocalProxy.SocksEnabled = true
	cfg.LocalProxy.SocksHost = "127.0.0.1"
	cfg.LocalProxy.SocksPort = 1080
	cfg.TransparentProxy.Enabled = true
	cfg.TransparentProxy.TCPPort = 10810
	cfg.TransparentProxy.ChainsPrefix = "SSHC"
	cfg.TransparentProxy.ApplyAfterSSH = true
	cfg.Hotspot.Enabled = true
	cfg.Hotspot.TCP = true
	cfg.Hotspot.Interfaces = []string{"wlan+", "swlan+", "ap+", "rndis+", "ncm+", "bt-pan+"}
	cfg.Performance.BufferSize = 131072
	cfg.Performance.ConnectTimeoutSec = 25
	cfg.Performance.KeepAliveSec = 15
	cfg.Performance.SSHPoolSize = 1
	cfg.Performance.MaxStreamsPerSSH = 256
	cfg.Performance.StreamIdleTimeoutSec = 120
	cfg.Performance.MemoryLimitMB = 0 // 0 means use Go's default (previously hardcoded 96MB)
	return cfg
}

// Normalize fills in missing defaults for a user-provided config.
func (c *Config) Normalize() {
	if c.DNS.Mode == "" {
		c.DNS.Mode = "device"
	}
	if c.DNS.TimeoutSec <= 0 {
		c.DNS.TimeoutSec = 4
	}
	if len(c.Hotspot.Interfaces) == 0 {
		c.Hotspot.Interfaces = []string{"wlan+", "swlan+", "ap+", "rndis+", "ncm+", "bt-pan+"}
	}
	if c.TransparentProxy.TCPPort <= 0 {
		c.TransparentProxy.TCPPort = 10810
	}
	if c.TransparentProxy.ChainsPrefix == "" {
		c.TransparentProxy.ChainsPrefix = "SSHC"
	}
	if c.Performance.BufferSize <= 0 {
		c.Performance.BufferSize = 128 * 1024
	}
	if c.Performance.KeepAliveSec <= 0 {
		c.Performance.KeepAliveSec = 15
	}
	if c.Performance.ConnectTimeoutSec <= 0 {
		c.Performance.ConnectTimeoutSec = 20
	}
	if c.Performance.MaxStreamsPerSSH <= 0 {
		c.Performance.MaxStreamsPerSSH = 256
	}
	if c.Performance.StreamIdleTimeoutSec <= 0 {
		c.Performance.StreamIdleTimeoutSec = 120
	}
	if c.LocalProxy.SocksPort <= 0 {
		c.LocalProxy.SocksPort = 1080
	}
}

// LoadConfig reads and normalizes a config file.
func LoadConfig(path string) (Config, error) {
	var cfg Config
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, err
	}
	cfg.Normalize()
	return cfg, nil
}

// SaveConfig atomically writes config to path.
func SaveConfig(path string, cfg Config) error {
	cfg.Normalize()
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ── Profiles ────────────────────────────────────────────────────────────────

type ProfilesFile struct {
	SelectedID string    `json:"selected_id"`
	Profiles   []Profile `json:"profiles"`
}

type Profile struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Selected  bool       `json:"selected,omitempty"`
	SSH       SSH        `json:"ssh"`
	Transport Transport  `json:"transport"`
}

type SSH struct {
	Host        string   `json:"host"`
	Port        int      `json:"port"`
	Username    string   `json:"username"`
	Password    string   `json:"password,omitempty"`
	AuthType    string   `json:"auth_type"`
	FallbackIPs []string `json:"fallback_ips,omitempty"`
}

type Transport struct {
	Mode      string        `json:"mode"`
	Chain     []string      `json:"chain"`
	HTTPProxy *HTTPProxyCfg `json:"http_proxy,omitempty"`
	TLS       *TLSCfg       `json:"tls,omitempty"`
	Payload   PayloadCfg    `json:"payload"`
}

type HTTPProxyCfg struct {
	Host          string   `json:"host"`
	Port          int      `json:"port"`
	ConnectMethod string   `json:"connect_method"`
	FallbackIPs   []string `json:"fallback_ips,omitempty"`
}

type TLSCfg struct {
	Enabled            bool     `json:"enabled"`
	ServerName         string   `json:"server_name"`
	InsecureSkipVerify bool     `json:"insecure_skip_verify"`
	ALPN               []string `json:"alpn"`
}

type PayloadCfg struct {
	Enabled       bool   `json:"enabled"`
	Template      string `json:"template"`
	SendTiming    string `json:"send_timing"`
	ReadResponse  bool   `json:"read_response"`
	AllowStatuses []int  `json:"allow_http_status"`
}

type SaveProfileRequest struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Select    bool   `json:"select"`
	Restart   bool   `json:"restart"`
	SSH       SSH    `json:"ssh"`
	Transport struct {
		Mode      string        `json:"mode"`
		HTTPProxy *HTTPProxyCfg `json:"http_proxy,omitempty"`
		TLS       *TLSCfg       `json:"tls,omitempty"`
		Payload   PayloadCfg    `json:"payload"`
	} `json:"transport"`
}

// ── Profile helpers ─────────────────────────────────────────────────────────

// SelectedProfile returns the currently selected profile, or the first profile
// if none is marked selected.
func (pf *ProfilesFile) SelectedProfile() *Profile {
	if pf.SelectedID != "" {
		for i := range pf.Profiles {
			if pf.Profiles[i].ID == pf.SelectedID {
				return &pf.Profiles[i]
			}
		}
	}
	for i := range pf.Profiles {
		if pf.Profiles[i].Selected {
			return &pf.Profiles[i]
		}
	}
	if len(pf.Profiles) > 0 {
		return &pf.Profiles[0]
	}
	return nil
}

// SelectByID marks a profile as selected.
func (pf *ProfilesFile) SelectByID(id string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return errors.New("selected_id is required")
	}
	found := false
	for i := range pf.Profiles {
		pf.Profiles[i].Selected = pf.Profiles[i].ID == id
		if pf.Profiles[i].Selected {
			found = true
		}
	}
	if !found {
		return fmt.Errorf("profile not found: %s", id)
	}
	pf.SelectedID = id
	return nil
}

// DeleteProfile removes a profile by ID.
func (pf *ProfilesFile) DeleteProfile(id string) error {
	idx := -1
	for i, p := range pf.Profiles {
		if p.ID == id {
			idx = i
			break
		}
	}
	if idx < 0 {
		return errors.New("profile not found")
	}
	pf.Profiles = append(pf.Profiles[:idx], pf.Profiles[idx+1:]...)
	if pf.SelectedID == id {
		pf.SelectedID = ""
	}
	return nil
}

// LoadProfiles reads profiles from disk.
func LoadProfiles(path string) (ProfilesFile, error) {
	var pf ProfilesFile
	data, err := os.ReadFile(path)
	if err != nil {
		return pf, err
	}
	if err := json.Unmarshal(data, &pf); err != nil {
		return pf, err
	}
	return pf, nil
}

// SaveProfiles atomically writes profiles to disk.
func SaveProfiles(path string, pf ProfilesFile) error {
	b, err := json.MarshalIndent(pf, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ── Utility ─────────────────────────────────────────────────────────────────

func SecondsDefault(v, def int) int {
	if v <= 0 {
		return def
	}
	return v
}

// Slugify converts a string into a URL-friendly slug.
func Slugify(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	lastDash := false
	for _, r := range s {
		ok := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
		if ok {
			b.WriteRune(r)
			lastDash = false
			continue
		}
		if !lastDash {
			b.WriteByte('-')
			lastDash = true
		}
	}
	return strings.Trim(b.String(), "-")
}

// UniqueProfileID returns a unique ID for a new profile.
func UniqueProfileID(pf *ProfilesFile, base string) string {
	base = strings.Trim(Slugify(base), "-")
	if base == "" {
		base = "profile"
	}
	used := map[string]bool{}
	for _, p := range pf.Profiles {
		used[p.ID] = true
	}
	if !used[base] {
		return base
	}
	for i := 2; i < 10000; i++ {
		candidate := fmt.Sprintf("%s-%d", base, i)
		if !used[candidate] {
			return candidate
		}
	}
	return fmt.Sprintf("%s-%d", base, time.Now().Unix())
}
