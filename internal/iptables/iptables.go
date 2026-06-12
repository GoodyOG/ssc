// Package iptables installs SSHCustom transparent-proxy rules.
//
// # Architecture: REDIRECT (local) + TPROXY (forwarded/hotspot)
//
// Android kernels vary wildly in TPROXY support. To be universally compatible:
//
//   nat OUTPUT  → REDIRECT chain: catches locally-generated TCP. Uses REDIRECT
//                 target (works on ALL kernels). SO_ORIGINAL_DST recovers dest.
//
//   mangle PREROUTING → TPROXY chain: catches forwarded/hotspot TCP+UDP traffic
//                 coming in from tether interfaces. TPROXY is available in
//                 PREROUTING on all Android kernels that have xt_TPROXY.
//
//   nat OUTPUT  → DNS DNAT chain: redirects device UDP:53 to local forwarder.
//
//   nat PREROUTING → DNS DNAT: redirects hotspot client UDP:53 to local forwarder.
//
// # Leak prevention
//   - QUIC block (UDP 443/80)
//   - IPv6 disabled
//   - TCP buffer tuning
//   - Captive portal bypass
//
// # Why not TPROXY in OUTPUT?
//   Stock Android kernels DO NOT support TPROXY in mangle OUTPUT.
//   The "iptables: Invalid argument" error means xt_TPROXY is only
//   registered for PREROUTING hooks. REDIRECT is universally available
//   in nat OUTPUT. Box Proxy and AndroidTProxyShell both use this pattern.
package iptables

import (
	"fmt"
	"log"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Config struct {
	ChainsPrefix   string
	TCPPort        int
	APIPort        int
	SocksPort      int
	DNSForwardPort int
	DNSHijack      bool
	Hotspot        bool
	HotspotDNS     bool
	HotspotIfaces  []string
}

const (
	Fwmark     = 0x1
	MarkStr    = "0x1/0x1"
	TableID    = 100
)

const DefaultPrefix = "SSHC"

var DefaultHotspotIfaces = []string{"wlan+", "swlan+", "ap+", "rndis+", "ncm+", "bt-pan+"}

var localCIDRs = []string{
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
	"169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16",
	"224.0.0.0/4", "240.0.0.0/4",
}

// Legacy chains from all versions, cleaned up on start.
func allChains(prefix string) []string {
	return []string{
		prefix + "_OUT", prefix + "_PRE", prefix + "_DNS", prefix + "_MOUT",
		prefix + "_OUTPUT", prefix + "_PREROUTING", prefix + "_PROXY",
		prefix + "_HOTSPOT", prefix + "_HOTSPOT_DNS", prefix + "_TPROXY",
	}
}

// ── Iptables helpers ──────────────────────────────────────────────────────

func ipt(args ...string) (string, error) {
	cmd := exec.Command("iptables", append([]string{"-w", "100"}, args...)...)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func ip6t(args ...string) (string, error) {
	cmd := exec.Command("ip6tables", append([]string{"-w", "100"}, args...)...)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func ruleExists(table, chain string, args ...string) bool {
	_, err := ipt(append([]string{"-t", table, "-C", chain}, args...)...)
	return err == nil
}

func chainExists(table, name string) bool {
	_, err := ipt("-t", table, "-L", name, "-n")
	return err == nil
}

func ensureChain(table, name string) {
	if !chainExists(table, name) {
		ipt("-t", table, "-N", name)
	}
	ipt("-t", table, "-F", name)
}

func addRule(table, chain string, args ...string) {
	ipt(append([]string{"-t", table, "-A", chain}, args...)...)
}

func insRule(table, chain string, args ...string) error {
	_, err := ipt(append([]string{"-t", table, "-I", chain}, args...)...)
	return err
}

func delRule(table, chain string, args ...string) {
	ipt(append([]string{"-t", table, "-D", chain}, args...)...)
}

// ── Apply ─────────────────────────────────────────────────────────────────

func Apply(cfg Config, bypassIPs []string) error {
	prefix := cfg.ChainsPrefix
	if prefix == "" {
		prefix = DefaultPrefix
	}
	tcpPort := cfg.TCPPort
	if tcpPort <= 0 {
		tcpPort = 10810
	}

	redirChain := prefix + "_OUT"  // nat OUTPUT REDIRECT (local TCP)
	tproxyChain := prefix + "_PRE" // mangle PREROUTING TPROXY (hotspot)
	dnsChain := prefix + "_DNS"    // nat DNS DNAT

	// ── Pre-pass ──
	cleanupRules(cfg)

	// ── Phase 1: Policy routing for TPROXY ──────────────────────────────
	setupPolicyRouting()
	setupSysctls()

	// ── Phase 2: nat OUTPUT REDIRECT chain (LOCAL TCP) ──────────────────
	ensureChain("nat", redirChain)

	// uid 0 (daemon) bypasses REDIRECT entirely
	addRule("nat", redirChain, "-m", "owner", "--uid-owner", "0", "-j", "RETURN")

	// Bypass private/local CIDRs
	for _, cidr := range localCIDRs {
		addRule("nat", redirChain, "-d", cidr, "-j", "RETURN")
	}

	// Bypass SSH server IPs
	for _, ip := range bypassIPs {
		ip = strings.TrimSpace(ip)
		if ip != "" {
			addRule("nat", redirChain, "-d", ip, "-j", "RETURN")
		}
	}

	// Bypass daemon's own ports
	for _, p := range []int{cfg.APIPort, cfg.SocksPort, tcpPort} {
		if p > 0 {
			addRule("nat", redirChain, "-p", "tcp", "--dport", strconv.Itoa(p), "-j", "RETURN")
		}
	}

	// DNS bypass (handled by nat DNAT separately)
	if cfg.DNSForwardPort > 0 {
		addRule("nat", redirChain, "-p", "udp", "--dport", "53", "-j", "RETURN")
	}

	// REDIRECT all remaining TCP to daemon
	addRule("nat", redirChain, "-p", "tcp", "-j", "REDIRECT", "--to-ports", strconv.Itoa(tcpPort))

	// Hook into nat OUTPUT at position 1
	delRule("nat", "OUTPUT", "-p", "tcp", "-j", redirChain)
	if err := insRule("nat", "OUTPUT", "-p", "tcp", "-j", redirChain); err != nil {
		cleanupRules(cfg)
		return fmt.Errorf("hook nat OUTPUT -> %s: %v", redirChain, err)
	}

	// ── Phase 3: mangle PREROUTING TPROXY chain (HOTSPOT TCP+UDP) ───────
	ensureChain("mangle", tproxyChain)

	// Bypass local CIDRs
	for _, cidr := range localCIDRs {
		addRule("mangle", tproxyChain, "-d", cidr, "-j", "RETURN")
	}

	// Bypass SSH server IPs
	for _, ip := range bypassIPs {
		ip = strings.TrimSpace(ip)
		if ip != "" {
			addRule("mangle", tproxyChain, "-d", ip, "-j", "RETURN")
		}
	}

	// Bypass loopback unless marked for proxying (policy routing fallback)
	addRule("mangle", tproxyChain, "-i", "lo", "-m", "mark", "!", "--mark", MarkStr, "-j", "RETURN")

	// DNS bypass
	if cfg.DNSForwardPort > 0 {
		addRule("mangle", tproxyChain, "-p", "udp", "--dport", "53", "-j", "RETURN")
	}

	// TPROXY for TCP
	addRule("mangle", tproxyChain, "-p", "tcp", "-j", "TPROXY",
		"--on-port", strconv.Itoa(tcpPort), "--tproxy-mark", MarkStr)

	// Hook PREROUTING → tproxyChain
	delRule("mangle", "PREROUTING", "-j", tproxyChain)
	if err := insRule("mangle", "PREROUTING", "-j", tproxyChain); err != nil {
		cleanupRules(cfg)
		return fmt.Errorf("hook mangle PREROUTING -> %s: %v", tproxyChain, err)
	}

	// ── Phase 4: DIVERT (TPROXY socket-transparent bypass) ───────────────
	ensureChain("mangle", "DIVERT")
	addRule("mangle", "DIVERT", "-j", "MARK", "--set-xmark", MarkStr)
	addRule("mangle", "DIVERT", "-j", "ACCEPT")
	// TCP DIVERT
	delRule("mangle", "PREROUTING", "-p", "tcp", "-m", "socket", "--transparent", "-j", "DIVERT")
	if err := insRule("mangle", "PREROUTING", "-p", "tcp", "-m", "socket", "--transparent", "-j", "DIVERT"); err != nil {
		log.Printf("[iptables] DIVERT TCP insert failed (non-fatal): %v", err)
	}

	// ── Phase 5: DNS hijack ─────────────────────────────────────────────
	if cfg.DNSHijack && cfg.DNSForwardPort > 0 {
		setupDNS(prefix, dnsChain, cfg.DNSForwardPort, cfg.Hotspot, cfg.HotspotDNS, cfg.HotspotIfaces)
	} else {
		log.Println("[iptables] DNS hijack disabled, port 53 traffic not redirected")
	}

	// ── Phase 6: Hotspot ip_forward ─────────────────────────────────────
	if cfg.Hotspot {
		exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").Run()
		if !ruleExists("filter", "FORWARD", "-j", "ACCEPT") {
			ipt("-t", "filter", "-I", "FORWARD", "1", "-j", "ACCEPT")
		}
	}

	// ── Phase 7: Leak prevention ────────────────────────────────────────
	blockQUIC()
	disableIPv6()
	tuneTCP()
	disableCaptivePortal()

	return nil
}

// ── Dump ──────────────────────────────────────────────────────────────────

// Dump returns the current iptables rules for debugging.
func Dump() string {
	var b strings.Builder
	for _, table := range []string{"nat", "mangle", "filter"} {
		out, _ := ipt("-t", table, "-L", "-n", "-v")
		b.WriteString(fmt.Sprintf("=== TABLE %s ===\n%s\n\n", table, out))
	}
	out, _ := exec.Command("ip", "rule", "show").CombinedOutput()
	b.WriteString(fmt.Sprintf("=== IP RULE ===\n%s\n\n", out))
	out, _ = exec.Command("ip", "route", "show", "table", strconv.Itoa(TableID)).CombinedOutput()
	b.WriteString(fmt.Sprintf("=== IP ROUTE TABLE %d ===\n%s\n", TableID, out))
	return b.String()
}

// ── Cleanup ───────────────────────────────────────────────────────────────

func Cleanup(cfg Config) error {
	cleanupRules(cfg)
	cleanupPolicyRouting()
	enableIPv6()
	restoreCaptivePortal()
	return nil
}

func cleanupRules(cfg Config) {
	prefix := cfg.ChainsPrefix
	if prefix == "" {
		prefix = DefaultPrefix
	}
	ifaces := cfg.HotspotIfaces
	if len(ifaces) == 0 {
		ifaces = DefaultHotspotIfaces
	}

	// Detach current hooks
	delRule("nat", "OUTPUT", "-p", "tcp", "-j", prefix+"_OUT")
	delRule("mangle", "PREROUTING", "-j", prefix+"_PRE")
	delRule("mangle", "PREROUTING", "-p", "tcp", "-m", "socket", "--transparent", "-j", "DIVERT")

	// Detach all legacy hooks
	for _, ch := range allChains(prefix) {
		// nat table
		delRule("nat", "OUTPUT", "-p", "tcp", "-j", ch)
		delRule("nat", "OUTPUT", "-j", ch)
		delRule("nat", "OUTPUT", "-p", "udp", "--dport", "53", "-j", ch)
		delRule("nat", "PREROUTING", "-p", "tcp", "-j", ch)
		delRule("nat", "PREROUTING", "-j", ch)
		delRule("nat", "PREROUTING", "-p", "udp", "--dport", "53", "-j", ch)
		for _, iface := range ifaces {
			if iface = strings.TrimSpace(iface); iface != "" {
				delRule("nat", "PREROUTING", "-i", iface, "-p", "tcp", "-j", ch)
				delRule("nat", "PREROUTING", "-i", iface, "-j", ch)
				delRule("nat", "PREROUTING", "-i", iface, "-p", "udp", "--dport", "53", "-j", ch)
			}
		}
		// mangle table
		delRule("mangle", "PREROUTING", "-j", ch)
		delRule("mangle", "OUTPUT", "-j", ch)

		// Destroy
		ipt("-t", "nat", "-F", ch)
		ipt("-t", "nat", "-X", ch)
		ipt("-t", "mangle", "-F", ch)
		ipt("-t", "mangle", "-X", ch)
	}

	// DIVERT
	ipt("-t", "mangle", "-F", "DIVERT")
	ipt("-t", "mangle", "-X", "DIVERT")

	delRule("filter", "FORWARD", "-j", "ACCEPT")
	unblockQUIC()
}

// ── Policy Routing ───────────────────────────────────────────────────────

func setupPolicyRouting() {
	sh("ip rule del fwmark " + strconv.Itoa(Fwmark) + " table " + strconv.Itoa(TableID) + " 2>/dev/null || true")
	sh("ip rule add fwmark " + strconv.Itoa(Fwmark) + " table " + strconv.Itoa(TableID) + " prio 100")
	sh("ip route flush table " + strconv.Itoa(TableID) + " 2>/dev/null || true")
	sh("ip route add local 0.0.0.0/0 dev lo table " + strconv.Itoa(TableID))
}

func cleanupPolicyRouting() {
	sh("ip rule del fwmark " + strconv.Itoa(Fwmark) + " table " + strconv.Itoa(TableID) + " 2>/dev/null || true")
	sh("ip route flush table " + strconv.Itoa(TableID) + " 2>/dev/null || true")
}

func setupSysctls() {
	sh("sysctl -w net.ipv4.conf.all.route_localnet=1 2>/dev/null || echo 1 > /proc/sys/net/ipv4/conf/all/route_localnet")
	sh("sysctl -w net.ipv4.conf.all.rp_filter=0 2>/dev/null || echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter")
	sh("sysctl -w net.ipv4.conf.lo.rp_filter=0 2>/dev/null || echo 0 > /proc/sys/net/ipv4/conf/lo/rp_filter")
	sh("sysctl -w net.ipv4.conf.all.accept_local=1 2>/dev/null || echo 1 > /proc/sys/net/ipv4/conf/all/accept_local")
}

// ── DNS ─────────────────────────────────────────────────────────────────

func setupDNS(prefix, dnsChain string, dnsPort int, hotspot, hotspotDNS bool, ifaces []string) {
	if dnsPort <= 0 {
		return
	}
	ensureChain("nat", dnsChain)
	addRule("nat", dnsChain, "-m", "owner", "--uid-owner", "0", "-j", "RETURN")
	addRule("nat", dnsChain, "-p", "udp", "--dport", "53",
		"-j", "DNAT", "--to-destination", fmt.Sprintf("127.0.0.1:%d", dnsPort))

	delRule("nat", "OUTPUT", "-p", "udp", "--dport", "53", "-j", dnsChain)
	insRule("nat", "OUTPUT", "-p", "udp", "--dport", "53", "-j", dnsChain)

	if hotspot && hotspotDNS {
		if len(ifaces) == 0 {
			ifaces = DefaultHotspotIfaces
		}
		for _, iface := range ifaces {
			if iface = strings.TrimSpace(iface); iface != "" {
				delRule("nat", "PREROUTING", "-i", iface, "-p", "udp", "--dport", "53", "-j", dnsChain)
				insRule("nat", "PREROUTING", "-i", iface, "-p", "udp", "--dport", "53", "-j", dnsChain)
			}
		}
	}
}

// ── QUIC ─────────────────────────────────────────────────────────────────

func blockQUIC() {
	for _, port := range []string{"443", "80"} {
		if !ruleExists("filter", "OUTPUT", "-p", "udp", "--dport", port, "-j", "REJECT", "--reject-with", "icmp-port-unreachable") {
			if _, err := ipt("-t", "filter", "-I", "OUTPUT", "-p", "udp", "--dport", port, "-j", "REJECT", "--reject-with", "icmp-port-unreachable"); err != nil {
				if !ruleExists("filter", "OUTPUT", "-p", "udp", "--dport", port, "-j", "DROP") {
					ipt("-t", "filter", "-I", "OUTPUT", "-p", "udp", "--dport", port, "-j", "DROP")
				}
			}
		}
	}
}

func unblockQUIC() {
	for _, port := range []string{"443", "80"} {
		for i := 0; i < 4; i++ {
			if !ruleExists("filter", "OUTPUT", "-p", "udp", "--dport", port, "-j", "DROP") { break }
			delRule("filter", "OUTPUT", "-p", "udp", "--dport", port, "-j", "DROP")
		}
		for i := 0; i < 4; i++ {
			if !ruleExists("filter", "OUTPUT", "-p", "udp", "--dport", port, "-j", "REJECT", "--reject-with", "icmp-port-unreachable") { break }
			delRule("filter", "OUTPUT", "-p", "udp", "--dport", port, "-j", "REJECT", "--reject-with", "icmp-port-unreachable")
		}
	}
}

// ── IPv6 ─────────────────────────────────────────────────────────────────

func disableIPv6() {
	sh("sysctl -w net.ipv6.conf.all.disable_ipv6=1 2>/dev/null || echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6")
	sh("sysctl -w net.ipv6.conf.default.disable_ipv6=1 2>/dev/null || echo 1 > /proc/sys/net/ipv6/conf/default/disable_ipv6")
	ip6t("-t", "filter", "-N", "SSHC_DROP6")
	ip6t("-t", "filter", "-F", "SSHC_DROP6")
	ip6t("-t", "filter", "-A", "SSHC_DROP6", "-o", "lo", "-j", "RETURN")
	if _, err := ip6t("-t", "filter", "-A", "SSHC_DROP6", "-j", "REJECT", "--reject-with", "icmp6-adm-prohibited"); err != nil {
		ip6t("-t", "filter", "-A", "SSHC_DROP6", "-j", "DROP")
	}
	ip6t("-t", "filter", "-D", "OUTPUT", "-j", "SSHC_DROP6")
	ip6t("-t", "filter", "-I", "OUTPUT", "1", "-j", "SSHC_DROP6")
	ip6t("-t", "filter", "-D", "FORWARD", "-j", "SSHC_DROP6")
	ip6t("-t", "filter", "-I", "FORWARD", "1", "-j", "SSHC_DROP6")
}

func enableIPv6() {
	sh("sysctl -w net.ipv6.conf.all.disable_ipv6=0 2>/dev/null || echo 0 > /proc/sys/net/ipv6/conf/all/disable_ipv6")
	sh("sysctl -w net.ipv6.conf.default.disable_ipv6=0 2>/dev/null || echo 0 > /proc/sys/net/ipv6/conf/default/disable_ipv6")
	ip6t("-t", "filter", "-D", "OUTPUT", "-j", "SSHC_DROP6")
	ip6t("-t", "filter", "-D", "FORWARD", "-j", "SSHC_DROP6")
	ip6t("-t", "filter", "-F", "SSHC_DROP6")
	ip6t("-t", "filter", "-X", "SSHC_DROP6")
}

// ── Captive Portal ───────────────────────────────────────────────────────

func disableCaptivePortal() {
	sh("settings put global captive_portal_mode 0")
	sh("settings put global captive_portal_use_https 0")
	sh("settings put global captive_portal_server 127.0.0.1")
	sh("settings put global captive_portal_http_url \"http://127.0.0.1:9190/generate_204\"")
	sh("settings delete global captive_portal_https_url 2>/dev/null || true")
	sh("ndc resolver clearnetdns 2>/dev/null || true")
	kickRevalidation()
}

func restoreCaptivePortal() {
	resetRevalidation()
	sh("settings put global captive_portal_mode 1")
	sh("settings put global captive_portal_use_https 1")
	sh("settings delete global captive_portal_server 2>/dev/null || true")
	sh("settings delete global captive_portal_http_url 2>/dev/null || true")
	sh("settings delete global captive_portal_https_url 2>/dev/null || true")
}

var (
	revalidateMu   sync.Mutex
	revalidateDone bool
)

func kickRevalidation() {
	revalidateMu.Lock()
	already := revalidateDone
	revalidateDone = true
	revalidateMu.Unlock()
	if already { return }
	go func() {
		time.Sleep(10 * time.Second)
		sh("cmd connectivity reevaluate 2>/dev/null || am broadcast -a android.net.conn.CONNECTIVITY_CHANGE 2>/dev/null")
	}()
}

func resetRevalidation() {
	revalidateMu.Lock()
	revalidateDone = false
	revalidateMu.Unlock()
}

// ── TCP Tuning ───────────────────────────────────────────────────────────

func tuneTCP() {
	sh("sysctl -w net.core.rmem_max=4194304 2>/dev/null || echo 4194304 > /proc/sys/net/core/rmem_max")
	sh("sysctl -w net.core.wmem_max=4194304 2>/dev/null || echo 4194304 > /proc/sys/net/core/wmem_max")
	sh("sysctl -w net.ipv4.tcp_congestion_control=bbr 2>/dev/null || true")
	sh("sysctl -w net.ipv4.tcp_notsent_lowat=131072 2>/dev/null || true")
}

func sh(cmdline string) {
	exec.Command("/system/bin/sh", "-c", cmdline).Run()
}

// LogRules logs the current iptables SSHCustom rules for debugging.
func LogRules(prefix string, tcpPort int) {
	out, err := exec.Command("iptables", "-w", "10", "-t", "nat", "-L", "OUTPUT", "-n", "-v").Output()
	if err == nil {
		log.Printf("[iptables] === nat OUTPUT ===")
		for _, line := range strings.Split(string(out), "\n") {
			if strings.Contains(line, prefix) || strings.Contains(line, "REDIRECT") || strings.Contains(line, "udp") {
				log.Printf("[iptables]   %s", strings.TrimRight(line, " \n\r"))
			}
		}
	}
	out, err = exec.Command("iptables", "-w", "10", "-t", "mangle", "-L", "PREROUTING", "-n", "-v").Output()
	if err == nil {
		log.Printf("[iptables] === mangle PREROUTING (SSHC rules) ===")
		for _, line := range strings.Split(string(out), "\n") {
			if strings.Contains(line, prefix) || strings.Contains(line, "TPROXY") || strings.Contains(line, "DIVERT") {
				log.Printf("[iptables]   %s", strings.TrimRight(line, " \n\r"))
			}
		}
	}
	out, err = exec.Command("iptables", "-w", "10", "-t", "nat", "-L", "SSHC_OUT", "-n", "-v").Output()
	if err == nil {
		log.Printf("[iptables] === SSHC_OUT chain ===")
		for _, line := range strings.Split(string(out), "\n") {
			log.Printf("[iptables]   %s", strings.TrimRight(line, " \n\r"))
		}
	}
	out, err = exec.Command("iptables", "-w", "10", "-t", "mangle", "-L", "SSHC_PRE", "-n", "-v").Output()
	if err == nil {
		log.Printf("[iptables] === SSHC_PRE chain ===")
		for _, line := range strings.Split(string(out), "\n") {
			log.Printf("[iptables]   %s", strings.TrimRight(line, " \n\r"))
		}
	}
}
