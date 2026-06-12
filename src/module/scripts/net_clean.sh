#!/system/bin/sh
#
# Belt-and-suspenders iptables cleanup. The Go daemon does its own cleanup
# in iptables.Cleanup() during shutdown, but if the daemon crashed or was
# killed mid-rule, leftover SSHC_* chains could remain and silently break
# the device's networking. This script is callable from sshcustom.sh stop
# and from customize.sh during a fresh install to guarantee a clean slate.
#
# v2.8.0: Updated chain names to match Go daemon (SSHC_OUT, SSHC_PRE, etc.)
#          Fixed IPv6 cleanup to use filter table (matching Go daemon's ip6tables rules)
#          Added SSHC_TPROXY to chain list
#
# Removes every SSHC_* chain name from both IPv4 and IPv6 tables,
# plus the FORWARD ACCEPT rule that hotspot mode adds. Errors are
# silenced because every -D against a missing rule is harmless noise.

RUN_DIR="/data/adb/sshcustom/run"
LOG="$RUN_DIR/net_clean.log"
mkdir -p "$RUN_DIR"

IPT="iptables -w 100"
IP6T="ip6tables -w 100"
# Every chain SSHCustom-Magisk has ever installed in any version.
# V2.8.0 chains (current):
#   SSHC_OUT  - nat OUTPUT REDIRECT (local TCP)
#   SSHC_PRE  - mangle PREROUTING TPROXY (hotspot TCP+UDP)
#   SSHC_DNS  - nat DNS DNAT
# Legacy chains from v2.6.x and earlier kept for upgrade cleanup:
#   SSHC_OUTPUT, SSHC_PREROUTING, SSHC_PROXY, SSHC_HOTSPOT, SSHC_HOTSPOT_DNS
CHAINS="SSHC_OUT SSHC_PRE SSHC_DNS SSHC_TPROXY SSHC_OUTPUT SSHC_PREROUTING SSHC_PROXY SSHC_HOTSPOT SSHC_HOTSPOT_DNS"
IFACES="wlan+ swlan+ ap+ rndis+ ncm+ bt-pan+"

log() { echo "$(date '+%Y-%m-%d %H:%M:%S') $*" >> "$LOG"; }
run() { "$@" >/dev/null 2>&1; }

clean_v4() {
  for C in $CHAINS; do
    # Detach from nat table
    run $IPT -t nat -D OUTPUT -p tcp -j "$C"
    run $IPT -t nat -D OUTPUT -j "$C"
    run $IPT -t nat -D OUTPUT -p udp --dport 53 -j "$C"
    run $IPT -t nat -D PREROUTING -p tcp -j "$C"
    run $IPT -t nat -D PREROUTING -j "$C"
    run $IPT -t nat -D PREROUTING -p udp --dport 53 -j "$C"
    for IF in $IFACES; do
      run $IPT -t nat -D PREROUTING -i "$IF" -p tcp -j "$C"
      run $IPT -t nat -D PREROUTING -i "$IF" -j "$C"
      run $IPT -t nat -D PREROUTING -i "$IF" -p udp --dport 53 -j "$C"
    done
    # Detach from mangle table
    run $IPT -t mangle -D PREROUTING -j "$C"
    run $IPT -t mangle -D PREROUTING -p tcp -m socket --transparent -j "$C"
    run $IPT -t mangle -D OUTPUT -j "$C"
  done
  # Destroy chains in nat table
  for C in $CHAINS; do
    run $IPT -t nat -F "$C"
    run $IPT -t nat -X "$C"
  done
  # Destroy chains in mangle table
  for C in $CHAINS SSHC_DROP6; do
    run $IPT -t mangle -F "$C"
    run $IPT -t mangle -X "$C"
  done
  # DIVERT chain
  run $IPT -t mangle -D PREROUTING -p tcp -m socket --transparent -j DIVERT
  run $IPT -t mangle -F DIVERT
  run $IPT -t mangle -X DIVERT
  # FORWARD ACCEPT (hotspot)
  run $IPT -D FORWARD -j ACCEPT
}

clean_v6() {
  for C in $CHAINS SSHC_DROP6; do
    # Detach from filter table (SSHC_DROP6 lives here)
    run $IP6T -t filter -D OUTPUT -j "$C"
    run $IP6T -t filter -D FORWARD -j "$C"
  done
  for C in $CHAINS; do
    # Detach legacy nat rules if any
    run $IP6T -t nat -D OUTPUT -p tcp -j "$C"
    run $IP6T -t nat -D OUTPUT -j "$C"
    run $IP6T -t nat -D PREROUTING -p tcp -j "$C"
    run $IP6T -t nat -D PREROUTING -j "$C"
    for IF in $IFACES; do
      run $IP6T -t nat -D PREROUTING -i "$IF" -p tcp -j "$C"
      run $IP6T -t nat -D PREROUTING -i "$IF" -j "$C"
    done
  done
  # Destroy chains
  for C in $CHAINS SSHC_DROP6; do
    run $IP6T -t filter -F "$C"
    run $IP6T -t filter -X "$C"
    run $IP6T -t nat -F "$C"
    run $IP6T -t nat -X "$C"
  done
}

clean_quic() {
  # Remove DROP and REJECT variants across all prior builds (loop for stacked dupes).
  for P in 443 80; do
    i=0
    while [ "$i" -lt 4 ]; do
      run $IPT -t filter -D OUTPUT -p udp --dport "$P" -j DROP || break
      i=$((i + 1))
    done
    i=0
    while [ "$i" -lt 4 ]; do
      run $IPT -t filter -D OUTPUT -p udp --dport "$P" -j REJECT --reject-with icmp-port-unreachable || break
      i=$((i + 1))
    done
  done
}

restore_ipv6() {
  run sysctl -w net.ipv6.conf.all.disable_ipv6=0
  run sysctl -w net.ipv6.conf.default.disable_ipv6=0
}

restore_captive_portal() {
  # Re-enable Android's captive-portal detection that the daemon disables
  # while the tunnel is active.
  run settings put global captive_portal_mode 1
  run settings put global captive_portal_detection_enabled 1
  run settings put global captive_portal_use_https 1
  run settings delete global captive_portal_server
  run settings delete global captive_portal_http_url
  run settings delete global captive_portal_https_url
}

log "clean start"
clean_v4
clean_v6
clean_quic
restore_ipv6
restore_captive_portal
log "clean complete"
exit 0
