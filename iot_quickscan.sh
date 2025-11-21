#!/usr/bin/env bash
#
# iot_quickscan.sh
# Simple IoT enumeration wrapper — non-destructive by default.
#
# Usage:
#   ./iot_quickscan.sh -t 192.168.1.0/24 -o ./reports --aggressive --firmware ./fw.bin --shodan-api ABC123
#
# Features (safe-by-default):
#  - nmap host discovery + common IoT NSE scripts (non-destructive)
#  - basic UDP/UPnP/SSDP checks
#  - SNMP info (read-only) if available
#  - MQTT/CoAP probes (banner/info)
#  - BLE scan (bettercap/hciconfig) if available (non-intrusive scan)
#  - Firmware analysis steps (binwalk, exiftool) if firmware file provided (local)
#  - Optional shodan lookup (if API key provided)
#  - Aggregates results to a readable text report
#
# IMPORTANT: Only run on targets you have explicit permission to test.
set -euo pipefail
IFS=$'\n\t'

##### Default config #####
PROG=$(basename "$0")
TARGET=""
OUTDIR="./iot_scan_reports"
THREADS=40
AGGRESSIVE=false
FIRMWARE_FILE=""
SHODAN_API=""
VERBOSE=false
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
REPORT=""
TMPDIR=""

##### Helpers #####
log() {
  local lvl="$1"; shift
  local msg="$*"
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$lvl] $msg"
  if [[ -n "$REPORT" ]]; then
    printf "[%s] [%s] %s\n" "$(date '+%Y-%m-%d %H:%M:%S')" "$lvl" "$msg" >> "$REPORT"
  fi
}

usage() {
  cat <<EOF
$PROG - Simple IoT enumeration & report generator (safe-by-default)

Usage:
  $PROG -t <target> [options]

Options:
  -t, --target        Target IP / CIDR / hostname (e.g. 192.168.1.0/24 or 10.0.0.5)
  -o, --outdir        Output directory (default: ./iot_scan_reports)
  -T, --threads       Threads for nmap/gobuster (default: 40)
  --aggressive        Enable additional checks (may be more noisy)
  --firmware <file>   Local firmware file to analyze (binwalk/exiftool)
  --shodan-api <key>  Shodan API key to do passive lookup (optional)
  -v, --verbose       Verbose mode
  -h, --help          Show this help

Examples:
  $PROG -t 192.168.1.0/24 -o ./reports
  $PROG -t 10.0.0.15 --firmware fw.bin --aggressive
  $PROG -t mycamera.local --shodan-api ABC123

Note: Use only on systems you are authorized to test.
EOF
  exit 1
}

check_tool() {
  command -v "$1" &>/dev/null || return 1
}

mkout() {
  mkdir -p "$OUTDIR"
  TMPDIR=$(mktemp -d)
  REPORT="$OUTDIR/report_${TARGET//\//_}_$TIMESTAMP.txt"
  echo "IoT Quick Scan Report" > "$REPORT"
  echo "Target: $TARGET" >> "$REPORT"
  echo "Generated: $(date)" >> "$REPORT"
  echo "============================================================" >> "$REPORT"
}

cleanup() {
  [[ -n "$TMPDIR" && -d "$TMPDIR" ]] && rm -rf "$TMPDIR"
}
trap cleanup EXIT

##### Parse args #####
while [[ $# -gt 0 ]]; do
  case "$1" in
    -t|--target) TARGET="$2"; shift 2;;
    -o|--outdir) OUTDIR="$2"; shift 2;;
    -T|--threads) THREADS="$2"; shift 2;;
    --aggressive) AGGRESSIVE=true; shift;;
    --firmware) FIRMWARE_FILE="$2"; shift 2;;
    --shodan-api) SHODAN_API="$2"; shift 2;;
    -v|--verbose) VERBOSE=true; shift;;
    -h|--help) usage;;
    *) echo "Unknown arg: $1"; usage;;
  esac
done

if [[ -z "$TARGET" ]]; then
  usage
fi

mkout

log INFO "Starting IoT quick scan for: $TARGET"
log INFO "Output dir: $OUTDIR"
if [[ "$AGGRESSIVE" == true ]]; then log INFO "Aggressive mode: ON (be careful)"; fi
if [[ -n "$FIRMWARE_FILE" ]]; then log INFO "Firmware analysis enabled: $FIRMWARE_FILE"; fi
if [[ -n "$SHODAN_API" ]]; then log INFO "Shodan lookup enabled"; fi

#########################################
# 1) Host discovery (ICMP + ARP)        #
#########################################
log INFO "1) Host discovery (ICMP/ARP)"
if check_tool nmap; then
  NMAP_OUTPUT="$TMPDIR/nmap_discovery.xml"
  log INFO "Running nmap ping sweep on $TARGET (this may take a minute)..."
  # -sn ping scan + ARP host discovery
  nmap -sn -PE -PA21,23,80,3389 -PR --min-rate 1000 -oX "$NMAP_OUTPUT" "$TARGET" || true
  log INFO "nmap discovery saved -> $NMAP_OUTPUT"
  echo -e "\n--- NMAP Discovery (hosts) ---" >> "$REPORT"
  xmllint --format "$NMAP_OUTPUT" 2>/dev/null || true
  # append a simple hosts list
  awk '/<host /{h=1} /<\/host>/{h=0} h{print}' "$NMAP_OUTPUT" 2>/dev/null >> "$REPORT" || true
else
  log WARN "nmap not found — skipping host discovery"
  echo -e "\n[nmap not available]" >> "$REPORT"
fi

#########################################
# 2) Service scan (safe, top ports)     #
#########################################
log INFO "2) Service scan (top common IoT ports)"
SAFE_PORTS="80,443,554,8000,8080,8443,23,22,21,161,1883,5683,1884,53,123"
if check_tool nmap; then
  NMAP_SVC="$TMPDIR/nmap_services.xml"
  # Non-intrusive version: version detection, script discovery limited to safe scripts
  # Uses NSE scripts that are informational only (no brute force)
  NMAP_SCRIPTS="http-title,http-server-header,banner,snmp-info,ssl-cert,amqp-info,mqtt-subscribe,coap-resources,modbus-discover"
  log INFO "Running nmap -sV with safe NSE scripts on discovered hosts (can take some time)..."
  nmap -sV -Pn --top-ports 100 -p "$SAFE_PORTS" --script "$NMAP_SCRIPTS" -oX "$NMAP_SVC" "$TARGET" || true
  log INFO "nmap service scan saved -> $NMAP_SVC"
  echo -e "\n--- NMAP Services (summary) ---" >> "$REPORT"
  xsltproc /usr/share/nmap/nmap.xsl "$NMAP_SVC" 2>/dev/null | sed -n '1,200p' >> "$REPORT" || true
else
  log WARN "nmap missing — service scan skipped"
  echo -e "\n[nmap not available]" >> "$REPORT"
fi

#########################################
# 3) UPnP/SSDP discovery                #
#########################################
log INFO "3) UPnP/SSDP discovery"
if check_tool nmap; then
  # Use nmap's broadcast-upnp-info script and SSDP
  UPnP_OUT="$TMPDIR/upnp.txt"
  nmap -sU -p 1900 --script broadcast-upnp-info --script-args='broadcast.address=239.255.255.250' -oN "$UPnP_OUT" "$TARGET" 2>/dev/null || true
  echo -e "\n--- UPnP/SSDP Results ---" >> "$REPORT"
  cat "$UPnP_OUT" >> "$REPORT" || true
else
  log WARN "nmap not found, cannot run UPnP/SSDP discovery"
  echo -e "\n[UPnP discovery skipped - nmap missing]" >> "$REPORT"
fi

#########################################
# 4) SNMP info (read-only)              #
#########################################
log INFO "4) SNMP read-only checks"
if check_tool nmap; then
  SNMP_OUT="$TMPDIR/snmp.txt"
  # SNMP info (no brute-force); tries public community
  nmap -sU -p 161 --script snmp-info --script-args=snmp.timeout=2 -oN "$SNMP_OUT" "$TARGET" 2>/dev/null || true
  echo -e "\n--- SNMP Info ---" >> "$REPORT"
  cat "$SNMP_OUT" >> "$REPORT" || true
else
  echo -e "\n[SNMP checks skipped - nmap missing]" >> "$REPORT"
fi

#########################################
# 5) MQTT / CoAP quick probes           #
#########################################
log INFO "5) MQTT / CoAP probes"
if check_tool nmap; then
  MQTT_OUT="$TMPDIR/mqtt_coap.txt"
  # mqtt: 1883, coap: 5683
  nmap -sV -p 1883,5683 --script mqtt-subscribe,coap-resources -oN "$MQTT_OUT" "$TARGET" 2>/dev/null || true
  echo -e "\n--- MQTT / CoAP ---" >> "$REPORT"
  cat "$MQTT_OUT" >> "$REPORT" || true
else
  echo -e "\n[MQTT/CoAP probes skipped - nmap missing]" >> "$REPORT"
fi

#########################################
# 6) Web admin panels quick look        #
#########################################
log INFO "6) Web admin pages discovery (HTTP enumeration)"
if check_tool curl; then
  echo -e "\n--- HTTP Admin / Title checks ---" >> "$REPORT"
  # If nmap XML exists, try to extract http ports and probe them for titles
  if [[ -f "$NMAP_SVC" ]]; then
    # crude extraction of IPs with http ports (fallback to TARGET itself)
    grep -oP '(?<=<address addr=")[^"]+' "$NMAP_SVC" 2>/dev/null | sort -u | while read -r host; do
      for p in 80 8080 8000 8443 443 8443; do
        url="http://$host:$p/"
        code=$(curl -sI --max-time 5 "$url" -o /dev/null -w '%{http_code}' || echo "000")
        if [[ "$code" =~ ^2|3 ]]; then
          title=$(curl -sL --max-time 5 "$url" | sed -n '1,200p' | sed -n 's/.*<title>\(.*\)<\/title>.*/\1/p' | head -n1 || true)
          printf "%s %s %s\n" "$host:$p" "$code" "${title:-(no title)}" >> "$REPORT"
        fi
      done
    done || true
  else
    printf "[no nmap service data to enumerate web hosts]\n" >> "$REPORT"
  fi
else
  echo -e "\n[HTTP checks skipped - curl missing]" >> "$REPORT"
fi

#########################################
# 7) Bluetooth LE scan (non-intrusive)  #
#########################################
log INFO "7) Bluetooth LE scan (if tools exist)"
if check_tool hcitool || check_tool btmgmt || check_tool hciconfig; then
  echo -e "\n--- BLE Scan (local adapter) ---" >> "$REPORT"
  if check_tool hcitool; then
    log INFO "Running hcitool lescan (5s) - requires local adapter and permissions"
    timeout 6s sudo hcitool lescan > "$TMPDIR/ble_scan.txt" 2>/dev/null || true
    cat "$TMPDIR/ble_scan.txt" >> "$REPORT" || true
  elif check_tool btmgmt; then
    sudo btmgmt find > "$TMPDIR/ble_scan.txt" 2>/dev/null || true
    cat "$TMPDIR/ble_scan.txt" >> "$REPORT" || true
  else
    echo "[BLE scan not available]" >> "$REPORT"
  fi
else
  echo -e "\n[BLE tools not installed]" >> "$REPORT"
fi

#########################################
# 8) Firmware analysis (local file)     #
#########################################
if [[ -n "$FIRMWARE_FILE" ]]; then
  log INFO "8) Firmware analysis (local file): $FIRMWARE_FILE"
  if [[ ! -f "$FIRMWARE_FILE" ]]; then
    log ERROR "Firmware file not found: $FIRMWARE_FILE"
    echo -e "\n[Firmware file not found]\n" >> "$REPORT"
  else
    FW_BASE="$OUTDIR/firmware_${TIMESTAMP}"
    mkdir -p "$FW_BASE"
    # 8.1: exiftool (metadata)
    if check_tool exiftool; then
      log INFO "Running exiftool on firmware (metadata)"
      exiftool "$FIRMWARE_FILE" > "$FW_BASE/firmware_exif.txt" || true
      echo -e "\n--- Firmware metadata (exiftool) ---" >> "$REPORT"
      sed -n '1,200p' "$FW_BASE/firmware_exif.txt" >> "$REPORT" || true
    fi
    # 8.2: binwalk extraction
    if check_tool binwalk; then
      log INFO "Running binwalk -e on firmware"
      binwalk -e "$FIRMWARE_FILE" -C "$FW_BASE/binwalk_extracted" || true
      echo -e "\n--- Binwalk extraction (list) ---" >> "$REPORT"
      ls -la "$FW_BASE/binwalk_extracted" >> "$REPORT" 2>/dev/null || true
    fi
    # 8.3: search for credentials/files (firmwalker-like)
    log INFO "Searching extracted firmware for likely secrets (strings / common filenames)"
    if [[ -d "$FW_BASE/binwalk_extracted" ]]; then
      grep -R --binary-files=text -iE "password|passwd|api_key|secret|token|username|login" "$FW_BASE/binwalk_extracted" | head -n 200 > "$FW_BASE/possible_secrets.txt" || true
      echo -e "\n--- Potential secret matches (grep) ---" >> "$REPORT"
      sed -n '1,200p' "$FW_BASE/possible_secrets.txt" >> "$REPORT" || true
    fi
  fi
fi

#########################################
# 9) Shodan passive lookup (optional)   #
#########################################
if [[ -n "$SHODAN_API" ]]; then
  log INFO "9) Shodan lookup (passive)"
  if check_tool curl; then
    SHODAN_OUT="$TMPDIR/shodan.json"
    # Query by IP or hostname if possible (simple approach)
    # If the target is a CIDR, skip Shodan bulk queries here.
    if [[ "$TARGET" =~ ^[0-9]+\.[0-9]+\.[0-9]+ ]]; then
      curl -s "https://api.shodan.io/shodan/host/$TARGET?key=$SHODAN_API" > "$SHODAN_OUT" || true
      echo -e "\n--- Shodan host lookup ---" >> "$REPORT"
      jq -r '. | "IP: \(.ip_str) | Org: \(.org) | Hostnames: \(.hostnames) | Ports: \(.ports)"' "$SHODAN_OUT" >> "$REPORT" 2>/dev/null || cat "$SHODAN_OUT" >> "$REPORT" || true
    else
      echo -e "\n[Shodan lookup skipped - target not a single IP]" >> "$REPORT"
    fi
  else
    log WARN "curl missing; cannot query Shodan"
  fi
fi

#########################################
# 10) Aggressive optional checks        #
#########################################
if [[ "$AGGRESSIVE" == true ]]; then
  log INFO "10) Aggressive mode checks (non-destructive but noisier)"
  echo -e "\n--- Aggressive Mode ---" >> "$REPORT"
  # Nikto (webserver checks)
  if check_tool nikto; then
    log INFO "Running nikto against detected web hosts (first host only)"
    nikto -h "$TARGET" -output "$TMPDIR/nikto.txt" || true
    sed -n '1,200p' "$TMPDIR/nikto.txt" >> "$REPORT" || true
  else
    echo -e "\n[nikto not installed]" >> "$REPORT"
  fi
  # Optionally list more aggressive checks (no brute-force included)
else
  log INFO "Aggressive mode off (skipping nikto/other noisy checks)"
fi

#########################################
# Finalize report                       #
#########################################
log INFO "Finalizing report: $REPORT"
echo -e "\n\nScan completed: $(date)\n" >> "$REPORT"
echo "Report saved to: $REPORT"
log INFO "All done. Review the report."

# exit cleanly
exit 0
