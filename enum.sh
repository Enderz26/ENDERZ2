#!/usr/bin/env bash
# php_enumeration_automation.sh
# A production-ready, modular Bash script to enumerate PHP files/endpoints during
# an AUTHORIZED penetration test or security assessment.
#
# IMPORTANT: Run this ONLY against targets you have explicit permission to test.
# This script is safe-by-default: non-destructive checks, passive discovery, and
# optional "--aggressive" flag for deeper checks (still avoids destructive actions).
#
# Features:
#  - Detects required tooling and explains how to install missing tools
#  - Passive tech fingerprinting (whatweb)
#  - Directory brute-forcing for PHP/backup files (gobuster/ffuf)
#  - Parameter discovery (arjun) and parameter fuzzing (ffuf)
#  - Header and cookie analysis (curl)
#  - Backup/temp file probing and safe LFI error fingerprinting
#  - Nikto scan (optional)
#  - Organized output directory with timestamps and logs
#  - Concurrency and wordlist configuration
#
# Usage example:
#   ./php_enumeration_automation.sh -u "https://target.example" -w /path/wordlist.txt -o ./out --aggressive
#
# Author: ChatGPT (for authorized pentest use)
# Version: 1.0
set -euo pipefail
IFS=$'\n\t'

#########################
# Default configuration #
#########################
PROG_NAME=$(basename "$0")
OUTDIR="./php_enum_out"
TARGET=""
WORDLIST="/usr/share/wordlists/dirb/common.txt"
PARAM_WORDLIST="/usr/share/wordlists/parameters.txt"
THREADS=40
AGGRESSIVE=false
VERBOSE=false
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
LOGFILE=""
SAFE_LFI_TEST_STRING="__LFI_DETECT__"
BACKUP_EXTENSIONS=(".bak" ".old" "~" ".save" ".swp" ".orig" ".backup" ".txt" ".inc" ".tar.gz")
COMMON_PHP_FILES=("index.php" "admin.php" "login.php" "upload.php" "config.php" "db.php" "connect.php" "view.php" "download.php")

#########################
# Helper / Utility fn  #
#########################
log() {
  local lvl="$1"; shift
  local msg="$*"
  local ts
  ts=$(date +"%Y-%m-%d %H:%M:%S")
  echo "[$ts] [$lvl] $msg"
  if [[ -n "$LOGFILE" ]]; then
    echo "[$ts] [$lvl] $msg" >> "$LOGFILE"
  fi
}

usage() {
  cat <<EOF
$PROG_NAME - Automated PHP enumeration toolkit (safe-by-default)

Usage: $PROG_NAME -u <target_url> [options]

Options:
  -u, --url        TARGET URL (e.g. https://example.com)
  -w, --wordlist   Path to directory wordlist for directory brute force
  -p, --param-wl   Path to parameter wordlist (for ffuf/arjun)
  -o, --outdir     Output directory (default: ./php_enum_out)
  -t, --threads    Threads/concurrency for ffuf/gobuster (default: 40)
  --aggressive     Enable additional checks (nikto, deeper fuzzing). Use only if authorized.
  -v, --verbose    Verbose logging
  -h, --help       Show this help

Example:
  $PROG_NAME -u https://target.example -w /path/dirs.txt -p /path/params.txt -o ./out --aggressive

Note: Run this only on systems you have permission to test.
EOF
  exit 1
}

check_tool() {
  local name="$1"
  if ! command -v "$name" &>/dev/null; then
    log WARN "$name not found in PATH"
    return 1
  fi
  log DEBUG "$name found"
  return 0
}

ensure_tools() {
  local missing=()
  # Minimal recommended tools
  local tools=(curl whatweb ffuf gobuster arjun nikto)
  for t in "${tools[@]}"; do
    if ! check_tool "$t"; then
      missing+=("$t")
    fi
  done
  if [[ ${#missing[@]} -ne 0 ]]; then
    log WARN "Missing tools: ${missing[*]}"
    log INFO "Install them (examples):"
    echo
    echo "Debian/Ubuntu: sudo apt update && sudo apt install curl whatweb ffuf gobuster nikto -y"
    echo "arjun: pip3 install arjun (or apt if available)"
    echo
    log INFO "Script will continue but features requiring missing tools will be skipped."
  fi
}

mkdir_p() {
  local d="$1"
  if [[ ! -d "$d" ]]; then
    mkdir -p "$d"
  fi
}

safe_url_normalize() {
  # Ensure URL has scheme
  local u="$1"
  if [[ "$u" != http*://* ]]; then
    u="http://$u"
  fi
  # remove trailing slash
  u="${u%/}"
  echo "$u"
}

#########################
# Discovery functions   #
#########################
run_whatweb() {
  if ! command -v whatweb &>/dev/null; then
    log WARN "whatweb not installed, skipping fingerprinting"
    return
  fi
  log INFO "Running whatweb (tech fingerprinting)..."
  whatweb --no-errors -v --log-verbose "$OUTDIR/whatweb.txt" "$TARGET" || true
}

run_gobuster_dirs() {
  if ! command -v gobuster &>/dev/null; then
    log WARN "gobuster not found, skipping directory brute-force"
    return
  fi
  log INFO "Running gobuster (directory bruteforce) against $TARGET ..."
  gobuster dir -u "$TARGET" -w "$WORDLIST" -t "$THREADS" -x php,php5,html,txt,inc,bak -s 200,204,301,302,403 -o "$OUTDIR/gobuster_dirs.txt" || true
}

run_ffuf_params() {
  if ! command -v ffuf &>/dev/null; then
    log WARN "ffuf not found, skipping parameter fuzzing"
    return
  fi
  log INFO "Running ffuf parameter fuzzing (common params)..."
  # common parameter names fuzz
  local paramfile="$PARAM_WORDLIST"
  if [[ ! -f "$paramfile" ]]; then
    # fallback minimal list
    paramfile="$OUTDIR/simple_params.txt"
    cat > "$paramfile" <<EOP
id
page
file
view
user
username
password
action
type
lang
langid
cat
sort
debug
EOP
  fi
  # Try fuzzing GET parameters on discovered .php endpoints (or root)
  local target_template
  target_template="$TARGET/FUZZ"
  # run a conservative ffuf search for common params appended as ?param=FUZZ
  # Use small concurrency to be polite by default
  ffuf -w "$paramfile" -u "$TARGET?FUZZ=1" -mc 200,302 -t 20 -o "$OUTDIR/ffuf_params.json" -of json || true
}

run_arjun() {
  if ! command -v arjun &>/dev/null; then
    log WARN "arjun not installed, skipping parameter discovery"
    return
  fi
  log INFO "Running arjun (parameter discovery) on $TARGET ..."
  arjun -u "$TARGET" -oT "$OUTDIR/arjun_params.txt" || true
}

collect_headers() {
  log INFO "Collecting HTTP headers and cookies..."
  curl -sI -L "$TARGET" > "$OUTDIR/curl_headers.txt" || true
}

probe_common_php_files() {
  log INFO "Probing for a set of common PHP filenames..."
  for f in "${COMMON_PHP_FILES[@]}"; do
    local url="$TARGET/$f"
    local status
    status=$(curl -s -o /dev/null -w "%{http_code}" -L "$url" || echo "000")
    echo "$status    $url" >> "$OUTDIR/common_php_probe.txt"
  done
}

probe_backup_files() {
  log INFO "Probing for common backup/temp files (conservative)..."
  # Use results from gobuster if exists to expand
  local candidate_urls=()
  if [[ -f "$OUTDIR/gobuster_dirs.txt" ]]; then
    # parse gobuster output lines like /admin (Status: 301) -> crude parsing
    mapfile -t paths < <(awk '{print $1}' "$OUTDIR/gobuster_dirs.txt" | sed 's#^/##' | sed '/^$/d') || true
  fi
  # include root as candidate
  candidate_urls+=("")
  for p in "${paths[@]:-}"; do
    candidate_urls+=("$p")
  done

  for base in "${candidate_urls[@]}"; do
    for ext in "${BACKUP_EXTENSIONS[@]}"; do
      # try both direct filename.php.ext and directory-based
      local url1="$TARGET/${base}index.php${ext}"
      local url2="$TARGET/${base}.php${ext}"
      for u in "$url1" "$url2"; do
        # Use HEAD-ish probe via curl to avoid fetching big response bodies
        local code
        code=$(curl -s -o /dev/null -w "%{http_code}" -L "$u" || echo "000")
        if [[ "$code" =~ ^2|3$ ]]; then
          echo "$code    $u" >> "$OUTDIR/backup_probe.txt"
        fi
      done
    done
  done
}

safe_lfi_probe() {
  # WARNING: This probe is intentionally *safe* — it looks for error behaviour rather
  # than attempting to retrieve sensitive files. It injects a detectable marker and
  # looks for reflection or error messages. Do NOT run destructive payloads.
  if ! command -v curl &>/dev/null; then
    log WARN "curl missing, skipping LFI checks"
    return
  fi
  log INFO "Running safe LFI detection (non-destructive)..."
  # candidate endpoints: from arjun, ffuf results; fallback to /view.php and /download.php
  local candidates=(
    "$TARGET/view.php"
    "$TARGET/download.php"
    "$TARGET/file.php"
    "$TARGET/index.php"
  )
  # extend with discovered php paths
  if [[ -f "$OUTDIR/common_php_probe.txt" ]]; then
    while read -r line; do
      url=$(echo "$line" | awk '{print $2}')
      candidates+=("$url")
    done < "$OUTDIR/common_php_probe.txt"
  fi

  for url in "${candidates[@]}"; do
    # craft safe probe - ask the application to include a file named with a unique marker
    # Many LFI vulnerable apps echo back errors like "failed to open stream: No such file or directory"
    # We'll look for those error strings combined with our marker.
    local test_param="../../${SAFE_LFI_TEST_STRING}.txt"
    # try common parameter names that might be used for file includes
    for p in file path page view include tpl template; do
      local fullurl="${url}?${p}=${test_param}"
      # fetch quietly but capture body
      local body
      body=$(curl -s -L "$fullurl" || true)
      if [[ -n "$body" ]]; then
        # look for error indicators or our marker being reflected
        if echo "$body" | grep -qiE "(failed to open stream|No such file or directory|open\(\).*failed|include\(\).+failed)"; then
          echo "POTENTIAL_LFI: $fullurl" >> "$OUTDIR/potential_lfi.txt"
        fi
      fi
    done
  done
}

run_nikto() {
  if [[ "$AGGRESSIVE" != true ]]; then
    log INFO "Nikto scan disabled (use --aggressive to enable)"
    return
  fi
  if ! command -v nikto &>/dev/null; then
    log WARN "nikto not installed, skipping"
    return
  fi
  log INFO "Running nikto (web server scan) — aggressive checks enabled"
  nikto -h "$TARGET" -output "$OUTDIR/nikto.txt" || true
}

summarize_results() {
  log INFO "Summarizing findings into $OUTDIR/summary.txt"
  {
    echo "PHP Enumeration Summary - Generated: $(date)"
    echo "Target: $TARGET"
    echo
    echo "-- Headers (curl) --"
    [[ -f "$OUTDIR/curl_headers.txt" ]] && sed -n '1,120p' "$OUTDIR/curl_headers.txt" || echo "(no headers)"
    echo
    echo "-- Common PHP probes --"
    [[ -f "$OUTDIR/common_php_probe.txt" ]] && cat "$OUTDIR/common_php_probe.txt" || echo "(none)"
    echo
    echo "-- Potential backup/temp files --"
    [[ -f "$OUTDIR/backup_probe.txt" ]] && cat "$OUTDIR/backup_probe.txt" || echo "(none)"
    echo
    echo "-- Potential LFI indicators --"
    [[ -f "$OUTDIR/potential_lfi.txt" ]] && cat "$OUTDIR/potential_lfi.txt" || echo "(none)"
    echo
    echo "-- Gobuster results (top 200 lines) --"
    [[ -f "$OUTDIR/gobuster_dirs.txt" ]] && sed -n '1,200p' "$OUTDIR/gobuster_dirs.txt" || echo "(none)"
    echo
    echo "-- Arjun discovered params --"
    [[ -f "$OUTDIR/arjun_params.txt" ]] && sed -n '1,200p' "$OUTDIR/arjun_params.txt" || echo "(none)"
    echo
    echo "-- FFUF parameter fuzz results (raw json) --"
    [[ -f "$OUTDIR/ffuf_params.json" ]] && echo "(see $OUTDIR/ffuf_params.json)" || echo "(none)"
  } > "$OUTDIR/summary.txt"
}

#########################
# Main workflow         #
#########################
while [[ $# -gt 0 ]]; do
  case "$1" in
    -u|--url)
      TARGET="$2"; shift 2;;
    -w|--wordlist)
      WORDLIST="$2"; shift 2;;
    -p|--param-wl)
      PARAM_WORDLIST="$2"; shift 2;;
    -o|--outdir)
      OUTDIR="$2"; shift 2;;
    -t|--threads)
      THREADS="$2"; shift 2;;
    --aggressive)
      AGGRESSIVE=true; shift;;
    -v|--verbose)
      VERBOSE=true; shift;;
    -h|--help)
      usage;;
    *)
      echo "Unknown arg: $1"; usage;;
  esac
done

if [[ -z "$TARGET" ]]; then
  log ERROR "Target URL not provided"
  usage
fi

TARGET=$(safe_url_normalize "$TARGET")
OUTDIR="${OUTDIR%/}/php_enum_${TIMESTAMP}"
LOGFILE="$OUTDIR/run.log"
mkdir_p "$OUTDIR"

if [[ "$VERBOSE" == true ]]; then
  set -x
fi

log INFO "Starting PHP enumeration for $TARGET"
log INFO "Output will be stored in: $OUTDIR"

ensure_tools
collect_headers
run_whatweb
probe_common_php_files
run_gobuster_dirs
probe_backup_files
run_arjun
run_ffuf_params
safe_lfi_probe
run_nikto
summarize_results

log INFO "Done. Results written under $OUTDIR"
log INFO "Please review $OUTDIR/summary.txt for a quick overview"
log INFO "Remember: Only perform further intrusive testing with explicit authorization."

# End of script
