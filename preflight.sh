#!/usr/bin/env bash
# preflight.sh — verify required tools for Haunt
# Does NOT install anything — reports what's missing with install hints.

set -euo pipefail

if [[ -t 1 ]]; then
    GREEN=$'\033[0;32m' RED=$'\033[0;31m' YELLOW=$'\033[0;33m'
    CYAN=$'\033[0;36m'  BOLD=$'\033[1m'   DIM=$'\033[2m' RESET=$'\033[0m'
else
    GREEN="" RED="" YELLOW="" CYAN="" BOLD="" DIM="" RESET=""
fi

PASS=0; FAIL=0; WARN=0

pass() { PASS=$((PASS+1)); printf "  ${GREEN}✓${RESET} %-20s %s\n" "$1" "${DIM}$(command -v "$1" 2>/dev/null)${RESET}"; }
fail() { FAIL=$((FAIL+1)); printf "  ${RED}✗${RESET} %-20s ${DIM}%s${RESET}\n" "$1" "$2"; }
warn() { WARN=$((WARN+1)); printf "  ${YELLOW}○${RESET} %-20s ${DIM}%s${RESET}\n" "$1" "$2"; }
has()  { command -v "$1" &>/dev/null; }
section() { echo ""; echo "${BOLD}${CYAN}[$1]${RESET}"; }

# ── Recon ───────────────────────────────────────────────────────────────────

section "Recon"

has subfinder  && pass subfinder  || fail subfinder  "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
has httpx      && pass httpx      || fail httpx      "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
has katana     && pass katana     || fail katana     "go install github.com/projectdiscovery/katana/cmd/katana@latest"
has nuclei     && pass nuclei     || fail nuclei     "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
has waymore    && pass waymore    || warn waymore    "pip3 install waymore"
has nmap       && pass nmap       || fail nmap       "sudo apt install nmap"

# ── Fuzzing ─────────────────────────────────────────────────────────────────

section "Fuzzing"

has ffuf       && pass ffuf       || fail ffuf       "go install github.com/ffuf/ffuf/v2@latest"
has gobuster   && pass gobuster   || fail gobuster   "go install github.com/OJ/gobuster/v3@latest"

# ── Exploitation ─────────────────────────────────────────────────────────────

section "Exploitation"

has sqlmap     && pass sqlmap     || fail sqlmap     "sudo apt install sqlmap  OR  pip3 install sqlmap"
has python3    && pass python3    || fail python3    "sudo apt install python3"
has curl       && pass curl       || fail curl       "sudo apt install curl"

# ── Burp MCP ────────────────────────────────────────────────────────────────

section "Burp MCP"

has java && pass java || fail java "sudo apt install default-jre  (required for Burp MCP proxy jar)"

if [[ -n "${MCP_JAR_PATH:-}" ]] && [[ -f "$MCP_JAR_PATH" ]]; then
    printf "  ${GREEN}✓${RESET} %-20s %s\n" "mcp-proxy.jar" "${DIM}${MCP_JAR_PATH}${RESET}"
    PASS=$((PASS+1))
elif ls ~/tools/mcp-proxy.jar &>/dev/null 2>&1; then
    printf "  ${GREEN}✓${RESET} %-20s %s\n" "mcp-proxy.jar" "${DIM}~/tools/mcp-proxy.jar${RESET}"
    PASS=$((PASS+1))
else
    warn "mcp-proxy.jar" "Download from https://github.com/PortSwigger/mcp-server — place jar in ~/tools/ or set MCP_JAR_PATH"
fi

# ── OOB ─────────────────────────────────────────────────────────────────────

section "Out-of-Band"

if grep -r "YOUR_EZXSS_DOMAIN" CLAUDE.md HAUNT_CHECKLIST.md &>/dev/null 2>&1; then
    warn "ezXSS domain" "Replace YOUR_EZXSS_DOMAIN in CLAUDE.md and HAUNT_CHECKLIST.md with your instance URL"
else
    printf "  ${GREEN}✓${RESET} %-20s\n" "ezXSS domain configured"
    PASS=$((PASS+1))
fi

# ── Summary ─────────────────────────────────────────────────────────────────

echo ""
echo "${BOLD}Results: ${GREEN}${PASS} passed${RESET}  ${RED}${FAIL} failed${RESET}  ${YELLOW}${WARN} warnings${RESET}"
echo ""

if [[ $FAIL -gt 0 ]]; then
    echo "${RED}Some required tools are missing. Install them before starting an engagement.${RESET}"
    exit 1
elif [[ $WARN -gt 0 ]]; then
    echo "${YELLOW}Optional items missing — check warnings above.${RESET}"
    exit 0
else
    echo "${GREEN}All checks passed. You're good to go.${RESET}"
    exit 0
fi
