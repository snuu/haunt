#!/usr/bin/env bash
# new-program.sh — scaffold a new bug bounty program folder
#
# Usage: bash new-program.sh <program-name>
#   e.g. bash new-program.sh acme-corp

set -euo pipefail

if [[ -t 1 ]]; then
    GREEN=$'\033[0;32m' CYAN=$'\033[0;36m' BOLD=$'\033[1m' DIM=$'\033[2m' RESET=$'\033[0m'
else
    GREEN="" CYAN="" BOLD="" DIM="" RESET=""
fi

if [[ $# -lt 1 ]]; then
    echo "Usage: bash new-program.sh <program-name>"
    exit 1
fi

NAME="$1"
DIR="programs/${NAME}"

if [[ -d "$DIR" ]]; then
    echo "Already exists: ${DIR}"
    exit 1
fi

mkdir -p "$DIR"

cat > "${DIR}/headers.conf" << 'EOF'
# Required headers — Claude appends these to EVERY request made during this engagement.
# One header per line. Lines starting with # are ignored.
# Example:
#   X-Bugbounty: yourhandle
#   User-Agent: Mozilla/5.0 (BugBounty/yourhandle)

# Rate limit — maximum requests Claude will make per minute (0 = no limit).
# Claude will pace its own curl calls to stay under this.
RATE_LIMIT=30
EOF

cat > "${DIR}/program-guidelines.txt" << 'EOF'
# Program Guidelines

Program:
Platform:
URL:

Out of scope:

Notes:
EOF

cat > "${DIR}/scope.txt" << 'EOF'
# Scope — one domain or wildcard per line
# e.g.
# *.example.com
# app.example.com
EOF

touch "${DIR}/httpx-live.txt"
mkdir -p "${DIR}/reports"

echo ""
echo "${BOLD}${CYAN}Created: ${DIR}/${RESET}"
echo "  ${GREEN}✓${RESET} headers.conf             ${DIM}← required headers + rate limit for every request${RESET}"
echo "  ${GREEN}✓${RESET} program-guidelines.txt  ${DIM}← scope rules, out-of-scope items, notes${RESET}"
echo "  ${GREEN}✓${RESET} scope.txt                ${DIM}← in-scope domains${RESET}"
echo "  ${GREEN}✓${RESET} httpx-live.txt           ${DIM}← paste httpx output here${RESET}"
echo "  ${GREEN}✓${RESET} reports/                 ${DIM}← findings.md written here automatically${RESET}"
echo ""
echo "${DIM}Fill in headers.conf first — Claude will use those headers on every request.${RESET}"
echo ""
echo "${DIM}Then start your session:${RESET}"
echo "  cd ${DIR} && claude"
