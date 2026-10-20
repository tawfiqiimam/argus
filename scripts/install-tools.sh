#!/usr/bin/env bash
# ============================================================
#  Argus VMS — installs the scanner tools Argus drives.
#  Kali / Debian / Ubuntu. Best effort:
#    - tools already on PATH are skipped (safe to re-run)
#    - apt first, then `go install` or pip as fallbacks
#    - a tool that cannot be installed is listed with a manual hint.
#      It never stops the run, and Argus skips that stage cleanly.
#  DRY_RUN=1 ./scripts/install-tools.sh   -> report only, install nothing
# ============================================================
set -u

GREEN='\033[0;32m'; RED='\033[0;31m'; NC='\033[0m'
DRY_RUN="${DRY_RUN:-0}"
SUDO=""
if [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1; then SUDO="sudo"; fi
export PATH="$PATH:$HOME/go/bin:$HOME/.local/bin"
FAILED=()

have() { command -v "$1" >/dev/null 2>&1; }
ok()   { printf "  ${GREEN}✓${NC} %s\n" "$1"; }
bad()  { printf "  ${RED}✗${NC} %s — %s\n" "$1" "$2"; FAILED+=("$1"); }

apt_install() {   # apt_install <package...>
  [ "$DRY_RUN" = 1 ] && return 1
  have apt-get || return 1
  $SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@" >/dev/null 2>&1
}

go_install() {    # go_install <module@version>
  [ "$DRY_RUN" = 1 ] && return 1
  have go || return 1
  go install "$1" >/dev/null 2>&1
}

# check <binary> <manual hint> — report the final state of one tool
check() { if have "$1"; then ok "$1"; else bad "$1" "$2"; fi; }

# ensure <binary> <apt-package|-> <go-module@version|-> <manual hint>
ensure() {
  local bin="$1" apt_pkg="$2" go_mod="$3" hint="$4"
  if have "$bin"; then ok "$bin (already installed)"; return; fi
  if [ "$DRY_RUN" = 1 ]; then echo "  … would install $bin"; return; fi
  if [ "$apt_pkg" != "-" ]; then apt_install "$apt_pkg"; fi
  if ! have "$bin" && [ "$go_mod" != "-" ]; then go_install "$go_mod"; fi
  check "$bin" "$hint"
}

echo "Argus · installing scanner tools (best effort, safe to re-run)"
echo
if [ "$DRY_RUN" != 1 ]; then
  echo "· package index"
  $SUDO apt-get update -qq >/dev/null 2>&1 || echo "  (apt update failed, using the cached index)"
fi

echo "· toolchain"
ensure go golang-go - "sudo apt install -y golang-go"

echo "· reconnaissance"
# httpx: the ProjectDiscovery binary is installed from Go on purpose. The pip
# 'httpx' CLI on PATH is a different program and is not what Argus needs.
ensure subfinder subfinder github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
  "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
ensure httpx - github.com/projectdiscovery/httpx/cmd/httpx@latest \
  "go install github.com/projectdiscovery/httpx/cmd/httpx@latest"
ensure whatweb whatweb - "sudo apt install -y whatweb"
ensure amass amass - "sudo apt install -y amass"
ensure katana - github.com/projectdiscovery/katana/cmd/katana@latest \
  "go install github.com/projectdiscovery/katana/cmd/katana@latest"
ensure gau - github.com/lc/gau/v2/cmd/gau@latest "go install github.com/lc/gau/v2/cmd/gau@latest"

echo "· vulnerability assessment"
ensure nuclei nuclei github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
  "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
ensure nmap nmap - "sudo apt install -y nmap"
ensure nikto nikto - "sudo apt install -y nikto"
ensure testssl.sh testssl.sh - "sudo apt install -y testssl.sh"
ensure dalfox - github.com/hahwul/dalfox/v2@latest "go install github.com/hahwul/dalfox/v2@latest"
ensure sqlmap sqlmap - "sudo apt install -y sqlmap"

if ! have wpscan && [ "$DRY_RUN" != 1 ]; then
  apt_install wpscan
  if ! have wpscan && have gem; then $SUDO gem install -q wpscan >/dev/null 2>&1; fi
fi
check wpscan "sudo gem install wpscan"

# OWASP ZAP: Kali ships the baseline script under /usr/share; link it onto PATH.
ZAP_BASE=/usr/share/zaproxy/zap-baseline.py
if [ "$DRY_RUN" != 1 ]; then
  if ! have zap-baseline.py && [ ! -f "$ZAP_BASE" ]; then apt_install zaproxy; fi
  if [ -f "$ZAP_BASE" ] && ! have zap-baseline.py; then
    $SUDO ln -sf "$ZAP_BASE" /usr/local/bin/zap-baseline.py
  fi
fi
check zap-baseline.py "sudo apt install -y zaproxy   (OWASP ZAP needs Java)"

echo "· source code, secrets and dependencies"
ensure gitleaks gitleaks github.com/gitleaks/gitleaks/v8@latest \
  "go install github.com/gitleaks/gitleaks/v8@latest"
ensure trivy trivy - "sudo apt install -y trivy   (or see https://trivy.dev)"
ensure dependency-check dependency-check - \
  "download OWASP Dependency-Check from github.com/jeremylong/DependencyCheck/releases (needs Java 11+)"
if ! have semgrep; then
  if [ "$DRY_RUN" = 1 ]; then
    echo "  … would install semgrep"
  elif have pipx; then
    pipx install -q semgrep >/dev/null 2>&1
  else
    python3 -m pip install -q --user --break-system-packages semgrep >/dev/null 2>&1
  fi
fi
if [ "$DRY_RUN" != 1 ]; then check semgrep "python3 -m pip install --user --break-system-packages semgrep"; fi

if [ "$DRY_RUN" != 1 ] && have nuclei; then
  echo "· nuclei templates"
  timeout 300 nuclei -silent -update-templates >/dev/null 2>&1 \
    || echo "  (template update failed; run 'nuclei -update-templates' later)"
fi

echo
if [ ${#FAILED[@]} -eq 0 ]; then
  echo "All tools are installed."
else
  echo "Not installed: ${FAILED[*]}"
  echo "Argus still runs. Stages that need these tools are skipped and logged."
  echo "Fix the hint above, then re-run:  ./scripts/install-tools.sh"
fi
