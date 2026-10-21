#!/usr/bin/env bash
# ============================================================
#  Argus VMS — installs the scanner tools Argus drives.
#  Kali / Debian / Ubuntu. Safe to re-run.
#
#    - Tools already on PATH are skipped.
#    - Each tool tries its routes in order: apt, then Go, a private Python venv,
#      or a download from the project's release page.
#    - Installer output goes to a log. A failed step shows its last error line,
#      so a ✗ always comes with a reason.
#    - A tool that still can't be installed is listed at the end. The run never
#      stops, and Argus skips the stages that need the missing tool.
#
#  DRY_RUN=1 ./scripts/install-tools.sh   report only, install nothing
#  ARGUS_INSTALL_LOG=/path/to/log         where full output goes (default ~/.argus/install.log)
# ============================================================
set -u

GREEN='\033[0;32m'; RED='\033[0;31m'; YEL='\033[1;33m'; NC='\033[0m'
DRY_RUN="${DRY_RUN:-0}"
LOG="${ARGUS_INSTALL_LOG:-$HOME/.argus/install.log}"
LOCAL_BIN="$HOME/.local/bin"
SHARE="$HOME/.local/share/argus-tools"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PY="$ROOT/.venv/bin/python"; [ -x "$PY" ] || PY="python3"   # Argus's own venv, if it exists

mkdir -p "$(dirname "$LOG")" "$LOCAL_BIN" "$SHARE" 2>/dev/null
export PATH="$PATH:$HOME/go/bin:$LOCAL_BIN"

SUDO=""
if [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1; then SUDO="sudo"; fi
FAILED=()

have() { command -v "$1" >/dev/null 2>&1; }
ok()   { printf "  ${GREEN}✓${NC} %s\n" "$1"; }
bad()  { printf "  ${RED}✗${NC} %s — %s\n" "$1" "$2"; FAILED+=("$1"); }
note() { printf "    ${YEL}·${NC} %s\n" "$1"; }

# quiet <cmd...>: run a command with all of its output in the log. Keeps the console readable.
quiet() { printf '\n$ %s\n' "$*" >>"$LOG"; "$@" >>"$LOG" 2>&1; }

# last_error: the last non-empty line of the log, shown next to a failure.
last_error() { grep -v '^[[:space:]]*$' "$LOG" 2>/dev/null | tail -n 1 | cut -c1-180; }

# try <label> <cmd...>: run one installer step. On failure, show why. Silent in DRY_RUN.
try() {
  local label="$1"; shift
  [ "$DRY_RUN" = 1 ] && return 1
  "$@" && return 0
  note "$label failed: $(last_error)"
  return 1
}

apt_install() {   # apt_install <package...>
  [ "$DRY_RUN" = 1 ] && return 1
  have apt-get || return 1
  quiet $SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y "$@"
}

go_install() {    # go_install <module@version>
  [ "$DRY_RUN" = 1 ] && return 1
  have go || return 1
  quiet go install "$1"
}

# git_tool <command> <repo-url> <entry script inside the repo>
git_tool() {
  [ "$DRY_RUN" = 1 ] && return 1
  local name="$1" repo="$2" entry="$3" dir="$SHARE/$1"
  if [ ! -f "$dir/$entry" ]; then
    have git || try "git" apt_install git || return 1
    rm -rf "$dir"
    quiet git clone --depth 1 "$repo" "$dir" || return 1
  fi
  chmod +x "$dir/$entry" && ln -sf "$dir/$entry" "$LOCAL_BIN/$name"
}

# venv_tool <command> <pip package>: a private venv, so system Python is never touched.
venv_tool() {
  [ "$DRY_RUN" = 1 ] && return 1
  local cmd="$1" pkg="$2" venv="$SHARE/venv-$1"
  if [ ! -x "$venv/bin/$cmd" ]; then
    rm -rf "$venv"
    if ! quiet python3 -m venv "$venv"; then
      try "python3-venv" apt_install python3-venv || return 1
      quiet python3 -m venv "$venv" || return 1
    fi
    quiet "$venv/bin/pip" install --quiet "$pkg" || return 1
  fi
  ln -sf "$venv/bin/$cmd" "$LOCAL_BIN/$cmd"
}

# ensure <binary> <apt package|-> <go module|-> <manual hint>
ensure() {
  local bin="$1" apt_pkg="$2" go_mod="$3" hint="$4"
  if have "$bin"; then ok "$bin"; return; fi
  if [ "$DRY_RUN" = 1 ]; then note "would install $bin"; return; fi
  [ "$apt_pkg" != "-" ] && try "apt $apt_pkg" apt_install "$apt_pkg"
  if ! have "$bin" && [ "$go_mod" != "-" ]; then try "go install $bin" go_install "$go_mod"; fi
  if have "$bin"; then ok "$bin (installed now)"; else bad "$bin" "$hint"; fi
}

# OWASP Dependency-Check: a Java program. Installed from the official release zip.
install_dependency_check() {
  have dependency-check && return 0
  [ "$DRY_RUN" = 1 ] && return 1
  if ! have java; then
    try "java" apt_install default-jre-headless || try "java" apt_install openjdk-21-jre-headless \
      || try "java" apt_install openjdk-17-jre-headless
  fi
  have unzip || try "unzip" apt_install unzip || return 1
  local url="" repo dir="$SHARE/dependency-check" entry
  for repo in dependency-check/DependencyCheck jeremylong/DependencyCheck; do
    url="$(curl -fsSL "https://api.github.com/repos/$repo/releases/latest" 2>>"$LOG" | python3 -c '
import json, sys
d = json.load(sys.stdin)
print(next(a["browser_download_url"] for a in d["assets"] if a["name"].endswith("-release.zip")))' 2>>"$LOG")"
    [ -n "$url" ] && break
  done
  if [ -z "$url" ]; then note "could not reach the Dependency-Check release page (check the internet connection)"; return 1; fi
  rm -rf "$dir" && mkdir -p "$dir"
  quiet curl -fsSL -o "$dir/release.zip" "$url" || return 1
  quiet unzip -q -o "$dir/release.zip" -d "$dir" || return 1
  entry="$(find "$dir" -name dependency-check.sh -path '*/bin/*' | head -n 1)"
  [ -n "$entry" ] || return 1
  chmod +x "$entry" && ln -sf "$entry" "$LOCAL_BIN/dependency-check"
}

echo "Argus · installing scanner tools (safe to re-run)"
echo "Full log: $LOG"
echo

if [ "$DRY_RUN" != 1 ] && [ -n "$SUDO" ] && ! $SUDO -n true 2>/dev/null; then
  echo "Some tools need administrator rights for apt. Enter your password once:"
  $SUDO -v || note "no administrator rights: apt installs will be skipped"
fi
if [ "$DRY_RUN" != 1 ] && have apt-get; then
  echo "· package index"
  try "apt update" quiet $SUDO apt-get update -qq || note "using the cached package index"
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
ensure jsluice - github.com/BishopFox/jsluice/cmd/jsluice@latest \
  "go install github.com/BishopFox/jsluice/cmd/jsluice@latest"
ensure gowitness - github.com/sensepost/gowitness@latest \
  "go install github.com/sensepost/gowitness@latest"
if ! have arjun; then try "arjun" venv_tool arjun arjun; fi
if have arjun; then ok "arjun"; else bad "arjun" "re-run ./update.sh, or: pipx install arjun"; fi

echo "· vulnerability assessment"
ensure nuclei nuclei github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
  "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
ensure nmap nmap - "sudo apt install -y nmap"
ensure nikto nikto - "sudo apt install -y nikto"
ensure dalfox - github.com/hahwul/dalfox/v2@latest "go install github.com/hahwul/dalfox/v2@latest"
ensure sqlmap sqlmap - "sudo apt install -y sqlmap"

# testssl.sh: the apt package first, then the project's repository.
if ! have testssl.sh; then try "apt testssl.sh" apt_install testssl.sh; fi
if ! have testssl.sh; then try "git testssl.sh" git_tool testssl.sh https://github.com/testssl/testssl.sh.git testssl.sh; fi
if have testssl.sh; then ok "testssl.sh"; else bad "testssl.sh" "sudo apt install -y testssl.sh"; fi

if ! have wpscan; then try "apt wpscan" apt_install wpscan; fi
if ! have wpscan && have gem; then try "gem wpscan" quiet $SUDO gem install -q wpscan; fi
if have wpscan; then ok "wpscan"; else bad "wpscan" "sudo gem install wpscan"; fi

# OWASP ZAP: Argus starts `zaproxy -daemon` and drives it with the zapv2 module.
ensure zaproxy zaproxy - "sudo apt install -y zaproxy   (ZAP needs Java)"
if "$PY" -c "import zapv2" >/dev/null 2>&1; then
  ok "zapv2 (Python module for ZAP)"
elif [ "$DRY_RUN" != 1 ]; then
  try "zapv2" quiet "$PY" -m pip install --quiet python-owasp-zap-v2.4
  if "$PY" -c "import zapv2" >/dev/null 2>&1; then ok "zapv2 (installed now)"
  else bad "zapv2 (Python module for ZAP)" "./update.sh installs it into .venv"; fi
else
  note "would install zapv2"
fi

echo "· source code, secrets and dependencies"
ensure gitleaks gitleaks github.com/gitleaks/gitleaks/v8@latest \
  "go install github.com/gitleaks/gitleaks/v8@latest"
ensure trivy trivy - "sudo apt install -y trivy   (or see https://trivy.dev)"

if ! have dependency-check; then try "dependency-check" install_dependency_check; fi
if have dependency-check; then ok "dependency-check"
else bad "dependency-check" "needs Java 11+. Re-run ./update.sh, or download from github.com/dependency-check/DependencyCheck/releases"; fi

if ! have semgrep; then try "semgrep" venv_tool semgrep semgrep; fi
if have semgrep; then ok "semgrep"; else bad "semgrep" "re-run ./update.sh, or: pipx install semgrep"; fi

if [ "$DRY_RUN" != 1 ] && have nuclei; then
  echo "· nuclei templates"
  timeout 300 nuclei -silent -update-templates >>"$LOG" 2>&1 \
    || note "template update failed. Run later: nuclei -update-templates"
fi

echo
if [ ${#FAILED[@]} -eq 0 ]; then
  echo "All tools are installed."
else
  echo "Still missing: ${FAILED[*]}"
  echo "Argus still runs. Stages that need these tools are skipped and logged."
  echo "Fix the hint above, then run ./update.sh again. Full log: $LOG"
fi
