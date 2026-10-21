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
#  No args                     install everything (the usual ./update.sh path)
#  <tool-key>                  install just that one tool (keys match tools.py)
#  --uninstall <tool-key>      remove just that one tool, if Argus installed it
#  DRY_RUN=1 ./scripts/install-tools.sh   report only, install nothing
#  ARGUS_INSTALL_LOG=/path/to/log         where full output goes (default ~/.argus/install.log)
#
#  Single-tool install/uninstall is what the Argus dashboard's "Tools" page
#  calls in the background (see t4wf1q/jobs.py). Exit code there is the signal:
#  0 = done, 1 = failed, 2 = refused (needs a human with sudo — see below).
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
export DEBIAN_FRONTEND=noninteractive   # kept across sudo via env_keep in argus-sudoers.example

# sudo: interactive runs (a person at a terminal) may enter a password once.
# A background job started by the dashboard has no terminal, so it must not
# hang waiting for one — it uses `sudo -n` and fails fast with a clear reason
# instead. Give the dashboard apt rights via a NOPASSWD sudoers rule (see
# scripts/argus-sudoers.example); nothing here edits sudoers itself.
SUDO=""
if [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1; then
  if [ -t 0 ]; then SUDO="sudo"; else SUDO="sudo -n"; fi
fi
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
  # DEBIAN_FRONTEND is exported below rather than passed as `env VAR=val apt-get`,
  # so the command sudo actually runs is plain `apt-get install -y <pkg>` — the
  # exact string a NOPASSWD sudoers rule matches (see argus-sudoers.example).
  quiet $SUDO apt-get install -y "$@"
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
install_dependency_check_tool() {
  have dependency-check && { ok "dependency-check"; return 0; }
  [ "$DRY_RUN" = 1 ] && { note "would install dependency-check"; return 1; }
  if ! have java; then
    try "java" apt_install default-jre-headless || try "java" apt_install openjdk-21-jre-headless \
      || try "java" apt_install openjdk-17-jre-headless
  fi
  have unzip || try "unzip" apt_install unzip || { bad "dependency-check" "needs unzip"; return 1; }
  local url="" repo dir="$SHARE/dependency-check" entry
  for repo in dependency-check/DependencyCheck jeremylong/DependencyCheck; do
    url="$(curl -fsSL "https://api.github.com/repos/$repo/releases/latest" 2>>"$LOG" | python3 -c '
import json, sys
d = json.load(sys.stdin)
print(next(a["browser_download_url"] for a in d["assets"] if a["name"].endswith("-release.zip")))' 2>>"$LOG")"
    [ -n "$url" ] && break
  done
  if [ -z "$url" ]; then
    bad "dependency-check" "could not reach the release page (check the internet connection)"; return 1
  fi
  rm -rf "$dir" && mkdir -p "$dir"
  quiet curl -fsSL -o "$dir/release.zip" "$url" || { bad "dependency-check" "download failed: $(last_error)"; return 1; }
  quiet unzip -q -o "$dir/release.zip" -d "$dir" || { bad "dependency-check" "unzip failed: $(last_error)"; return 1; }
  entry="$(find "$dir" -name dependency-check.sh -path '*/bin/*' | head -n 1)"
  if [ -z "$entry" ]; then bad "dependency-check" "release zip had no bin/dependency-check.sh"; return 1; fi
  chmod +x "$entry" && ln -sf "$entry" "$LOCAL_BIN/dependency-check"
  if have dependency-check; then ok "dependency-check (installed now)"; else bad "dependency-check" "install did not take"; return 1; fi
}

# ---- one function per tool, keyed exactly like tools.TOOLS -----------------
# A single-tool install/uninstall job calls exactly one of these; the full
# run below calls them all in the same order as before this refactor.

_GO_CHECKED=0
install_go() {   # toolchain, not a scanner itself — only announce it once per run
  [ "$_GO_CHECKED" = 1 ] && return 0
  _GO_CHECKED=1
  ensure go golang-go - "sudo apt install -y golang-go"
}
install_subfinder()  { install_go; ensure subfinder subfinder github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
                          "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"; }
install_httpx()      { install_go; ensure httpx - github.com/projectdiscovery/httpx/cmd/httpx@latest \
                          "go install github.com/projectdiscovery/httpx/cmd/httpx@latest"; }
install_whatweb()    { ensure whatweb whatweb - "sudo apt install -y whatweb"; }
install_amass()      { ensure amass amass - "sudo apt install -y amass"; }
install_katana()     { install_go; ensure katana - github.com/projectdiscovery/katana/cmd/katana@latest \
                          "go install github.com/projectdiscovery/katana/cmd/katana@latest"; }
install_gau()        { install_go; ensure gau - github.com/lc/gau/v2/cmd/gau@latest \
                          "go install github.com/lc/gau/v2/cmd/gau@latest"; }
install_jsluice()    { install_go; ensure jsluice - github.com/BishopFox/jsluice/cmd/jsluice@latest \
                          "go install github.com/BishopFox/jsluice/cmd/jsluice@latest"; }
install_gowitness()  { install_go; ensure gowitness - github.com/sensepost/gowitness@latest \
                          "go install github.com/sensepost/gowitness@latest"; }
install_arjun() {
  have arjun && { ok "arjun"; return 0; }
  if try "arjun" venv_tool arjun arjun && have arjun; then ok "arjun (installed now)"
  else bad "arjun" "re-run ./update.sh, or: pipx install arjun"; return 1; fi
}
install_nuclei() {
  install_go
  ensure nuclei nuclei github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
    "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
  if [ "$DRY_RUN" != 1 ] && have nuclei; then
    note "updating nuclei templates…"
    timeout 300 nuclei -silent -update-templates >>"$LOG" 2>&1 \
      || note "template update failed. Run later: nuclei -update-templates"
  fi
}
install_nmap()    { ensure nmap nmap - "sudo apt install -y nmap"; }
install_nikto()   { ensure nikto nikto - "sudo apt install -y nikto"; }
install_dalfox()  { install_go; ensure dalfox - github.com/hahwul/dalfox/v2@latest \
                       "go install github.com/hahwul/dalfox/v2@latest"; }
install_sqlmap()  { ensure sqlmap sqlmap - "sudo apt install -y sqlmap"; }

install_testsslsh() {
  if ! have testssl.sh; then try "apt testssl.sh" apt_install testssl.sh; fi
  if ! have testssl.sh; then try "git testssl.sh" git_tool testssl.sh https://github.com/testssl/testssl.sh.git testssl.sh; fi
  if have testssl.sh; then ok "testssl.sh"; else bad "testssl.sh" "sudo apt install -y testssl.sh"; return 1; fi
}
install_wpscan() {
  if ! have wpscan; then try "apt wpscan" apt_install wpscan; fi
  if ! have wpscan && have gem; then try "gem wpscan" quiet $SUDO gem install -q wpscan; fi
  if have wpscan; then ok "wpscan"; else bad "wpscan" "sudo gem install wpscan"; return 1; fi
}
install_zaproxy() {
  # Argus starts `zaproxy -daemon` and drives it with the zapv2 module.
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
}
install_gitleaks() { install_go; ensure gitleaks gitleaks github.com/gitleaks/gitleaks/v8@latest \
                        "go install github.com/gitleaks/gitleaks/v8@latest"; }
install_trivy()    { ensure trivy trivy - "sudo apt install -y trivy   (or see https://trivy.dev)"; }
install_dependencycheck() { install_dependency_check_tool; }
install_semgrep() {
  have semgrep && { ok "semgrep"; return 0; }
  if try "semgrep" venv_tool semgrep semgrep && have semgrep; then ok "semgrep (installed now)"
  else bad "semgrep" "re-run ./update.sh, or: pipx install semgrep"; return 1; fi
}

# key (as in tools.TOOLS) -> function name. Bash function names can't hold a
# "." or "-", so the handful of keys that do get a stable alias here.
dispatch_install() {
  case "$1" in
    subfinder) install_subfinder ;; httpx) install_httpx ;; whatweb) install_whatweb ;;
    amass) install_amass ;; katana) install_katana ;; gau) install_gau ;;
    arjun) install_arjun ;; jsluice) install_jsluice ;; gowitness) install_gowitness ;;
    nuclei) install_nuclei ;; nmap) install_nmap ;; nikto) install_nikto ;;
    "testssl.sh") install_testsslsh ;; wpscan) install_wpscan ;; dalfox) install_dalfox ;;
    sqlmap) install_sqlmap ;; zaproxy) install_zaproxy ;; semgrep) install_semgrep ;;
    gitleaks) install_gitleaks ;; trivy) install_trivy ;; "dependency-check") install_dependencycheck ;;
    *) echo "unknown tool key: $1" >&2; return 2 ;;
  esac
}

# key -> the binary name Argus actually runs (tools.TOOLS, 2nd field).
_binary_for() {
  case "$1" in
    subfinder) echo subfinder ;; httpx) echo httpx ;; whatweb) echo whatweb ;;
    amass) echo amass ;; katana) echo katana ;; gau) echo gau ;;
    arjun) echo arjun ;; jsluice) echo jsluice ;; gowitness) echo gowitness ;;
    nuclei) echo nuclei ;; nmap) echo nmap ;; nikto) echo nikto ;;
    "testssl.sh") echo testssl.sh ;; wpscan) echo wpscan ;; dalfox) echo dalfox ;;
    sqlmap) echo sqlmap ;; zaproxy) echo zaproxy ;; semgrep) echo semgrep ;;
    gitleaks) echo gitleaks ;; trivy) echo trivy ;; "dependency-check") echo dependency-check ;;
    *) return 2 ;;
  esac
}

# uninstall_tool <key>: generic, binary-location-based. Argus only ever
# removes what IT installed (a symlink into $LOCAL_BIN pointing at $SHARE or
# $HOME/go/bin). A binary that apt or gem put straight on the system PATH
# (/usr/bin, /usr/local/bin, a gem shim) is left alone — removing a system
# package from a web dashboard can break other software on the box, so that
# always needs a human with sudo, on purpose.
uninstall_tool() {
  local key="$1" bin path real
  bin="$(_binary_for "$key")" || { echo "unknown tool key: $key" >&2; return 2; }
  path="$(command -v "$bin" 2>/dev/null)"
  if [ -z "$path" ]; then echo "$bin is not installed — nothing to do"; return 0; fi
  real="$(readlink -f "$path" 2>/dev/null || echo "$path")"
  case "$real" in
    "$SHARE"/*)
      # venv_tool or git_tool install: drop the whole private dir plus the symlink.
      local toolname
      toolname="$(echo "$real" | sed -E "s#^$SHARE/(venv-)?([^/]+).*#\\2#")"
      rm -rf "$SHARE/$toolname" "$SHARE/venv-$toolname"
      rm -f "$LOCAL_BIN/$bin"
      echo "removed $bin ($SHARE/$toolname)"; return 0 ;;
    "$HOME/go/bin"/*)
      rm -f "$real"
      echo "removed $bin ($real)"; return 0 ;;
    *)
      echo "$bin is installed by the system (at $path), not by Argus." \
           " Remove it yourself, e.g.: sudo apt remove $bin   (or the matching gem/package name)" >&2
      return 2 ;;
  esac
}

# ---- entry point -------------------------------------------------------
if [ "${1:-}" = "--uninstall" ]; then
  [ -n "${2:-}" ] || { echo "usage: $0 --uninstall <tool-key>" >&2; exit 2; }
  uninstall_tool "$2"; exit $?
fi

if [ -n "${1:-}" ]; then
  echo "Argus · installing just: $1"
  echo "Full log: $LOG"
  if [ "$DRY_RUN" != 1 ] && [ -n "$SUDO" ] && [[ "$SUDO" != *-n* ]] && ! $SUDO -n true 2>/dev/null; then
    echo "This may need administrator rights for apt. Enter your password once:"
    $SUDO -v || note "no administrator rights: apt installs will be skipped"
  fi
  if [ "$DRY_RUN" != 1 ] && have apt-get; then
    try "apt update" quiet $SUDO apt-get update -qq || note "using the cached package index"
  fi
  dispatch_install "$1"
  rc=$?
  [ "$DRY_RUN" = 1 ] && exit 0
  bin="$(_binary_for "$1" 2>/dev/null || echo "$1")"
  if have "$bin"; then exit 0; else exit "${rc:-1}"; fi
fi

echo "Argus · installing scanner tools (safe to re-run)"
echo "Full log: $LOG"
echo

if [ "$DRY_RUN" != 1 ] && [ -n "$SUDO" ] && [[ "$SUDO" != *-n* ]] && ! $SUDO -n true 2>/dev/null; then
  echo "Some tools need administrator rights for apt. Enter your password once:"
  $SUDO -v || note "no administrator rights: apt installs will be skipped"
fi
if [ "$DRY_RUN" != 1 ] && have apt-get; then
  echo "· package index"
  try "apt update" quiet $SUDO apt-get update -qq || note "using the cached package index"
fi

echo "· toolchain"
install_go

echo "· reconnaissance"
# httpx: the ProjectDiscovery binary is installed from Go on purpose. The pip
# 'httpx' CLI on PATH is a different program and is not what Argus needs.
install_subfinder; install_httpx; install_whatweb; install_amass
install_katana; install_gau; install_jsluice; install_gowitness; install_arjun

echo "· vulnerability assessment"
install_nuclei; install_nmap; install_nikto; install_dalfox; install_sqlmap
install_testsslsh; install_wpscan; install_zaproxy

echo "· source code, secrets and dependencies"
install_gitleaks; install_trivy; install_dependencycheck; install_semgrep

echo
if [ ${#FAILED[@]} -eq 0 ]; then
  echo "All tools are installed."
else
  echo "Still missing: ${FAILED[*]}"
  echo "Argus still runs. Stages that need these tools are skipped and logged."
  echo "Fix the hint above, then run ./update.sh again. Full log: $LOG"
fi
