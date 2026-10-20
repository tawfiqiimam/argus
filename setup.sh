#!/usr/bin/env bash
# ============================================================
#  Argus VMS — setup for Kali Linux / Debian / Ubuntu  (by T4WF1Q)
# ============================================================
set -e
cd "$(dirname "$0")"

GREEN='\033[0;32m'; YEL='\033[1;33m'; MAG='\033[0;35m'; NC='\033[0m'
echo -e "${MAG}"
cat <<'EOF'
    _
   / \   _ __ __ _ _   _ ___     Vulnerability
  / _ \ | '__/ _` | | | / __|    Management
 / ___ \| | | (_| | |_| \__ \    System  ·  setup
/_/   \_\_|  \__, |\__,_|___/     by T4WF1Q
             |___/
EOF
echo -e "${NC}"

# 1) Python venv -------------------------------------------------
echo -e "${GREEN}[1/4]${NC} Creating Python virtualenv…"
python3 -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate
pip install --quiet --upgrade pip
pip install --quiet -r requirements.txt
echo "      done."

# 2) config ------------------------------------------------------
echo -e "${GREEN}[2/4]${NC} Preparing config…"
if [ ! -f config.yaml ]; then
  cp config.yaml.example config.yaml
  KEY="$(python3 -c 'import secrets;print(secrets.token_urlsafe(32))')"
  # portable in-place sed (GNU + BSD)
  sed -i.bak "s|CHANGE_ME_please_generate_a_long_random_key|${KEY}|" config.yaml && rm -f config.yaml.bak
  echo -e "      ${YEL}Generated API key:${NC} ${KEY}"
  echo "      (saved in config.yaml → auth.api_key)"
else
  echo "      config.yaml already exists — leaving it."
fi
mkdir -p data reports

# 3) scanner tools ----------------------------------------------
# Installs every tool Argus drives (apt first, Go/pip fallback). Best effort:
# a tool that fails is reported and skipped at scan time, never fatal here.
echo -e "${GREEN}[3/4]${NC} Scanner tools…"
if [ "${SKIP_TOOLS:-0}" = "1" ]; then
  echo "      skipped (SKIP_TOOLS=1). Run ./scripts/install-tools.sh later."
else
  bash scripts/install-tools.sh || echo "      tool install finished with warnings (see above)."
fi

# 4) done --------------------------------------------------------
echo -e "${GREEN}[4/4]${NC} Setup complete."
echo
echo -e "Start the server:   ${MAG}./run.sh${NC}"
echo -e "Then open:          ${MAG}http://127.0.0.1:8000${NC}"
echo -e "CLI login:          ${MAG}./cli/t4wf1q.py login --key <API_KEY from config.yaml>${NC}"
