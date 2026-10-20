#!/usr/bin/env bash
# Start the Argus VMS server. (by T4WF1Q)
set -e
cd "$(dirname "$0")"

if [ ! -d .venv ]; then
  echo "No virtualenv found. Run ./setup.sh first."
  exit 1
fi
# shellcheck disable=SC1091
source .venv/bin/activate

HOST="$(python3 -c 'from t4wf1q.config import get_config as g;print(g().host)')"
PORT="$(python3 -c 'from t4wf1q.config import get_config as g;print(g().port)')"

echo "Argus VMS → http://${HOST}:${PORT}"
exec uvicorn t4wf1q.main:app --host "$HOST" --port "$PORT"
