# T4WF1Q VMS — container image (bundles nmap + nuclei for a batteries-included run)
FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
      nmap ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

# Optional: pull in nuclei (static binary) for template scanning.
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in amd64) n=amd64;; arm64) n=arm64;; *) n="";; esac; \
    if [ -n "$n" ]; then \
      curl -sL "https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_linux_${n}.zip" -o /tmp/n.zip || true; \
      (cd /tmp && unzip -o n.zip nuclei -d /usr/local/bin || true); \
      chmod +x /usr/local/bin/nuclei 2>/dev/null || true; \
    fi

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN mkdir -p data reports

EXPOSE 8000
ENV T4WF1Q_API_KEY=""
CMD ["uvicorn", "t4wf1q.main:app", "--host", "0.0.0.0", "--port", "8000"]
