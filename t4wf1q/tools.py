"""Scanner tool detection: availability + version, for the Settings page.

Never assumes a tool is installed. Each entry reports whether the binary is
on PATH and, if so, tries a best-effort version string.
"""
from __future__ import annotations

import shutil
import subprocess

TOOLS = [
    # (key, binary, version_args, category)
    ("subfinder", "subfinder", ["-version"], "Reconnaissance"),
    ("httpx", "httpx", ["-version"], "Reconnaissance"),
    ("whatweb", "whatweb", ["--version"], "Reconnaissance"),
    ("katana", "katana", ["-version"], "Reconnaissance"),
    ("gau", "gau", ["--version"], "Reconnaissance"),
    ("amass", "amass", ["-version"], "Reconnaissance"),
    ("nuclei", "nuclei", ["-version"], "Vulnerability Assessment"),
    ("nmap", "nmap", ["-V"], "Vulnerability Assessment"),
    ("nikto", "nikto", ["-Version"], "Vulnerability Assessment"),
    ("testssl.sh", "testssl.sh", ["--version"], "Vulnerability Assessment"),
    ("wpscan", "wpscan", ["--version"], "Vulnerability Assessment"),
    ("dalfox", "dalfox", ["version"], "Vulnerability Assessment"),
    ("sqlmap", "sqlmap", ["--version"], "Vulnerability Assessment"),
    ("zap-baseline", "zap-baseline.py", [], "Vulnerability Assessment"),
    ("semgrep", "semgrep", ["--version"], "Code & Dependencies"),
    ("gitleaks", "gitleaks", ["version"], "Code & Dependencies"),
    ("trivy", "trivy", ["--version"], "Code & Dependencies"),
    ("dependency-check", "dependency-check", ["--version"], "Code & Dependencies"),
]

INSTALL_HINTS = {
    "subfinder": "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "httpx": "go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "whatweb": "sudo apt install -y whatweb",
    "katana": "go install github.com/projectdiscovery/katana/cmd/katana@latest",
    "gau": "go install github.com/lc/gau/v2/cmd/gau@latest",
    "amass": "sudo apt install -y amass",
    "nuclei": "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && nuclei -update-templates",
    "nmap": "sudo apt install -y nmap",
    "nikto": "sudo apt install -y nikto",
    "testssl.sh": "sudo apt install -y testssl.sh",
    "wpscan": "sudo gem install wpscan",
    "dalfox": "go install github.com/hahwul/dalfox/v2@latest",
    "sqlmap": "sudo apt install -y sqlmap",
    "zap-baseline": "sudo apt install -y zaproxy   # OWASP ZAP needs Java",
    "semgrep": "pip install --break-system-packages semgrep",
    "gitleaks": "go install github.com/gitleaks/gitleaks/v8@latest",
    "trivy": "sudo apt install -y trivy",
    "dependency-check": "download OWASP Dependency-Check from github.com/jeremylong/DependencyCheck/releases (needs Java 11+)",
}


def detect() -> list[dict]:
    out = []
    for key, binary, vargs, category in TOOLS:
        path = shutil.which(binary)
        version = None
        if path:
            try:
                p = subprocess.run([binary] + vargs, capture_output=True, text=True, timeout=10)
                raw = (p.stdout or p.stderr or "").strip().splitlines()
                version = raw[0][:80] if raw else "installed"
            except Exception:
                version = "installed"
        out.append({
            "key": key, "binary": binary, "category": category,
            "installed": bool(path), "path": path, "version": version,
            "install_hint": INSTALL_HINTS.get(key),
        })
    return out
