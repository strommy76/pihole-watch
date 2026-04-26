#!/usr/bin/env bash
#
# install-ollama.sh — Manual Ollama install for Pi 5 (ARM64).
#
# Idempotent: safe to re-run. Each step checks current state before acting.
#
# Steps:
#   1. Pre-flight (arch, sudo, disk)
#   2. Download + extract Ollama binary into /usr/local
#   3. Create dedicated 'ollama' system user
#   4. Install systemd unit with loopback-only bind + idle unload
#   5. Enable + start service, wait for API
#   6. Pull triage model
#   7. Smoke-test
#
# Usage:
#   ./install-ollama.sh                 # full install with default model
#   MODEL=gemma3:4b ./install-ollama.sh  # override model
#   SKIP_MODEL=1 ./install-ollama.sh     # install daemon only
#
set -euo pipefail

MODEL="${MODEL:-qwen3:4b}"
OLLAMA_HOST_BIND="${OLLAMA_HOST_BIND:-127.0.0.1:11434}"
OLLAMA_KEEP_ALIVE="${OLLAMA_KEEP_ALIVE:-5m}"
TARBALL_URL="https://github.com/ollama/ollama/releases/latest/download/ollama-linux-arm64.tar.zst"
TARBALL="/tmp/ollama-linux-arm64.tar.zst"
INSTALL_PREFIX="/usr/local"
SERVICE_FILE="/etc/systemd/system/ollama.service"

log()  { printf '\033[1;34m[install-ollama]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[install-ollama]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[install-ollama]\033[0m %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------------- 1. Pre-flight
log "preflight: checking architecture, sudo, disk"

arch="$(uname -m)"
[[ "$arch" == "aarch64" || "$arch" == "arm64" ]] || die "unsupported arch: $arch (need aarch64/arm64)"

if ! sudo -n true 2>/dev/null; then
  log "sudo will prompt for password"
  sudo -v || die "sudo required"
fi

free_gb=$(df -BG /usr/local | awk 'NR==2 {sub("G","",$4); print $4}')
[[ "$free_gb" -ge 5 ]] || die "need ≥5 GB free in /usr/local; have ${free_gb} GB"

command -v zstd >/dev/null || die "zstd not installed; run: sudo apt install zstd"
tar --help 2>&1 | grep -q -- '--zstd' || die "tar lacks --zstd support; upgrade tar"

# ---------------------------------------------------------------------- 2. Download + extract
if command -v ollama >/dev/null 2>&1 && [[ -x "$INSTALL_PREFIX/bin/ollama" ]]; then
  log "ollama already installed at $INSTALL_PREFIX/bin/ollama ($(ollama --version 2>&1 | head -1))"
else
  log "downloading $TARBALL_URL"
  curl -fL --progress-bar -o "$TARBALL" "$TARBALL_URL" || die "download failed"

  log "extracting to $INSTALL_PREFIX"
  sudo tar -C "$INSTALL_PREFIX" --zstd -xf "$TARBALL" || die "extract failed"
  rm -f "$TARBALL"

  [[ -x "$INSTALL_PREFIX/bin/ollama" ]] || die "ollama binary not found after extract"
  log "installed: $($INSTALL_PREFIX/bin/ollama --version 2>&1 | head -1)"
fi

# ---------------------------------------------------------------------- 3. System user
if id ollama >/dev/null 2>&1; then
  log "user 'ollama' already exists"
else
  log "creating system user 'ollama' (home /usr/share/ollama)"
  sudo useradd -r -s /bin/false -U -m -d /usr/share/ollama ollama
fi

if id -nG "$USER" | tr ' ' '\n' | grep -qx ollama; then
  log "$USER already in 'ollama' group"
else
  log "adding $USER to 'ollama' group (relogin or 'newgrp ollama' to apply)"
  sudo usermod -a -G ollama "$USER"
fi

# ---------------------------------------------------------------------- 4. systemd unit
log "writing $SERVICE_FILE"
sudo tee "$SERVICE_FILE" >/dev/null <<EOF
[Unit]
Description=Ollama local LLM daemon
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=$INSTALL_PREFIX/bin/ollama serve
User=ollama
Group=ollama
Restart=always
RestartSec=3
Environment="OLLAMA_HOST=$OLLAMA_HOST_BIND"
Environment="OLLAMA_KEEP_ALIVE=$OLLAMA_KEEP_ALIVE"
Environment="OLLAMA_MODELS=/usr/share/ollama/.ollama/models"
Environment="PATH=/usr/local/bin:/usr/bin:/bin"

# Hardening
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

# ---------------------------------------------------------------------- 5. Enable + start
log "reloading systemd"
sudo systemctl daemon-reload

log "enabling + starting ollama.service"
sudo systemctl enable --now ollama.service

log "waiting for API on $OLLAMA_HOST_BIND ..."
for i in {1..30}; do
  if curl -fsS "http://${OLLAMA_HOST_BIND}/api/version" >/dev/null 2>&1; then
    version_json="$(curl -fsS http://${OLLAMA_HOST_BIND}/api/version)"
    log "API ready: $version_json"
    break
  fi
  sleep 1
  [[ "$i" -eq 30 ]] && die "API did not come up within 30s"
done

# ---------------------------------------------------------------------- 6. Pull model
if [[ "${SKIP_MODEL:-0}" == "1" ]]; then
  log "SKIP_MODEL=1 — skipping model pull"
else
  if "$INSTALL_PREFIX/bin/ollama" list 2>/dev/null | awk '{print $1}' | grep -qx "$MODEL"; then
    log "model '$MODEL' already pulled"
  else
    log "pulling $MODEL (this can take several minutes on Pi 5)"
    "$INSTALL_PREFIX/bin/ollama" pull "$MODEL"
  fi
fi

# ---------------------------------------------------------------------- 7. Smoke test
if [[ "${SKIP_MODEL:-0}" != "1" ]]; then
  log "smoke test against $MODEL"
  resp="$(curl -fsS http://${OLLAMA_HOST_BIND}/api/generate \
    -H 'content-type: application/json' \
    -d "{\"model\":\"$MODEL\",\"prompt\":\"Reply with one word: ok\",\"stream\":false}" \
    | python3 -c 'import json,sys; print(json.load(sys.stdin).get("response","").strip())')"
  log "model replied: '$resp'"
fi

log "done. service status:"
systemctl status ollama.service --no-pager --lines=5 || true

cat <<'NOTE'

Next steps:
  - 'newgrp ollama' (or re-login) to pick up group membership in your shell
  - Models live at /usr/share/ollama/.ollama/models
  - Logs:           journalctl -u ollama -f
  - Disable:        sudo systemctl disable --now ollama
  - Uninstall:      sudo rm /usr/local/bin/ollama && sudo rm -rf /usr/local/lib/ollama \
                       && sudo userdel -r ollama && sudo rm /etc/systemd/system/ollama.service \
                       && sudo systemctl daemon-reload
NOTE
