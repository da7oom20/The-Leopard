#!/usr/bin/env bash
# The Leopard — online installer.
#
# Two modes:
#   --direct              Host has direct internet access to Docker Hub / npm /
#                         Debian / Alpine repos. Default.
#   --proxy URL           Host only has internet via an HTTP proxy (e.g.
#                         http://10.5.13.13:8080). The proxy is used ONLY
#                         during install (image pulls + RUN-step package
#                         installs). It is explicitly torn down before the
#                         stack is brought up so runtime containers never
#                         inherit the proxy env — SIEM requests and
#                         container healthchecks go direct.
#
# For air-gapped targets, use `scripts/install-from-bundle.sh` instead.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

MODE="direct"
PROXY_URL=""
NO_PROXY_EXTRA=""
DRY_RUN=0
AUTO_YES=0

usage() {
  cat <<'EOF'
Usage: scripts/install.sh [--direct | --proxy URL] [options]

Modes (pick one):
  --direct              Install with direct internet access (default).
  --proxy URL           Install through an HTTP proxy (e.g. http://10.5.13.13:8080).
                        Proxy is applied only to image pulls and build RUN steps.
                        Container runtime will NOT use the proxy.

Options:
  --no-proxy HOSTS      Comma-separated additional hosts to bypass the proxy.
                        Local hostnames (mysql-v5, backend-v5, frontend-v5,
                        localhost, 127.0.0.1) are always bypassed.
  -y, --yes             Skip confirmation prompts (non-interactive).
  --dry-run             Print what would happen without making changes.
  -h, --help            Show this help.

Examples:
  scripts/install.sh                                      # direct
  scripts/install.sh --proxy http://10.5.13.13:8080       # via proxy, install-time only
  scripts/install.sh --proxy http://proxy.corp:3128 \
                     --no-proxy 10.0.0.0/8,.corp.local    # with extra bypass list
EOF
}

log() { printf '\033[36m[install]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[install]\033[0m %s\n' "$*" >&2; }
die() { printf '\033[31m[install]\033[0m %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --direct) MODE="direct"; shift ;;
    --proxy) MODE="proxy"; PROXY_URL="${2:-}"; shift 2 ;;
    --proxy=*) MODE="proxy"; PROXY_URL="${1#--proxy=}"; shift ;;
    --no-proxy) NO_PROXY_EXTRA="${2:-}"; shift 2 ;;
    --no-proxy=*) NO_PROXY_EXTRA="${1#--no-proxy=}"; shift ;;
    -y|--yes) AUTO_YES=1; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) warn "Unknown option: $1"; usage; exit 1 ;;
  esac
done

if [ "$MODE" = "proxy" ] && [ -z "$PROXY_URL" ]; then
  die "--proxy requires a URL (e.g. --proxy http://10.5.13.13:8080)"
fi
if [ "$MODE" = "proxy" ] && ! [[ "$PROXY_URL" =~ ^https?:// ]]; then
  die "Proxy URL must start with http:// or https:// — got '$PROXY_URL'"
fi

# ---- preflight --------------------------------------------------------------

cd "$REPO_ROOT"

command -v docker >/dev/null 2>&1 \
  || die "docker not found. Install Docker 24+ first: https://docs.docker.com/engine/install/"

if ! docker info >/dev/null 2>&1; then
  if id -nG "$USER" | grep -qw docker; then
    warn "Your user is in the docker group but this shell hasn't picked it up."
    warn "Re-running each docker call with 'sg docker -c ...' instead."
    DOCKER="sg docker -c"
    COMPOSE_CMD() { sg docker -c "docker compose $*"; }
    PLAIN_DOCKER() { sg docker -c "docker $*"; }
  else
    die "Cannot talk to docker daemon. Add yourself to the docker group: sudo usermod -aG docker \$USER"
  fi
else
  DOCKER="docker"
  COMPOSE_CMD() { docker compose "$@"; }
  PLAIN_DOCKER() { docker "$@"; }
fi

# ---- summary + confirm ------------------------------------------------------

NO_PROXY_LOCAL="localhost,127.0.0.1,mysql-v5,backend-v5,frontend-v5"
NO_PROXY_FULL="$NO_PROXY_LOCAL"
[ -n "$NO_PROXY_EXTRA" ] && NO_PROXY_FULL="$NO_PROXY_FULL,$NO_PROXY_EXTRA"

log "Mode: $MODE"
if [ "$MODE" = "proxy" ]; then
  log "  proxy:     $PROXY_URL   (install-time only)"
  log "  no_proxy:  $NO_PROXY_FULL"
fi
log "  repo root: $REPO_ROOT"
log "  compose:   docker-compose.yml"
[ "$DRY_RUN" = 1 ] && log "  DRY RUN — no changes will be made"

if [ "$AUTO_YES" != 1 ] && [ -t 0 ] && [ "$DRY_RUN" != 1 ]; then
  printf '\n[install] Proceed? [y/N] '
  read -r ans
  case "${ans:-}" in [yY]|[yY][eE][sS]) ;; *) die "Aborted." ;; esac
fi

run() {
  if [ "$DRY_RUN" = 1 ]; then
    printf '\033[90m[dry-run]\033[0m %s\n' "$*"
  else
    eval "$@"
  fi
}

# ---- housekeeping: strip persistent proxies from ~/.docker/config.json ------

DOCKER_CFG="$HOME/.docker/config.json"
if [ -f "$DOCKER_CFG" ] && grep -q '"proxies"' "$DOCKER_CFG" 2>/dev/null; then
  warn "~/.docker/config.json has a persistent 'proxies' block."
  warn "This would be auto-injected into every container's runtime env —"
  warn "the exact cause of SIEM 501s and frontend healthcheck 503s."
  warn "Backing it up and removing the 'proxies' block."
  if [ "$DRY_RUN" != 1 ]; then
    cp "$DOCKER_CFG" "$DOCKER_CFG.bak.$(date +%s)"
    if command -v jq >/dev/null 2>&1; then
      jq 'del(.proxies)' "$DOCKER_CFG" > "$DOCKER_CFG.tmp" && mv "$DOCKER_CFG.tmp" "$DOCKER_CFG"
    else
      # No jq — be conservative, zero out the file (backup still exists).
      printf '{}\n' > "$DOCKER_CFG"
    fi
  fi
fi

# ---- install-time daemon proxy (transient, only if needed) ------------------

DAEMON_DROPIN="/etc/systemd/system/docker.service.d/leopard-install-proxy.conf"
PRE_EXISTING_DAEMON_PROXY=0
OUR_DROPIN_INSTALLED=0

if [ "$MODE" = "proxy" ]; then
  current_env="$(systemctl show --property=Environment docker 2>/dev/null || true)"
  if echo "$current_env" | grep -qE "HTTP_PROXY=http"; then
    log "Docker daemon already has a proxy configured. Leaving it as-is."
    PRE_EXISTING_DAEMON_PROXY=1
  else
    log "Configuring transient Docker daemon proxy (will be removed after install)."
    if [ "$DRY_RUN" != 1 ]; then
      sudo -n true 2>/dev/null || {
        log "sudo will prompt for your password to edit /etc/systemd/system/docker.service.d/"
      }
      sudo mkdir -p /etc/systemd/system/docker.service.d
      sudo tee "$DAEMON_DROPIN" >/dev/null <<EOF
# Transient — written by The Leopard's scripts/install.sh. Safe to remove.
[Service]
Environment="HTTP_PROXY=$PROXY_URL"
Environment="HTTPS_PROXY=$PROXY_URL"
Environment="NO_PROXY=$NO_PROXY_FULL"
EOF
      sudo systemctl daemon-reload
      sudo systemctl restart docker
      # Wait for docker to be back.
      for _ in $(seq 1 30); do
        if docker info >/dev/null 2>&1 || sg docker -c "docker info" >/dev/null 2>&1; then
          break
        fi
        sleep 1
      done
    fi
    OUR_DROPIN_INSTALLED=1
  fi
fi

# Guarantee the drop-in is torn down even if the build / up fails.
cleanup_daemon_proxy() {
  if [ "$OUR_DROPIN_INSTALLED" = 1 ] && [ "$DRY_RUN" != 1 ]; then
    log "Removing transient Docker daemon proxy."
    sudo rm -f "$DAEMON_DROPIN" || true
    sudo systemctl daemon-reload || true
    sudo systemctl restart docker || true
    for _ in $(seq 1 30); do
      if docker info >/dev/null 2>&1 || sg docker -c "docker info" >/dev/null 2>&1; then
        break
      fi
      sleep 1
    done
  fi
}
trap cleanup_daemon_proxy EXIT

# ---- build + up -------------------------------------------------------------

if [ "$MODE" = "proxy" ]; then
  log "Building images with proxy as build-args (not persisted into the images)."
  run "COMPOSE_CMD build \
    --build-arg HTTP_PROXY='$PROXY_URL' \
    --build-arg HTTPS_PROXY='$PROXY_URL' \
    --build-arg http_proxy='$PROXY_URL' \
    --build-arg https_proxy='$PROXY_URL' \
    --build-arg NO_PROXY='$NO_PROXY_FULL' \
    --build-arg no_proxy='$NO_PROXY_FULL'"
else
  log "Building images (direct internet)."
  run "COMPOSE_CMD build"
fi

log "Starting stack..."
run "COMPOSE_CMD up -d"

# ---- health wait ------------------------------------------------------------

if [ "$DRY_RUN" != 1 ]; then
  log "Waiting for services to become healthy (up to 5 min)..."
  deadline=$(( $(date +%s) + 300 ))
  check_health() {
    local name="$1"
    PLAIN_DOCKER inspect "$name" --format '{{.State.Health.Status}}' 2>/dev/null
  }
  while :; do
    now=$(date +%s)
    [ "$now" -gt "$deadline" ] && { warn "Timeout waiting for health. Check 'docker compose ps' and 'docker logs'."; break; }
    mysql_h=$(check_health mysql-v5 || echo "?")
    back_h=$(check_health ioc-backend-v5 || echo "?")
    front_h=$(check_health ioc-frontend-v5 || echo "?")
    printf '\r\033[36m[install]\033[0m mysql=%s  backend=%s  frontend=%s ' \
      "$mysql_h" "$back_h" "$front_h"
    if [ "$mysql_h" = "healthy" ] && [ "$back_h" = "healthy" ] && [ "$front_h" = "healthy" ]; then
      printf '\n'
      log "All services healthy."
      break
    fi
    sleep 3
  done
fi

cat <<EOF

$(log "Done.")
  URL:  https://127.0.0.1:3000  (self-signed cert — expect a browser warning)
  Logs: docker compose logs -f
  Docs: docs/TROUBLESHOOTING.md, docs/OFFLINE_INSTALL.md

Runtime containers have NO proxy env — SIEM requests go direct.
EOF
