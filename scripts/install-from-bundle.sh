#!/usr/bin/env bash
# install-from-bundle.sh
#
# Runs on the offline / air-gapped target. Assumes this script sits inside
# an extracted Leopard offline bundle next to:
#   images.tar           - docker save of mysql:8.0, backend, frontend
#   images.manifest      - plain-text list of image tags in images.tar
#   docker-compose.yml   - unmodified compose spec from the source repo
#   .env.example         - env template
#   docs/                - runbooks shipped with the bundle
#   README.offline.md    - short operator README
#   VERSION              - bundle version tag
#
# End state: the three containers up and healthy, .env populated with a
# real JWT_SECRET, and the UI reachable on https://127.0.0.1:3000 .

set -euo pipefail

# ----- helpers ---------------------------------------------------------------

log()  { printf '[install] %s\n' "$*"; }
warn() { printf '[install] WARN: %s\n' "$*" >&2; }
die()  { printf '[install] ERROR: %s\n' "$*" >&2; exit 1; }

have() { command -v "$1" >/dev/null 2>&1; }

# Locate our own directory so the script works regardless of CWD.
BUNDLE_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$BUNDLE_DIR"

if [ -f "$BUNDLE_DIR/VERSION" ]; then
  BUNDLE_VERSION="$(cat "$BUNDLE_DIR/VERSION")"
else
  BUNDLE_VERSION="unknown"
fi

log "bundle : $BUNDLE_VERSION"
log "dir    : $BUNDLE_DIR"

# ----- preflight -------------------------------------------------------------

if ! have docker; then
  die "docker not found on PATH. Install Docker Engine 24+ and retry."
fi

if ! docker info >/dev/null 2>&1; then
  die "cannot talk to the docker daemon. Ensure dockerd is running and \
your user is in the docker group (re-login or 'newgrp docker' after \
usermod -aG docker \$USER)."
fi

if ! docker compose version >/dev/null 2>&1; then
  die "docker compose v2 plugin not found. Install it and retry."
fi

if [ ! -f "$BUNDLE_DIR/images.tar" ]; then
  die "images.tar missing from bundle dir. Did the tarball extract fully?"
fi

if [ ! -f "$BUNDLE_DIR/docker-compose.yml" ]; then
  die "docker-compose.yml missing from bundle dir."
fi

# ----- load images -----------------------------------------------------------

log "loading images from images.tar ..."
# docker load prints "Loaded image: <tag>" lines; surface them to the user
# so they know exactly what entered their local daemon.
docker load -i "$BUNDLE_DIR/images.tar" | sed 's/^/[install]   /'

# ----- env file --------------------------------------------------------------

ENV_FILE="$BUNDLE_DIR/.env"
ENV_EXAMPLE="$BUNDLE_DIR/.env.example"

if [ ! -f "$ENV_FILE" ]; then
  if [ ! -f "$ENV_EXAMPLE" ]; then
    die ".env.example missing from bundle; cannot seed .env"
  fi
  log "no .env found; seeding from .env.example"
  cp "$ENV_EXAMPLE" "$ENV_FILE"
else
  log ".env already exists; leaving it alone"
fi

# Generate a JWT_SECRET if the value is blank or matches a known placeholder.
gen_secret() {
  if have openssl; then
    openssl rand -hex 48
  else
    # Fallback: 48 bytes of /dev/urandom rendered as hex via od. Present on
    # every POSIX system worth the name; no openssl required.
    od -vN 48 -An -tx1 /dev/urandom | tr -d ' \n'
  fi
}

# Pull the current value (if any) using a simple grep; we don't source the
# file because we don't want to execute arbitrary assignments.
current_secret="$(grep -E '^JWT_SECRET=' "$ENV_FILE" | head -n1 | cut -d= -f2- || true)"

needs_secret=0
case "$current_secret" in
  ""|"change-this-in-production"|"change-this-to-a-secure-random-string"|"change-this-to-a-long-random-string")
    needs_secret=1
    ;;
esac

if [ "$needs_secret" = "1" ]; then
  new_secret="$(gen_secret)"
  # Rewrite (or append) JWT_SECRET in .env. Using a temp file keeps this
  # safe on filesystems where in-place edits are awkward.
  tmp="$(mktemp)"
  if grep -qE '^JWT_SECRET=' "$ENV_FILE"; then
    # Use awk rather than sed to dodge slash/ampersand escaping headaches.
    awk -v s="$new_secret" '
      BEGIN { FS = OFS = "=" }
      /^JWT_SECRET=/ { print "JWT_SECRET=" s; next }
      { print }
    ' "$ENV_FILE" > "$tmp"
  else
    cp "$ENV_FILE" "$tmp"
    printf '\nJWT_SECRET=%s\n' "$new_secret" >> "$tmp"
  fi
  mv "$tmp" "$ENV_FILE"
  log "generated JWT_SECRET (48 random bytes, hex-encoded) into .env"
else
  log "JWT_SECRET already set in .env; leaving it alone"
fi

# ----- optional DB password prompt ------------------------------------------

# Only prompt if we're attached to a TTY. Non-interactive installs (e.g.
# Ansible) get whatever is already in .env.
if [ -t 0 ] && [ -t 1 ]; then
  current_db_pw="$(grep -E '^DB_PASSWORD=' "$ENV_FILE" | head -n1 | cut -d= -f2- || true)"
  : "${current_db_pw:=password}"
  printf '[install] DB_PASSWORD [current: %s] (enter to keep, or type new): ' "$current_db_pw"
  # Read without -s so the user can see what they're typing; this value
  # also lands in .env in plaintext, so hiding it here buys nothing.
  IFS= read -r new_db_pw || new_db_pw=""
  if [ -n "$new_db_pw" ] && [ "$new_db_pw" != "$current_db_pw" ]; then
    tmp="$(mktemp)"
    awk -v p="$new_db_pw" '
      BEGIN { FS = OFS = "=" }
      /^DB_PASSWORD=/ { print "DB_PASSWORD=" p; next }
      { print }
    ' "$ENV_FILE" > "$tmp"
    mv "$tmp" "$ENV_FILE"
    log "DB_PASSWORD updated in .env"
  fi
else
  log "non-interactive mode; skipping DB_PASSWORD prompt"
fi

# ----- bring up --------------------------------------------------------------

log "starting stack via docker compose up -d --no-build ..."
# --no-build guarantees we never try to reach a registry. Any missing image
# at this point would be a bug in build-offline-bundle.sh, not an install
# problem.
docker compose --env-file "$ENV_FILE" up -d --no-build

# ----- wait for health -------------------------------------------------------

TIMEOUT_SECS=300          # 5 minutes
SLEEP_SECS=5
elapsed=0

log "waiting for backend + frontend to report healthy (timeout: ${TIMEOUT_SECS}s) ..."

container_state() {
  # Prints "healthy" / "starting" / "unhealthy" / "nohealthcheck" / "missing"
  local name="$1"
  local state
  state="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{if .State.Running}}nohealthcheck{{else}}stopped{{end}}{{end}}' "$name" 2>/dev/null || echo "missing")"
  printf '%s' "$state"
}

while :; do
  backend_state="$(container_state ioc-backend-v5)"
  frontend_state="$(container_state ioc-frontend-v5)"

  log "  backend=$backend_state  frontend=$frontend_state  (${elapsed}s/${TIMEOUT_SECS}s)"

  if [ "$backend_state" = "healthy" ] && [ "$frontend_state" = "healthy" ]; then
    log "both services healthy"
    break
  fi

  if [ "$elapsed" -ge "$TIMEOUT_SECS" ]; then
    warn "timed out waiting for healthy state"
    warn "inspect with: docker compose ps"
    warn "            : docker logs ioc-backend-v5"
    warn "            : docker logs ioc-frontend-v5"
    die  "aborting; stack is up but not confirmed healthy"
  fi

  sleep "$SLEEP_SECS"
  elapsed=$((elapsed + SLEEP_SECS))
done

# ----- done ------------------------------------------------------------------

printf '\n'
log "=============================================="
log "The Leopard is up"
log "=============================================="
log "  URL : https://127.0.0.1:3000"
log ""
log "  First visit will show a self-signed cert warning; accept it to"
log "  proceed. You can upload your own cert later under Admin -> Security."
log ""
log "  Containers:"
log "    mysql-v5         (database)"
log "    ioc-backend-v5   (API)"
log "    ioc-frontend-v5  (nginx + UI, HTTPS on 3000)"
log ""
log "  Tail logs with: docker logs -f ioc-backend-v5"
printf '\n'
