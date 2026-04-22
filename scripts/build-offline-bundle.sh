#!/usr/bin/env bash
# build-offline-bundle.sh
#
# Produce a single portable tarball that contains everything needed to run
# The Leopard on an air-gapped / offline target host.
#
# Intended to run on an online staging box (or any machine that can reach
# Docker Hub) that also holds a clone of this repository.
#
# Output:
#   dist/leopard-offline-<version>.tar.gz
#   dist/leopard-offline-<version>.tar.gz.sha256
#
# Usage:
#   bash scripts/build-offline-bundle.sh
#
# The script never needs root. It does need the docker CLI available and
# the invoking user in the docker group (or a working DOCKER_HOST).

set -euo pipefail

# ----- helpers ---------------------------------------------------------------

log()  { printf '[build-offline] %s\n' "$*"; }
warn() { printf '[build-offline] WARN: %s\n' "$*" >&2; }
die()  { printf '[build-offline] ERROR: %s\n' "$*" >&2; exit 1; }

have() { command -v "$1" >/dev/null 2>&1; }

# Portable sha256. Prefer sha256sum (coreutils); fall back to `shasum -a 256`
# (BSD/macOS). If neither exists we emit a warning and skip the sidecar.
sha256_of() {
  local f="$1"
  if have sha256sum; then
    sha256sum "$f"
  elif have shasum; then
    shasum -a 256 "$f"
  else
    return 1
  fi
}

# Human-readable size. `du -h` is broadly available; fall back to `ls -lh`.
human_size() {
  local f="$1"
  if have du; then
    du -h "$f" | awk '{print $1}'
  else
    ls -lh "$f" | awk '{print $5}'
  fi
}

# ----- locate repo root ------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

# ----- preflight -------------------------------------------------------------

log "working dir: $REPO_ROOT"

if ! have docker; then
  die "docker not found on PATH. Install Docker Engine 24+ before running."
fi

# A reliable way to confirm the current user can talk to the daemon without
# sudo: run a harmless info command. If the user was added to the docker
# group after their shell started they'll get permission denied; tell them
# how to fix it rather than failing opaquely.
if ! docker info >/dev/null 2>&1; then
  die "docker daemon unreachable. Either dockerd is down, or your shell was \
started before you were added to the docker group. Try: newgrp docker, or \
re-login, then re-run this script."
fi

if ! docker compose version >/dev/null 2>&1; then
  die "docker compose v2 plugin not found. Install it and retry."
fi

if ! have tar; then
  die "tar not found on PATH."
fi

# ----- version string --------------------------------------------------------

if have git && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  GIT_SHORT="$(git rev-parse --short HEAD)"
else
  GIT_SHORT="nogit"
  warn "not a git repo (or git missing); using '$GIT_SHORT' for version"
fi

DATE_STAMP="$(date +%Y%m%d)"
VERSION="leopard-v${GIT_SHORT}-${DATE_STAMP}"
log "version: $VERSION"

# ----- pull base images ------------------------------------------------------

BASE_IMAGES=( "mysql:8.0" "node:20-slim" "nginx:alpine" )

log "pulling base images (mysql:8.0, node:20-slim, nginx:alpine) ..."
for img in "${BASE_IMAGES[@]}"; do
  if docker image inspect "$img" >/dev/null 2>&1; then
    log "  already present: $img"
  else
    log "  pulling: $img"
    docker pull "$img" >/dev/null
  fi
done

# ----- build app images ------------------------------------------------------

log "building app images via docker compose build (cached where possible) ..."
docker compose build

# After build, the compose-built images are named from the project name +
# service name. Compose's default project name is the directory name
# lowercased. We compute the project name the same way compose does so we
# emit the correct tag into images.tar.
if [ -n "${COMPOSE_PROJECT_NAME:-}" ]; then
  PROJECT_NAME="$COMPOSE_PROJECT_NAME"
else
  PROJECT_NAME="$(basename "$REPO_ROOT" | tr '[:upper:]' '[:lower:]')"
fi

BACKEND_IMAGE="${PROJECT_NAME}-backend-v5:latest"
FRONTEND_IMAGE="${PROJECT_NAME}-frontend-v5:latest"

# Sanity-check the built images are actually present. If the user has
# customized project name, we still want to fail loudly.
for img in "$BACKEND_IMAGE" "$FRONTEND_IMAGE"; do
  if ! docker image inspect "$img" >/dev/null 2>&1; then
    die "expected image '$img' not found after compose build. Check your \
COMPOSE_PROJECT_NAME / directory name."
  fi
done

log "app images:"
log "  $BACKEND_IMAGE"
log "  $FRONTEND_IMAGE"

# ----- stage bundle dir ------------------------------------------------------

DIST_DIR="$REPO_ROOT/dist"
STAGE_DIR="$DIST_DIR/${VERSION}"

log "staging bundle at: $STAGE_DIR"
rm -rf "$STAGE_DIR"
mkdir -p "$STAGE_DIR"

# Save the three runtime images into a single tarball. We ship mysql:8.0
# raw (it's the runtime image for the mysql-v5 service) alongside the two
# built app images.
log "saving images to images.tar (this takes a minute) ..."
docker save \
  "mysql:8.0" \
  "$BACKEND_IMAGE" \
  "$FRONTEND_IMAGE" \
  -o "$STAGE_DIR/images.tar"

# Drop a small manifest so the install script can report what it loaded
# without re-querying the tarball.
cat > "$STAGE_DIR/images.manifest" <<EOF
# Images bundled in images.tar
mysql:8.0
$BACKEND_IMAGE
$FRONTEND_IMAGE
EOF

# Copy the compose file + env template + docs into the bundle.
cp "$REPO_ROOT/docker-compose.yml" "$STAGE_DIR/docker-compose.yml"
cp "$REPO_ROOT/.env.example"       "$STAGE_DIR/.env.example"

if [ -d "$REPO_ROOT/docs" ]; then
  mkdir -p "$STAGE_DIR/docs"
  cp -r "$REPO_ROOT/docs/." "$STAGE_DIR/docs/"
fi

# Ship the installer and README.
cp "$SCRIPT_DIR/install-from-bundle.sh" "$STAGE_DIR/install.sh"
chmod +x "$STAGE_DIR/install.sh"

# The README lives alongside this build script so we can version it with the
# installer.
if [ -f "$SCRIPT_DIR/README.offline.md" ]; then
  cp "$SCRIPT_DIR/README.offline.md" "$STAGE_DIR/README.offline.md"
else
  warn "scripts/README.offline.md missing; bundle will not include it"
fi

# Stamp the bundle with its version so the installer can print it.
printf '%s\n' "$VERSION" > "$STAGE_DIR/VERSION"

# ----- tar it up -------------------------------------------------------------

TARBALL="$DIST_DIR/${VERSION}.tar.gz"
log "creating tarball: $TARBALL"

# Tar from DIST_DIR with the version directory as the top-level entry so the
# tarball extracts cleanly into ./leopard-v<sha>-<date>/ on the target.
tar -C "$DIST_DIR" -czf "$TARBALL" "${VERSION}"

# ----- checksum --------------------------------------------------------------

CHECKSUM_FILE="${TARBALL}.sha256"
if sha256_of "$TARBALL" > "$CHECKSUM_FILE" 2>/dev/null; then
  log "checksum written: $CHECKSUM_FILE"
else
  warn "no sha256sum/shasum available; skipping checksum sidecar"
  CHECKSUM_FILE=""
fi

# ----- summary ---------------------------------------------------------------

SIZE_HUMAN="$(human_size "$TARBALL")"

printf '\n'
log "=============================================="
log "bundle ready"
log "=============================================="
log "  path    : $TARBALL"
log "  size    : $SIZE_HUMAN"
if [ -n "$CHECKSUM_FILE" ]; then
  log "  sha256  : $(awk '{print $1}' "$CHECKSUM_FILE")"
fi
log "  version : $VERSION"
printf '\n'
log "ship it:"
log "  scp $TARBALL user@offline-host:/tmp/"
log "  # or"
log "  rsync -avh --progress $TARBALL user@offline-host:/tmp/"
printf '\n'
log "on the target:"
log "  tar -xzf $(basename "$TARBALL")"
log "  cd ${VERSION}"
log "  ./install.sh"
printf '\n'
