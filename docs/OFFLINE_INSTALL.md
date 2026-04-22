# Offline / Air-Gapped Install

The Leopard supports three install modes, picked according to what
network the target host can reach:

| Target host reaches… | Install command | Docs |
| -------------------- | --------------- | ---- |
| Docker Hub + npm + apt/apk directly | `make install` | [README.md](../README.md) |
| Internet only via an HTTP proxy | `make install-proxy PROXY=http://host:port` | Below (`## Proxy-assisted install`) |
| Nothing outside the internal SIEM VLAN | `make bundle` on a staging box, then `./install.sh` on the target | This document |

This file covers modes 2 and 3. Read it alongside the shorter
`README.offline.md` that ships inside each offline bundle — that's the
operator quickstart; this is the long-form reference.

## Proxy-assisted install (proxy only at install, never at runtime)

When the host can't see Docker Hub directly but can reach a corporate
HTTP proxy, run:

```bash
make install-proxy PROXY=http://proxy.example.com:8080
# optionally:
make install-proxy PROXY=http://proxy.example.com:8080 NO_PROXY=10.0.0.0/8,.corp.local
```

The installer (`scripts/install.sh --proxy`) guarantees the proxy
touches only the build phase, never the runtime containers. It does
this with three specific moves:

1. **Transient systemd drop-in for the Docker daemon.** The daemon
   needs proxy access to pull `mysql:8.0`, `node:20-slim`, and
   `nginx:alpine` from Docker Hub. The installer writes
   `/etc/systemd/system/docker.service.d/leopard-install-proxy.conf`,
   reloads systemd, and restarts Docker. After the stack is up, it
   removes that file and restarts Docker again — so the daemon
   forgets the proxy. If the operator already had a daemon-wide proxy
   configured (outside this installer), the installer detects that
   and does **not** touch it.
2. **Build-args instead of `~/.docker/config.json`.** `docker compose
   build` is invoked with explicit `--build-arg HTTP_PROXY=...` /
   `HTTPS_PROXY` / lowercase equivalents / `NO_PROXY`. That reaches
   `npm ci`, `apt-get install`, and `apk add` inside the build stages
   via the standard conventions, but those build args live in the
   build stage only — they don't end up in the final image's runtime
   env. Critically, the installer **refuses to write a `proxies` block
   into `~/.docker/config.json`** and actively purges any existing one
   (backing it up first). That block is what caused the earlier
   incidents: Docker auto-injects its contents into every container's
   runtime env, so SIEM requests went through the proxy and came back
   `501 Not Implemented`, and the frontend's busybox `wget` health
   check hit the proxy and got `503`.
3. **Defensive empty env in compose.** The `backend-v5` and
   `frontend-v5` services in `docker-compose.yml` already set both
   upper- and lowercase `HTTP_PROXY`/`HTTPS_PROXY` to the empty string
   and declare a sane `NO_PROXY`. Even if some future change to the
   install flow leaked a proxy into container runtime, that clear
   would still zero it out.

If you ever need to verify, run these commands post-install:

```bash
# Daemon env must not mention the proxy anymore (or only what you
# had before install).
systemctl show --property=Environment docker

# ~/.docker/config.json must not contain a 'proxies' block.
cat ~/.docker/config.json

# Inside the running containers, HTTP_PROXY / http_proxy must be empty.
docker exec ioc-backend-v5 env  | grep -i proxy
docker exec ioc-frontend-v5 env | grep -i proxy
```

All three should be clean.

## Air-gapped install (no internet on the target at all)

For sites where the target host cannot reach any external network — no
Docker Hub, no npm, no proxy either — use the offline bundle flow. This
is the typical LogRhythm SOC deployment where the only network the box
can see is the internal SIEM management VLAN.

## How the two paths compare

The **online install** is the one documented in the repo root
`README.md`. You clone the repo, copy `.env.example` to `.env`, edit a
handful of values, and run `docker compose up -d`. Compose pulls
`mysql:8.0`, `node:20-slim`, and `nginx:alpine` from Docker Hub, runs
`npm ci` inside the backend and frontend builder stages, and installs
`netcat-openbsd` / `openssl` via apt and apk. The build takes a few
minutes; the resulting stack starts and the wizard takes over.

The **offline install** splits that process in two. On an online staging
host (your laptop, a jump box, a dedicated build VM - anything that can
reach Docker Hub), you run one script that pulls all base images, builds
the two app images via `docker compose build`, saves the three runtime
images with `docker save`, and tars them together with the compose file,
an env template, and an installer script into a single `.tar.gz`. You
then ship that tarball to the offline target through whatever channel
your change control allows: USB stick, internal file share, scp through
a jump host. On the target, you extract the tarball and run one
installer script. The installer loads the images with `docker load`,
seeds `.env` with a random `JWT_SECRET`, and calls
`docker compose up -d --no-build`. No outbound network access from the
target is required at any point.

## Build the bundle

On the online staging host, from a clone of this repository:

```
make bundle
```

or equivalently:

```
bash scripts/build-offline-bundle.sh
```

The script aborts early if docker is not available, if your user cannot
talk to the daemon (the usual "newly-added to the docker group" trap),
or if the compose v2 plugin is missing. Otherwise it pulls the three
base images, runs `docker compose build` (cache-hitting if you've built
before), then saves `mysql:8.0`, the backend, and the frontend into a
single `images.tar`. It derives a version string from
`git rev-parse --short HEAD` and the current date, of the form
`leopard-v<sha>-<YYYYMMDD>`, and emits:

```
dist/leopard-v<sha>-<YYYYMMDD>.tar.gz
dist/leopard-v<sha>-<YYYYMMDD>.tar.gz.sha256
```

The final summary prints the bundle path, its size, the sha256 digest,
and an scp command you can paste to ship it. Ship both the `.tar.gz`
and the `.sha256` - the operator on the far side should verify the
checksum before running the installer.

## Ship the bundle

Whatever transport your environment allows: `scp`, `rsync`, a USB drive
with a sneakernet policy, a one-way data diode, an internal artifact
server. The tarball is a single file and verifies with `sha256sum -c`.
It contains no secrets - the `.env.example` inside has only defaults
and placeholders, and the installer generates real values on first run.

## Install on the offline target

Extract the tarball and run the installer. From the operator's point of
view it is a one-liner:

```
tar -xzf leopard-v<sha>-<YYYYMMDD>.tar.gz
cd leopard-v<sha>-<YYYYMMDD>
./install.sh
```

The installer loads the bundled images into the local docker daemon
(echoing each `Loaded image:` line so there is no mystery about what
entered the daemon), copies `.env.example` to `.env` if no `.env`
exists, and auto-generates a 48-byte random `JWT_SECRET` if the
template still has its placeholder. If it is running on a TTY it
prompts for the MySQL root password, defaulting to whatever is already
in `.env`. It then calls `docker compose up -d --no-build` so nothing
ever tries to reach a registry.

After the stack starts the script polls container health for up to five
minutes. When the backend and frontend report healthy it prints the
final URL and logs-tailing commands.

## Upgrades

Upgrades use the same mechanics as the initial install. Build a new
bundle on the online host, ship it, extract it next to the old one, and
run its `install.sh`. Docker loads the new images; compose's reconciler
recreates whichever containers have new image tags and leaves the rest
alone. The `mysql_data_v5` named volume persists across upgrades, so
users, SIEM configs, audit logs, and search history survive untouched.

For a clean rollback, keep the previous bundle directory around and
re-run its installer. Docker will reload the older images, compose will
recreate containers with the older tags, and MySQL will come up against
the same data volume. Note that schema changes between releases are
applied on startup, so if the newer version performed an additive
migration the older binary may or may not still work against the
migrated schema; check the release notes.

## Troubleshooting

**Permission denied on `/var/run/docker.sock`.** Your shell was started
before your user was added to the docker group. Run `newgrp docker`, or
log out and back in, before retrying the installer. The installer
refuses to `sudo` on your behalf; that decision is yours.

**Port already in use.** The frontend binds 3000 and 3080, MySQL binds
3316 on loopback. Find the conflicting process with
`ss -tlnp | grep -E ':3000|:3080|:3316'` (as root) and stop it. If you
need different ports, edit `docker-compose.yml` in the extracted bundle
directory before running the installer.

**A container restart-loops.** Start with the logs:
`docker logs ioc-backend-v5`, then `ioc-frontend-v5`, then `mysql-v5`.
The backend almost always tells you exactly what is wrong in the first
few lines: unset `JWT_SECRET`, unreachable database, or a malformed env
value. The frontend logs include nginx startup errors for TLS cert
issues. MySQL logs tend to be verbose but the first error after
"InnoDB: ..." is usually the real one.

**Install succeeded but the UI is unreachable from another host.** The
app binds to `0.0.0.0` on 3000 and 3080 by default, so the likely cause
is a host firewall. On RHEL-family hosts check `firewall-cmd
--list-ports`; on Debian/Ubuntu check `ufw status` or `iptables -L`.
For localhost-only (`127.0.0.1:3000`) testing from the host itself, no
firewall change is needed.

## Layout inside the bundle

```
leopard-v<sha>-<YYYYMMDD>/
  images.tar            # docker save of the three runtime images
  images.manifest       # plain-text list of image tags in images.tar
  docker-compose.yml    # unmodified from the source repo
  .env.example          # environment template (installer seeds .env from this)
  install.sh            # the offline installer
  README.offline.md     # operator quickstart
  VERSION               # single-line version tag (matches the directory name)
  docs/                 # copy of the repo's docs/ directory
```

The bundle is intentionally a single tarball rather than a multi-part
archive. A single file is trivial to verify (`sha256sum -c`), trivial to
move across a one-way transfer, and trivial to audit. The tradeoff is
size - expect 1-2 GB compressed. If your transport requires splitting,
`split -b 500M` the tarball on one side and `cat` the parts back
together on the other; the sha256 still verifies against the whole.
