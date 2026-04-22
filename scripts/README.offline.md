# The Leopard - Offline Install Bundle

This directory is a self-contained, air-gapped installer for The Leopard.
Everything the app needs at runtime is already here: the three container
images, the compose file that wires them together, an environment
template, and the install script itself. Nothing in the install path
reaches out to the network.

## What's in this bundle

The following files ship together. If any are missing the installer will
refuse to run, so trust what you see below as the complete manifest.

`images.tar` is the output of `docker save` for the three runtime images:
the official `mysql:8.0` server, the compiled Leopard backend, and the
nginx-based frontend. `images.manifest` is a plain-text copy of the tags
inside that tarball so you can sanity-check what got loaded without
opening a multi-gigabyte archive.

`docker-compose.yml` is copied verbatim from the source repo. It carries
the service wiring, healthchecks, resource limits, and network topology.
The installer uses it with `--no-build`, so nothing here tries to pull or
build at install time.

`.env.example` is the environment template. The installer copies it to
`.env` on first run and auto-generates a strong `JWT_SECRET` if the
template still has its placeholder value. Your real secrets (DB password,
JWT signing key, optional `ENCRYPTION_KEY`) live in `.env` after install.

`install.sh` is the one-shot installer described below.

`docs/` is a copy of the repository's documentation directory, including
the longer-form offline-install runbook (`docs/OFFLINE_INSTALL.md`), the
API reference, the user guide, and the proxy setup notes.

`VERSION` is a single-line file containing the bundle's version tag, of
the form `leopard-v<short-sha>-<YYYYMMDD>`.

## Prerequisites on the target

You need Docker Engine 24 or newer with the compose v2 plugin. Your user
must be in the `docker` group; if you installed Docker in the same shell
session you're using now, run `newgrp docker` (or log out and back in)
before running the installer, or the script will fail with a clear
message about daemon access.

Budget roughly 8 GB of free disk space. `images.tar` is about 1-2 GB
compressed and unpacks into the docker graph driver; MySQL's data
directory grows from there. The app binds to host ports 3000 (HTTPS)
and 3080 (HTTP redirect) on all interfaces, and to 3316 on the loopback
interface for the database. Free those ports before running the
installer or the compose up will fail.

The host only needs outbound network access to your SIEM APIs. The
install itself does not touch the internet.

## Install

Copy the tarball to the target (USB stick, internal share, scp via a jump
host, whatever your change control allows), extract it, and run the
installer:

```
tar -xzf leopard-offline-<version>.tar.gz
cd leopard-offline-<version>
./install.sh
```

The installer loads the three images, seeds `.env` from `.env.example`
(generating a random `JWT_SECRET` if the template placeholder is still in
place), optionally prompts you to set the MySQL root password if you are
running interactively, then calls `docker compose up -d --no-build`. It
polls container health for up to five minutes; when the backend and
frontend both report healthy it prints the final URL.

On success, browse to `https://127.0.0.1:3000`. The first visit will show
a self-signed cert warning. Accept it to reach the setup wizard, which
walks you through creating the admin user and configuring your first
SIEM connection.

## Upgrade

Upgrades follow the same path as the initial install. On your online
staging box, pull the latest code and run `make bundle` (or
`bash scripts/build-offline-bundle.sh` directly). Ship the new tarball
to the target, extract it into a fresh directory, and run `./install.sh`
again. The installer loads the new images into the local docker daemon
and `docker compose up -d` recreates any containers whose image tags
changed. MySQL's data volume (`mysql_data_v5`) is preserved across
upgrades, so your users, settings, and search history survive.

If you want to roll back, keep the previous bundle directory around and
run its `install.sh` again; docker will reload the older images on top
of the newer ones and compose will recreate containers with the older
tags. Schema migrations run on startup, so data compatibility with a
previous minor version depends on the release notes.

## Troubleshooting

If `install.sh` dies on the very first docker call with a permission
denied error against `/var/run/docker.sock`, your shell pre-dates your
addition to the `docker` group. Fix it with
`sudo usermod -aG docker "$USER"` followed by `newgrp docker`, or log out
and back in. The installer refuses to call `sudo` on your behalf.

If compose reports a port is already in use, identify the offender with
`ss -tlnp | grep -E ':3000|:3080|:3316'` (run as root to see process
names) and stop whatever is bound there. Changing the app's exposed
ports means editing `docker-compose.yml` before running the installer.

If a container restart-loops after install, `docker logs ioc-backend-v5`
(or `ioc-frontend-v5`, or `mysql-v5`) is the first place to look. The
backend usually fails for one of three reasons: `JWT_SECRET` unset,
database not yet healthy (transient on slow disks; it retries), or a bad
env value. Each of those leaves a clear message in the first ten lines
of the log.

## Where things live

Logs are captured by the docker json-file driver with 10 MB rotation.
Read them with `docker logs ioc-backend-v5`, `docker logs
ioc-frontend-v5`, and `docker logs mysql-v5`. Compose state is tracked
in the docker daemon, so `docker compose ps` from this bundle directory
shows the live status of the stack.

Persistent data lives in the `mysql_data_v5` named volume. It survives
`docker compose down` and `docker compose up` cycles. To wipe everything
(destructive), run `docker compose down -v` from this directory.

Uploaded TLS certificates, if any, live inside the frontend container at
`/etc/ssl/leopard/`. The setup wizard and the Security tab in the admin
UI manage them through the API; you should not need to touch the
filesystem directly.
