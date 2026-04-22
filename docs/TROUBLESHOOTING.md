# Troubleshooting — reading the logs

Every container writes structured logs to stdout, so `docker logs` is the
single entry point. Lines are tagged with an ISO timestamp, level, and a
short *area* tag (`boot`, `setup`, `search`, `siem`, `shutdown`,
`runtime`). Relevant context is appended as `key=value` pairs so `grep`
stays useful.

```
[2026-04-22T10:23:00.123Z] [INFO ] [search  ] — SIEM search complete client=acme siemType=logrhythm filterType=IP durationMs=1842 resultCount=3 hit=true
```

## Cheat sheet

```bash
# Stream everything live
docker compose logs -f backend-v5

# Last 200 lines, any level
docker logs ioc-backend-v5 --tail 200

# Only warnings and errors
docker logs ioc-backend-v5 | grep -E '\[WARN \]|\[ERROR\]'

# Watch one hunt end-to-end (lifecycle + SIEM + errors)
docker logs -f ioc-backend-v5 | grep -E 'hunt|SIEM search|\[ERROR\]'

# See SIEM HTTP requests with latency (debug level)
LOG_LEVEL=debug  # set in .env / compose to enable
docker logs ioc-backend-v5 | grep '\[siem'

# Every error, with the hint line that follows it
docker logs ioc-backend-v5 | grep -B1 -A1 '\[ERROR\]'
```

To raise verbosity, set `LOG_LEVEL=debug` (or `DEBUG_LOG=1`) in the
backend service's environment and recreate the container.

## What each stage logs

### Boot (`area=boot`)

- `environment validated` — env var checks passed; Node version and effective log level.
- `encryption key source` — says whether `ENCRYPTION_KEY` or `JWT_SECRET` is being used.
- `database config` — the DB host/port/user/name actually being used.
- `synchronizing database schema` / `schema synchronized` — models → tables.
- `initialization complete — ready to serve` — the app is ready.
- `HTTP server listening port=4000` — Express is up.

Failure modes to watch for:

- `schema sync failed` → MySQL is unreachable or the user lacks ALTER privilege. Hint line suggests sync-db from the admin panel after fixing.
- `fatal initialization error` → process exits; check the error message printed just before.

### Setup wizard (`area=setup`)

One log line per state transition. Useful for confirming the wizard's
backend calls actually land.

- `db test passed` / `db test failed` — the Database step's "Test Connection" button.
- `testing SIEM connection` / `SIEM test ok` / `SIEM test failed` — the SIEM step's button. Failure lines include `category` (connection|auth|timeout|server) and a `hint`.
- `SIEM connection saved` — the Save button.
- `listing log sources` / `log sources fetched count=N` — the new Log Sources step.
- `log-source mappings saved (setup)` — per-IOC-type checkbox save.
- `first admin created` — the admin user step.
- `setup marked complete` — wizard finished.

### Hunt / upload (`area=search`)

The lifecycle of a single search, from HTTP request to SIEM query to
result write:

1. `hunt request received` / `upload request received` — arrived at the API. Carries user, file name, minutes.
2. `hunt dispatch` — normalized IOCs + list of clients that will be queried. Carries `iocs=IP:3,Hash:2` type summary.
3. For each (client, IOC type):
   - `no log-source mapping — scanning all sources` (warn) — only if the admin hasn't configured mappings; the hint points at Admin → Field Mappings → Log Source Mapping.
   - `SIEM search executing` — the outbound query is about to go.
   - `polling for async results` (debug, LR/Splunk/QRadar) — adapter is waiting on a task id.
   - `SIEM search complete` — resultCount, durationMs, hit=true/false.
   - `SIEM search failed` (error) — with category + hint.
4. `hunt dispatch complete` — summary: total, hits, noHits, errors, total durationMs.

### SIEM adapter (`area=siem`)

One line per outbound HTTP request:

- Debug: `logrhythm GET /lr-admin-api/logsources status=200 ms=420` — normal responses.
- Warn: `logrhythm GET failed code=ECONNREFUSED reason="connect ECONNREFUSED 10.1.1.1:8501" ms=30012` — with the reason, code, and how long we waited.

The request logs are debug-level by default (set `LOG_LEVEL=debug` to
see them). Failure lines are always warn-level.

### Runtime / shutdown

- `unhandled promise rejection` / `uncaught exception` — bugs. Hints suggest common causes.
- `SIGTERM received` → `waiting for in-flight work activeSearchCount=X` → `all in-flight operations completed` → `database connection closed — goodbye`. A graceful shutdown looks like that sequence within 30 s.

## Common failure modes and what you'll see

| Symptom | Log signature | Fix |
| ------- | ------------- | --- |
| Backend crash-looping, `SyntaxError: Invalid or unexpected token` on `wait-for-mysql.sh:2` | Dockerfile didn't chmod +x the wait script; see `docs/PROXY_SETUP.md` §2 | Rebuild after `chmod +x server/wait-for-mysql.sh`. |
| Frontend unhealthy, repeated 503 on `/health` | `wget: server returned error: HTTP/1.1 503` from healthcheck | Proxy env var injected into container is intercepting loopback; see `docs/PROXY_SETUP.md` §3. |
| Hunt returns instantly with no results | `[WARN ] [search  ] no log-source mapping — scanning all sources` OR SIEM test worked but search didn't hit | Admin → Field Mappings → Log Source Mapping and pick at least one source per IOC type. |
| SIEM test succeeds, hunt fails with 501 | `SIEM search failed category=server` referencing the proxy hostname | Backend's outbound request is going through the proxy; clear both `HTTP_PROXY` and lowercase `http_proxy` on `backend-v5`. |
| Can't list log sources, 400 from LR | `[WARN ] [LR] entities param parentEntityId=0: HTTP 400` | Adapter already tries five variants; if all 400, your LR version uses a different param. Capture the 400 body and open an issue. |
| "SSL certificate error" testing LR | `[WARN ] [siem   ] logrhythm GET failed code=DEPTH_ZERO_SELF_SIGNED_CERT` | Turn off "Verify SSL Certificate" in the SIEM config. |
| Hunt hangs then times out | `poll did not complete status=timeout` | Either reduce the time window, narrow the log source mapping, or the SIEM itself is overloaded. |
| `Environment=HTTP_PROXY=...` still set after you thought you cleared it | `systemctl status docker` shows an old `Active: since` timestamp | `daemon-reload` alone doesn't restart Docker — run `sudo systemctl restart docker`. |

## Raising log volume temporarily

```yaml
# docker-compose.yml (backend-v5 environment)
environment:
  LOG_LEVEL: debug   # or DEBUG_LOG=1
```

Then `docker compose up -d backend-v5` (no rebuild needed since this is
env-only). Debug-level lines include every SIEM HTTP round-trip plus
adapter internals.

## Where else to look

- `docker compose ps` — container health state
- `docker inspect ioc-backend-v5 --format '{{json .State.Health}}'` — last healthcheck attempts + output
- MySQL: `docker exec mysql-v5 mysql -uroot -p$DB_PASSWORD -e 'SELECT * FROM iocdb.results ORDER BY createdAt DESC LIMIT 5;'`
- `docs/PROXY_SETUP.md` for the full history of proxy / SSL / log-source fixes
- `docs/OFFLINE_INSTALL.md` for air-gapped deployment (bundle-based install)
