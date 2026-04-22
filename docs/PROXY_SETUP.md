# Running Behind an HTTP Proxy

Notes on changes made to get `docker compose up -d` working on a host
whose only outbound path is an unauthenticated HTTP proxy
(example: `http://proxy.example.com:8080`).

The stack was verified healthy after the changes below:

| Container         | Port(s)                  | Status   |
| ----------------- | ------------------------ | -------- |
| `mysql-v5`        | `127.0.0.1:3316 -> 3306` | healthy  |
| `ioc-backend-v5`  | internal `4000`          | healthy  |
| `ioc-frontend-v5` | `3000` (HTTPS), `3080`   | healthy  |

## 1. Host prerequisites

### 1a. Docker daemon proxy (for pulling base images)

Create `/etc/systemd/system/docker.service.d/http-proxy.conf`:

```ini
[Service]
Environment="HTTP_PROXY=http://proxy.example.com:8080/"
Environment="HTTPS_PROXY=http://proxy.example.com:8080/"
Environment="NO_PROXY=localhost,127.0.0.1"
```

Reload and restart:

```bash
sudo systemctl daemon-reload
sudo systemctl restart docker
```

Needed so `docker pull` of `mysql:8.0`, `node:20-slim`, and `nginx:alpine`
can reach Docker Hub.

### 1b. Docker CLI proxy (for `RUN` steps inside image builds)

Create or update `~/.docker/config.json`:

```json
{
  "proxies": {
    "default": {
      "httpProxy":  "http://proxy.example.com:8080",
      "httpsProxy": "http://proxy.example.com:8080",
      "noProxy":    "localhost,127.0.0.1"
    }
  }
}
```

Docker automatically injects these as build args and env vars so
`npm ci`, `apt-get install`, and `apk add` reach the internet during
image builds. Side effect: the same vars are also injected into every
**running** container (addressed in section 3 below).

### 1c. `docker` group membership

Running user must be in the `docker` group:

```bash
sudo usermod -aG docker "$USER"
```

The group change only applies to new login sessions. Either log out and
back in, or use `newgrp docker` / `sg docker -c "<cmd>"` in the current
shell. Symptom if this is missing:

```
permission denied while trying to connect to the docker API at unix:///var/run/docker.sock
```

## 2. Fix: `wait-for-mysql.sh` missing exec bit

### Symptom

`ioc-backend-v5` crash-looped with:

```
/app/wait-for-mysql.sh:2
# wait-for-mysql.sh
^
SyntaxError: Invalid or unexpected token
```

### Cause

`server/wait-for-mysql.sh` was checked into git without the execute bit.
The `node:20-slim` image's entrypoint falls back to invoking `node` on
the arg when it can't exec it, so Node tried to parse the shell script
as JavaScript.

### Fix

Two changes, both required:

1. Set the bit on the file in the repo so it's correct on a fresh clone
   on Linux/macOS:

   ```bash
   chmod +x server/wait-for-mysql.sh
   ```

2. Add a guard in `server/Dockerfile` so the bit is correct inside the
   image even if the host-side bit is ever lost (e.g. cloned on Windows
   or extracted from an archive):

   ```dockerfile
   COPY --from=builder /app/node_modules ./node_modules
   COPY . .
   RUN chmod +x wait-for-mysql.sh          # <-- added
   RUN chown -R appuser:appuser /app
   ```

## 3. Fix: frontend healthcheck 503 via proxy

### Symptom

After mysql and backend were healthy, `ioc-frontend-v5` stayed
`unhealthy`. `docker inspect` showed:

```
wget: server returned error: HTTP/1.1 503 Service Unavailable
```

Running `wget` inside the container made the problem obvious:

```
$ docker exec ioc-frontend-v5 wget -S -O- http://127.0.0.1:3080/health
Connecting to proxy.example.com:8080 (proxy.example.com:8080)
  HTTP/1.1 503 Service Unavailable
```

The healthcheck was being sent to the corporate proxy instead of
loopback.

### Cause

Two things combine:

- `~/.docker/config.json`'s `proxies.default` injects **both**
  uppercase (`HTTP_PROXY`) and lowercase (`http_proxy`) variants into
  every container.
- The frontend image is Alpine-based. Its `wget` is the busybox
  applet, which **does not honor `NO_PROXY`** and only reads
  `http_proxy` (lowercase). So the healthcheck to `127.0.0.1:3080`
  was being proxied through `proxy.example.com:8080`, which returned 503.

The `backend-v5` service in compose already cleared `HTTP_PROXY` and
`HTTPS_PROXY`, but only the uppercase variants, and the frontend
service had no proxy overrides at all.

The same lowercase-variant bug affected the backend at runtime:
testing a SIEM connection failed with `Request failed with status
code 501` because Node's axios honored the lowercase `http_proxy`
env var and routed the SIEM request through the corporate proxy,
which returned `501 Not Implemented` for that destination. The fix
below clears both cases on both services.

### Fix

Added an `environment:` block to `frontend-v5` in `docker-compose.yml`
that clears both cases of the proxy vars and sets `no_proxy` for the
internal service names:

```yaml
  frontend-v5:
    ...
    environment:
      HTTP_PROXY: ""
      HTTPS_PROXY: ""
      http_proxy: ""
      https_proxy: ""
      NO_PROXY: localhost,127.0.0.1,backend-v5,mysql-v5
      no_proxy: localhost,127.0.0.1,backend-v5,mysql-v5
```

nginx's `proxy_pass http://backend` doesn't read these env vars, so
clearing them is safe — the frontend container has no need to reach
the outside world at runtime.

Added the lowercase counterparts to `backend-v5` for the same reason:

```yaml
  backend-v5:
    ...
    environment:
      ...
      HTTP_PROXY: ""
      HTTPS_PROXY: ""
      http_proxy: ""
      https_proxy: ""
      NO_PROXY: localhost,127.0.0.1,frontend-v5,mysql-v5
      no_proxy: localhost,127.0.0.1,frontend-v5,mysql-v5
```

> If your SIEM is only reachable **through** the corporate proxy
> (external SaaS SIEM, etc.), don't clear the backend's proxy vars —
> instead add the SIEM host to `NO_PROXY`/`no_proxy` exclusions only
> for hosts you want to reach directly, and leave the proxy pointed
> at `proxy.example.com:8080` for the rest.

## 4. Verifying

From the host (use `--noproxy '*'` so curl bypasses the system proxy
when hitting loopback):

```bash
curl -sk --noproxy '*' -o /dev/null -w "%{http_code}\n" https://127.0.0.1:3000/
# -> 200

curl -s  --noproxy '*' -o /dev/null -w "%{http_code}\n" http://127.0.0.1:3080/health
# -> 200

curl -sk --noproxy '*' https://127.0.0.1:3000/api/setup/status
# -> {"isComplete":false,"dbConnected":true,...}
```

## 5. Fix: LogRhythm SSL cert error, no "Skip SSL" toggle in UI

### Symptom

Testing a LogRhythm connection at `https://10.204.20.11:8501`
returned:

```
SSL certificate error connecting to Logrhythm at https://10.204.20.11:8501.
```

### Cause

The backend is already wired to accept self-signed certs —
`server/siem-adapters/base.adapter.js:21-24` creates an
`https.Agent({ rejectUnauthorized: false })` when `verifySSL === false`
is present in the SIEM config. But the frontend forms didn't expose
that option for LogRhythm:

- `frontend/src/pages/SetupWizard.jsx` — `siemForm` state had no
  `verifySSL` field and no checkbox UI, so the setup wizard could
  never disable verification.
- `frontend/src/pages/AdminPage.jsx` — the LogRhythm block in
  `SIEM_CONFIGS` was missing the `verifySSL` field that every other
  SIEM had.

Without the field in the request body, `verifySSL` was `undefined` on
the backend, which is *not* strict-equal to `false`, so the
permissive `https.Agent` was never attached — Node's default TLS
verification rejected the self-signed cert.

### Fix

- `SetupWizard.jsx`: added `verifySSL: false` to the initial
  `siemForm` state and rendered a "Verify SSL certificate" checkbox in
  the SIEM step (default unchecked — self-signed LogRhythm is the
  common case).
- `AdminPage.jsx`: added the missing `verifySSL` checkbox field to
  the `logrhythm` config block so it behaves the same as the other
  SIEMs.

## 6. Fix: searches finished instantly without hitting LogRhythm

### Symptom

After completing setup, an IOC search for `1.1.1.1` returned in
milliseconds with no results. Backend logs showed:

```
Running logsDigging with multi-SIEM adapter support
logsDigging complete.
No MsgSource for SD Centeralized SIEM, type=IP
```

No `Result` row was even written.

### Cause

`server/routes/search.js` had a LogRhythm-specific gate:

```js
if (siemType === 'logrhythm') {
  const logSource = await MsgSource.findOne({ where: { client, filterType } });
  if (!logSource) { console.warn(...); continue; }   // <-- skipped the SIEM call entirely
  logSourceListId = logSource.listId;
}
```

The `msgsources` table is a per-(client, IOC type) pointer to a
LogRhythm Log Source List ID, but **there was no UI anywhere in the
app to populate it** (model existed, no admin route, no admin page
section). So every LR search short-circuited before reaching the
SIEM and silently returned nothing.

### Fix — new "Log Sources" wizard step + admin CRUD

The `msgsources` table was generalized so it can also hold Splunk
indexes, Elastic indexes, etc. — the lookup is now keyed by
`(client, siemType, filterType)` and the search no longer skips when
the table is empty. A full CRUD path for these mappings was added,
both in the setup wizard and the admin panel.

**Backend changes:**

| File | Change |
| ---- | ------ |
| `server/models/MsgSource.js` | Added `siemType` column (default `logrhythm` for back-compat) and a composite index on `(client, siemType, filterType)`. |
| `server/routes/search.js` | Removed the LR-specific gate. Now does `MsgSource.findAll({where:{client, siemType, filterType}})` for **all** SIEM types, builds a `logSources` array, and passes it as a buildQuery option. Empty array → adapter falls back to "all sources" (logged as a warning). |
| `server/siem-adapters/logrhythm.adapter.js` | `buildQuery` now accepts `logSources: [{listId,name,guid}, ...]` and uses it for `queryLogSourceLists`. Legacy `logSourceListId` still honored. |
| `server/routes/setup.js` | Added `POST /api/setup/list-log-sources` (calls `adapter.getLogSources()` for the just-saved client) and `POST /api/setup/save-log-source-mappings` (bulk replace). Both refuse to run after first admin user exists. |
| `server/routes/admin.js` | Added `GET /api/admin/log-sources/:clientId`, `GET /api/admin/log-source-mappings/:clientId`, `POST /api/admin/log-source-mappings`, `DELETE /api/admin/log-source-mappings/:id`. All gated by `canManageMappings`. |

**Frontend changes:**

| File | Change |
| ---- | ------ |
| `frontend/src/pages/SetupWizard.jsx` | Inserted a new step **"Log Sources"** between SIEM Setup and Admin User. Per IOC type: searchable checkbox card listing the SIEM's log sources fetched via `/api/setup/list-log-sources`. **Skip** button shows an explicit warning (escalated for LogRhythm) before saving an empty mapping. Step labels are SIEM-aware ("Indexes" for Splunk, "Log Source Lists" for LR, "Agents" for Wazuh, etc.). |
| `frontend/src/components/LogSourceMappingsSection.jsx` | New component. Per-client log source mapping editor with the same per-IOC-type cards. Loads existing mappings + live SIEM sources side-by-side, allows toggling, saves via `POST /api/admin/log-source-mappings`. |
| `frontend/src/pages/AdminPage.jsx` | Imports and renders `<LogSourceMappingsSection>` under the existing `<FieldMappingsTab>` in the **Field Mappings** tab. |

### Behavior after the fix

- IOC search hits LogRhythm whether or not a mapping exists.
- With a mapping, `queryLogSourceLists` is sent populated → LR scans
  only those lists (fast).
- Without a mapping, `queryLogSourceLists: []` is sent and
  `useDefaultLogRepositories: true` makes LR scan every default
  repository (slow but works) — and the backend logs a warning so the
  operator notices.

### Follow-up fixes after first user test

The Field Mappings → Log Source Mapping section initially returned
`{"error":"Invalid ID parameter"}` and the LogRhythm dropdown showed
the wrong objects. Two related issues:

1. **Wrong validator.** The new admin routes used `:clientId` URL
   params, but `validateIdParam` middleware (`server/middleware.js`)
   hardcodes `req.params.id`. So the validator rejected the request
   before the auth check even ran. Fixed by adding a local
   `validateClientIdParam` helper in `server/routes/admin.js` that
   reads `:clientId` instead. `validateIdParam` itself is unchanged
   (other routes that legitimately use `:id` still depend on it).
2. **Wrong LogRhythm endpoint.** `getLogSources()` calls
   `/lr-admin-api/logsources` and returns individual log sources, but
   the `msgsources.listId` column and `queryLogSourceLists` query
   field are about *Log Source Lists*, not individual sources.
   Returning the wrong objects meant the saved `listId` values
   wouldn't match anything LR knows. Fixed by adding a separate
   `getLogSourceLists()` method on the LR adapter that hits
   `/lr-admin-api/lists`, filters by `listType` containing
   "logsource"/"log source"/"log_source" (case-insensitive, with a
   fallback to the unfiltered set if the filter strips everything),
   and returns `{ id, listId, name, guid, listType }`. The base
   adapter's default `getLogSourceLists()` just delegates to
   `getLogSources()` so other SIEMs (Splunk indexes, Wazuh agents,
   Elastic indexes, QRadar/ManageEngine log sources) work unchanged.
   Recon's `getLogSources()` consumer is untouched.

The admin route and the setup-time route both call the new method
when the SIEM is LogRhythm, and fall back to `getLogSources()` for
everything else.

### Multi-SIEM consumption of `logSources` in queries

To make the saved mappings actually narrow the SIEM search (not just
LogRhythm), each adapter's `buildQuery` now accepts a
`logSources: [{id, listId, name, guid, listType}]` option:

| Adapter | How `logSources` is applied |
| ------- | --------------------------- |
| LogRhythm | `queryLogSourceLists: logSources.map(ls => ls.listId)` (legacy `logSourceListId` still honored). |
| Splunk | The first source's `name` becomes the `index=...` clause; multiple sources expand to `(index=a OR index=b ...)`. |
| Elastic | `index` URL segment becomes `logSources.map(s=>s.name).join(',')`. |
| QRadar | AQL gets `AND logsourceid IN (id1, id2, ...)`. Custom templates can also reference `{{logSourceFilter}}`. |
| Wazuh | Indexer DSL gets a `terms: { 'agent.id': [...] }` must-clause; alerts API gets `agents_list=id1,id2`. |
| ManageEngine | Falls into the existing `log_source_ids` request-body field. |

Empty/absent `logSources` → all adapters fall back to their previous
"scan everything" behavior, so installs without mappings still work.

## 7. Summary of files changed

| File                     | Change                                                  |
| ------------------------ | ------------------------------------------------------- |
| `server/wait-for-mysql.sh` | Set executable bit (`chmod +x`).                      |
| `server/Dockerfile`      | Added `RUN chmod +x wait-for-mysql.sh` after `COPY . .`. |
| `docker-compose.yml`     | Cleared upper- AND lowercase proxy env vars on both `backend-v5` and `frontend-v5`; added internal hostnames to `no_proxy`. |
| `frontend/src/pages/SetupWizard.jsx` | Added `verifySSL` to setup SIEM form + checkbox UI; added new "Log Sources" wizard step. |
| `frontend/src/pages/AdminPage.jsx` | Added missing `verifySSL` field to LogRhythm config; mounted `<LogSourceMappingsSection>` in Field Mappings tab. |
| `server/models/MsgSource.js` | Added `siemType` column + composite index. |
| `server/routes/search.js` | Removed LR-only gate; generalized log-source lookup; passes `logSources` to `buildQuery` for all SIEMs. |
| `server/siem-adapters/logrhythm.adapter.js` | Accepts new `logSources` array option in `buildQuery`. |
| `server/routes/setup.js` | New `/list-log-sources` and `/save-log-source-mappings` endpoints. |
| `server/routes/admin.js` | New `/log-sources/:clientId` and CRUD on `/log-source-mappings`. |
| `frontend/src/components/LogSourceMappingsSection.jsx` | New component for admin-side log source mapping CRUD. |

## See also

If the target host has no outbound connectivity at all (not even via
proxy) see [OFFLINE_INSTALL.md](OFFLINE_INSTALL.md) for the air-gapped
bundle install path. That flow sidesteps every network requirement -
base images, npm, apt, apk - by building everything on an online
staging host and shipping a single tarball to the target.
