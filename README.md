# The Leopard - IOC Search App v5.6

A powerful Indicator of Compromise (IOC) search and analysis platform that integrates with multiple SIEM platforms and Threat Intelligence sources. Built for SOC analysts and threat hunters.

![Version](https://img.shields.io/badge/version-5.6-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Docker](https://img.shields.io/badge/docker-ready-blue)

---

## Features

### Multi-SIEM Support
Search across multiple SIEM platforms simultaneously:
- **LogRhythm** - Full API integration with log source filtering (Tested)
- **Splunk** - Search and alert integration (Tested)
- **IBM QRadar** - AQL query support (Tested)
- **Elastic/ELK** - Elasticsearch query DSL (Experimental)
- **Wazuh** - Security event search (Experimental)
- **ManageEngine** - EventLog Analyzer integration (Experimental)

### Threat Intelligence Integration
Automatically fetch IOCs from 18 threat intel sources:

| Category | Platforms |
|----------|-----------|
| API Platforms | AlienVault OTX, MISP, PhishTank |
| abuse.ch | ThreatFox, URLhaus, MalwareBazaar, Feodo Tracker, SSLBL |
| IP Blocklists | Blocklist.de, Emerging Threats, Spamhaus DROP, FireHOL, Cisco Talos, CrowdSec |
| C2 & Malware | C2 Intel Feeds, Bambenek C2, DigitalSide |

### Hunt Mode
One-click threat hunting:
1. Select a TI source and IOC type
2. Choose target SIEM clients
3. Automatically fetch fresh IOCs and search across all SIEMs

### Field Discovery (Recon)
Intelligent field mapping for custom SIEM configurations:
- Analyze SIEM logs to discover which fields contain IOC data
- Approve and save custom field mappings per client
- Automatic fallback to defaults when no mapping exists

### Search History (Repo)
Track and export all IOC searches:
- View past submissions with timestamps
- Export results as CSV or JSON
- SSE progress streaming for large exports

### User Management
Granular permission-based access control with 10 individual permissions:

**Feature Permissions** (default enabled):
- Search, Hunt, Export, View Repository

**Admin Permissions** (default disabled):
- Recon, Manage SIEM, Manage TI, Manage Mappings, Manage Users, Manage Security

### Security Features (v5.5+)
- **MFA (Two-Factor Authentication)** - TOTP with backup codes
- **Strong Password Policy** - 8+ chars, uppercase, lowercase, digit, special character
- **Account Lockout** - 5 failed attempts triggers 15-minute lock
- **Session Invalidation** - Password changes immediately revoke all active tokens
- **Credential Encryption** - AES-256-GCM with separate ENCRYPTION_KEY for defense-in-depth
- **Input Length Limits** - Prevents bcrypt DoS (username 100, password 128 chars)
- **Request Tracing** - UUID `X-Request-ID` on every response
- **Audit Logging** - All admin actions logged with actor, target, IP, timestamp
- **SSL/TLS Support** - Self-signed certs auto-generated, custom cert upload
- **HTTPS Redirect** - HTTP requests redirect to HTTPS (both port 3000 and 3080)
- **Rate Limiting** - IP-based rate limiting on all endpoints
- **Security Headers** - Helmet CSP, HSTS, X-Frame-Options, X-Content-Type-Options
- **Error Sanitization** - No stack traces or internal paths in API responses

### v5.6 Enhancements
- **Search Progress Tracking** - Real-time SSE progress for IOC searches (per-SIEM status)
- **Repository Filters** - Filter search history by client, IOC type, hit status, date range
- **Health Checks** - Docker healthchecks on all containers, nginx health endpoint
- **Environment Validation** - Startup checks for all required env vars
- **Nginx Upstream** - Keepalive connections to backend with upstream block
- **DB Connection Pool Tuning** - Configurable pool via `DB_POOL_*` env vars with monitoring
- **Custom Error Pages** - Branded 502/503/504 error pages with auto-retry
- **Reproducible Builds** - `npm ci` for deterministic dependency resolution
- **Accessibility** - WCAG improvements (aria-hidden, aria-label, aria-labelledby, aria-live, role attributes)

### TI Feed Caching
- In-memory feed cache with 15-minute TTL
- Reduces redundant network calls for repeated queries

---

## Quick Start

### Prerequisites
- Docker & Docker Compose
- 4GB+ RAM recommended
- Network access to your SIEM APIs

### Installation

1. **Clone or extract:**
```bash
git clone https://github.com/da7oom20/The-Leopard.git
cd The-Leopard
```

2. **Configure environment:**
```bash
cp .env.example .env
# Edit .env — at minimum, set JWT_SECRET to a secure random string
```

3. **Start the application:**
```bash
docker compose up -d
```

4. **Access the app:**
```
HTTPS: https://localhost:3000
HTTP:  http://localhost:3000 or http://localhost:3080 (both redirect to HTTPS)
```

5. **Complete the Setup Wizard** to configure your first SIEM and create an admin user.

### Default Ports

| Service | Port | Description |
|---------|------|-------------|
| App (HTTPS) | 3000 | Web UI + API (nginx reverse proxy) |
| App (HTTP) | 3080 | Redirects to HTTPS (also handles HTTP on port 3000) |
| MySQL | 3316 | Database (localhost only) |

---

## Configuration

### Environment Variables

Create a `.env` file in the root directory:

```env
# Required
JWT_SECRET=change-this-to-a-long-random-string

# Database (defaults work out of the box)
DB_HOST=mysql-v5
DB_PORT=3306
DB_NAME=iocdb
DB_USER=root
DB_PASSWORD=your-secure-password

# Optional: separate encryption key for credentials at rest
ENCRYPTION_KEY=another-long-random-string

# CORS origin (default: https://localhost:3000)
CORS_ORIGIN=https://your-domain:3000

# Proxy (if behind corporate firewall)
HTTP_PROXY=http://proxy.example.com:3128
HTTPS_PROXY=http://proxy.example.com:3128
```

### SIEM Configuration

Configure SIEMs through the Admin Panel > SIEM Clients tab:
1. Click **Add SIEM Connection**
2. Select SIEM type and fill in API host + credentials
3. **Test Connection** to verify
4. Save

### Threat Intelligence Sources

Admin Panel > TI Sources tab:
1. Select a platform (OTX, MISP, ThreatFox, etc.)
2. Enter API keys if required (most feed-based sources need no key)
3. Test and save

---

## Architecture

```
The-Leopard/
├── docker-compose.yml          # Container orchestration
├── .env                        # Environment configuration
├── CLAUDE.md                   # Developer documentation
├── docs/
│   ├── API.md                  # Complete API reference
│   └── USER_GUIDE.md           # End-to-end usage guide
│
├── frontend/                   # React frontend
│   ├── Dockerfile              # Multi-stage build
│   ├── nginx.conf              # HTTPS, reverse proxy, security headers
│   ├── entrypoint.sh           # Auto-generates self-signed SSL cert
│   └── src/
│       ├── App.jsx             # Router, auth context, setup guard
│       ├── pages/              # LoginPage, UploadPage, AdminPage, RepoPage, SetupWizard
│       └── components/         # HuntModal, ReconSection, SecurityTab, FieldMappingsTab
│
└── server/                     # Node.js/Express backend
    ├── Dockerfile              # Multi-stage build, non-root user
    ├── index.js                # Entry point, middleware, initialization
    ├── middleware.js            # Auth, rate limiting, permissions, concurrency
    ├── db.js                   # Sequelize/MySQL connection pool
    ├── models/                 # User, ApiKey, TISource, AuditLog, etc.
    ├── routes/
    │   ├── auth.js             # Login, MFA, account lockout
    │   ├── admin.js            # Users, SIEM, TI, SSL, settings, audit logs
    │   ├── search.js           # Upload, hunt, export, repo
    │   ├── recon.js            # Field discovery
    │   └── setup.js            # First-time setup wizard
    ├── siem-adapters/          # 6 SIEM adapters (LR, Splunk, QRadar, Elastic, Wazuh, ME)
    ├── ti-adapters/            # 18 TI sources (3 API + 15 feed-based)
    └── utils/
        ├── crypto.js           # AES-256-GCM encryption
        ├── mfa.js              # TOTP implementation
        ├── password.js         # Password validation
        └── audit.js            # Audit logging
```

---

## Docker Commands

```bash
# Start all services
docker compose up -d

# View logs
docker logs ioc-backend-v5 --tail 50 -f
docker logs ioc-frontend-v5 --tail 50 -f

# Restart services
docker restart ioc-backend-v5
docker restart ioc-frontend-v5

# Rebuild after code changes
docker compose build --no-cache && docker compose up -d

# Stop all services
docker compose down
```

---

## API Reference

See [docs/API.md](docs/API.md) for the complete API reference covering all endpoints, request/response formats, authentication, and error handling.

### Quick Overview

| Category | Endpoints |
|----------|-----------|
| Health | `GET /api/health` |
| Auth | `POST /api/auth/login`, MFA endpoints |
| Users | CRUD `/api/admin/users` with password policy |
| SIEM | CRUD `/api/admin/api-keys`, connection testing |
| TI Sources | CRUD `/api/admin/ti-sources`, testing |
| Search | `POST /api/upload`, `POST /api/hunt`, `GET /api/search-events` (SSE) |
| Export | `GET /export-results`, `GET /api/export-json` |
| Repo | `GET /api/repo`, `GET /api/repo/filters` |
| Recon | `POST /api/recon/dig`, field mapping CRUD |
| Audit Logs | `GET /api/admin/audit-logs` with pagination |
| Settings | `GET/PUT /api/admin/settings` |
| SSL | `GET/POST/DELETE /api/admin/ssl` |

---

## Security Considerations

- **Set `JWT_SECRET`** — Server refuses to start without it
- **Change MySQL password** — Update `DB_PASSWORD` in `.env`
- **Enable MFA** for all admin accounts
- **Set `CORS_ORIGIN`** — Don't use `*` in production
- **Set `ENCRYPTION_KEY`** — Separate from JWT_SECRET for defense-in-depth
- Upload SSL certificates for production HTTPS
- Keep server time synchronized (required for MFA)
- Regularly rotate API keys for SIEM and TI integrations

### MFA Troubleshooting

If MFA codes are always invalid:
1. **Check time sync:** `sudo timedatectl set-ntp true`
2. **Use backup codes** — Each of the 8 codes works once
3. **Admin reset:** Admin can reset MFA from Users tab
4. **Database reset:**
   ```bash
   docker exec mysql-v5 mysql -uroot -ppassword iocdb -e \
     "UPDATE users SET mfaEnabled=0, mfaSecret=NULL WHERE username='admin';"
   ```

---

## Troubleshooting

### Cannot Access Frontend
- Check containers: `docker compose ps`
- HTTPS: `https://localhost:3000`, HTTP: `http://localhost:3000` or `http://localhost:3080` (both redirect)
- Check firewall allows ports 3000 and 3080

### SIEM Connection Failed
- Verify API endpoint is reachable from Docker container
- Check API key/token is valid
- If behind proxy, set HTTP_PROXY/HTTPS_PROXY in `.env`

### Account Locked Out
- Wait 15 minutes for automatic unlock
- Or restart the backend container to clear lockout state

### Search Returns No Results
- Verify log sources are configured for the client
- Check field mappings match your SIEM's field names
- Extend the search time range

---

## Development

### Adding a New SIEM Adapter

1. Create `server/siem-adapters/your-siem.adapter.js`
2. Extend `BaseSiemAdapter` class
3. Implement: `testConnection()`, `buildQuery()`, `executeSearch()`, `pollResults()`, `getLogSources()`, `normalizeResults()`
4. Register in `server/siem-adapters/index.js`

### Adding a New TI Adapter

1. Create `server/ti-adapters/your-platform.adapter.js`
2. Implement `fetchIOCs(iocType, options)`
3. Register in `server/ti-adapters/index.js`

---

## Version History

### v5.6 (Current)
- Real-time search progress via Server-Sent Events (SSE)
- Repository filters (client, IOC type, hit status, date range)
- Docker healthchecks on all containers
- Environment validation at startup
- Nginx upstream with keepalive connections
- Configurable DB connection pool (DB_POOL_* env vars)
- Separate ENCRYPTION_KEY for credential encryption
- Custom nginx error pages (502/503/504)
- Health endpoint with public/admin detail modes
- Reproducible builds with npm ci
- NODE_ENV=production in frontend Dockerfile
- Comprehensive .env.example documentation
- WCAG accessibility improvements across all components
- Body size limit (10MB) on nginx proxy
- HTTP-to-HTTPS redirect on port 3000 (error_page 497)
- Elastic adapter reads indexPattern from extraConfig

### v5.5
- Split monolithic server into route modules
- Strong password policy (8+ chars, complexity requirements)
- Account lockout (5 failed attempts, 15-minute lock)
- Session invalidation on password change
- Input length limits (bcrypt DoS prevention)
- Error message sanitization
- HTTPS redirect (HTTP 3080 -> HTTPS 3000)
- Request ID tracing (X-Request-ID)
- Audit logging with pagination and filtering
- TI feed caching (15-minute TTL)
- SIEM adapter connection timeouts
- Audit log pagination (page/limit/total)

### v5.4
- Credential encryption at rest (AES-256-GCM)
- CSP security headers (Helmet)
- Graceful shutdown (drain in-flight searches)
- MFA secret encryption

### v5.0
- Setup Wizard, dark zinc theme
- 6 SIEM adapters, 18 TI sources
- Hunt mode, Recon, Field Mappings
- MFA, SSL/TLS, permission-based access
- Docker multi-stage builds, non-root containers

---

## Credits

**Developed by:** Abdulrahman Almahameed

**GitHub:** [https://github.com/da7oom20](https://github.com/da7oom20)

**The Leopard** - Community Edition v5.6

Happy Hunting!
