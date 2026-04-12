# The Leopard - API Reference v5.6

Base URL: `https://<host>:3000/api`

All responses include an `X-Request-ID` header (UUID) for tracing.

---

## Authentication

JWT Bearer tokens. Obtain via `POST /api/auth/login`.

```
Authorization: Bearer <token>
```

Tokens expire after 8 hours. Tokens are invalidated immediately on password change.

### Rate Limits

| Scope | Limit | Window |
|-------|-------|--------|
| General API | 100 requests | 1 minute |
| Login | 10 attempts | 1 minute |
| Search/Hunt | 20 requests | 1 minute |
| Account lockout | 5 failed logins | 15-minute lock |

---

## Health

### GET /api/health

No auth required. Returns basic status.

**Response (public):**
```json
{ "status": "ok" }
```

### GET /api/health?detail=true

**Auth:** Required (admin). Returns detailed health info.

**Response:**
```json
{
  "status": "ok",
  "uptime": 3600,
  "memoryUsage": 128,
  "activeSearches": 0,
  "activeExports": 0,
  "queuedSearches": 0,
  "dbPool": { "size": 5, "available": 3, "using": 2, "waiting": 0 }
}
```

---

## Setup (First-Time Only)

These endpoints are blocked after the first admin user is created.

| Method | Path | Description |
|--------|------|-------------|
| GET | /api/setup/status | Check if setup is complete |
| POST | /api/setup/test-db | Test database connection |
| POST | /api/setup/add-siem | Add first SIEM connection |
| POST | /api/setup/test-siem | Test SIEM connection |
| POST | /api/setup/create-admin | Create first admin user |
| POST | /api/setup/complete | Mark setup as complete |

### POST /api/setup/create-admin

**Request:**
```json
{
  "username": "admin",
  "password": "SecureP@ss1"
}
```

**Password requirements:** Min 8 chars, uppercase, lowercase, digit, special character.

---

## Auth & MFA

### POST /api/auth/login

**Request:**
```json
{
  "username": "admin",
  "password": "SecureP@ss1",
  "mfaToken": "123456",
  "backupCode": "A1B2C3D4"
}
```

- `mfaToken` and `backupCode` are optional (only needed if MFA is enabled)
- Username max 100 chars, password max 128 chars

**Responses:**

Success (no MFA):
```json
{ "token": "eyJhbG..." }
```

MFA required (password correct, MFA not yet provided):
```json
{
  "mfaRequired": true,
  "message": "MFA verification required",
  "username": "admin"
}
```

Account locked:
```json
{ "error": "Account temporarily locked due to too many failed attempts. Try again in 15 minutes." }
```
Status: `429`

### GET /api/auth/mfa/status
**Auth:** Required

```json
{
  "mfaEnabled": true,
  "backupCodesRemaining": 7
}
```

### POST /api/auth/mfa/setup
**Auth:** Required

Returns QR code and backup codes. Secret is saved but MFA is NOT enabled until verified.

```json
{
  "secret": "JBSWY3DPEHPK3PXP",
  "qrCode": "data:image/png;base64,...",
  "otpauthUri": "otpauth://totp/...",
  "backupCodes": ["A1B2C3D4", "..."],
  "message": "Scan the QR code..."
}
```

### POST /api/auth/mfa/verify
**Auth:** Required

```json
{ "token": "123456" }
```

Enables MFA after successful TOTP verification.

### POST /api/auth/mfa/disable
**Auth:** Required

```json
{ "password": "YourPassword" }
```

### POST /api/auth/mfa/backup-codes
**Auth:** Required

```json
{ "password": "YourPassword" }
```

Regenerates 8 new backup codes (old ones are invalidated).

---

## Admin — Users

**Permission required:** `canManageUsers`

### GET /api/admin/users

Returns all users (passwords and MFA secrets excluded).

### POST /api/admin/users

**Request:**
```json
{
  "username": "analyst1",
  "password": "Str0ng!Pass",
  "role": "analyst",
  "canSearch": true,
  "canHunt": true,
  "canExport": true,
  "canViewRepo": true,
  "canRecon": false,
  "canManageSIEM": false,
  "canManageTI": false,
  "canManageMappings": false,
  "canManageUsers": false,
  "canManageSecurity": false
}
```

**Password policy:** Min 8 chars, at least one uppercase, lowercase, digit, and special character. Max 128 chars.

**Roles:** `admin`, `analyst`, `viewer` — set default permissions per role. Individual permissions can be overridden.

### PUT /api/admin/users/:id

Partial update. Only include fields to change. Changing password invalidates all existing tokens for that user.

```json
{
  "role": "admin",
  "password": "NewStr0ng!Pass",
  "isActive": true,
  "canManageSIEM": true
}
```

### DELETE /api/admin/users/:id

Cannot delete yourself. Cannot delete the last admin.

### GET /api/admin/users/:id/mfa

Returns MFA status for a specific user.

### POST /api/admin/users/:id/mfa/reset

Disables MFA and clears secret for a user.

### POST /api/admin/users/:id/mfa/setup

Force-initiates MFA setup for a user.

### POST /api/admin/users/:id/mfa/backup-codes

Regenerates backup codes for a user.

---

## Admin — SIEM Connections

**Permission required:** `canManageSIEM`

### GET /api/admin/api-keys

Returns all SIEM connections. API keys are masked (`••••last4`).

### GET /api/admin/siem-types

Returns supported SIEM types with their configuration schemas.

### POST /api/admin/api-keys

```json
{
  "client": "Production-LR",
  "siemType": "logrhythm",
  "apiHost": "https://siem.example.com:8501",
  "apiKey": "your-api-key",
  "verifySSL": true
}
```

**Supported SIEM types:** `logrhythm`, `splunk`, `qradar`, `elastic`, `wazuh`, `manageengine`

### POST /api/admin/check-api-key

Test a SIEM connection without saving.

```json
{
  "siemType": "logrhythm",
  "apiHost": "https://siem.example.com:8501",
  "apiKey": "your-api-key",
  "id": 1
}
```

### DELETE /api/admin/api-keys/:id

---

## Admin — TI Sources

**Permission required:** `canManageTI`

### GET /api/admin/ti-sources

Returns all TI sources. API keys masked.

### GET /api/admin/ti-platforms

Returns supported TI platform types.

### POST /api/admin/ti-sources

```json
{
  "name": "My OTX Feed",
  "platform": "otx",
  "apiKey": "your-otx-api-key",
  "baseUrl": "https://otx.alienvault.com",
  "isActive": true
}
```

### PUT /api/admin/ti-sources/:id

Partial update.

### POST /api/admin/ti-sources/test

```json
{
  "platform": "otx",
  "apiKey": "your-key",
  "baseUrl": "https://otx.alienvault.com"
}
```

### DELETE /api/admin/ti-sources/:id

---

## Admin — Settings

**Permission required:** `canManageSecurity`

### GET /api/admin/settings

### PUT /api/admin/settings

```json
{
  "key": "requireSearchAuth",
  "value": "true"
}
```

**Allowed keys:** `requireSearchAuth`

---

## Admin — SSL/TLS

**Permission required:** `canManageSecurity`

### GET /api/admin/ssl
### POST /api/admin/ssl/upload

Multipart form: `certificate` (.crt/.pem), `privateKey` (.key), `ca` (optional).

### POST /api/admin/ssl/toggle

```json
{ "isEnabled": true }
```

### DELETE /api/admin/ssl

---

## Admin — Audit Logs

**Permission required:** `canManageSecurity`

### GET /api/admin/audit-logs

**Query parameters:**
| Param | Type | Default | Description |
|-------|------|---------|-------------|
| page | int | 1 | Page number |
| limit | int | 50 | Items per page (max 200) |
| offset | int | - | Alternative to page-based pagination |
| category | string | - | Filter: `user`, `siem`, `ti`, `security`, `settings`, `auth` |
| actorId | int | - | Filter by user ID |

**Response:**
```json
{
  "items": [
    {
      "id": 1,
      "action": "user.create",
      "category": "user",
      "actorId": 1,
      "actorUsername": "admin",
      "targetType": "user",
      "targetId": 5,
      "details": { "username": "analyst1", "role": "analyst" },
      "ip": "::1",
      "createdAt": "2026-03-07T22:00:00.000Z"
    }
  ],
  "total": 42,
  "page": 1,
  "pages": 1,
  "offset": 0,
  "limit": 50
}
```

**Audited actions:** `auth.login`, `user.create`, `user.update`, `user.delete`, `mfa.reset`, `siem.create`, `siem.delete`, `ti.create`, `ti.delete`, `settings.update`

---

## Admin — Query Templates

**Permission required:** `canManageSIEM`

### GET /api/admin/query-templates
### GET /api/admin/query-templates/defaults/:siemType

### POST /api/admin/query-templates

```json
{
  "client": "Production-LR",
  "siemType": "logrhythm",
  "filterType": "IP",
  "template": "SELECT * FROM logs WHERE sourceip IN ({{values}})"
}
```

### PUT /api/admin/query-templates/:id
### DELETE /api/admin/query-templates/:id

---

## Admin — Database

### POST /api/admin/sync-db

**Auth:** Admin only. Synchronizes database schema.

---

## Search

Auth is optional (controlled by `requireSearchAuth` setting).

### GET /api/clients

Returns active SIEM client names.

### GET /api/ti-sources

Returns active TI source names (public).

### GET /api/settings/search-auth

Returns whether search auth is required.

```json
{ "requireSearchAuth": false }
```

### POST /api/upload

Multipart form upload for IOC search.

**Form fields:**
| Field | Type | Description |
|-------|------|-------------|
| file | File | PDF, XLSX, CSV, or TXT file |
| text | string | Raw IOC text (alternative to file) |
| selectedClients | string | Comma-separated client names |
| minutesBack | int | Search time range (1-525600) |
| maxResults | int | Max results per query |

**Auto-detected IOC types:** IP, Domain, URL, Hash (MD5/SHA1/SHA256), Email, Filename

**Deobfuscation supported:** `[.]` `(dot)` `hxxp://` `hxxps://` `[at]` `(at)`

### POST /api/hunt

```json
{
  "tiSourceId": 1,
  "iocType": "IP",
  "selectedClients": ["Production-LR", "Splunk-Main"],
  "minutesBack": 1440,
  "limit": 100
}
```

### GET /api/search-progress

Poll search progress by searchId.

**Query parameters:** `searchId` (required)

**Response:**
```json
{
  "searchId": "abc123",
  "status": "searching",
  "steps": [
    { "client": "Splunk-Main", "status": "done", "hits": 3 },
    { "client": "QRadar-Prod", "status": "searching", "hits": 0 }
  ]
}
```

### GET /api/search-events

SSE stream for real-time search progress. Opens a persistent connection.

**Query parameters:** `searchId` (required)

**Events:** `data: {"searchId":"abc123","steps":[...]}\n\n`

### GET /api/repo

**Query parameters:**

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| limit | int | 10 | Items per page (max 100) |
| offset | int | 0 | Pagination offset |
| client | string | - | Filter by client name |
| filterType | string | - | Filter by IOC type (IP, Hash, etc.) |
| hit | string | - | Filter by hit status (hit, no hit, error, all) |
| dateFrom | string | - | Filter from date (ISO 8601) |
| dateTo | string | - | Filter to date (ISO 8601) |

### GET /api/repo/filters

Returns distinct filter values for the repo filter dropdowns.

**Response:**
```json
{
  "clients": ["Splunk-Main", "QRadar-Prod"],
  "filterTypes": ["IP", "Hash", "Domain"]
}
```

---

## Export

### GET /export-results

**Query parameters:**
| Param | Description |
|-------|-------------|
| submissionId | Submission ID to export |
| layout | `block` or `flat` |

### GET /api/export-json?submissionId=1

### GET /api/export-status

```json
{ "activeExports": 0 }
```

### GET /api/export-events?token=JWT

SSE stream for export progress. Token passed as query param (EventSource limitation).

---

## Recon (Field Discovery)

**Permission required:** `canRecon`

### GET /api/recon/log-sources/:clientId

Returns available SIEM log sources for a client.

### POST /api/recon/dig

```json
{
  "clientId": 1,
  "logSource": "syslog",
  "iocType": "IP",
  "depth": 1000
}
```

### POST /api/recon/approve

```json
{
  "clientId": 1,
  "filterType": "IP",
  "fields": ["sourceip", "destip"],
  "logSource": "syslog"
}
```

### GET /api/recon/mappings

Returns all field mappings.

### GET /api/recon/mappings/:clientId

Returns mappings for a specific client.

### PUT /api/recon/mappings/:id

```json
{
  "fields": ["sourceip", "destip", "natip"],
  "isApproved": true
}
```

### DELETE /api/recon/mappings/:id

---

## Error Responses

All errors follow this format:

```json
{
  "error": "Human-readable error message",
  "suggestion": "Optional suggestion for fixing the issue",
  "category": "validation|auth|connection|timeout|server"
}
```

Error responses never include stack traces, file paths, or internal details.

### Common Status Codes

| Code | Meaning |
|------|---------|
| 200 | Success |
| 201 | Created |
| 400 | Bad request / validation error |
| 401 | Authentication required or session expired |
| 403 | Forbidden / insufficient permissions |
| 404 | Resource not found |
| 429 | Rate limited or account locked |
| 500 | Internal server error |
