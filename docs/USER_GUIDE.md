# The Leopard - Complete User Guide

## Full Scenario: From Download to Threat Hunting

---

## Phase 1: Download & Installation

### Step 1: Download the Project
```bash
# Option A: Clone from GitHub
git clone https://github.com/da7oom20/The-Leopard.git
cd The-Leopard

# Option B: Download ZIP
wget https://github.com/da7oom20/The-Leopard/archive/refs/heads/master.zip
unzip master.zip
cd The-Leopard-master
```

### Step 2: Configure Environment (Optional)
```bash
# Copy the environment template
cp .env.example .env

# Edit if needed (change passwords, set proxy, etc.)
nano .env
```

**Default `.env` settings work out of the box for local testing.**

### Step 3: Start the Application
```bash
# Start all containers (MySQL, Backend, Frontend)
docker compose up -d

# Wait for containers to start (~30-60 seconds)
docker compose ps

# Check logs if needed
docker logs ioc-frontend-v5 --tail 20
```

**What happens automatically:**
- MySQL database created with all required tables
- Backend API server starts on port 4000 (internal)
- Frontend nginx serves on port 3000 (HTTPS) and 3080 (HTTP redirect). Plain HTTP on port 3000 also redirects to HTTPS.
- Self-signed SSL certificate auto-generated on first start

### Step 4: Access the Application
Open browser to:
```
https://localhost:3000
```
Or for network access:
```
https://<your-server-ip>:3000
```

---

## Phase 2: Setup Wizard (First-Time Only)

The Setup Wizard automatically appears on first launch.

### Step 2.1: Welcome Screen
1. Read the welcome message
2. **Select deployment mode:**
   - **Standalone** - Single organization with one or more SIEMs
   - **MSSP Mode** - Multiple clients with separate SIEM instances
3. Click **"Get Started"**

### Step 2.2: Database Connection
1. Click **"Test Connection"**
2. Wait for green success message: "Database connected!"
3. Click **"Continue"**

*(The database is pre-configured in Docker - this just verifies it's working)*

### Step 2.3: First SIEM Configuration
1. Enter **Client Name**: e.g., `MyCompany` or `ClientA`
2. Select **SIEM Type**: LogRhythm, Splunk, QRadar, etc.
3. Enter **API Host URL**: e.g., `https://logrhythm.mycompany.com:8501`
4. Enter **API Key/Token**: Your SIEM's API authentication token
5. Click **"Test Connection"** to verify
6. Click **"Save SIEM"**
7. Click **"Continue"** (or "Skip for Now" to configure later)

### Step 2.4: Create Admin User
1. Enter **Username**: e.g., `admin`
2. Enter **Password**: minimum 8 characters (uppercase, lowercase, digit, special character required)
3. **Confirm Password**
4. Click **"Create Admin User"**
5. Click **"Continue"**

### Step 2.5: Setup Complete
1. Review the "Next Steps" checklist
2. Click **"Go to Login"**

---

## Phase 3: Login & Admin Configuration

### Step 3.1: Login
1. Enter the admin username and password you just created
2. Click **"Login"**
3. You're redirected to the main Upload page

### Step 3.2: Access Admin Panel
1. Click **"Admin"** button in the top navigation
2. You see 6 tabs: **SIEM Clients | TI Sources | Recon | Field Mappings | Users | Security**

---

## Phase 4: Configure SIEM Connections

### Add More SIEM Clients (if needed)
1. Go to **Admin → SIEM Clients** tab
2. Fill in the form:
   - **Client Name**: `ClientB`
   - **SIEM Type**: Select from dropdown
   - **API Host**: SIEM's API endpoint
   - **API Key**: Authentication token
3. Click **"Test Connection"** to verify connectivity
4. Click **"Add SIEM Connection"**

### SIEM-Specific Configuration Examples:

**LogRhythm:**
```
API Host: https://logrhythm-api.company.com:8501
API Key: eyJhbGciOiJSUzI1NiIs... (Bearer token)
```

**Splunk:**
```
API Host: https://splunk.company.com
Port: 8089
Username: splunk_user
Password: ********
```

**Elastic/ELK:**
```
API Host: https://elasticsearch.company.com:9200
API Key: base64-encoded-api-key
Index Pattern: logs-*
```

**IBM QRadar:**
```
API Host: https://qradar.company.com
API Key: SEC token from QRadar admin
```

**Wazuh:**
```
API Host: https://wazuh-manager.company.com
Port: 55000
Username: wazuh-wui
Password: ********
```

**ManageEngine:**
```
API Host: https://manageengine.company.com
Port: 8400
API Key: ManageEngine API key
```

---

## Phase 5: Configure Threat Intelligence Sources

### Add TI Sources
1. Go to **Admin → TI Sources** tab
2. Fill in:
   - **Source Name**: e.g., `My OTX Feed`
   - **Platform**: Select from dropdown (grouped by category)
3. For API-based platforms, enter the API key
4. Click **"Test Connection"**
5. Click **"Add TI Source"**

### Recommended TI Sources (No API Key Required):
| Platform | IOC Types |
|----------|-----------|
| ThreatFox (abuse.ch) | IPs, Domains, URLs, Hashes |
| URLhaus (abuse.ch) | URLs, Domains |
| MalwareBazaar (abuse.ch) | Hashes |
| Feodo Tracker (abuse.ch) | IPs (C2 servers) |
| SSL Blacklist (abuse.ch) | IPs, Hashes |
| Blocklist.de | IPs |
| Emerging Threats | IPs |
| Spamhaus DROP | IPs |
| FireHOL Level 1 | IPs |
| OpenPhish | URLs |

### API-Based Sources:
| Platform | Registration |
|----------|--------------|
| AlienVault OTX | Free at otx.alienvault.com |
| MISP | Your own MISP instance |
| PhishTank | Optional API key for faster updates |

---

## Phase 6: Field Discovery (Recon)

Recon discovers which SIEM fields contain IOC data.

### Why Use Recon?
- Different SIEMs use different field names
- Custom log sources may have unique fields
- Ensures searches find all relevant data

### Run Recon
1. Go to **Admin → Recon** tab
2. Select **SIEM Client**: e.g., `MyCompany`
3. Select **Log Source**: Choose from the dropdown (fetched from your SIEM)
4. Select **IOC Type**: IP, Hash, Domain, URL, Email, or FileName
5. Click **"Dig"**

### Review Results
1. The system analyzes sample logs and identifies fields containing IOC-like data
2. Review the discovered fields (e.g., `originHostName`, `impactedHostId`, `sip`, `dip`)
3. **Check the boxes** next to fields you want to use for searching
4. Click **"Approve Selected"**

### Manage Field Mappings
1. Go to **Admin → Field Mappings** tab
2. View all approved mappings
3. **Edit** - Change fields, toggle active/inactive
4. **Delete** - Remove unwanted mappings

---

## Phase 7: User Management

### Create Additional Users
1. Go to **Admin → Users** tab
2. Fill in:
   - **Username**: `analyst1`
   - **Password**: secure password
   - **Role**: Admin / Analyst / Viewer (sets default permissions)
3. Click **"Add User"**

### User Permissions (Granular Control)

**Feature Permissions** (what users can do):
| Permission | Description |
|------------|-------------|
| Search | Upload and search for IOCs |
| Hunt | Automated threat hunting from TI feeds |
| Export | Download CSV/JSON results |
| View Repository | Access search history |

**Admin Permissions** (management access):
| Permission | Description |
|------------|-------------|
| Recon | Field discovery & analysis |
| Manage SIEM | Add/edit SIEM connections |
| Manage TI | Configure threat intel sources |
| Manage Mappings | Edit field mappings |
| Manage Users | Create/edit user accounts |
| Manage Security | MFA & SSL configuration |

### Default Permissions by Role:
| Role | Feature Permissions | Admin Permissions |
|------|---------------------|-------------------|
| **Admin** | All enabled | All enabled |
| **Analyst** | All enabled | None |
| **Viewer** | View Repo only | None |

### Edit User Permissions
1. Click **"Edit"** next to any user
2. Toggle individual permissions on/off
3. Change password or status if needed
4. Click **"Save Changes"**

---

## Phase 7.5: Security Configuration

### Enable MFA (Two-Factor Authentication)
1. Go to **Admin → Security** tab
2. Click **"Enable MFA"**
3. Scan the QR code with your authenticator app:
   - Google Authenticator
   - Authy
   - Microsoft Authenticator
4. Enter the 6-digit code from your app
5. Click **"Verify"**
6. **Save your backup codes** securely (8 one-time codes)

### Using MFA to Login
1. Enter username and password
2. When prompted, enter the 6-digit code from your app
3. Or click "Use backup code" if you lost your phone

### Admin MFA Management
Admins can manage MFA for other users:
1. Go to **Admin → Users** tab
2. Click **"Edit"** next to a user
3. Options available:
   - **Reset MFA** - Disable and clear MFA for the user
   - **Regenerate Backup Codes** - Generate new backup codes

### SSL/TLS Certificates (HTTPS)
1. Go to **Admin → Security** tab
2. Upload your certificate files:
   - **Certificate** (.crt, .pem)
   - **Private Key** (.key)
   - **CA Bundle** (optional)
3. Click **"Upload Certificates"**
4. Toggle **"Enable HTTPS"**
5. Restart the application

---

## Phase 8: IOC Search (Main Feature)

### Method 1: Manual IOC Input
1. Go to **Home** (Upload page)
2. In the text area, paste IOCs:
   ```
   192.168.1.100
   8.8.8.8
   malware.exe
   e99a18c428cb38d5f260853678922e03
   evil-domain.com
   ```
3. Select **Clients** to search (checkboxes)
4. Set **Search Period**: Last 24 hours, 7 days, 30 days, or custom
5. Click **"Submit"**

### Method 2: File Upload
1. Click **"Choose File"** or drag & drop
2. Supported formats: **PDF, XLSX, CSV, TXT**
3. IOCs are automatically extracted from the file
4. Select clients and time range
5. Click **"Submit"**

### Supported IOC Types (Auto-Detected):
| Type | Examples |
|------|----------|
| IPv4 | 192.168.1.1, 8.8.8.8 |
| IPv6 | 2001:0db8:85a3::8a2e:0370:7334 |
| Domain | evil-domain.com, malware.net |
| URL | http://bad-site.com/malware.exe |
| MD5 | d41d8cd98f00b204e9800998ecf8427e |
| SHA1 | da39a3ee5e6b4b0d3255bfef95601890afd80709 |
| SHA256 | e3b0c44298fc1c149afbf4c8996fb924... |
| Email | attacker@evil.com |
| Filename | malware.exe, payload.dll |

### View Results
1. Results appear in a table grouped by client
2. Each row shows:
   - IOC value
   - IOC type (IP, Hash, Domain, etc.)
   - Match count
   - Log details (expandable)
3. **Export** results as CSV or JSON

---

## Phase 9: Hunt Mode (TI-Powered Search)

Hunt mode automatically fetches IOCs from Threat Intelligence and searches your SIEMs.

### Start a Hunt
1. Click **"Hunt"** button on the main page
2. Select **TI Platform**: e.g., ThreatFox, URLhaus, OTX
3. Select **IOC Type**: IP, Domain, Hash, URL
4. Optionally set **Limit**: Max IOCs to fetch (default: 100)
5. Select **Target Clients** (which SIEMs to search)
6. Click **"Hunt"**

### What Happens:
1. System fetches fresh IOCs from the TI platform
2. IOCs are searched across all selected SIEMs
3. Results show which IOCs were found in your environment
4. **Red alert** = IOC found in your logs (potential compromise!)

---

## Phase 10: Search History (Repo)

### View Past Searches
1. Click **"Repo"** in the navigation
2. See all past submissions with:
   - Timestamp
   - IOC count
   - Clients searched
   - Status
3. Click any row to view detailed results

### Export Historical Results
1. Click the **Export** button on any submission
2. Download as CSV or JSON

---

## Phase 11: Daily Workflow Examples

### Morning Routine (SOC Analyst):
```
1. Login to The Leopard
2. Click "Hunt" → Select ThreatFox → IP → Last 24h IOCs
3. Select all clients → Click "Hunt"
4. Review results for any matches
5. If matches found → Investigate in SIEM
6. Export results for reporting
```

### Incident Response:
```
1. Receive IOC list from threat report (PDF)
2. Upload PDF to The Leopard
3. Select affected clients
4. Set time range to cover incident window
5. Submit search
6. Review matches across all SIEMs
7. Export evidence for incident report
```

### Weekly TI Update:
```
1. Go to Admin → TI Sources
2. Test all sources are working
3. Run Hunt for each IOC type (IP, Domain, Hash)
4. Document any findings
5. Update field mappings if needed (Recon)
```

### New Client Onboarding (MSSP):
```
1. Go to Admin → SIEM Clients
2. Add new client's SIEM connection
3. Test connection
4. Go to Recon → Run field discovery for each IOC type
5. Approve relevant field mappings
6. Client is ready for IOC searches
```

---

## Quick Reference

### URLs
| Page | URL |
|------|-----|
| Main Search | https://localhost:3000/ |
| Login | https://localhost:3000/login |
| Admin | https://localhost:3000/admin |
| Search History | https://localhost:3000/repo |
| Setup Wizard | https://localhost:3000/setup |

### Docker Commands
```bash
# Start all services
docker compose up -d

# Stop all services
docker compose down

# Restart all services
docker compose restart

# Restart specific service
docker restart ioc-backend-v5
docker restart ioc-frontend-v5

# View logs (follow mode)
docker logs ioc-backend-v5 --tail 50 -f
docker logs ioc-frontend-v5 --tail 50 -f

# Rebuild after code updates
docker compose build --no-cache && docker compose up -d

# Access MySQL directly
docker exec -it mysql-v5 mysql -uroot -ppassword iocdb

# View database tables
docker exec mysql-v5 mysql -uroot -ppassword iocdb -e "SHOW TABLES;"
```

### Default Ports
| Service | Port |
|---------|------|
| App (HTTPS) | 3000 |
| App (HTTP) | 3080 (redirects to HTTPS). Port 3000 also handles HTTP redirect. |
| MySQL | 3316 (localhost only) |

### API Endpoints (for integrations)
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | /api/upload | Submit IOCs for search |
| POST | /api/hunt | TI-based hunt |
| GET | /api/clients | List SIEM clients |
| GET | /api/repo | Get search history |

---

## Troubleshooting

### Common Issues

| Issue | Solution |
|-------|----------|
| Can't access frontend | Check `docker compose ps`, ensure all containers are running |
| "Connection refused" | Wait 30-60 seconds for containers to fully start |
| SIEM connection failed | Verify API host is reachable, check API key permissions |
| No search results | Check field mappings in Admin → Field Mappings |
| Login fails | Verify user is Active in Admin → Users |
| Setup wizard won't appear | Go to Admin → click "Setup Wizard" button |
| Database connection error | Check MySQL container is running: `docker logs mysql-v5` |

### Checking Container Health
```bash
# See all container status
docker compose ps

# Check backend logs for errors
docker logs ioc-backend-v5 --tail 100

# Check frontend compilation
docker logs ioc-frontend-v5 --tail 50

# Check MySQL is accepting connections
docker exec mysql-v5 mysqladmin -uroot -ppassword ping
```

### Reset Everything (Fresh Start)
```bash
# Stop and remove containers, volumes, and images
docker compose down -v --rmi all

# Start fresh
docker compose up -d
```

---

## Testing the Installation

### Quick API Tests
```bash
# Run basic API tests (13 tests)
bash tests/run-tests.sh
```

### Security Tests
```bash
# Run security validation (13 tests)
bash tests/run-security-tests.sh
```

**Security tests check for:**
- SQL injection protection
- XSS prevention
- JWT token validation
- Authorization enforcement
- Rate limiting
- Sensitive data protection

---

## Security Best Practices

1. **Change default passwords** in `.env` before production deployment
2. **Enable MFA** for all admin accounts (Admin → Security)
3. **Use HTTPS** - Upload SSL certificates or place behind nginx reverse proxy
4. **Restrict network access** - Only allow trusted IPs to port 3000
5. **Regular updates** - Pull latest version from GitHub periodically
6. **Backup database** - Export MySQL data regularly
7. **Audit users** - Review user accounts and disable unused ones
8. **API key rotation** - Update SIEM API keys periodically
9. **Run security tests** - Periodically run `bash tests/run-security-tests.sh`
10. **Keep server time synchronized** - Required for MFA to work properly

---

## Getting Help

- **GitHub Issues**: Report bugs and request features
- **Documentation**: See CLAUDE.md for developer details
- **Logs**: Always check Docker logs first when troubleshooting

---

**The Leopard** - Community Edition v5.6

Developed by Abdulrahman Almahameed

Happy Hunting! 🐆
