require('dotenv').config();

// ============ ENVIRONMENT VALIDATION ============

function validateEnv() {
  const errors = [];

  // JWT_SECRET (critical security)
  if (!process.env.JWT_SECRET || process.env.JWT_SECRET === 'change-this-in-production') {
    errors.push('JWT_SECRET must be set to a secure random string (not "change-this-in-production").');
  } else if (process.env.JWT_SECRET.length < 16) {
    errors.push('JWT_SECRET should be at least 16 characters for adequate security.');
  }

  // Database config
  if (!process.env.DB_HOST) errors.push('DB_HOST is required (e.g. "mysql-v5" or "localhost").');
  if (!process.env.DB_NAME) errors.push('DB_NAME is required (e.g. "iocdb").');
  if (!process.env.DB_USER) errors.push('DB_USER is required (e.g. "root").');
  if (!process.env.DB_PASSWORD && process.env.DB_PASSWORD !== '') {
    errors.push('DB_PASSWORD is required (set to empty string if intentionally blank).');
  }
  if (process.env.DB_PORT && isNaN(parseInt(process.env.DB_PORT, 10))) {
    errors.push('DB_PORT must be a valid number (e.g. 3306).');
  }

  // Encryption key validation
  if (process.env.ENCRYPTION_KEY && process.env.ENCRYPTION_KEY.length < 16) {
    errors.push('ENCRYPTION_KEY should be at least 16 characters for adequate security.');
  }

  // DB pool validation
  for (const key of ['DB_POOL_MAX', 'DB_POOL_MIN', 'DB_POOL_ACQUIRE', 'DB_POOL_IDLE']) {
    if (process.env[key] && (isNaN(parseInt(process.env[key], 10)) || parseInt(process.env[key], 10) < 1)) {
      errors.push(`${key} must be a positive number.`);
    }
  }

  // PORT validation
  if (process.env.PORT) {
    const port = parseInt(process.env.PORT, 10);
    if (isNaN(port) || port < 1 || port > 65535) {
      errors.push('PORT must be a valid number between 1 and 65535.');
    }
  }

  if (errors.length > 0) {
    console.error('');
    console.error('=== STARTUP FAILED: Environment configuration errors ===');
    errors.forEach((e, i) => console.error(`  ${i + 1}. ${e}`));
    console.error('');
    console.error('Check your .env file or docker-compose.yml environment variables.');
    console.error('========================================================');
    process.exit(1);
  }
}

validateEnv();

const crypto = require('crypto');
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const sequelize = require('./db');
const { log } = require('./utils/logger');
const { getKeySource } = require('./utils/crypto');

log.info('boot', 'environment validated', {
  node: process.version,
  env: process.env.NODE_ENV || 'development',
  logLevel: process.env.LOG_LEVEL || (process.env.DEBUG_LOG === '1' ? 'debug' : 'info')
});
log.info('boot', 'encryption key source', {
  source: getKeySource(),
  hint: getKeySource() === 'JWT_SECRET' ? 'set ENCRYPTION_KEY for independent rotation' : undefined
});

// Models (import to register with Sequelize)
require('./models/User');
require('./models/ApiKey');
require('./models/Submission');
require('./models/Result');
require('./models/MsgSource');
require('./models/TISource');
require('./models/FieldMapping');
require('./models/SSLConfig');
require('./models/QueryTemplate');
require('./models/AppSetting');
require('./models/AuditLog');

// Middleware
const { generalLimiter, loadSearchAuthSetting, getSearchConcurrencyState } = require('./middleware');

// Crypto utilities for credential migration
const { encrypt, isEncrypted, encryptJsonFields } = require('./utils/crypto');

// Route modules
const setupRoutes = require('./routes/setup');
const authRoutes = require('./routes/auth');
const adminRoutes = require('./routes/admin');
const reconRoutes = require('./routes/recon');
const searchRoutes = require('./routes/search');

const app = express();
const PORT = process.env.PORT || 4000;

// ============ GLOBAL MIDDLEWARE ============

app.use(cors({
  origin: process.env.CORS_ORIGIN || 'https://localhost:3000',
  credentials: true
}));
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"],
    }
  }
}));
app.use(express.json({ limit: '5mb' }));
app.use((req, res, next) => {
  req.requestId = crypto.randomUUID();
  res.setHeader('X-Request-ID', req.requestId);
  next();
});
app.use(generalLimiter);
app.set('trust proxy', 1);

log.info('boot', 'database config', {
  host: process.env.DB_HOST,
  port: process.env.DB_PORT || '3306',
  user: process.env.DB_USER,
  db: process.env.DB_NAME
});

// ============ MOUNT ROUTES ============

app.use('/api/setup', setupRoutes);
app.use('/api/auth', authRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api/recon', reconRoutes);

// Search routes are mounted at multiple prefixes
// /api/* routes
app.use('/api', searchRoutes);
// /export-results is outside /api prefix
app.use('/', searchRoutes);

// ============ HEALTH ENDPOINT ============

app.get('/api/health', (req, res) => {
  // Public: minimal status for uptime monitors / Docker healthcheck
  if (req.query.detail !== 'true') {
    return res.json({ status: 'ok' });
  }

  // Detailed: requires valid admin JWT
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Authentication required for detailed health' });

  const jwt = require('jsonwebtoken');
  try {
    const user = jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] });
    if (!user.isAdmin) return res.status(403).json({ error: 'Admin access required' });
  } catch {
    return res.status(403).json({ error: 'Invalid or expired token' });
  }

  const { activeSearchCount, searchQueue } = getSearchConcurrencyState();
  const { activeExportCount } = searchRoutes.getExportState();
  const pool = sequelize.connectionManager.pool;
  const dbPool = pool ? { size: pool.size, available: pool.available, using: pool.using, waiting: pool.waiting } : null;
  res.json({
    status: 'ok',
    uptime: Math.floor(process.uptime()),
    memoryUsage: Math.round(process.memoryUsage().heapUsed / 1024 / 1024),
    activeSearches: activeSearchCount,
    activeExports: activeExportCount,
    queuedSearches: searchQueue.length,
    dbPool
  });
});

// ============ ERROR HANDLERS ============

app.use((err, req, res, next) => {
  console.error(`Server error [${req.requestId}]:`, err.message);

  if (err.type === 'entity.parse.failed') {
    return res.status(400).json({ error: 'Invalid request body' });
  }
  if (err.name === 'SyntaxError') {
    return res.status(400).json({ error: 'Invalid JSON format' });
  }
  if (err.name === 'UnauthorizedError') {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }

  res.status(err.status || 500).json({ error: 'Internal server error' });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

// ============ INITIALIZATION ============

// Clean up duplicate indexes created by Sequelize sync({ alter: true })
async function cleanDuplicateIndexes() {
  try {
    const tables = await sequelize.getQueryInterface().showAllTables();
    for (const table of tables) {
      const indexes = await sequelize.getQueryInterface().showIndex(table);
      const seen = new Map();
      for (const idx of indexes) {
        const key = idx.column || (idx.fields && idx.fields.map(f => f.attribute).join(','));
        if (!key) continue;
        const uniqueKey = `${key}:${idx.unique}`;
        if (seen.has(uniqueKey)) {
          try { await sequelize.getQueryInterface().removeIndex(table, idx.name); } catch (e) { /* ignore */ }
        } else {
          seen.set(uniqueKey, idx.name);
        }
      }
    }
  } catch (e) { /* ignore cleanup errors */ }
}

// Migrate existing plaintext credentials to encrypted form (one-time)
async function migrateCredentials() {
  try {
    const apiKeys = await sequelize.query('SELECT id, apiKey, password, extraConfig FROM apikeys', { type: sequelize.QueryTypes.SELECT });
    for (const row of apiKeys) {
      const updates = {};
      if (row.apiKey && !isEncrypted(row.apiKey)) updates.apiKey = encrypt(row.apiKey);
      if (row.password && !isEncrypted(row.password)) updates.password = encrypt(row.password);
      if (row.extraConfig) {
        const ec = typeof row.extraConfig === 'string' ? JSON.parse(row.extraConfig) : row.extraConfig;
        let needsUpdate = false;
        for (const key of Object.keys(ec)) {
          if (/password|secret|token/i.test(key) && typeof ec[key] === 'string' && ec[key] && !isEncrypted(ec[key])) {
            needsUpdate = true;
            break;
          }
        }
        if (needsUpdate) updates.extraConfig = JSON.stringify(encryptJsonFields(ec));
      }
      if (Object.keys(updates).length > 0) {
        const setClauses = Object.keys(updates).map(k => `${k} = ?`).join(', ');
        await sequelize.query(`UPDATE apikeys SET ${setClauses} WHERE id = ?`, {
          replacements: [...Object.values(updates), row.id],
          type: sequelize.QueryTypes.UPDATE
        });
      }
    }

    const tiSources = await sequelize.query('SELECT id, apiKey FROM ti_sources', { type: sequelize.QueryTypes.SELECT });
    for (const row of tiSources) {
      if (row.apiKey && !isEncrypted(row.apiKey)) {
        await sequelize.query('UPDATE ti_sources SET apiKey = ? WHERE id = ?', {
          replacements: [encrypt(row.apiKey), row.id],
          type: sequelize.QueryTypes.UPDATE
        });
      }
    }

    const users = await sequelize.query('SELECT id, mfaSecret FROM users WHERE mfaSecret IS NOT NULL', { type: sequelize.QueryTypes.SELECT });
    for (const row of users) {
      if (row.mfaSecret && !isEncrypted(row.mfaSecret)) {
        await sequelize.query('UPDATE users SET mfaSecret = ? WHERE id = ?', {
          replacements: [encrypt(row.mfaSecret), row.id],
          type: sequelize.QueryTypes.UPDATE
        });
      }
    }

    const migratedApi = apiKeys.filter(r => (r.apiKey && !isEncrypted(r.apiKey)) || (r.password && !isEncrypted(r.password))).length;
    const migratedTi = tiSources.filter(r => r.apiKey && !isEncrypted(r.apiKey)).length;
    const migratedMfa = users.filter(r => r.mfaSecret && !isEncrypted(r.mfaSecret)).length;
    if (migratedApi > 0 || migratedTi > 0 || migratedMfa > 0) {
      console.log(`Encrypted credentials: ${migratedApi} SIEM connections, ${migratedTi} TI sources, ${migratedMfa} MFA secrets`);
    }
  } catch (err) {
    console.error('Credential migration error (non-fatal):', err.message);
  }
}

async function initialize() {
  log.info('boot', 'synchronizing database schema');
  try {
    await sequelize.sync({ alter: true });
    log.info('boot', 'schema synchronized');
  } catch (err) {
    log.error('boot', 'schema sync failed — tables may be out of date', {
      error: err.message,
      hint: 'Check DB connectivity and permissions. Run sync-db from the admin panel after fixing.'
    });
    throw err;
  }
  try {
    await cleanDuplicateIndexes();
    log.debug('boot', 'duplicate indexes cleaned');
  } catch (err) {
    log.warn('boot', 'index cleanup failed (non-fatal)', { error: err.message });
  }
  try {
    await migrateCredentials();
  } catch (err) {
    log.warn('boot', 'credential migration failed (non-fatal)', { error: err.message });
  }
  await loadSearchAuthSetting();
  log.info('boot', 'initialization complete — ready to serve', {
    hint: 'If setup is not complete, point a browser at /setup. Otherwise /login.'
  });
}
initialize().catch(err => {
  log.error('boot', 'fatal initialization error', { error: err.message });
  process.exit(1);
});

// ============ PROCESS ERROR HANDLERS ============

process.on('unhandledRejection', (reason) => {
  log.error('runtime', 'unhandled promise rejection', {
    error: reason?.message || String(reason),
    hint: 'Check recent SIEM calls or DB transactions for a missing await / error handler.'
  });
});

process.on('uncaughtException', (err) => {
  log.error('runtime', 'uncaught exception', { error: err.message, code: err.code });
  if (err.stack) process.stderr.write(err.stack + '\n');
  if (err.code === 'ERR_OUT_OF_MEMORY' || err.message?.includes('ENOMEM')) {
    log.error('runtime', 'fatal memory error — exiting', {
      hint: 'Raise NODE_OPTIONS --max-old-space-size or reduce concurrent searches.'
    });
    process.exit(1);
  }
});

// ============ START SERVER ============

const server = app.listen(PORT, () => {
  log.info('boot', 'HTTP server listening', { port: PORT });
});

async function gracefulShutdown(signal) {
  log.info('shutdown', 'signal received', { signal });
  server.close(() => log.info('shutdown', 'HTTP server closed (no new connections)'));

  const SHUTDOWN_TIMEOUT = 30000;
  const start = Date.now();
  const getState = () => {
    const { activeSearchCount, searchQueue } = getSearchConcurrencyState();
    const { activeExportCount } = searchRoutes.getExportState();
    return { activeSearchCount, activeExportCount, queuedSearches: searchQueue.length };
  };

  let state = getState();
  while ((state.activeSearchCount > 0 || state.activeExportCount > 0 || state.queuedSearches > 0) && (Date.now() - start < SHUTDOWN_TIMEOUT)) {
    log.info('shutdown', 'waiting for in-flight work', state);
    await new Promise(r => setTimeout(r, 1000));
    state = getState();
  }

  if (state.activeSearchCount > 0 || state.activeExportCount > 0) {
    log.warn('shutdown', 'timeout — forcing exit', state);
  } else {
    log.info('shutdown', 'all in-flight operations completed');
  }

  try { await sequelize.close(); } catch(e) { /* ignore */ }
  log.info('shutdown', 'database connection closed — goodbye');
  process.exit(0);
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));
