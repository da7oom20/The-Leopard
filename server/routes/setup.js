const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const router = express.Router();

const User = require('../models/User');
const ApiKey = require('../models/ApiKey');
const AppSetting = require('../models/AppSetting');
const MsgSource = require('../models/MsgSource');
const sequelize = require('../db');
const { getSiemAdapter } = require('../siem-adapters');
const { classifySiemError, setRequireSearchAuth } = require('../middleware');
const { validatePassword } = require('../utils/password');
const { child } = require('../utils/logger');
const log = child({ area: 'setup' });

// Explicit "setup is finished" flag. Lives in AppSetting so it survives
// restarts. Set exactly once by POST /api/setup/complete (the wizard's
// last step). The runtime check is the flag alone — no lazy inference
// from row counts, because a fresh install legitimately has admin+SIEM
// mid-wizard and would otherwise be wrongly treated as complete.
//
// For upgrades from v5.6 (which has no flag): operators walk the wizard
// once, add-siem upserts existing rows, create-admin rejects with a
// friendly "admin already exists" message, and Complete sets the flag.
async function isSetupComplete() {
  const flagRow = await AppSetting.findOne({ where: { key: 'setupComplete' } });
  return !!flagRow && flagRow.value === 'true';
}

// Check setup status
router.get('/status', async (req, res) => {
  try {
    const [userCount, siemCount, complete] = await Promise.all([
      User.count(), ApiKey.count(), isSetupComplete()
    ]);

    res.json({
      isComplete: complete,
      dbConnected: true,
      siemConfigured: siemCount > 0,
      adminCreated: userCount > 0,
      ...(complete && {
        warning: 'Setup is already complete. Re-running setup requires admin authentication. Existing configurations will be preserved.',
        userCount,
        siemCount
      })
    });
  } catch (err) {
    res.json({
      isComplete: false,
      dbConnected: false,
      siemConfigured: false,
      adminCreated: false
    });
  }
});

router.use((req, res, next) => {
  log.debug(`${req.method} ${req.path}`, { request: req.requestId });
  next();
});

// Test database connection
router.post('/test-db', async (req, res) => {
  try {
    if (await isSetupComplete()) {
      const authHeader = req.headers['authorization'];
      const token = authHeader && authHeader.split(' ')[1];
      if (!token) {
        return res.status(401).json({
          error: 'Authentication required. Setup is already complete.',
          suggestion: 'Log in as an admin to use this endpoint, or use the Admin panel sync-db feature instead.',
          category: 'auth'
        });
      }
      try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] });
        if (decoded.role !== 'admin') {
          return res.status(403).json({
            error: 'Admin access required.',
            suggestion: 'Only admin users can trigger database sync after setup is complete.',
            category: 'auth'
          });
        }
      } catch (jwtErr) {
        return res.status(403).json({
          error: 'Invalid or expired token.',
          suggestion: 'Please log in again and retry.',
          category: 'auth'
        });
      }
    }

    await sequelize.authenticate();
    await sequelize.sync({ alter: true });
    log.info('db test passed', { request: req.requestId });
    res.json({ success: true, message: 'Database connection successful and schema synced' });
  } catch (err) {
    log.error('db test failed', {
      request: req.requestId,
      error: err.message,
      hint: 'Check DB_HOST/DB_USER/DB_PASSWORD in docker-compose.yml and that mysql-v5 is healthy.'
    });
    res.json({ success: false, message: 'Database connection failed' });
  }
});

// Add SIEM during setup. The wizard may call this more than once in a
// single session — operator fat-fingers a host, edits, hits Save & Continue
// again; or adds one SIEM, goes back, adds another. Upsert by client name
// so re-saves update the existing row instead of being rejected. Real
// security is the isSetupComplete() gate: once the wizard's last step
// flips the setupComplete flag, this endpoint stops accepting writes.
router.post('/add-siem', async (req, res) => {
  try {
    if (await isSetupComplete()) {
      return res.status(403).json({
        success: false,
        error: 'Setup already completed. Use the Admin panel to add or edit SIEM connections.',
        category: 'auth'
      });
    }

    const { client, siemType, apiHost, apiKey, username, password, port, verifySSL, extraConfig } = req.body;

    if (!client || !siemType || !apiHost) {
      return res.status(400).json({ success: false, error: 'Client, SIEM type, and API host are required' });
    }

    const validSiemTypes = ['logrhythm', 'splunk', 'qradar', 'manageengine', 'wazuh', 'elastic'];
    if (!validSiemTypes.includes(String(siemType).toLowerCase())) {
      return res.status(400).json({ success: false, error: `Invalid SIEM type. Must be one of: ${validSiemTypes.join(', ')}` });
    }

    const fields = {
      siemType,
      apiHost,
      apiKey: apiKey || '',
      username: username || '',
      password: password || '',
      port: port || null,
      verifySSL: verifySSL !== false,
      extraConfig: extraConfig || {},
      isActive: true
    };

    const existing = await ApiKey.findOne({ where: { client } });
    if (existing) {
      await existing.update(fields);
      log.info('SIEM connection updated (setup)', { request: req.requestId, client, siemType, apiHost });
      return res.json({ success: true, message: 'SIEM connection updated', updated: true });
    }

    await ApiKey.create({ client, ...fields });
    log.info('SIEM connection saved (setup)', { request: req.requestId, client, siemType, apiHost, verifySSL: verifySSL !== false });
    res.status(201).json({ success: true, message: 'SIEM connection added', created: true });
  } catch (err) {
    log.error('add-siem failed', { request: req.requestId, error: err.message });
    res.status(500).json({ success: false, error: 'Failed to add SIEM connection' });
  }
});

// Create first admin during setup
router.post('/create-admin', async (req, res) => {
  try {
    if (await isSetupComplete()) {
      return res.status(403).json({ error: 'Setup already completed. Use admin panel instead.' });
    }
    // Only one admin may be created via the wizard. Additional admins must
    // be added from the admin panel by an authenticated admin.
    const userCount = await User.count();
    if (userCount > 0) {
      return res.status(403).json({
        success: false,
        error: 'An admin user already exists. Continue to the next step, or use the Admin panel to create additional users.'
      });
    }

    const { username, password } = req.body;

    if (!username || !password || typeof username !== 'string' || typeof password !== 'string') {
      return res.status(400).json({ success: false, error: 'Username and password are required and must be strings' });
    }

    if (username.length < 3 || username.length > 50) {
      return res.status(400).json({ success: false, error: 'Username must be between 3 and 50 characters' });
    }

    const pwCheck = validatePassword(password);
    if (!pwCheck.valid) {
      return res.status(400).json({ success: false, error: pwCheck.errors.join('. ') });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    await User.create({
      username,
      passwordHash: hashedPassword,
      role: 'admin',
      isActive: true,
      canSearch: true, canHunt: true, canExport: true, canViewRepo: true,
      canManageSIEM: true, canManageTI: true, canRecon: true,
      canManageMappings: true, canManageUsers: true, canManageSecurity: true
    });

    log.info('first admin created', { request: req.requestId, username });
    res.status(201).json({ success: true, message: 'Admin user created' });
  } catch (err) {
    if (err.name === 'SequelizeUniqueConstraintError') {
      log.warn('create-admin rejected — duplicate username', { request: req.requestId });
      return res.status(400).json({ success: false, error: 'Username already exists' });
    }
    log.error('create-admin failed', { request: req.requestId, error: err.message });
    res.status(500).json({ success: false, error: 'Failed to create admin user' });
  }
});

// Test SIEM connection during setup
router.post('/test-siem', async (req, res) => {
  try {
    if (await isSetupComplete()) {
      return res.status(403).json({ success: false, error: 'Setup already completed. Use admin panel instead.' });
    }

    const { siemType, apiHost, apiKey, username, password, port, verifySSL } = req.body;
    if (!siemType || !apiHost) {
      return res.status(400).json({ success: false, error: 'SIEM type and API host are required' });
    }

    const adapter = getSiemAdapter(siemType, {
      apiHost, apiKey, username, password, port, verifySSL, client: 'setup-test'
    });

    log.info('testing SIEM connection', { request: req.requestId, siemType, apiHost });
    const result = await adapter.testConnection();
    if (result.success) {
      log.info('SIEM test ok', { request: req.requestId, siemType, apiHost });
      res.json({ success: true, message: result.message, data: result.data });
    } else {
      log.warn('SIEM test failed', {
        request: req.requestId,
        siemType,
        apiHost,
        category: result.category || 'connection',
        reason: result.message,
        hint: result.suggestion
      });
      res.status(400).json({
        success: false,
        error: result.message,
        suggestion: result.suggestion || 'Check the SIEM connection settings and try again.',
        category: result.category || 'connection'
      });
    }
  } catch (err) {
    log.error('test-siem error', { request: req.requestId, error: err.message });
    const classified = classifySiemError(err, req.body?.siemType, req.body?.apiHost);
    res.status(400).json({
      success: false,
      error: classified.message,
      suggestion: classified.suggestion,
      category: classified.category
    });
  }
});

// Fetch live log sources from a SIEM that was just added in setup
// Body: { client }
router.post('/list-log-sources', async (req, res) => {
  try {
    if (await isSetupComplete()) {
      return res.status(403).json({ success: false, error: 'Setup already completed. Use /api/admin/log-sources/:clientId instead.' });
    }
    const { client } = req.body || {};
    if (!client) return res.status(400).json({ success: false, error: 'client is required' });

    const apiKeyObj = await ApiKey.findOne({ where: { client } });
    if (!apiKeyObj) return res.status(404).json({ success: false, error: `No SIEM connection found for client: ${client}` });

    const siemType = (apiKeyObj.siemType || 'logrhythm').toLowerCase();
    const adapter = getSiemAdapter(siemType, { ...apiKeyObj.dataValues, client: apiKeyObj.client });
    log.info('listing log sources', { request: req.requestId, client, siemType });
    const sources = await adapter.getLogSources();
    log.info('log sources fetched', { request: req.requestId, client, siemType, count: Array.isArray(sources) ? sources.length : 0 });
    res.json({ success: true, siemType, sources: Array.isArray(sources) ? sources : [] });
  } catch (err) {
    log.error('list-log-sources failed', {
      request: req.requestId,
      error: err.message,
      hint: err.suggestion || 'Ensure the API credentials have permission to list log sources / indexes / agents.'
    });
    res.status(400).json({
      success: false,
      error: err.message || 'Failed to fetch log sources',
      suggestion: err.suggestion || 'Verify the SIEM credentials and that the API user can list log sources.',
      category: err.category || 'connection'
    });
  }
});

// Bulk save log-source mappings for a client during setup
// Body: { client, mappings: { IP: [{listId,name,guid,listType}, ...], Hash: [...], ... } }
router.post('/save-log-source-mappings', async (req, res) => {
  try {
    if (await isSetupComplete()) {
      return res.status(403).json({ success: false, error: 'Setup already completed. Use /api/admin/log-source-mappings instead.' });
    }
    const { client, mappings } = req.body || {};
    if (!client || !mappings || typeof mappings !== 'object') {
      return res.status(400).json({ success: false, error: 'client and mappings are required' });
    }
    const apiKeyObj = await ApiKey.findOne({ where: { client } });
    if (!apiKeyObj) return res.status(404).json({ success: false, error: `No SIEM connection found for client: ${client}` });
    const siemType = (apiKeyObj.siemType || 'logrhythm').toLowerCase();

    let written = 0;
    await sequelize.transaction(async (t) => {
      await MsgSource.destroy({ where: { client, siemType }, transaction: t });
      for (const [filterType, list] of Object.entries(mappings)) {
        if (!Array.isArray(list)) continue;
        for (const item of list) {
          await MsgSource.create({
            client,
            siemType,
            filterType,
            listId: item?.listId != null ? parseInt(item.listId, 10) : (item?.id != null ? parseInt(item.id, 10) : null),
            guid: item?.guid || null,
            name: item?.name || null,
            listType: item?.listType || null
          }, { transaction: t });
          written += 1;
        }
      }
    });
    log.info('log-source mappings saved (setup)', { request: req.requestId, client, written });
    res.json({ success: true, written });
  } catch (err) {
    log.error('save-log-source-mappings failed', { request: req.requestId, error: err.message });
    res.status(500).json({ success: false, error: 'Failed to save log source mappings' });
  }
});

// Mark setup as complete. This is the only call that flips the
// setupComplete flag — intermediate steps (db test, SIEM save, admin
// create) no longer mark setup done on their own. Requires at least
// one admin user to exist, otherwise setup is trivially incomplete.
router.post('/complete', async (req, res) => {
  try {
    if (await isSetupComplete()) {
      return res.status(403).json({ error: 'Setup already completed. Use admin panel instead.' });
    }

    const userCount = await User.count();
    if (userCount === 0) {
      return res.status(400).json({
        error: 'No admin user has been created yet. Finish the Admin User step first.',
        category: 'validation'
      });
    }

    const { requireSearchAuth } = req.body || {};
    if (typeof requireSearchAuth === 'boolean') {
      await AppSetting.upsert({ key: 'requireSearchAuth', value: String(requireSearchAuth) });
      setRequireSearchAuth(requireSearchAuth);
    }

    await AppSetting.upsert({ key: 'setupComplete', value: 'true' });

    log.info('setup marked complete', {
      request: req.requestId,
      requireSearchAuth: requireSearchAuth ?? null,
      userCount,
      siemCount: await ApiKey.count()
    });
    res.json({ success: true });
  } catch (err) {
    log.error('complete failed', { request: req.requestId, error: err.message });
    res.status(500).json({ error: 'Failed to mark setup complete.' });
  }
});

module.exports = router;
