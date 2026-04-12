const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const router = express.Router();

const User = require('../models/User');
const ApiKey = require('../models/ApiKey');
const AppSetting = require('../models/AppSetting');
const sequelize = require('../db');
const { getSiemAdapter } = require('../siem-adapters');
const { classifySiemError, setRequireSearchAuth } = require('../middleware');
const { validatePassword } = require('../utils/password');

// Check setup status
router.get('/status', async (req, res) => {
  try {
    const userCount = await User.count();
    const siemCount = await ApiKey.count();

    const isComplete = userCount > 0;
    res.json({
      isComplete,
      dbConnected: true,
      siemConfigured: siemCount > 0,
      adminCreated: userCount > 0,
      ...(isComplete && {
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

// Test database connection
router.post('/test-db', async (req, res) => {
  try {
    const userCount = await User.count();
    if (userCount > 0) {
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
    res.json({ success: true, message: 'Database connection successful and schema synced' });
  } catch (err) {
    console.error('Database connection test failed:', err.message);
    res.json({ success: false, message: 'Database connection failed' });
  }
});

// Add SIEM during setup
router.post('/add-siem', async (req, res) => {
  try {
    const userCount = await User.count();
    if (userCount > 0) {
      return res.status(403).json({ error: 'Setup already completed. Use admin panel instead.' });
    }

    const existingCount = await ApiKey.count();
    if (existingCount > 0) {
      const authHeader = req.headers['authorization'];
      const token = authHeader && authHeader.split(' ')[1];
      if (!token) {
        return res.status(403).json({
          success: false,
          error: 'Setup already complete. SIEM connections already exist.',
          suggestion: 'Use the Admin panel to add more SIEMs, or log in as admin to re-run setup.',
          category: 'auth'
        });
      }
      try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] });
        if (decoded.role !== 'admin') {
          return res.status(403).json({ success: false, error: 'Admin access required to add SIEMs after initial setup.' });
        }
      } catch (jwtErr) {
        return res.status(403).json({ success: false, error: 'Invalid or expired token. Please log in again.' });
      }
    }

    const { client, siemType, apiHost, apiKey, username, password, port, verifySSL, extraConfig } = req.body;

    if (!client || !siemType || !apiHost) {
      return res.status(400).json({ success: false, error: 'Client, SIEM type, and API host are required' });
    }

    const validSiemTypes = ['logrhythm', 'splunk', 'qradar', 'manageengine', 'wazuh', 'elastic'];
    if (!validSiemTypes.includes(String(siemType).toLowerCase())) {
      return res.status(400).json({ success: false, error: `Invalid SIEM type. Must be one of: ${validSiemTypes.join(', ')}` });
    }

    await ApiKey.create({
      client,
      siemType,
      apiHost,
      apiKey: apiKey || '',
      username: username || '',
      password: password || '',
      port: port || null,
      verifySSL: verifySSL !== false,
      extraConfig: extraConfig || {},
      isActive: true
    });

    res.status(201).json({ success: true, message: 'SIEM connection added' });
  } catch (err) {
    console.error('Setup add-siem error:', err.message);
    res.status(500).json({ success: false, error: 'Failed to add SIEM connection' });
  }
});

// Create first admin during setup
router.post('/create-admin', async (req, res) => {
  try {
    const userCount = await User.count();
    if (userCount > 0) {
      return res.status(403).json({ error: 'Setup already completed. Use admin panel instead.' });
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

    res.status(201).json({ success: true, message: 'Admin user created' });
  } catch (err) {
    if (err.name === 'SequelizeUniqueConstraintError') {
      return res.status(400).json({ success: false, error: 'Username already exists' });
    }
    console.error('Setup create-admin error:', err.message);
    res.status(500).json({ success: false, error: 'Failed to create admin user' });
  }
});

// Test SIEM connection during setup
router.post('/test-siem', async (req, res) => {
  try {
    const userCount = await User.count();
    if (userCount > 0) {
      return res.status(403).json({ success: false, error: 'Setup already completed. Use admin panel instead.' });
    }

    const { siemType, apiHost, apiKey, username, password, port, verifySSL } = req.body;
    if (!siemType || !apiHost) {
      return res.status(400).json({ success: false, error: 'SIEM type and API host are required' });
    }

    const adapter = getSiemAdapter(siemType, {
      apiHost, apiKey, username, password, port, verifySSL, client: 'setup-test'
    });

    const result = await adapter.testConnection();
    if (result.success) {
      res.json({ success: true, message: result.message, data: result.data });
    } else {
      res.status(400).json({
        success: false,
        error: result.message,
        suggestion: result.suggestion || 'Check the SIEM connection settings and try again.',
        category: result.category || 'connection'
      });
    }
  } catch (err) {
    console.error('Setup test-siem error:', err.message);
    const classified = classifySiemError(err, req.body?.siemType, req.body?.apiHost);
    res.status(400).json({
      success: false,
      error: classified.message,
      suggestion: classified.suggestion,
      category: classified.category
    });
  }
});

// Mark setup as complete
router.post('/complete', async (req, res) => {
  try {
    const userCount = await User.count();
    if (userCount > 0) {
      return res.status(403).json({ error: 'Setup already completed. Use admin panel instead.' });
    }

    const { requireSearchAuth } = req.body || {};
    if (typeof requireSearchAuth === 'boolean') {
      await AppSetting.upsert({ key: 'requireSearchAuth', value: String(requireSearchAuth) });
      setRequireSearchAuth(requireSearchAuth);
    }

    res.json({ success: true });
  } catch (err) {
    console.error('Setup complete check failed:', err.message);
    res.status(500).json({ error: 'Failed to verify setup status.' });
  }
});

module.exports = router;
