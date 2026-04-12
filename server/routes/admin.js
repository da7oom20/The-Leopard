const express = require('express');
const bcrypt = require('bcrypt');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const router = express.Router();

const User = require('../models/User');
const ApiKey = require('../models/ApiKey');
const TISource = require('../models/TISource');
const SSLConfig = require('../models/SSLConfig');
const QueryTemplate = require('../models/QueryTemplate');
const AppSetting = require('../models/AppSetting');
const AuditLog = require('../models/AuditLog');
const sequelize = require('../db');
const MFA = require('../utils/mfa');
const { authenticateToken, requirePermission, validateIdParam, classifySiemError, setRequireSearchAuth, getRequireSearchAuth } = require('../middleware');
const { getSiemAdapter, getSupportedTypes, validateConfig, getConfigSchema, getDisplayName, getAllDefaultConfigs } = require('../siem-adapters');
const { getTiAdapter, getSupportedPlatforms, getPlatformInfo, getDefaultUrl } = require('../ti-adapters');
const { audit } = require('../utils/audit');
const { validatePassword } = require('../utils/password');

// ============ DATABASE SYNC ============

router.post('/sync-db', authenticateToken, requirePermission('canManageSIEM'), async (req, res) => {
  try {
    await sequelize.sync({ alter: true });
    res.json({ success: true, message: 'Database schema synchronized successfully' });
  } catch (err) {
    console.error('Database sync error:', err);
    res.status(500).json({ success: false, error: 'Database sync failed' });
  }
});

// ============ SSL/TLS ENDPOINTS ============

const sslUpload = multer({
  dest: '/app/ssl/',
  limits: { fileSize: 10 * 1024 * 1024 }
});

router.get('/ssl', authenticateToken, requirePermission('canManageSecurity'), async (req, res) => {
  try {
    let config = await SSLConfig.findOne();
    if (!config) {
      config = await SSLConfig.create({ isEnabled: false });
    }
    res.json(config);
  } catch (err) {
    console.error('SSL config error:', err);
    res.status(500).json({ error: 'Failed to get SSL configuration' });
  }
});

router.post('/ssl/upload', authenticateToken, requirePermission('canManageSecurity'), sslUpload.fields([
  { name: 'certificate', maxCount: 1 },
  { name: 'privateKey', maxCount: 1 },
  { name: 'ca', maxCount: 1 }
]), async (req, res) => {
  try {
    const files = req.files;
    if (!files.certificate || !files.privateKey) {
      return res.status(400).json({ error: 'Certificate and private key are required' });
    }

    const certContent = fs.readFileSync(files.certificate[0].path, 'utf8');
    const keyContent = fs.readFileSync(files.privateKey[0].path, 'utf8');

    if (!certContent.includes('-----BEGIN CERTIFICATE-----') || !certContent.includes('-----END CERTIFICATE-----')) {
      try { fs.unlinkSync(files.certificate[0].path); } catch (e) {}
      try { fs.unlinkSync(files.privateKey[0].path); } catch (e) {}
      if (files.ca) try { fs.unlinkSync(files.ca[0].path); } catch (e) {}
      return res.status(400).json({
        error: 'Invalid certificate file. Expected PEM format with BEGIN/END CERTIFICATE markers.',
        suggestion: 'Upload a valid PEM-encoded certificate file (.crt or .pem).',
        category: 'validation'
      });
    }

    if (!keyContent.includes('-----BEGIN') || !keyContent.includes('PRIVATE KEY-----')) {
      try { fs.unlinkSync(files.certificate[0].path); } catch (e) {}
      try { fs.unlinkSync(files.privateKey[0].path); } catch (e) {}
      if (files.ca) try { fs.unlinkSync(files.ca[0].path); } catch (e) {}
      return res.status(400).json({
        error: 'Invalid private key file. Expected PEM format with BEGIN/END PRIVATE KEY markers.',
        suggestion: 'Upload a valid PEM-encoded private key file (.key or .pem).',
        category: 'validation'
      });
    }

    if (files.ca) {
      const caContent = fs.readFileSync(files.ca[0].path, 'utf8');
      if (!caContent.includes('-----BEGIN CERTIFICATE-----')) {
        try { fs.unlinkSync(files.certificate[0].path); } catch (e) {}
        try { fs.unlinkSync(files.privateKey[0].path); } catch (e) {}
        try { fs.unlinkSync(files.ca[0].path); } catch (e) {}
        return res.status(400).json({
          error: 'Invalid CA bundle file. Expected PEM format with BEGIN/END CERTIFICATE markers.',
          category: 'validation'
        });
      }
    }

    const sslDir = '/app/ssl';
    if (!fs.existsSync(sslDir)) {
      fs.mkdirSync(sslDir, { recursive: true });
    }

    const certPath = path.join(sslDir, 'certificate.crt');
    const keyPath = path.join(sslDir, 'private.key');
    const caPath = files.ca ? path.join(sslDir, 'ca.crt') : null;

    fs.renameSync(files.certificate[0].path, certPath);
    fs.renameSync(files.privateKey[0].path, keyPath);
    if (files.ca) {
      fs.renameSync(files.ca[0].path, caPath);
    }

    let certInfo = {};
    try {
      const certData = fs.readFileSync(certPath, 'utf8');
      const subjectMatch = certData.match(/Subject:.*CN\s*=\s*([^\n,]+)/i);
      const issuerMatch = certData.match(/Issuer:.*CN\s*=\s*([^\n,]+)/i);
      const validFromMatch = certData.match(/Not Before:\s*(.+)/i);
      const validToMatch = certData.match(/Not After\s*:\s*(.+)/i);
      certInfo = {
        commonName: subjectMatch ? subjectMatch[1].trim() : 'Unknown',
        issuer: issuerMatch ? issuerMatch[1].trim() : 'Unknown',
        validFrom: validFromMatch ? validFromMatch[1].trim() : null,
        validTo: validToMatch ? validToMatch[1].trim() : null,
        uploadedAt: new Date().toISOString()
      };
    } catch (parseErr) {
      console.warn('Could not parse certificate info:', parseErr.message);
    }

    let config = await SSLConfig.findOne();
    if (!config) {
      config = await SSLConfig.create({ isEnabled: false, certificatePath: certPath, privateKeyPath: keyPath, caPath, certificateInfo: certInfo });
    } else {
      await config.update({ certificatePath: certPath, privateKeyPath: keyPath, caPath, certificateInfo: certInfo });
    }

    res.json({
      success: true,
      message: 'SSL certificates uploaded successfully',
      certificateInfo: certInfo,
      note: 'Restart the application to apply HTTPS. Update docker-compose.yml to expose port 443.'
    });
  } catch (err) {
    console.error('SSL upload error:', err);
    res.status(500).json({ error: 'Failed to upload SSL certificates' });
  }
});

router.post('/ssl/toggle', authenticateToken, requirePermission('canManageSecurity'), async (req, res) => {
  try {
    const { enabled } = req.body;
    let config = await SSLConfig.findOne();
    if (!config) {
      return res.status(400).json({ error: 'No SSL configuration found. Upload certificates first.' });
    }
    if (enabled && (!config.certificatePath || !config.privateKeyPath)) {
      return res.status(400).json({ error: 'Cannot enable SSL without certificates' });
    }
    await config.update({ isEnabled: enabled });
    res.json({
      success: true,
      isEnabled: enabled,
      message: enabled
        ? 'SSL enabled. Restart the application and update docker-compose.yml to apply.'
        : 'SSL disabled. Restart the application to apply.'
    });
  } catch (err) {
    console.error('SSL toggle error:', err);
    res.status(500).json({ error: 'Failed to toggle SSL' });
  }
});

router.delete('/ssl', authenticateToken, requirePermission('canManageSecurity'), async (req, res) => {
  try {
    const config = await SSLConfig.findOne();
    if (!config) {
      return res.json({ success: true, message: 'No SSL configuration to delete' });
    }
    const sslDir = '/app/ssl/';
    const filesToDelete = [config.certificatePath, config.privateKeyPath, config.caPath].filter(Boolean);
    for (const filePath of filesToDelete) {
      const resolved = path.resolve(filePath);
      if (!resolved.startsWith(sslDir) && resolved !== '/app/ssl') {
        console.warn(`Skipping deletion of file outside SSL dir: ${filePath}`);
        continue;
      }
      if (fs.existsSync(resolved)) {
        fs.unlinkSync(resolved);
      }
    }
    await config.update({ isEnabled: false, certificatePath: null, privateKeyPath: null, caPath: null, certificateInfo: null, expiresAt: null });
    res.json({ success: true, message: 'SSL certificates deleted' });
  } catch (err) {
    console.error('SSL delete error:', err);
    res.status(500).json({ error: 'Failed to delete SSL certificates' });
  }
});

// ============ APP SETTINGS ============

router.get('/settings', authenticateToken, requirePermission('canManageSecurity'), async (req, res) => {
  try {
    const settings = await AppSetting.findAll();
    const result = {};
    for (const s of settings) result[s.key] = s.value;
    res.json(result);
  } catch (err) {
    console.error('Settings fetch error:', err.message);
    res.status(500).json({ error: 'Failed to fetch settings' });
  }
});

router.put('/settings', authenticateToken, requirePermission('canManageSecurity'), async (req, res) => {
  try {
    const { key, value } = req.body;
    const allowedKeys = ['requireSearchAuth'];
    if (!key || !allowedKeys.includes(key)) {
      return res.status(400).json({ error: `Invalid setting key. Allowed: ${allowedKeys.join(', ')}` });
    }
    await AppSetting.upsert({ key, value: String(value) });
    if (key === 'requireSearchAuth') {
      setRequireSearchAuth(value === true || value === 'true');
    }
    audit(req, 'settings.update', 'settings', { details: { key, value: String(value) } });
    res.json({ success: true, key, value: String(value) });
  } catch (err) {
    console.error('Settings update error:', err.message);
    res.status(500).json({ error: 'Failed to update setting' });
  }
});

// ============ AUDIT LOGS ============

router.get('/audit-logs', authenticateToken, requirePermission('canManageSecurity'), async (req, res) => {
  try {
    const limit = Math.max(1, Math.min(200, parseInt(req.query.limit || '50', 10)));
    const page = Math.max(1, parseInt(req.query.page || '1', 10));
    const offset = req.query.offset != null ? Math.max(0, parseInt(req.query.offset, 10)) : (page - 1) * limit;
    const where = {};
    if (req.query.category) where.category = req.query.category;
    if (req.query.actorId) where.actorId = parseInt(req.query.actorId, 10);
    const { rows: items, count: total } = await AuditLog.findAndCountAll({ where, order: [['createdAt', 'DESC']], limit, offset });
    res.json({ items, total, page, pages: Math.ceil(total / limit), offset, limit });
  } catch (err) {
    console.error('Audit log fetch error:', err.message);
    res.status(500).json({ error: 'Failed to fetch audit logs' });
  }
});

// ============ USERS ============

router.get('/users', authenticateToken, requirePermission('canManageUsers'), async (req, res) => {
  try {
    const users = await User.findAll({
      attributes: [
        'id', 'username', 'role', 'isActive', 'mfaEnabled', 'createdAt', 'updatedAt',
        'canSearch', 'canHunt', 'canExport', 'canViewRepo',
        'canManageSIEM', 'canManageTI', 'canRecon', 'canManageMappings',
        'canManageUsers', 'canManageSecurity'
      ]
    });
    res.json(users);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error fetching users' });
  }
});

router.post('/users', authenticateToken, requirePermission('canManageUsers'), async (req, res) => {
  const { username, password, role = 'analyst' } = req.body;

  if (!username || !password || typeof username !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ error: 'Username and password are required and must be strings' });
  }
  if (!username || username.length < 3 || username.length > 50) {
    return res.status(400).json({ error: 'Username must be between 3 and 50 characters' });
  }
  if (!/^[a-zA-Z0-9_.\-@]+$/.test(username)) {
    return res.status(400).json({ error: 'Username can only contain letters, numbers, underscores, dots, hyphens, and @' });
  }
  const pwCheck = validatePassword(password);
  if (!pwCheck.valid) return res.status(400).json({ error: pwCheck.errors.join('. '), category: 'validation' });
  const validRoles = ['admin', 'analyst', 'viewer'];
  if (!validRoles.includes(role)) return res.status(400).json({ error: `Invalid role. Must be one of: ${validRoles.join(', ')}` });

  const roleDefaults = {
    admin:   { canSearch: true,  canHunt: true,  canExport: true,  canViewRepo: true,  canRecon: true,  canManageSIEM: true,  canManageTI: true,  canManageMappings: true,  canManageUsers: true,  canManageSecurity: true },
    analyst: { canSearch: true,  canHunt: true,  canExport: true,  canViewRepo: true,  canRecon: false, canManageSIEM: false, canManageTI: false, canManageMappings: false, canManageUsers: false, canManageSecurity: false },
    viewer:  { canSearch: false, canHunt: false, canExport: false, canViewRepo: true,  canRecon: false, canManageSIEM: false, canManageTI: false, canManageMappings: false, canManageUsers: false, canManageSecurity: false },
  };
  const defaults = roleDefaults[role] || roleDefaults.analyst;

  const perms = {};
  const permissionFields = ['canSearch', 'canHunt', 'canExport', 'canViewRepo',
    'canRecon', 'canManageSIEM', 'canManageTI', 'canManageMappings',
    'canManageUsers', 'canManageSecurity'];
  for (const field of permissionFields) {
    perms[field] = typeof req.body[field] === 'boolean' ? req.body[field] : defaults[field];
  }

  try {
    const hash = await bcrypt.hash(password, 10);
    const existing = await User.findOne({ where: { username } });
    if (existing) return res.status(400).json({
      error: `A user with the username "${username}" already exists.`,
      suggestion: 'Choose a different username.',
      category: 'validation'
    });

    const user = await User.create({ username, passwordHash: hash, role, isActive: true, ...perms });
    audit(req, 'user.create', 'user', { targetType: 'user', targetId: user.id, details: { username, role } });
    res.status(201).json({ success: true, id: user.id, username: user.username });
  } catch (err) {
    if (err.name === 'SequelizeUniqueConstraintError') {
      return res.status(409).json({
        error: `A user with the username "${username}" already exists.`,
        suggestion: 'Choose a different username.',
        category: 'validation'
      });
    }
    console.error('Error creating user:', err.message);
    res.status(500).json({ error: 'Error creating user' });
  }
});

router.put('/users/:id', authenticateToken, requirePermission('canManageUsers'), validateIdParam, async (req, res) => {
  const { id } = req.params;
  const {
    username, password, role, isActive,
    canSearch, canHunt, canExport, canViewRepo,
    canManageSIEM, canManageTI, canRecon, canManageMappings,
    canManageUsers, canManageSecurity
  } = req.body;

  try {
    const t = await sequelize.transaction();
    try {
      const user = await User.findByPk(id, { transaction: t });
      if (!user) {
        await t.rollback();
        return res.status(404).json({ error: 'User not found' });
      }

      if (user.role === 'admin' && (role !== 'admin' || isActive === false)) {
        const adminCount = await User.count({ where: { role: 'admin', isActive: true }, transaction: t, lock: t.LOCK.UPDATE });
        if (adminCount <= 1) {
          await t.rollback();
          return res.status(400).json({
            error: 'Cannot demote or deactivate the last active admin.',
            suggestion: 'Create another admin account first, then you can modify this one.',
            category: 'validation'
          });
        }
      }

      const updates = {};
      if (username && username !== user.username) {
        const existing = await User.findOne({ where: { username }, transaction: t });
        if (existing) {
          await t.rollback();
          return res.status(400).json({
            error: `The username "${username}" is already taken.`,
            suggestion: 'Choose a different username.',
            category: 'validation'
          });
        }
        updates.username = username;
      }
      if (password) {
        const pwCheck = validatePassword(password);
        if (!pwCheck.valid) {
          await t.rollback();
          return res.status(400).json({ error: pwCheck.errors.join('. '), category: 'validation' });
        }
        updates.passwordHash = await bcrypt.hash(password, 10);
        updates.tokenIssuedAfter = new Date();
      }
      if (role && ['admin', 'analyst', 'viewer'].includes(role)) updates.role = role;
      if (typeof isActive === 'boolean') updates.isActive = isActive;

      const permissionFields = ['canSearch', 'canHunt', 'canExport', 'canViewRepo',
        'canManageSIEM', 'canManageTI', 'canRecon', 'canManageMappings',
        'canManageUsers', 'canManageSecurity'];
      const permissionValues = { canSearch, canHunt, canExport, canViewRepo, canManageSIEM, canManageTI, canRecon, canManageMappings, canManageUsers, canManageSecurity };
      permissionFields.forEach(field => {
        if (typeof permissionValues[field] === 'boolean') updates[field] = permissionValues[field];
      });

      await user.update(updates, { transaction: t });
      await t.commit();
      audit(req, 'user.update', 'user', { targetType: 'user', targetId: user.id, details: { fields: Object.keys(updates) } });
      res.json({
        success: true,
        user: {
          id: user.id, username: user.username, role: user.role, isActive: user.isActive,
          canSearch: user.canSearch, canHunt: user.canHunt, canExport: user.canExport, canViewRepo: user.canViewRepo,
          canManageSIEM: user.canManageSIEM, canManageTI: user.canManageTI, canRecon: user.canRecon,
          canManageMappings: user.canManageMappings, canManageUsers: user.canManageUsers, canManageSecurity: user.canManageSecurity
        }
      });
    } catch (innerErr) {
      await t.rollback();
      throw innerErr;
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error updating user' });
  }
});

router.delete('/users/:id', authenticateToken, requirePermission('canManageUsers'), validateIdParam, async (req, res) => {
  const { id } = req.params;

  if (parseInt(id, 10) === req.user.userId) {
    return res.status(400).json({
      error: 'Cannot delete your own account.',
      suggestion: 'Ask another admin to delete your account, or deactivate it instead.',
      category: 'validation'
    });
  }

  try {
    const t = await sequelize.transaction();
    try {
      const user = await User.findByPk(id, { transaction: t });
      if (!user) {
        await t.rollback();
        return res.status(404).json({ error: 'User not found' });
      }

      if (user.role === 'admin') {
        const adminCount = await User.count({ where: { role: 'admin', isActive: true }, transaction: t, lock: t.LOCK.UPDATE });
        if (adminCount <= 1) {
          await t.rollback();
          return res.status(400).json({
            error: 'Cannot delete the last admin user.',
            suggestion: 'Create another admin account first, then you can delete this one.',
            category: 'validation'
          });
        }
      }

      const userCount = await User.count({ transaction: t });
      if (userCount <= 1) {
        await t.rollback();
        return res.status(400).json({
          error: 'Cannot delete the last user.',
          suggestion: 'At least one user account must exist.',
          category: 'validation'
        });
      }

      const deletedUsername = user.username;
      await user.destroy({ transaction: t });
      await t.commit();
      audit(req, 'user.delete', 'user', { targetType: 'user', targetId: parseInt(id, 10), details: { username: deletedUsername } });
      res.json({ success: true });
    } catch (innerErr) {
      await t.rollback();
      throw innerErr;
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error deleting user' });
  }
});

// Admin MFA management
router.get('/users/:id/mfa', authenticateToken, requirePermission('canManageUsers'), validateIdParam, async (req, res) => {
  try {
    const user = await User.findByPk(req.params.id, { attributes: ['id', 'username', 'mfaEnabled', 'mfaBackupCodes'] });
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({ userId: user.id, username: user.username, mfaEnabled: user.mfaEnabled, backupCodesRemaining: (user.mfaBackupCodes || []).length });
  } catch (err) {
    console.error('Error fetching user MFA status:', err);
    res.status(500).json({ error: 'Error fetching MFA status' });
  }
});

router.post('/users/:id/mfa/reset', authenticateToken, requirePermission('canManageUsers'), validateIdParam, async (req, res) => {
  try {
    const requestingUser = await User.findByPk(req.user.userId);
    if (!requestingUser || requestingUser.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }
    const targetUser = await User.findByPk(req.params.id);
    if (!targetUser) return res.status(404).json({ error: 'User not found' });
    await targetUser.update({ mfaEnabled: false, mfaSecret: null, mfaBackupCodes: null });
    audit(req, 'mfa.reset', 'security', { targetType: 'user', targetId: targetUser.id, details: { username: targetUser.username } });
    res.json({ success: true, message: `MFA has been disabled for user ${targetUser.username}` });
  } catch (err) {
    console.error('Error resetting user MFA:', err);
    res.status(500).json({ error: 'Error resetting MFA' });
  }
});

router.post('/users/:id/mfa/setup', authenticateToken, requirePermission('canManageUsers'), validateIdParam, async (req, res) => {
  try {
    const requestingUser = await User.findByPk(req.user.userId);
    if (!requestingUser || requestingUser.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }
    const targetUser = await User.findByPk(req.params.id);
    if (!targetUser) return res.status(404).json({ error: 'User not found' });

    const secret = MFA.generateSecret();
    const qrCodeDataUrl = await MFA.generateQRCodeDataURL(secret, targetUser.username);
    const backupCodes = MFA.generateBackupCodes();

    await targetUser.update({ mfaSecret: secret, mfaBackupCodes: backupCodes });
    res.json({ success: true, secret, qrCode: qrCodeDataUrl, backupCodes, message: `MFA setup initiated for user ${targetUser.username}.` });
  } catch (err) {
    console.error('Error setting up user MFA:', err);
    res.status(500).json({ error: 'Error setting up MFA' });
  }
});

router.post('/users/:id/mfa/backup-codes', authenticateToken, requirePermission('canManageUsers'), validateIdParam, async (req, res) => {
  try {
    const requestingUser = await User.findByPk(req.user.userId);
    if (!requestingUser || requestingUser.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }
    const targetUser = await User.findByPk(req.params.id);
    if (!targetUser) return res.status(404).json({ error: 'User not found' });
    if (!targetUser.mfaEnabled) return res.status(400).json({ error: 'MFA is not enabled for this user' });

    const backupCodes = MFA.generateBackupCodes();
    await targetUser.update({ mfaBackupCodes: backupCodes });
    res.json({ success: true, backupCodes, message: `New backup codes generated for user ${targetUser.username}` });
  } catch (err) {
    console.error('Error regenerating backup codes:', err);
    res.status(500).json({ error: 'Error regenerating backup codes' });
  }
});

// ============ SIEM MANAGEMENT ============

router.get('/api-keys', authenticateToken, requirePermission('canManageSIEM'), async (req, res) => {
  try {
    const keys = await ApiKey.findAll({ attributes: { exclude: ['password'] } });
    const masked = keys.map(k => {
      const j = k.toJSON();
      if (j.apiKey) j.apiKey = '••••' + j.apiKey.slice(-4);
      if (j.extraConfig && typeof j.extraConfig === 'object') {
        for (const key of Object.keys(j.extraConfig)) {
          if (/password|secret|token/i.test(key) && j.extraConfig[key]) {
            j.extraConfig[key] = '••••' + String(j.extraConfig[key]).slice(-4);
          }
        }
      }
      return j;
    });
    res.json(masked);
  } catch (err) {
    console.error('Error fetching API keys:', err.message);
    res.status(500).json({ error: 'Failed to fetch API keys' });
  }
});

router.get('/siem-types', authenticateToken, requirePermission('canManageSIEM'), (req, res) => {
  const types = getSupportedTypes().map(type => ({
    value: type,
    label: getDisplayName(type),
    configSchema: getConfigSchema(type)
  }));
  res.json(types);
});

router.get('/siem-config/:siemType', authenticateToken, requirePermission('canManageSIEM'), (req, res) => {
  try {
    const schema = getConfigSchema(req.params.siemType);
    res.json({ siemType: req.params.siemType, schema });
  } catch (err) {
    res.status(400).json({ error: 'Unsupported or invalid SIEM type' });
  }
});

router.get('/siem-defaults', authenticateToken, requirePermission('canManageSIEM'), (req, res) => {
  res.json(getAllDefaultConfigs());
});

router.post('/api-keys', authenticateToken, requirePermission('canManageSIEM'), async (req, res) => {
  const { client, siemType, apiHost, apiKey, username, password, port, verifySSL, extraConfig } = req.body;

  if (!client || !siemType || !apiHost) {
    return res.status(400).json({ error: 'Client, SIEM Type, and API Host are required' });
  }

  const validation = validateConfig(siemType, req.body);
  if (!validation.valid) {
    return res.status(400).json({ error: validation.errors.join(', ') });
  }

  try {
    const newKey = await ApiKey.create({
      client, siemType: siemType.toLowerCase(), apiHost, apiKey, username, password,
      port: port ? parseInt(port, 10) : null, verifySSL: verifySSL !== false,
      extraConfig: extraConfig || {}, isActive: true
    });
    audit(req, 'siem.create', 'siem', { targetType: 'apikey', targetId: newKey.id, details: { client, siemType } });
    const response = newKey.toJSON();
    delete response.password;
    if (response.apiKey) response.apiKey = '••••' + response.apiKey.slice(-4);
    res.status(201).json(response);
  } catch (err) {
    console.error('Error creating API key:', err.message);
    res.status(500).json({ error: 'Failed to create API key' });
  }
});

router.delete('/api-keys/:id', authenticateToken, requirePermission('canManageSIEM'), validateIdParam, async (req, res) => {
  try {
    const deletedCount = await ApiKey.destroy({ where: { id: req.params.id } });
    if (deletedCount === 0) return res.status(404).json({ error: 'API key not found' });
    audit(req, 'siem.delete', 'siem', { targetType: 'apikey', targetId: req.params.id });
    res.json({ message: 'API key deleted successfully' });
  } catch (error) {
    console.error('Error deleting API key:', error);
    res.status(500).json({ error: 'Failed to delete SIEM connection.', category: 'server' });
  }
});

router.post('/check-api-key', authenticateToken, requirePermission('canManageSIEM'), async (req, res) => {
  const { siemType, apiHost, apiKey, username, password, port, verifySSL } = req.body;

  if (!siemType || !apiHost) {
    return res.status(400).json({ error: 'Fields "siemType" and "apiHost" are required' });
  }

  try {
    const adapter = getSiemAdapter(siemType, { apiHost, apiKey, username, password, port, verifySSL, client: 'test' });
    const result = await adapter.testConnection();

    if (result.success) {
      if (req.body.id) {
        await ApiKey.update({ lastTestedAt: new Date(), lastTestStatus: 'success' }, { where: { id: req.body.id } });
      }
      res.json({ success: true, message: result.message, data: result.data });
    } else {
      if (req.body.id) {
        await ApiKey.update({ lastTestedAt: new Date(), lastTestStatus: 'failed' }, { where: { id: req.body.id } });
      }
      res.status(400).json({
        success: false, error: result.message,
        suggestion: result.suggestion || 'Check the SIEM connection settings and try again.',
        category: result.category || 'connection'
      });
    }
  } catch (err) {
    console.error('SIEM connection test error:', err);
    const classified = classifySiemError(err, siemType, apiHost);
    res.status(400).json({ success: false, error: classified.message, suggestion: classified.suggestion, category: classified.category });
  }
});

// ============ TI SOURCE MANAGEMENT ============

router.get('/ti-sources', authenticateToken, requirePermission('canManageTI'), async (req, res) => {
  try {
    const sources = await TISource.findAll({ order: [['createdAt', 'DESC']] });
    const masked = sources.map(s => {
      const j = s.toJSON();
      if (j.apiKey) j.apiKey = '••••' + j.apiKey.slice(-4);
      return j;
    });
    res.json(masked);
  } catch (err) {
    console.error('Failed to list TI sources:', err);
    res.status(500).json({ error: 'Failed to list TI sources' });
  }
});

router.post('/ti-sources', authenticateToken, requirePermission('canManageTI'), async (req, res) => {
  const { name, platformType, apiUrl, apiKey, extraConfig } = req.body;
  if (!name || !platformType) {
    return res.status(400).json({ error: 'Name and platform type are required' });
  }
  try {
    const defaultUrl = getDefaultUrl(platformType);
    const source = await TISource.create({
      name, platformType, apiUrl: apiUrl || defaultUrl || '',
      apiKey: apiKey || null, extraConfig: extraConfig || {}, isActive: true
    });
    audit(req, 'ti.create', 'ti', { targetType: 'ti_source', targetId: source.id, details: { name, platformType } });
    res.status(201).json(source);
  } catch (err) {
    console.error('Failed to add TI source:', err.message);
    res.status(500).json({ error: 'Failed to add TI source' });
  }
});

router.put('/ti-sources/:id', authenticateToken, requirePermission('canManageTI'), validateIdParam, async (req, res) => {
  const { name, platformType, apiUrl, apiKey, isActive, extraConfig } = req.body;
  try {
    const source = await TISource.findByPk(req.params.id);
    if (!source) return res.status(404).json({ error: 'TI source not found' });
    await source.update({
      ...(name !== undefined && { name }), ...(platformType !== undefined && { platformType }),
      ...(apiUrl !== undefined && { apiUrl }), ...(apiKey !== undefined && { apiKey }),
      ...(isActive !== undefined && { isActive }), ...(extraConfig !== undefined && { extraConfig })
    });
    res.json(source);
  } catch (err) {
    console.error('Failed to update TI source:', err);
    res.status(500).json({ error: 'Failed to update TI source' });
  }
});

router.delete('/ti-sources/:id', authenticateToken, requirePermission('canManageTI'), validateIdParam, async (req, res) => {
  try {
    const source = await TISource.findByPk(req.params.id);
    if (!source) return res.status(404).json({ error: 'TI source not found' });
    const deletedName = source.name;
    await source.destroy();
    audit(req, 'ti.delete', 'ti', { targetType: 'ti_source', targetId: req.params.id, details: { name: deletedName } });
    res.json({ message: 'TI source deleted' });
  } catch (err) {
    console.error('Failed to delete TI source:', err);
    res.status(500).json({ error: 'Failed to delete TI source' });
  }
});

router.post('/ti-sources/test', authenticateToken, requirePermission('canManageTI'), async (req, res) => {
  const { platformType, apiUrl, apiKey, id } = req.body;
  if (!platformType) {
    return res.status(400).json({ error: 'Platform type is required' });
  }
  try {
    const adapter = getTiAdapter(platformType, { apiUrl, apiKey });
    const result = await adapter.testConnection();
    if (id) {
      await TISource.update({ lastTestedAt: new Date(), lastTestStatus: result.success ? 'success' : 'failed' }, { where: { id } });
    }
    if (result.success) {
      res.json({ success: true, message: result.message });
    } else {
      res.status(400).json({
        success: false, error: result.message,
        suggestion: result.suggestion || 'Check the TI platform URL and API key.',
        category: result.category || 'connection'
      });
    }
  } catch (err) {
    console.error('TI connection test error:', err.message);
    res.status(400).json({
      success: false, error: 'Failed to connect to the TI platform.',
      suggestion: 'Check the TI platform URL and API key.',
      category: 'connection'
    });
  }
});

router.get('/ti-platforms', authenticateToken, requirePermission('canManageTI'), (req, res) => {
  res.json(getPlatformInfo());
});

// ============ QUERY TEMPLATES ============

router.get('/query-templates', authenticateToken, requirePermission('canManageSIEM'), async (req, res) => {
  try {
    const where = {};
    if (req.query.client) where.client = req.query.client;
    if (req.query.siemType) where.siemType = req.query.siemType;
    const templates = await QueryTemplate.findAll({ where, order: [['client', 'ASC'], ['filterType', 'ASC']] });
    res.json(templates);
  } catch (err) {
    console.error('Query templates list error:', err.message);
    res.status(500).json({ error: 'Failed to retrieve query templates' });
  }
});

router.get('/query-templates/defaults/:siemType', authenticateToken, requirePermission('canManageSIEM'), async (req, res) => {
  try {
    const defaults = getDefaultQueryTemplates(req.params.siemType);
    res.json(defaults);
  } catch (err) {
    console.error('Query template defaults error:', err.message);
    res.status(500).json({ error: 'Failed to retrieve default templates' });
  }
});

router.post('/query-templates', authenticateToken, requirePermission('canManageSIEM'), async (req, res) => {
  try {
    const { client, siemType, filterType, template, description } = req.body;
    if (!client || !siemType || !filterType || !template) {
      return res.status(400).json({ error: 'client, siemType, filterType, and template are required' });
    }
    const existing = await QueryTemplate.findOne({ where: { client, siemType, filterType } });
    if (existing) {
      return res.status(400).json({ error: 'A template already exists for this combination. Use PUT to update.' });
    }
    const qt = await QueryTemplate.create({ client, siemType, filterType, template, description });
    res.json(qt);
  } catch (err) {
    console.error('Query template create error:', err.message);
    res.status(500).json({ error: 'Failed to create query template' });
  }
});

router.put('/query-templates/:id', authenticateToken, requirePermission('canManageSIEM'), validateIdParam, async (req, res) => {
  try {
    const qt = await QueryTemplate.findByPk(req.params.id);
    if (!qt) return res.status(404).json({ error: 'Template not found' });
    const { template, description, isActive } = req.body;
    await qt.update({
      template: template !== undefined ? template : qt.template,
      description: description !== undefined ? description : qt.description,
      isActive: isActive !== undefined ? isActive : qt.isActive
    });
    res.json(qt);
  } catch (err) {
    console.error('Query template update error:', err.message);
    res.status(500).json({ error: 'Failed to update query template' });
  }
});

router.delete('/query-templates/:id', authenticateToken, requirePermission('canManageSIEM'), validateIdParam, async (req, res) => {
  try {
    const deleted = await QueryTemplate.destroy({ where: { id: req.params.id } });
    if (!deleted) return res.status(404).json({ error: 'Template not found' });
    res.json({ message: 'Template deleted' });
  } catch (err) {
    console.error('Query template delete error:', err.message);
    res.status(500).json({ error: 'Failed to delete query template' });
  }
});

function getDefaultQueryTemplates(siemType) {
  const templates = {
    splunk: {
      IP: { template: 'search index={{index}} ({{fieldConditions}}) | head 1000', description: 'Default Splunk IP search' },
      Hash: { template: 'search index={{index}} ({{fieldConditions}}) | head 1000', description: 'Default Splunk Hash search' },
      Domain: { template: 'search index={{index}} ({{fieldConditions}}) | head 1000', description: 'Default Splunk Domain search' },
      URL: { template: 'search index={{index}} ({{fieldConditions}}) | head 1000', description: 'Default Splunk URL search' },
      Email: { template: 'search index={{index}} ({{fieldConditions}}) | head 1000', description: 'Default Splunk Email search' },
      FileName: { template: 'search index={{index}} ({{fieldConditions}}) | head 1000', description: 'Default Splunk FileName search' },
    },
    qradar: {
      IP: { template: 'SELECT * FROM events WHERE ({{fieldConditions}}) LAST {{minutesBack}} MINUTES', description: 'Default QRadar AQL for IP' },
      Hash: { template: 'SELECT * FROM events WHERE ({{fieldConditions}}) LAST {{minutesBack}} MINUTES', description: 'Default QRadar AQL for Hash' },
      Domain: { template: 'SELECT * FROM events WHERE ({{fieldConditions}}) LAST {{minutesBack}} MINUTES', description: 'Default QRadar AQL for Domain' },
      URL: { template: 'SELECT * FROM events WHERE ({{fieldConditions}}) LAST {{minutesBack}} MINUTES', description: 'Default QRadar AQL for URL' },
      Email: { template: 'SELECT * FROM events WHERE ({{fieldConditions}}) LAST {{minutesBack}} MINUTES', description: 'Default QRadar AQL for Email' },
      FileName: { template: 'SELECT * FROM events WHERE ({{fieldConditions}}) LAST {{minutesBack}} MINUTES', description: 'Default QRadar AQL for FileName' },
    },
    elastic: {
      IP: { template: '{"query":{"bool":{"must":[{"range":{"@timestamp":{"gte":"now-{{minutesBack}}m"}}}],"should":[{{fieldConditions}}],"minimum_should_match":1}},"size":1000}', description: 'Default Elastic DSL for IP' },
      Hash: { template: '{"query":{"bool":{"must":[{"range":{"@timestamp":{"gte":"now-{{minutesBack}}m"}}}],"should":[{{fieldConditions}}],"minimum_should_match":1}},"size":1000}', description: 'Default Elastic DSL for Hash' },
      Domain: { template: '{"query":{"bool":{"must":[{"range":{"@timestamp":{"gte":"now-{{minutesBack}}m"}}}],"should":[{{fieldConditions}}],"minimum_should_match":1}},"size":1000}', description: 'Default Elastic DSL for Domain' },
      URL: { template: '{"query":{"bool":{"must":[{"range":{"@timestamp":{"gte":"now-{{minutesBack}}m"}}}],"should":[{{fieldConditions}}],"minimum_should_match":1}},"size":1000}', description: 'Default Elastic DSL for URL' },
      Email: { template: '{"query":{"bool":{"must":[{"range":{"@timestamp":{"gte":"now-{{minutesBack}}m"}}}],"should":[{{fieldConditions}}],"minimum_should_match":1}},"size":1000}', description: 'Default Elastic DSL for Email' },
      FileName: { template: '{"query":{"bool":{"must":[{"range":{"@timestamp":{"gte":"now-{{minutesBack}}m"}}}],"should":[{{fieldConditions}}],"minimum_should_match":1}},"size":1000}', description: 'Default Elastic DSL for FileName' },
    },
    wazuh: {
      IP: { template: 'q=data.srcip={{values}};data.dstip={{values}}', description: 'Default Wazuh API query for IP' },
      Hash: { template: 'q=data.md5={{values}};data.sha256={{values}}', description: 'Default Wazuh API query for Hash' },
      Domain: { template: 'q=data.hostname={{values}};data.url={{values}}', description: 'Default Wazuh API query for Domain' },
      URL: { template: 'q=data.url={{values}}', description: 'Default Wazuh API query for URL' },
      Email: { template: 'q=data.srcuser={{values}};data.dstuser={{values}}', description: 'Default Wazuh API query for Email' },
      FileName: { template: 'q=data.filename={{values}}', description: 'Default Wazuh API query for FileName' },
    },
    logrhythm: {
      IP: { template: '(LogRhythm uses structured JSON filters - customize fields via Field Mappings tab)', description: 'LogRhythm uses filter groups' },
      Hash: { template: '(LogRhythm uses structured JSON filters)', description: 'LogRhythm uses filter groups' },
      Domain: { template: '(LogRhythm uses structured JSON filters)', description: 'LogRhythm uses filter groups' },
      URL: { template: '(LogRhythm uses structured JSON filters)', description: 'LogRhythm uses filter groups' },
      Email: { template: '(LogRhythm uses structured JSON filters)', description: 'LogRhythm uses filter groups' },
      FileName: { template: '(LogRhythm uses structured JSON filters)', description: 'LogRhythm uses filter groups' },
    },
    manageengine: {
      IP: { template: 'SRCIP={{values}} OR DSTIP={{values}}', description: 'Default ManageEngine IP query' },
      Hash: { template: 'HASH={{values}}', description: 'Default ManageEngine Hash query' },
      Domain: { template: 'DOMAIN={{values}} OR HOST={{values}}', description: 'Default ManageEngine Domain query' },
      URL: { template: 'URL={{values}}', description: 'Default ManageEngine URL query' },
      Email: { template: 'SENDER={{values}} OR RECIPIENT={{values}}', description: 'Default ManageEngine Email query' },
      FileName: { template: 'FILENAME={{values}}', description: 'Default ManageEngine FileName query' },
    },
  };
  return templates[siemType] || {};
}

module.exports = router;
