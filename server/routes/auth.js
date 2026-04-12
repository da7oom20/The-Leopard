const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const QRCode = require('qrcode');
const router = express.Router();

const User = require('../models/User');
const sequelize = require('../db');
const MFA = require('../utils/mfa');
const { authLimiter, authenticateToken } = require('../middleware');
const { audit } = require('../utils/audit');
const { MAX_USERNAME_LENGTH } = require('../utils/password');

// Account lockout tracking
const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_DURATION_MS = 15 * 60 * 1000; // 15 minutes
const loginAttempts = new Map(); // username -> { count, lockedUntil }

function checkLockout(username) {
  const entry = loginAttempts.get(username);
  if (!entry) return { locked: false };
  if (entry.lockedUntil && Date.now() < entry.lockedUntil) {
    const remainingMs = entry.lockedUntil - Date.now();
    const remainingMin = Math.ceil(remainingMs / 60000);
    return { locked: true, remainingMin };
  }
  if (entry.lockedUntil && Date.now() >= entry.lockedUntil) {
    loginAttempts.delete(username);
  }
  return { locked: false };
}

function recordFailedAttempt(username) {
  const entry = loginAttempts.get(username) || { count: 0, lockedUntil: null };
  entry.count += 1;
  if (entry.count >= MAX_FAILED_ATTEMPTS) {
    entry.lockedUntil = Date.now() + LOCKOUT_DURATION_MS;
  }
  loginAttempts.set(username, entry);
  return entry;
}

function clearFailedAttempts(username) {
  loginAttempts.delete(username);
}

// Build JWT payload for a user
function buildToken(user) {
  return jwt.sign({
    userId: user.id,
    username: user.username,
    role: user.role || 'analyst',
    isAdmin: user.role === 'admin',
    permissions: {
      canSearch: user.canSearch, canHunt: user.canHunt,
      canExport: user.canExport, canViewRepo: user.canViewRepo,
      canManageSIEM: user.canManageSIEM, canManageTI: user.canManageTI,
      canRecon: user.canRecon, canManageMappings: user.canManageMappings,
      canManageUsers: user.canManageUsers, canManageSecurity: user.canManageSecurity
    }
  }, process.env.JWT_SECRET, {
    algorithm: 'HS256',
    expiresIn: '8h',
  });
}

// Login
router.post('/login', authLimiter, async (req, res) => {
  try {
    const { username, password, mfaToken, backupCode } = req.body;

    if (!username || !password || typeof username !== 'string' || typeof password !== 'string') {
      return res.status(400).json({
        error: 'Username and password are required.',
        suggestion: 'Please enter both your username and password to log in.',
        category: 'validation'
      });
    }

    if (username.length > MAX_USERNAME_LENGTH || password.length > 128) {
      return res.status(400).json({
        error: 'Username or password exceeds maximum length.',
        category: 'validation'
      });
    }

    // Check account lockout
    const lockout = checkLockout(username);
    if (lockout.locked) {
      return res.status(429).json({
        error: `Account temporarily locked due to too many failed attempts. Try again in ${lockout.remainingMin} minute${lockout.remainingMin === 1 ? '' : 's'}.`,
        suggestion: 'If you forgot your password, contact your administrator.',
        category: 'auth'
      });
    }

    const user = await User.findOne({ where: { username } });
    if (!user) {
      recordFailedAttempt(username);
      return res.status(401).json({
        error: 'Invalid username or password. Please check your credentials and try again.',
        category: 'auth'
      });
    }

    if (user.isActive === false) {
      return res.status(401).json({
        error: 'Your account is disabled.',
        suggestion: 'Contact your administrator to re-enable your account.',
        category: 'auth'
      });
    }

    const match = await bcrypt.compare(password, user.passwordHash);
    if (!match) {
      const entry = recordFailedAttempt(username);
      const remaining = MAX_FAILED_ATTEMPTS - entry.count;
      const extra = remaining > 0 ? ` ${remaining} attempt${remaining === 1 ? '' : 's'} remaining before lockout.` : '';
      return res.status(401).json({
        error: `Invalid username or password. Please check your credentials and try again.${extra}`,
        category: 'auth'
      });
    }

    // Check if MFA is enabled
    if (user.mfaEnabled && user.mfaSecret) {
      if (!mfaToken && !backupCode) {
        return res.status(200).json({
          mfaRequired: true,
          message: 'MFA verification required',
          username: user.username
        });
      }

      if (mfaToken) {
        if (typeof mfaToken !== 'string') {
          return res.status(400).json({ error: 'MFA token must be a string' });
        }
        const isValid = MFA.verifyTOTP(user.mfaSecret, mfaToken);
        if (!isValid) {
          recordFailedAttempt(username);
          return res.status(401).json({
            error: 'Invalid MFA code. Please try again.',
            suggestion: 'Make sure your authenticator app time is synchronized. The code refreshes every 30 seconds.',
            category: 'auth'
          });
        }
      } else if (backupCode) {
        if (typeof backupCode !== 'string') {
          return res.status(400).json({ error: 'Backup code must be a string', category: 'validation' });
        }
        const backupResult = await sequelize.transaction(async (t) => {
          const freshUser = await User.findByPk(user.id, { transaction: t, lock: t.LOCK.UPDATE });
          const codes = freshUser.mfaBackupCodes || [];
          const idx = codes.indexOf(backupCode.toUpperCase());
          if (idx === -1) return { valid: false };
          codes.splice(idx, 1);
          await freshUser.update({ mfaBackupCodes: codes }, { transaction: t });
          return { valid: true };
        });
        if (!backupResult.valid) {
          recordFailedAttempt(username);
          return res.status(401).json({
            error: 'Invalid backup code.',
            suggestion: 'Backup codes are single-use. If you have used all your codes, contact an administrator to reset your MFA.',
            category: 'auth'
          });
        }
      }
    }

    clearFailedAttempts(username);

    const token = buildToken(user);
    audit(req, 'auth.login', 'auth', { targetType: 'user', targetId: user.id, details: { username: user.username } });
    res.json({ token });
  } catch (err) {
    console.error('Login error:', err.message);
    res.status(500).json({
      error: 'An unexpected error occurred during login. Please try again.',
      suggestion: 'If this problem persists, contact your administrator.',
      category: 'server'
    });
  }
});

// Refresh token — returns a fresh JWT if the current one is still valid
router.post('/refresh', authenticateToken, async (req, res) => {
  try {
    const user = await User.findByPk(req.user.userId);
    if (!user || !user.isActive) {
      return res.status(403).json({ error: 'Account is disabled or no longer exists' });
    }
    const token = buildToken(user);
    res.json({ token });
  } catch (err) {
    console.error('Token refresh error:', err.message);
    res.status(500).json({ error: 'Failed to refresh token' });
  }
});

// Logout — invalidate all tokens for the current user
router.post('/logout', authenticateToken, async (req, res) => {
  try {
    const user = await User.findByPk(req.user.userId);
    if (!user) return res.status(404).json({ error: 'User not found' });
    await user.update({ tokenIssuedAfter: new Date() });
    res.json({ message: 'Logged out successfully. All sessions have been invalidated.' });
  } catch (err) {
    console.error('Logout error:', err.message);
    res.status(500).json({ error: 'Failed to logout' });
  }
});

// Change own password
router.post('/change-password', authenticateToken, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword || typeof currentPassword !== 'string' || typeof newPassword !== 'string') {
      return res.status(400).json({ error: 'Current password and new password are required.', category: 'validation' });
    }

    const { validatePassword } = require('../utils/password');
    const validation = validatePassword(newPassword);
    if (!validation.valid) {
      return res.status(400).json({ error: validation.errors.join(' '), category: 'validation' });
    }

    const user = await User.findByPk(req.user.userId);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const match = await bcrypt.compare(currentPassword, user.passwordHash);
    if (!match) {
      return res.status(401).json({ error: 'Current password is incorrect.', category: 'auth' });
    }

    const hash = await bcrypt.hash(newPassword, 10);
    await user.update({ passwordHash: hash, tokenIssuedAfter: new Date() });

    // Brief delay so the new token's iat (whole seconds) is strictly after tokenIssuedAfter
    await new Promise(r => setTimeout(r, 1100));
    const token = buildToken(user);
    audit(req, 'user.password_change', 'auth', { targetType: 'user', targetId: user.id, details: { username: user.username, selfService: true } });
    res.json({ token, message: 'Password changed successfully. All other sessions have been invalidated.' });
  } catch (err) {
    console.error('Change password error:', err.message);
    res.status(500).json({ error: 'Failed to change password.' });
  }
});

// Get MFA status for current user
router.get('/mfa/status', authenticateToken, async (req, res) => {
  try {
    const user = await User.findByPk(req.user.userId);
    if (!user) return res.status(404).json({ error: 'User not found' });

    res.json({
      mfaEnabled: user.mfaEnabled || false,
      backupCodesRemaining: (user.mfaBackupCodes || []).length
    });
  } catch (err) {
    console.error('MFA status error:', err);
    res.status(500).json({ error: 'Failed to get MFA status' });
  }
});

// Setup MFA
router.post('/mfa/setup', authenticateToken, async (req, res) => {
  try {
    const user = await User.findByPk(req.user.userId);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const secret = MFA.generateSecret();
    const backupCodes = MFA.generateBackupCodes();

    const issuer = 'The Leopard';
    const otpauthUri = `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(user.username)}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;

    const qrCodeDataUrl = await QRCode.toDataURL(otpauthUri);

    await user.update({
      mfaSecret: secret,
      mfaBackupCodes: backupCodes
    });

    res.json({
      secret,
      qrCode: qrCodeDataUrl,
      otpauthUri,
      backupCodes,
      message: 'Scan the QR code with your authenticator app, then verify with a code'
    });
  } catch (err) {
    console.error('MFA setup error:', err);
    res.status(500).json({ error: 'Failed to setup MFA' });
  }
});

// Verify and enable MFA
router.post('/mfa/verify', authenticateToken, async (req, res) => {
  try {
    const { token: mfaToken } = req.body;
    if (!mfaToken || typeof mfaToken !== 'string') return res.status(400).json({ error: 'MFA token required and must be a string' });

    const user = await User.findByPk(req.user.userId);
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (!user.mfaSecret) return res.status(400).json({ error: 'MFA not setup. Call /api/auth/mfa/setup first' });

    const isValid = MFA.verifyTOTP(user.mfaSecret, mfaToken);
    if (!isValid) {
      return res.status(401).json({ error: 'Invalid MFA code. Please try again.' });
    }

    await user.update({ mfaEnabled: true });

    res.json({
      success: true,
      message: 'MFA enabled successfully',
      backupCodes: user.mfaBackupCodes
    });
  } catch (err) {
    console.error('MFA verify error:', err);
    res.status(500).json({ error: 'Failed to verify MFA' });
  }
});

// Disable MFA
router.post('/mfa/disable', authenticateToken, async (req, res) => {
  try {
    const { password } = req.body;
    if (!password || typeof password !== 'string') return res.status(400).json({ error: 'Password required (string) to disable MFA' });

    const user = await User.findByPk(req.user.userId);
    if (!user) return res.status(404).json({ error: 'User not found' });

    if (!user.mfaEnabled) {
      return res.status(400).json({
        error: 'MFA is not currently enabled.',
        suggestion: 'MFA must be fully set up and verified before it can be disabled.',
        category: 'validation'
      });
    }

    const match = await bcrypt.compare(password, user.passwordHash);
    if (!match) return res.status(401).json({ error: 'Invalid password' });

    await user.update({
      mfaEnabled: false,
      mfaSecret: null,
      mfaBackupCodes: null
    });

    res.json({ success: true, message: 'MFA disabled successfully' });
  } catch (err) {
    console.error('MFA disable error:', err);
    res.status(500).json({ error: 'Failed to disable MFA' });
  }
});

// Regenerate backup codes
router.post('/mfa/backup-codes', authenticateToken, async (req, res) => {
  try {
    const { password } = req.body;
    if (!password || typeof password !== 'string') return res.status(400).json({ error: 'Password required and must be a string' });

    const user = await User.findByPk(req.user.userId);
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (!user.mfaEnabled) return res.status(400).json({ error: 'MFA is not enabled' });

    const match = await bcrypt.compare(password, user.passwordHash);
    if (!match) return res.status(401).json({ error: 'Invalid password' });

    const backupCodes = MFA.generateBackupCodes();
    await user.update({ mfaBackupCodes: backupCodes });

    res.json({
      success: true,
      backupCodes,
      message: 'New backup codes generated. Save them securely.'
    });
  } catch (err) {
    console.error('Backup codes error:', err);
    res.status(500).json({ error: 'Failed to generate backup codes' });
  }
});

module.exports = router;
