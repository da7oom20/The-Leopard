const jwt = require('jsonwebtoken');
const User = require('./models/User');
const AppSetting = require('./models/AppSetting');

// ============ RATE LIMITING ============
const createRateLimiter = (options = {}) => {
  const {
    windowMs = 60 * 1000,
    max = 100,
    message = 'Too many requests, please try again later.'
  } = options;

  const store = new Map();

  const cleanupInterval = setInterval(() => {
    const now = Date.now();
    for (const [key, data] of store.entries()) {
      if (now - data.startTime > windowMs) {
        store.delete(key);
      }
    }
  }, windowMs);
  if (cleanupInterval.unref) cleanupInterval.unref();

  return (req, res, next) => {
    const key = req.ip || req.connection.remoteAddress;
    const now = Date.now();

    let record = store.get(key);

    if (!record || now - record.startTime > windowMs) {
      record = { count: 1, startTime: now };
      store.set(key, record);
      return next();
    }

    record.count++;

    if (record.count > max) {
      return res.status(429).json({ error: message });
    }

    next();
  };
};

const generalLimiter = createRateLimiter({ windowMs: 60000, max: 100 });
const authLimiter = createRateLimiter({ windowMs: 60000, max: 10, message: 'Too many login attempts. Please wait 60 seconds before trying again.' });
const searchLimiter = createRateLimiter({ windowMs: 60000, max: 20 });

// ============ SEARCH CONCURRENCY LIMITER ============
const MAX_CONCURRENT_SEARCHES = 10;
let activeSearchCount = 0;
const searchQueue = [];

function acquireSearchSlot() {
  return new Promise((resolve, reject) => {
    if (activeSearchCount < MAX_CONCURRENT_SEARCHES) {
      activeSearchCount++;
      resolve();
    } else {
      const timeout = setTimeout(() => {
        const idx = searchQueue.indexOf(entry);
        if (idx > -1) searchQueue.splice(idx, 1);
        reject(new Error('Search queue timeout'));
      }, 60000);
      const entry = () => {
        clearTimeout(timeout);
        resolve();
      };
      searchQueue.push(entry);
    }
  });
}

function releaseSearchSlot() {
  if (searchQueue.length > 0) {
    const next = searchQueue.shift();
    next();
  } else {
    activeSearchCount = Math.max(0, activeSearchCount - 1);
  }
}

// ============ AUTH MIDDLEWARE ============

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const queryToken = req.path.includes('export-events') ? req.query.token : null;
  const token = (authHeader && authHeader.split(' ')[1]) || queryToken;
  if (!token) return res.status(401).json({ error: 'Authentication required' });
  jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] }, async (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token' });
    try {
      const dbUser = await User.findByPk(user.userId, {
        attributes: ['id', 'isActive', 'role', 'tokenIssuedAfter', 'canSearch', 'canHunt', 'canExport', 'canViewRepo',
                     'canManageSIEM', 'canManageTI', 'canRecon', 'canManageMappings',
                     'canManageUsers', 'canManageSecurity']
      });
      if (!dbUser || dbUser.isActive === false) {
        return res.status(403).json({ error: 'Account is disabled or no longer exists' });
      }
      if (dbUser.tokenIssuedAfter && user.iat && user.iat < Math.floor(dbUser.tokenIssuedAfter.getTime() / 1000)) {
        return res.status(401).json({ error: 'Session expired due to password change. Please log in again.' });
      }
      req.user = {
        ...user,
        role: dbUser.role,
        permissions: {
          canSearch: dbUser.canSearch,
          canHunt: dbUser.canHunt,
          canExport: dbUser.canExport,
          canViewRepo: dbUser.canViewRepo,
          canManageSIEM: dbUser.canManageSIEM,
          canManageTI: dbUser.canManageTI,
          canRecon: dbUser.canRecon,
          canManageMappings: dbUser.canManageMappings,
          canManageUsers: dbUser.canManageUsers,
          canManageSecurity: dbUser.canManageSecurity
        }
      };
      next();
    } catch (dbErr) {
      console.error('Token validation DB error:', dbErr.message);
      req.user = {
        ...user,
        permissions: {}
      };
      next();
    }
  });
}

function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
}

function requirePermission(permissionName) {
  return (req, res, next) => {
    if (!req.user?.permissions?.[permissionName]) {
      return res.status(403).json({
        error: `Permission denied: ${permissionName} is required for this action.`,
        suggestion: 'Contact your administrator to update your permissions.',
        category: 'auth'
      });
    }
    next();
  };
}

function validateIdParam(req, res, next) {
  const raw = req.params.id;
  const id = parseInt(raw, 10);
  if (isNaN(id) || id < 1 || String(id) !== String(raw)) {
    return res.status(400).json({ error: 'Invalid ID parameter' });
  }
  req.params.id = id;
  next();
}

// ============ OPTIONAL SEARCH AUTH ============

let _requireSearchAuth = false;

async function loadSearchAuthSetting() {
  try {
    const row = await AppSetting.findByPk('requireSearchAuth');
    _requireSearchAuth = row ? row.value === 'true' : false;
  } catch { _requireSearchAuth = false; }
}

function setRequireSearchAuth(value) {
  _requireSearchAuth = value;
}

function getRequireSearchAuth() {
  return _requireSearchAuth;
}

function optionalSearchAuth(req, res, next) {
  if (!_requireSearchAuth) return next();
  return authenticateToken(req, res, (err) => {
    if (err) return;
    const permMap = {
      '/api/upload': 'canSearch',
      '/api/hunt': 'canHunt',
      '/api/repo': 'canViewRepo',
      '/export-results': 'canExport',
      '/api/export-json': 'canExport',
      '/api/export-events': 'canExport',
      '/api/export-status': 'canExport',
    };
    const perm = permMap[req.path];
    if (perm && !req.user?.permissions?.[perm]) {
      return res.status(403).json({
        error: `Permission denied: ${perm} is required for this action.`,
        suggestion: 'Contact your administrator to update your permissions.',
        category: 'auth'
      });
    }
    next();
  });
}

// ============ ERROR HELPERS ============

function errorResponse(res, statusCode, message, suggestion = null, category = null) {
  const response = { error: message };
  if (suggestion) response.suggestion = suggestion;
  if (category) response.category = category;
  return res.status(statusCode).json(response);
}

function classifySiemError(err, siemType, host) {
  const displayType = (siemType || 'SIEM').charAt(0).toUpperCase() + (siemType || 'siem').slice(1);
  const safeHost = host ? host.replace(/\/+$/, '') : 'the configured host';
  const code = err.code || '';
  const status = err.response?.status || err.status;
  const msg = err.message || '';

  if (code === 'ECONNREFUSED') {
    return {
      message: `Cannot connect to ${displayType} at ${safeHost}. The service may be down or the URL may be incorrect.`,
      suggestion: `Verify that ${displayType} is running and accessible from this server. Check the SIEM URL and port.`,
      category: 'connection'
    };
  }
  if (code === 'ETIMEDOUT' || code === 'ECONNABORTED' || code === 'ESOCKETTIMEDOUT') {
    return {
      message: `Connection timed out to ${displayType} at ${safeHost}.`,
      suggestion: `The service may be overloaded or unreachable. Check network connectivity and try again.`,
      category: 'timeout'
    };
  }
  if (code === 'ENOTFOUND' || code === 'EAI_AGAIN') {
    return {
      message: `Cannot resolve hostname for ${displayType}. The URL "${safeHost}" could not be found.`,
      suggestion: `Check that the SIEM URL is correct and that DNS is working properly.`,
      category: 'connection'
    };
  }
  if (code === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' || code === 'DEPTH_ZERO_SELF_SIGNED_CERT' ||
      code === 'SELF_SIGNED_CERT_IN_CHAIN' || code === 'ERR_TLS_CERT_ALTNAME_INVALID' ||
      msg.includes('certificate') || msg.includes('SSL') || msg.includes('self signed')) {
    return {
      message: `SSL certificate error connecting to ${displayType} at ${safeHost}.`,
      suggestion: `Enable 'Skip SSL Verification' in the SIEM configuration, or install a valid SSL certificate.`,
      category: 'connection'
    };
  }
  if (status === 401 || status === 403) {
    return {
      message: `Authentication failed for ${displayType} at ${safeHost}.`,
      suggestion: `Check your API token, username, or password. The credentials may be expired or incorrect.`,
      category: 'auth'
    };
  }
  if (status === 404) {
    return {
      message: `${displayType} API endpoint not found at ${safeHost}.`,
      suggestion: `Verify the SIEM URL is correct and includes the proper base path. The API version may have changed.`,
      category: 'notfound'
    };
  }
  if (status === 429) {
    return {
      message: `Too many requests to ${displayType}. The SIEM is rate-limiting connections.`,
      suggestion: `Wait a moment before trying again, or reduce the number of concurrent searches.`,
      category: 'timeout'
    };
  }
  if (status >= 500) {
    return {
      message: `${displayType} returned a server error (HTTP ${status}).`,
      suggestion: `The SIEM service may be experiencing issues. Check ${displayType} server health and logs.`,
      category: 'server'
    };
  }

  const safeMsg = msg
    .replace(/at\s+\S+\s*\(.*\)/g, '')
    .replace(/\/[^\s:]+/g, '[path]')
    .replace(/password[=:]\S+/gi, 'password=[hidden]')
    .substring(0, 200);

  return {
    message: `${displayType} error: ${safeMsg || 'An unexpected error occurred.'}`,
    suggestion: `Check the SIEM connection settings and try again. If the problem persists, review the server logs.`,
    category: 'server'
  };
}

module.exports = {
  createRateLimiter,
  generalLimiter,
  authLimiter,
  searchLimiter,
  acquireSearchSlot,
  releaseSearchSlot,
  getSearchConcurrencyState: () => ({ activeSearchCount, searchQueue }),
  authenticateToken,
  requireAdmin,
  requirePermission,
  validateIdParam,
  optionalSearchAuth,
  loadSearchAuthSetting,
  setRequireSearchAuth,
  getRequireSearchAuth,
  errorResponse,
  classifySiemError
};
