const AuditLog = require('../models/AuditLog');

/**
 * Log an audit event. Non-blocking — errors are swallowed to avoid
 * breaking the main request flow.
 */
function audit(req, action, category, opts = {}) {
  const { targetType, targetId, details } = opts;
  AuditLog.create({
    action,
    category,
    actorId: req.user?.userId || null,
    actorUsername: req.user?.username || null,
    targetType: targetType || null,
    targetId: targetId || null,
    details: details || null,
    ip: req.ip || req.connection?.remoteAddress || null
  }).catch(err => {
    console.error('Audit log error (non-fatal):', err.message);
  });
}

module.exports = { audit };
