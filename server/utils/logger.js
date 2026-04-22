/**
 * Tiny structured logger. No external deps.
 *
 * Format:
 *   [2026-04-22T10:23:00.123Z] [INFO ] [search ] request=a1b2c3 — hunt received client=acme iocs=IP:3,Hash:2
 *
 * Levels: debug, info, warn, error. debug emits only when DEBUG_LOG=1 or NODE_ENV=development.
 * The area tag names the subsystem (boot, setup, search, hunt, siem:lr, db, export, etc.).
 *
 * meta is an optional object; keys are rendered as key=value pairs, comma-joined.
 * Strings with spaces/quotes are auto-quoted so `grep "key=value"` stays safe.
 *
 * Usage:
 *   const { log, child } = require('./utils/logger');
 *   log.info('boot', 'server listening', { port: 4000 });
 *   const l = child({ area: 'search', request: req.requestId });
 *   l.info('hunt received', { client, filterTypes: 'IP,Hash' });
 */

const LEVELS = { debug: 10, info: 20, warn: 30, error: 40 };
const MIN_LEVEL = (() => {
  const raw = (process.env.LOG_LEVEL || '').toLowerCase();
  if (LEVELS[raw]) return LEVELS[raw];
  if (process.env.DEBUG_LOG === '1' || process.env.NODE_ENV === 'development') return LEVELS.debug;
  return LEVELS.info;
})();

const LEVEL_TAG = { debug: 'DEBUG', info: 'INFO ', warn: 'WARN ', error: 'ERROR' };

function pad(s, n) {
  s = String(s);
  return s.length >= n ? s : (s + ' '.repeat(n - s.length));
}

function fmtValue(v) {
  if (v === null || v === undefined) return '-';
  if (typeof v === 'number' || typeof v === 'boolean') return String(v);
  if (v instanceof Error) return fmtValue(v.message || v.name || 'error');
  const s = typeof v === 'string' ? v : JSON.stringify(v);
  if (/[\s",=]/.test(s)) return `"${s.replace(/"/g, '\\"')}"`;
  return s;
}

function fmtMeta(meta) {
  if (!meta || typeof meta !== 'object') return '';
  const pairs = Object.entries(meta)
    .filter(([, v]) => v !== undefined)
    .map(([k, v]) => `${k}=${fmtValue(v)}`);
  return pairs.length ? ' ' + pairs.join(' ') : '';
}

function emit(level, area, message, meta, baseMeta) {
  if (LEVELS[level] < MIN_LEVEL) return;
  const ts = new Date().toISOString();
  const lvl = LEVEL_TAG[level] || level.toUpperCase();
  const a = pad((area || '-').slice(0, 10), 8);
  const merged = baseMeta ? Object.assign({}, baseMeta, meta || {}) : meta;
  const line = `[${ts}] [${lvl}] [${a}] — ${message}${fmtMeta(merged)}`;
  const out = level === 'error' ? process.stderr : process.stdout;
  out.write(line + '\n');
}

function makeLog(baseMeta) {
  const base = baseMeta || {};
  const bound = (level) => (areaOrMsg, msgOrMeta, maybeMeta) => {
    // log.info('area', 'msg', { meta })    — three args
    // log.info('area', 'msg')              — two args
    // child bound to area: .info('msg', { meta })   — two args, area comes from baseMeta
    // child bound to area: .info('msg')            — one arg
    let area, message, meta;
    if (base.area && (typeof msgOrMeta === 'undefined' || typeof msgOrMeta === 'object')) {
      // child(area).info(msg, meta?)
      area = base.area;
      message = areaOrMsg;
      meta = msgOrMeta;
    } else {
      area = areaOrMsg;
      message = msgOrMeta;
      meta = maybeMeta;
    }
    emit(level, area, message, meta, base.area ? { ...base, area: undefined } : base);
  };
  return {
    debug: bound('debug'),
    info:  bound('info'),
    warn:  bound('warn'),
    error: bound('error')
  };
}

const log = makeLog({});
const child = (baseMeta) => makeLog(baseMeta || {});

module.exports = { log, child, LEVELS };
