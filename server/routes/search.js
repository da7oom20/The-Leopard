const express = require('express');
const multer = require('multer');
const pdf = require('pdf-parse');
const XLSX = require('xlsx');
const tmp = require('tmp');
const fs = require('fs');
const { Op } = require('sequelize');
const router = express.Router();

const ApiKey = require('../models/ApiKey');
const TISource = require('../models/TISource');
const MsgSource = require('../models/MsgSource');
const Result = require('../models/Result');
const FieldMapping = require('../models/FieldMapping');
const QueryTemplate = require('../models/QueryTemplate');
const AppSetting = require('../models/AppSetting');
const { searchLimiter, optionalSearchAuth, acquireSearchSlot, releaseSearchSlot, getRequireSearchAuth } = require('../middleware');
const { getSiemAdapter } = require('../siem-adapters');
const { getTiAdapter, getPlatformInfo } = require('../ti-adapters');
const { child } = require('../utils/logger');
const log = child({ area: 'search' });

const upload = multer({
  limits: { fileSize: 50 * 1024 * 1024, files: 1 }
});

// ============ PUBLIC ENDPOINTS ============

// Get active client names for upload page dropdown
router.get('/clients', async (req, res) => {
  try {
    const keys = await ApiKey.findAll({
      where: { isActive: true },
      attributes: ['id', 'client', 'siemType'],
      group: ['id', 'client', 'siemType']
    });
    const clients = keys.map(k => ({ id: k.id, name: k.client, siemType: k.siemType }));
    res.json(clients);
  } catch (err) {
    console.error('Error fetching clients:', err);
    res.json([]);
  }
});

// List active TI sources for dropdown (public)
router.get('/ti-sources', async (req, res) => {
  try {
    const sources = await TISource.findAll({
      where: { isActive: true },
      attributes: ['id', 'name', 'platformType']
    });
    const platformInfoList = getPlatformInfo();
    const enriched = sources.map(s => {
      const info = platformInfoList.find(p => p.type === s.platformType);
      return {
        id: s.id, name: s.name, platformType: s.platformType,
        supportedTypes: info?.supportedTypes || []
      };
    });
    res.json(enriched);
  } catch (err) {
    console.error('Failed to list active TI sources:', err);
    res.status(500).json({ error: 'Failed to list TI sources' });
  }
});

// Public endpoint to check if search auth is required
router.get('/settings/search-auth', (req, res) => {
  res.json({ requireSearchAuth: getRequireSearchAuth() });
});

// ============ HUNT ============

router.post('/hunt', searchLimiter, optionalSearchAuth, async (req, res) => {
  log.info('hunt request received', {
    request: req.requestId,
    user: req.user?.username || 'anonymous',
    tiSourceId: req.body?.tiSourceId,
    iocType: req.body?.iocType,
    client: req.body?.client || 'ALL',
    minutes: req.body?.searchMinutesAgo
  });

  try {
    const { tiSourceId, iocType, client, searchMinutesAgo, feedOptions = {} } = req.body;

    if (!tiSourceId || !iocType) {
      return res.status(400).json({
        error: 'TI source and IOC type are required.',
        suggestion: 'Select a Threat Intelligence source and an IOC type (IP, Hash, Domain, URL) to begin hunting.',
        category: 'validation'
      });
    }

    let minutesBack = parseInt(searchMinutesAgo || '1440');
    if (isNaN(minutesBack) || minutesBack < 1) {
      return res.status(400).json({
        error: 'Invalid time range. minutesBack must be a positive number (1 or greater).',
        suggestion: 'Specify how many minutes back to search.',
        category: 'validation'
      });
    }
    if (minutesBack > 525600) minutesBack = 525600;

    const tiSource = await TISource.findByPk(tiSourceId);
    if (!tiSource) return res.status(404).json({ error: 'TI source not found' });
    if (!tiSource.isActive) return res.status(400).json({ error: 'TI source is inactive' });

    console.log(`Fetching ${iocType} feed from ${tiSource.name} (${tiSource.platformType})`);
    const tiAdapter = getTiAdapter(tiSource.platformType, {
      apiUrl: tiSource.apiUrl, apiKey: tiSource.apiKey, extraConfig: tiSource.extraConfig
    });

    const feedResult = await tiAdapter.fetchFeed(iocType, {
      limit: feedOptions.limit || 100,
      daysBack: feedOptions.daysBack || 1,
      confidenceMin: feedOptions.confidenceMin || 0
    });

    const iocList = feedResult.iocs || [];
    console.log(`Fetched ${iocList.length} IOCs from ${tiSource.name}`);

    if (iocList.length === 0) {
      return res.json({
        huntId: `hunt_${Date.now()}_${tiSource.platformType}`,
        iocsFetched: 0, iocList: [], siemResults: [], resultIds: [],
        summary: { totalIOCs: 0, clientsSearched: 0, hits: 0, noHits: 0 },
        message: feedResult.message || 'No IOCs returned from this TI source for the selected IOC type.'
      });
    }

    let apiKeys;
    if (!client?.trim() || client.trim() === 'ALL') {
      apiKeys = await ApiKey.findAll({ where: { isActive: true } });
    } else {
      const clientList = client.split(',').map(c => c.trim()).filter(Boolean);
      apiKeys = await ApiKey.findAll({ where: { client: clientList, isActive: true } });
    }

    if (!apiKeys.length) {
      return res.status(400).json({
        error: `No active SIEM connections found${client && client !== 'ALL' ? ` for client: ${client}` : ''}.`,
        suggestion: 'Add SIEM connections in the Admin panel.',
        category: 'validation'
      });
    }

    const huntFileName = `hunt_${Date.now()}_${tiSource.platformType}`;
    const iocValues = iocList.map(ioc => ioc.value);
    const iocGroups = {};
    iocGroups[iocType] = iocValues.map(value => ({ ioc: value, type: iocType }));

    console.log(`Searching ${apiKeys.length} SIEM clients for ${iocList.length} ${iocType} IOCs`);
    await acquireSearchSlot();
    let searchResults;
    try {
      searchResults = await logsDigging(iocGroups, huntFileName, 'hunt', minutesBack, apiKeys);
    } finally {
      releaseSearchSlot();
    }

    const createdResults = await Result.findAll({
      where: { fileName: huntFileName },
      attributes: ['id', 'client', 'filterType', 'hit', 'createdAt'],
      order: [['createdAt', 'DESC']],
      limit: 1000
    });

    const resultIds = createdResults.map(r => r.id);
    const hits = createdResults.filter(r => r.hit === 'hit').length;
    const noHits = createdResults.filter(r => r.hit === 'no hit').length;
    const errors = createdResults.filter(r => r.hit === 'error').length;

    res.json({
      huntId: huntFileName,
      iocsFetched: iocList.length,
      iocList: iocValues.slice(0, 200),
      siemResults: createdResults.map(r => ({ client: r.client, filterType: r.filterType, status: r.hit })),
      resultIds,
      summary: { totalIOCs: iocList.length, clientsSearched: apiKeys.length, hits, noHits, errors }
    });

  } catch (err) {
    log.error('hunt failed', { request: req.requestId, error: err.message, hint: 'Check SIEM connectivity and recent errors above.' });
    res.status(500).json({
      error: 'Hunt operation failed.',
      suggestion: 'Try again with different feed options, or verify the TI source and SIEM connections.',
      category: 'server'
    });
  }
});

// ============ UPLOAD/SEARCH ============

router.post('/upload', searchLimiter, optionalSearchAuth, upload.single('file'), async (req, res) => {
  log.info('upload request received', {
    request: req.requestId,
    user: req.user?.username || 'anonymous',
    file: req.file?.originalname,
    fileSize: req.file?.size,
    hasText: !!req.body?.text,
    minutes: req.body?.searchMinutesAgo,
    client: req.body?.client || 'ALL'
  });

  try {
    const { text, password, searchMinutesAgo, client } = req.body;
    let minutesBack = parseInt(searchMinutesAgo || '5');
    if (isNaN(minutesBack) || minutesBack < 1) {
      return res.status(400).json({
        error: 'Invalid time range. minutesBack must be a positive number (1 or greater).',
        category: 'validation'
      });
    }
    if (minutesBack > 525600) minutesBack = 525600;
    const username = req.user?.username || 'anonymous';

    let content = '';
    let type = 'text';

    if (req.file) {
      const buffer = req.file.buffer;
      const originalName = req.file.originalname.toLowerCase();

      if (!buffer || buffer.length === 0) {
        return res.status(400).json({ error: 'Uploaded file is empty.', category: 'validation' });
      }

      if (originalName.endsWith('.pdf')) {
        const pdfData = await pdf(buffer, password ? { password } : {});
        content = pdfData.text;
      } else if (originalName.endsWith('.xlsx')) {
        const tmpFile = tmp.fileSync({ postfix: '.xlsx' });
        try {
          fs.writeFileSync(tmpFile.name, buffer);
          const workbook = XLSX.readFile(tmpFile.name);
          content = Object.values(workbook.Sheets).map(sheet => XLSX.utils.sheet_to_csv(sheet)).join('\n');
        } finally {
          try { tmpFile.removeCallback(); } catch (e) {}
        }
      } else if (originalName.endsWith('.csv')) {
        content = buffer.toString('utf-8');
      } else if (originalName.endsWith('.txt')) {
        content = buffer.toString('utf-8');
      } else {
        return res.status(400).json({
          error: 'Unsupported file type.',
          suggestion: 'Supported: PDF, XLSX, CSV, TXT.',
          category: 'validation'
        });
      }
      type = 'file';
    } else if (text?.trim()) {
      content = text.trim();
    } else {
      return res.status(400).json({
        error: 'No file or text provided.',
        suggestion: 'Upload a file (PDF, XLSX, CSV, TXT) or paste IOC text to search.',
        category: 'validation'
      });
    }

    const uploadedFileName = req.file?.originalname || `upload-${Date.now()}.txt`;

    let apiKeys;
    if (!client?.trim() || client.trim() === 'ALL') {
      apiKeys = await ApiKey.findAll({ where: { isActive: true } });
    } else {
      const clientList = client.split(',').map(c => c.trim()).filter(Boolean);
      apiKeys = await ApiKey.findAll({ where: { client: clientList, isActive: true } });
    }

    if (!apiKeys.length) {
      return res.status(400).json({
        error: `No active SIEM connections found${client && client !== 'ALL' ? ` for client: ${client}` : ''}.`,
        suggestion: 'Add SIEM connections in the Admin panel.',
        category: 'validation'
      });
    }

    const iocGroups = await extractIOCs(content);

    if (Object.keys(iocGroups).length === 0) {
      return res.status(400).json({
        error: 'No valid IOCs detected in the provided input.',
        suggestion: 'Enter valid IOCs such as IP addresses, domains, URLs, file hashes, email addresses, or filenames.',
        category: 'validation'
      });
    }

    const searchId = req.body.searchId || `search_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
    const filterTypeCount = Object.keys(iocGroups).length;
    const onProgress = createSearchTracker(searchId, apiKeys.length, filterTypeCount);

    await acquireSearchSlot();
    let searchResults;
    try {
      searchResults = await logsDigging(iocGroups, uploadedFileName, username, minutesBack, apiKeys, onProgress);
    } finally {
      releaseSearchSlot();
      completeSearchTracker(searchId);
    }

    const createdResults = await Result.findAll({
      where: { fileName: uploadedFileName },
      attributes: ['id', 'client', 'filterType', 'hit', 'createdAt'],
      order: [['createdAt', 'DESC']],
      limit: 1000
    });

    res.json({
      searchId,
      uploadId: uploadedFileName,
      resultIds: createdResults.map(r => r.id),
      siemResults: createdResults.map(r => ({ client: r.client, filterType: r.filterType, status: r.hit })),
      fullResults: createdResults.map(r => r.toJSON()),
    });

  } catch (err) {
    log.error('upload failed', { request: req.requestId, error: err.message, hint: 'If the file is PDF/XLSX, verify it is not encrypted or corrupted.' });
    res.status(500).json({
      error: 'Search operation failed.',
      suggestion: 'Try again with fewer IOCs or a shorter search period.',
      category: 'server'
    });
  }
});

// ============ REPO ============

router.get('/repo', optionalSearchAuth, async (req, res) => {
  try {
    const limit = Math.max(1, Math.min(100, parseInt(req.query.limit || '10', 10)));
    const offset = Math.max(0, parseInt(req.query.offset || '0', 10));

    // Build WHERE clause from filters
    const where = {};
    if (req.query.client) where.client = req.query.client;
    if (req.query.filterType) where.filterType = req.query.filterType;
    if (req.query.hit) where.hit = req.query.hit;
    if (req.query.dateFrom || req.query.dateTo) {
      where.createdAt = {};
      if (req.query.dateFrom) where.createdAt[Op.gte] = new Date(req.query.dateFrom);
      if (req.query.dateTo) {
        const to = new Date(req.query.dateTo);
        to.setHours(23, 59, 59, 999);
        where.createdAt[Op.lte] = to;
      }
    }

    const rows = await Result.findAll({ where, order: [['createdAt', 'DESC']], limit, offset });

    const data = rows.map(r => {
      const j = r.toJSON();
      return {
        id: j.id, createdAt: j.createdAt, client: j.client, hit: j.hit,
        filterType: j.filterType || '', fileName: j.fileName || '',
        iocTypes: getIocTypesFromDetails(j.details)
      };
    });

    res.json({ items: data, offset, limit, hasMore: rows.length === limit });
  } catch (err) {
    console.error('Repo list failed:', err);
    res.status(500).json({ error: 'Failed to list recent searches' });
  }
});

// Distinct values for repo filters
router.get('/repo/filters', optionalSearchAuth, async (req, res) => {
  try {
    const clients = await Result.findAll({ attributes: [[require('sequelize').fn('DISTINCT', require('sequelize').col('client')), 'client']], raw: true });
    const filterTypes = await Result.findAll({ attributes: [[require('sequelize').fn('DISTINCT', require('sequelize').col('filterType')), 'filterType']], raw: true });
    res.json({
      clients: clients.map(r => r.client).filter(Boolean).sort(),
      filterTypes: filterTypes.map(r => r.filterType).filter(Boolean).sort(),
    });
  } catch (err) {
    console.error('Repo filters failed:', err);
    res.json({ clients: [], filterTypes: [] });
  }
});

// ============ EXPORT ============

const MAX_CONCURRENT_EXPORTS = 3;
let activeExportCount = 0;

Object.defineProperty(global, 'isExportRunning', {
  get: () => activeExportCount > 0,
  enumerable: true
});

// Expose for health endpoint
function getExportState() {
  return { activeExportCount };
}

router.get('/export-results', optionalSearchAuth, async (req, res) => {
  if (activeExportCount >= MAX_CONCURRENT_EXPORTS) {
    return res.status(429).json({ error: `${MAX_CONCURRENT_EXPORTS} exports are already running, please wait...` });
  }

  activeExportCount++;
  const exportSafetyTimer = setTimeout(() => {
    activeExportCount = Math.max(0, activeExportCount - 1);
    console.warn('Export safety timeout: auto-released export lock after 5 minutes');
  }, 5 * 60 * 1000);

  console.log('Export started...');
  try {
    const defangValue = (v) => {
      if (v == null) return '';
      let s = String(v);
      s = s.replace(/https:\/\//gi, 'hxxps://').replace(/http:\/\//gi, 'hxxp://');
      s = s.replace(/(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/g, '$1[.]$2[.]$3[.]$4');
      s = s.replace(/([a-zA-Z0-9-]+)\.(com|net|org|io|gov|edu|mil|info|biz|co|uk|de|ru|cn|br|au|in|jp|fr|it|nl|es|se|no|fi|dk|pl|cz|sk|hu|ro|bg|hr|si|rs|me|xyz|top|online|site|tech|app|dev|cloud)\b/gi,
        (match, name, tld) => `${name}[.]${tld}`);
      if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
      return s;
    };

    const qCSV = (v) => JSON.stringify(v == null ? '' : defangValue(v));
    const safeParse = (s) => { try { return JSON.parse(s || '{}'); } catch { return {}; } };

    const toISOifDateKey = (key, value) => {
      if (value == null) return '';
      const looksLikeDateKey = typeof key === 'string' && key.toLowerCase().includes('date');
      if (!looksLikeDateKey) return value;
      const n = typeof value === 'number' ? value : Number(value);
      if (Number.isFinite(n) && n > 0) {
        const ms = n < 1e12 ? n * 1000 : n;
        const d = new Date(ms);
        if (!isNaN(d.getTime())) return d.toISOString();
      }
      const d2 = new Date(value);
      if (!isNaN(d2.getTime())) return d2.toISOString();
      return value;
    };

    const getItemsFromRow = (row) => {
      const detailsObj = typeof row.details === 'string' ? safeParse(row.details) : (row.details || {});
      if (Array.isArray(detailsObj?.result?.Items)) return detailsObj.result.Items;
      if (Array.isArray(detailsObj?.Items)) return detailsObj.Items;
      if (Array.isArray(detailsObj?.items)) return detailsObj.items;
      try {
        const logsParsed = typeof row.logs === 'string' ? JSON.parse(row.logs) : row.logs;
        if (Array.isArray(logsParsed)) return logsParsed;
      } catch { }
      return [];
    };

    const getIocSummaryFromRow = (row) => {
      let iocs = row.iocs;
      if (!iocs) {
        const detailsObj = typeof row.details === 'string' ? safeParse(row.details) : (row.details || {});
        iocs = detailsObj?.iocs;
      }
      if (Array.isArray(iocs)) {
        const map = {};
        for (const entry of iocs) {
          if (entry == null) continue;
          if (typeof entry === 'string') { (map.misc ??= []).push(entry); continue; }
          if (typeof entry === 'object') {
            const t = String(entry.type ?? '').trim().toLowerCase() || 'misc';
            const v = String(entry.value ?? entry.ioc ?? '').trim();
            if (!v) continue;
            (map[t] ??= []).push(v);
            if (['md5', 'sha1', 'sha256'].includes(t)) (map.hash ??= []).push(v);
          }
        }
        iocs = map;
      }
      if (!iocs || typeof iocs !== 'object') return { types: '', values: '' };
      const types = [];
      const values = [];
      for (const [k, v] of Object.entries(iocs)) {
        if (Array.isArray(v) && v.length) { types.push(k.toUpperCase()); values.push(...v.map(x => String(x))); }
        else if (typeof v === 'string' && v.trim()) { types.push(k.toUpperCase()); values.push(v.trim()); }
      }
      return { types: Array.from(new Set(types)).join(', '), values: values.join(', ') };
    };

    const layout = (req.query.layout || (req.query.format === 'wide' ? 'flat' : 'block')).toLowerCase();
    const FIXED = ['client', 'Time', 'hit', 'IOC_Types', 'IOC_Values'];

    let where;
    const { resultId, ids } = req.query;
    if (resultId) {
      const idNum = Number(resultId);
      if (Number.isInteger(idNum) && idNum > 0) where = { id: idNum };
    } else if (ids) {
      const idList = String(ids).split(',').map(s => Number(s.trim())).filter(n => Number.isInteger(n) && n > 0);
      if (idList.length) where = { id: { [Op.in]: idList } };
    }

    const rows = await Result.findAll({ where, order: [['createdAt', 'DESC']], limit: 10000 });

    if (layout === 'flat') {
      const itemKeyOrder = [];
      for (const rec of rows) {
        const items = getItemsFromRow(rec.toJSON());
        for (const it of items) {
          for (const k of Object.keys(it)) {
            if (!itemKeyOrder.includes(k)) itemKeyOrder.push(k);
          }
        }
      }

      const header = [...FIXED, ...itemKeyOrder].map(qCSV).join(',');
      const lines = [header];

      for (const rec of rows) {
        const row = rec.toJSON();
        const timeISO = row.createdAt ? new Date(row.createdAt).toISOString() : '';
        const ioc = getIocSummaryFromRow(row);
        const items = getItemsFromRow(row);

        if (!items.length) {
          lines.push([row.client || '', timeISO, row.hit ?? '', ioc.types, ioc.values, ...itemKeyOrder.map(() => '')].map(qCSV).join(','));
          continue;
        }

        for (const it of items) {
          const fixedVals = [row.client || '', timeISO, row.hit ?? '', ioc.types, ioc.values];
          const itemVals = itemKeyOrder.map(k => {
            const v = it[k];
            if (v == null) return '';
            if (typeof v === 'object') return JSON.stringify(v);
            return String(toISOifDateKey(k, v));
          });
          lines.push([...fixedVals, ...itemVals].map(qCSV).join(','));
        }
      }

      res.header('Content-Type', 'text/csv');
      res.attachment('siem_results_flat.csv');
      return res.send(lines.join('\n'));
    }

    // BLOCK layout
    const out = [];
    for (const rec of rows) {
      const row = rec.toJSON();
      const timeISO = row.createdAt ? new Date(row.createdAt).toISOString() : '';
      const ioc = getIocSummaryFromRow(row);
      const items = getItemsFromRow(row);

      if (!items.length) {
        const header = [...FIXED, 'RawLogs'].map(qCSV).join(',');
        const raw = (() => { try { return JSON.stringify(JSON.parse(row.details || '{}'), null, 2); } catch { return row.details || ''; } })();
        const vals = [row.client || '', timeISO, row.hit ?? '', ioc.types, ioc.values, raw].map(qCSV).join(',');
        out.push(header, vals, '');
        continue;
      }

      for (const it of items) {
        const keys = Object.keys(it);
        const header = [...FIXED, ...keys].map(qCSV).join(',');
        const vals = [...FIXED, ...keys].map(col => {
          if (col === 'client') return qCSV(row.client || '');
          if (col === 'Time') return qCSV(timeISO);
          if (col === 'hit') return qCSV(row.hit ?? '');
          if (col === 'IOC_Types') return qCSV(ioc.types);
          if (col === 'IOC_Values') return qCSV(ioc.values);
          const v = it[col];
          if (v == null) return qCSV('');
          if (typeof v === 'object') return qCSV(JSON.stringify(v));
          return qCSV(String(toISOifDateKey(col, v)));
        }).join(',');
        out.push(header, vals, '');
      }
    }

    res.header('Content-Type', 'text/csv');
    res.attachment('siem_results_block.csv');
    res.send(out.join('\n'));
  } catch (err) {
    console.error('Failed to export results as CSV:', err.stack || err.message);
    res.status(500).json({ error: 'Failed to export CSV' });
  } finally {
    clearTimeout(exportSafetyTimer);
    activeExportCount = Math.max(0, activeExportCount - 1);
    console.log(`Export finished. Active exports: ${activeExportCount}`);
  }
});

router.get('/export-events', optionalSearchAuth, (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders?.();

  const send = () => {
    res.write(`data: ${JSON.stringify({ exporting: activeExportCount > 0, activeExports: activeExportCount })}\n\n`);
  };

  send();
  const interval = setInterval(send, 2000);

  req.on('close', () => {
    clearInterval(interval);
    res.end();
  });
});

router.get('/export-status', optionalSearchAuth, (req, res) => {
  res.json({ exporting: activeExportCount > 0, activeExports: activeExportCount });
});

router.get('/export-json', optionalSearchAuth, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit || '10000', 10), 10000);
    const data = await Result.findAll({ limit, order: [['createdAt', 'DESC']] });
    res.header('Content-Type', 'application/json');
    res.attachment('siem_results.json');
    res.send(JSON.stringify(data.map(d => d.toJSON()), null, 2));
  } catch (err) {
    console.error('Failed to export results as JSON:', err.message);
    res.status(500).json({ error: 'Failed to export JSON' });
  }
});

// ============ SEARCH PROGRESS ============

// Track active search progress: searchId -> { steps: [...], done: boolean }
const searchProgress = new Map();

// Clean up stale entries after 5 minutes
setInterval(() => {
  const cutoff = Date.now() - 5 * 60 * 1000;
  for (const [id, info] of searchProgress) {
    if (info.startedAt < cutoff) searchProgress.delete(id);
  }
}, 60 * 1000);

function createSearchTracker(searchId, totalClients, totalFilterTypes) {
  const tracker = {
    searchId,
    startedAt: Date.now(),
    totalClients,
    totalFilterTypes,
    steps: [],
    done: false,
  };
  searchProgress.set(searchId, tracker);
  return (client, filterType, status) => {
    tracker.steps.push({ client, filterType, status, ts: Date.now() });
  };
}

function completeSearchTracker(searchId) {
  const tracker = searchProgress.get(searchId);
  if (tracker) tracker.done = true;
}

router.get('/search-progress', optionalSearchAuth, (req, res) => {
  const { searchId } = req.query;
  if (!searchId) return res.status(400).json({ error: 'searchId required' });
  const tracker = searchProgress.get(searchId);
  if (!tracker) return res.json({ found: false });
  res.json({
    found: true,
    done: tracker.done,
    totalClients: tracker.totalClients,
    totalFilterTypes: tracker.totalFilterTypes,
    steps: tracker.steps,
    elapsed: Date.now() - tracker.startedAt,
  });
});

router.get('/search-events', optionalSearchAuth, (req, res) => {
  const { searchId } = req.query;
  if (!searchId) { res.status(400).end(); return; }

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders?.();

  let lastSent = 0;
  const send = () => {
    const tracker = searchProgress.get(searchId);
    if (!tracker) {
      res.write(`data: ${JSON.stringify({ found: false })}\n\n`);
      return;
    }
    const newSteps = tracker.steps.slice(lastSent);
    lastSent = tracker.steps.length;
    res.write(`data: ${JSON.stringify({
      found: true,
      done: tracker.done,
      totalClients: tracker.totalClients,
      totalFilterTypes: tracker.totalFilterTypes,
      completedSteps: tracker.steps.length,
      newSteps,
      elapsed: Date.now() - tracker.startedAt,
    })}\n\n`);
  };

  send();
  const interval = setInterval(send, 1000);
  req.on('close', () => { clearInterval(interval); res.end(); });
});

// ============ HELPER FUNCTIONS ============

function safeParseJSON(s) {
  try { return JSON.parse(s); } catch { return {}; }
}

function getIocTypesFromDetails(details) {
  const obj = typeof details === 'string' ? safeParseJSON(details) : (details || {});
  const iocs = obj?.iocs;
  if (!iocs || typeof iocs !== 'object') return '';
  const types = [];
  for (const [k, v] of Object.entries(iocs)) {
    if ((Array.isArray(v) && v.length) || (typeof v === 'string' && v.trim())) {
      types.push(k.toUpperCase());
    }
  }
  return Array.from(new Set(types)).join(', ');
}

function normalizeFilterType(rawType) {
  const map = {
    IP: 'IP', Hash: 'Hash', SHA1: 'Hash', SHA256: 'Hash', MD5: 'Hash',
    Domain: 'Domain', URL: 'URL', Email: 'Email', Filename: 'FileName'
  };
  return map[rawType] || null;
}

function deobfuscateIOC(ioc) {
  return ioc
    .replace(/\[\.]/g, '.')
    .replace(/\(dot\)/gi, '.')
    .replace(/\[\/]/g, '/')
    .replace(/\[:]/g, ':')
    .replace(/\[at]/gi, '@')
    .replace(/\(at\)/gi, '@')
    .replace(/\bhxxp(s)?:\/\//gi, 'http$1://');
}

async function extractIOCs(text) {
  console.log("accessing extractIOCs");
  text = deobfuscateIOC(text);
  const iocs = [];
  const md5Regex = /\b[a-fA-F0-9]{32}\b/g;
  const sha1Regex = /\b[a-fA-F0-9]{40}\b/g;
  const sha256Regex = /\b[a-fA-F0-9]{64}\b/g;
  const urlRegex = /\b(?:hxxps?|https?):\/\/(?:[^\s"'<>[\]]+\.)+[^\s"'<>[\].]+\b/g;
  const ipRegex = /(?:(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.|\[\.\])){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/g;
  const emailRegex = /\b[A-Za-z0-9._%+-]+(?:@|\[at\]|\(at\))(?:[A-Za-z0-9-]+(?:\[\.\]|\(dot\)|\.)){1,}[A-Za-z]{2,}\b/gi;
  const domainRegex = /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\[\.\]|\(dot\)|\.)){1,}(?:[a-zA-Z]{2,63})\b/g;
  const filenameRegex = /\b[A-Za-z0-9][\w \t\-()]*\.(?:exe|dll|scr|bat|cmd|vbs|vbe|js|jse|wsf|wsh|ps1|psm1|psd1|msi|msp|jar|pif|cpl|sys|lnk|reg|sct|doc|docx|docm|dotm|dot|xls|xlsx|xlsm|xltm|ppt|pptx|pptm|rtf|pdf|htm|html|php|asp|aspx|jsp|psd|iso|img|bin|apk|ipa|7z|zip|rar|gz|tar|bz2)\b/gi;

  const seenHashValues = new Set();

  function addMatches(regex, type, LogRhythmType, LogRhythmListType, skipSeen) {
    const matches = text.match(regex);
    if (matches) {
      matches.forEach((m) => {
        if (skipSeen && seenHashValues.has(m)) return;
        iocs.push({ ioc: m, type, LogRhythmType, LogRhythmListType });
        if (skipSeen !== undefined) seenHashValues.add(m);
      });
    }
  }

  addMatches(sha256Regex, 'SHA256', ['Hash'], 'GeneralValue', false);
  addMatches(sha1Regex, 'SHA1', ['Hash'], 'GeneralValue', true);
  addMatches(md5Regex, 'MD5', ['Hash'], 'GeneralValue', true);
  addMatches(urlRegex, 'URL', ['URL', 'DomainImpacted', 'HostName', 'DomainOrigin'], 'GeneralValue');
  addMatches(ipRegex, 'IP', 'None', 'IP');
  addMatches(domainRegex, 'Domain', ['DomainImpacted', 'HostName', 'DomainOrigin', 'URL'], 'GeneralValue');
  addMatches(filenameRegex, 'Filename', ['ThreatName', 'ParentProcessName', 'ObjectName', 'Process', 'Object'], 'GeneralValue');
  addMatches(emailRegex, 'Email', ['User'], 'GeneralValue');

  const unique = [];
  const seen = new Set();
  for (const item of iocs) {
    const key = item.ioc + '|' + item.type + '|' + item.LogRhythmType + '|' + item.LogRhythmListType;
    if (!seen.has(key)) { unique.push(item); seen.add(key); }
  }

  const aggregated = unique.reduce((acc, { ioc, type, LogRhythmType, LogRhythmListType }) => {
    if (!acc[type]) acc[type] = [];
    acc[type].push({ ioc, type, LogRhythmType, LogRhythmListType });
    return acc;
  }, {});

  return aggregated;
}

async function logsDigging(iocGroups, fileName, email, minutesBack, apiKeys, onProgress) {
  const huntStart = Date.now();
  const results = [];

  const normalizedGroups = {};
  for (const [originalType, group] of Object.entries(iocGroups)) {
    const normalized = normalizeFilterType(originalType);
    if (!normalized) continue;
    if (!normalizedGroups[normalized]) normalizedGroups[normalized] = [];
    normalizedGroups[normalized].push(...group);
  }

  const typeSummary = Object.entries(normalizedGroups).map(([t, g]) => `${t}:${g.length}`).join(',');
  log.info('hunt dispatch', {
    fileName,
    user: email,
    minutes: minutesBack,
    clients: apiKeys.map(k => k.client).join(','),
    iocs: typeSummary
  });

  const clientTasks = apiKeys.map(async (apiKeyObj) => {
    const siemType = (apiKeyObj.siemType || 'logrhythm').toLowerCase();
    if (apiKeyObj.isActive === false) return;

    let adapter;
    try {
      adapter = getSiemAdapter(siemType, { ...apiKeyObj.dataValues || apiKeyObj, client: apiKeyObj.client });
    } catch (err) {
      log.error('adapter construction failed', {
        client: apiKeyObj.client,
        siemType,
        error: err.message,
        hint: 'Check the SIEM connection config in Admin → SIEM Clients.'
      });
      return;
    }

    for (const filterType of Object.keys(normalizedGroups)) {
      const group = normalizedGroups[filterType];
      const iocs = group.map(({ ioc }) => deobfuscateIOC(ioc));
      const startTime = Date.now();

      try {
        const logSourceRows = await MsgSource.findAll({
          where: { client: apiKeyObj.client, siemType, filterType }
        });
        const logSources = logSourceRows.map(r => ({
          id: r.listId,
          listId: r.listId,
          guid: r.guid,
          name: r.name,
          listType: r.listType
        }));
        if (logSources.length === 0) {
          log.warn('no log-source mapping — scanning all sources', {
            client: apiKeyObj.client,
            siemType,
            filterType,
            hint: 'Admin → Field Mappings → Log Source Mapping to narrow the search.'
          });
        }
        // LR adapter still accepts the legacy single-id option
        const logSourceListId = (siemType === 'logrhythm' && logSources[0]?.listId) || null;

        let customFields = null;
        try {
          const mapping = await FieldMapping.findOne({ where: { client: apiKeyObj.client, siemType, filterType, isApproved: true } });
          if (mapping?.fields?.length) {
            customFields = mapping.fields;
            console.log(`[RECON] Using custom fields for ${apiKeyObj.client} | ${filterType}: ${customFields.join(', ')}`);
          }
        } catch (e) {}

        let customQueryTemplate = null;
        try {
          const qt = await QueryTemplate.findOne({ where: { client: apiKeyObj.client, siemType, filterType, isActive: true } });
          if (qt?.template) {
            customQueryTemplate = qt.template;
            console.log(`[TEMPLATE] Using custom query template for ${apiKeyObj.client} | ${filterType}`);
          }
        } catch (e) {}

        log.info('SIEM search executing', {
          client: apiKeyObj.client,
          siemType,
          filterType,
          iocCount: iocs.length,
          minutes: minutesBack,
          logSources: logSources.length
        });

        const query = adapter.buildQuery(filterType, iocs, { minutesBack, logSourceListId, logSources, customFields, customQueryTemplate });
        const searchResult = await adapter.executeSearch(query);

        let finalResults = [];
        if (searchResult.taskId && !searchResult.complete) {
          const pollingInterval = adapter.getPollingInterval(minutesBack);
          const maxAttempts = adapter.getRetryLimit(minutesBack);
          log.debug('polling for async results', {
            client: apiKeyObj.client,
            siemType,
            filterType,
            taskId: searchResult.taskId,
            intervalMs: pollingInterval,
            maxAttempts
          });
          const pollResult = await adapter.pollResults(searchResult.taskId, { pollingInterval, maxAttempts });
          if (pollResult.status === 'complete') {
            finalResults = pollResult.results || [];
          } else {
            log.warn('poll did not complete', {
              client: apiKeyObj.client,
              siemType,
              filterType,
              status: pollResult.status,
              reason: pollResult.error,
              hint: pollResult.status === 'timeout' ? 'Try a smaller time window or fewer IOCs.' : undefined
            });
          }
        } else {
          finalResults = searchResult.results || [];
        }

        const searchDuration = Date.now() - startTime;
        const hasHit = finalResults.length > 0;

        log.info('SIEM search complete', {
          client: apiKeyObj.client,
          siemType,
          filterType,
          durationMs: searchDuration,
          resultCount: finalResults.length,
          hit: hasHit
        });

        const iocsByType = group.reduce((acc, it) => {
          const rawType = (it.type || '').trim().toLowerCase();
          const clean = deobfuscateIOC(it.ioc);
          if (!acc[rawType]) acc[rawType] = [];
          acc[rawType].push(clean);
          if (['md5', 'sha1', 'sha256'].includes(rawType)) {
            if (!acc.hash) acc.hash = [];
            acc.hash.push(clean);
          }
          return acc;
        }, {});

        await Result.create({
          client: apiKeyObj.client, siemType, hit: hasHit ? "hit" : "no hit", filterType, fileName, email,
          searchDuration, resultCount: finalResults.length,
          details: JSON.stringify({ result: { Items: finalResults }, iocs: iocsByType })
        });

        results.push({
          client: apiKeyObj.client, siemType, hit: hasHit ? "hit" : "no hit", filterType, fileName,
          resultCount: finalResults.length,
          details: JSON.stringify({ result: { Items: finalResults }, iocs: iocsByType })
        });

        if (onProgress) onProgress(apiKeyObj.client, filterType, hasHit ? 'hit' : 'no hit');

      } catch (err) {
        log.error('SIEM search failed', {
          client: apiKeyObj.client,
          siemType,
          filterType,
          error: err.message,
          category: err.category,
          hint: err.suggestion
        });
        await Result.create({
          client: apiKeyObj.client, siemType, hit: "error", filterType, fileName, email,
          searchDuration: Date.now() - startTime, resultCount: 0,
          details: JSON.stringify({ error: 'SIEM search failed', iocs: {} })
        });
        if (onProgress) onProgress(apiKeyObj.client, filterType, 'error');
      }
    }
  });

  await Promise.all(clientTasks);
  const hitCount = results.filter(r => r.hit === 'hit').length;
  const errorCount = results.filter(r => r.hit === 'error').length;
  log.info('hunt dispatch complete', {
    fileName,
    durationMs: Date.now() - huntStart,
    total: results.length,
    hits: hitCount,
    noHits: results.length - hitCount - errorCount,
    errors: errorCount
  });
  return results;
}

module.exports = router;
module.exports.getExportState = getExportState;
