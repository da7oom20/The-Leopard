const express = require('express');
const router = express.Router();

const ApiKey = require('../models/ApiKey');
const FieldMapping = require('../models/FieldMapping');
const { authenticateToken, requirePermission, validateIdParam } = require('../middleware');
const { getSiemAdapter } = require('../siem-adapters');
const { analyzeFields } = require('../utils/fieldAnalyzer');

// Get log sources for a SIEM client
router.get('/log-sources/:clientId', authenticateToken, requirePermission('canRecon'), async (req, res) => {
  try {
    const clientId = parseInt(req.params.clientId, 10);
    if (isNaN(clientId)) return res.status(400).json({ error: 'Invalid client ID' });
    const apiKeyObj = await ApiKey.findByPk(clientId);
    if (!apiKeyObj) return res.status(404).json({ error: 'Client not found' });

    const siemType = (apiKeyObj.siemType || 'logrhythm').toLowerCase();
    const adapter = getSiemAdapter(siemType, {
      ...apiKeyObj.dataValues,
      client: apiKeyObj.client
    });

    const sources = await adapter.getLogSources();
    res.json(sources);
  } catch (err) {
    console.error('Recon getLogSources error:', err.message);
    res.status(500).json({
      error: 'Failed to fetch log sources from this SIEM.',
      suggestion: err.suggestion || 'Check that the SIEM connection is active and the credentials have permission to list log sources.',
      category: err.category || 'connection'
    });
  }
});

// Execute field discovery (dig)
router.post('/dig', authenticateToken, requirePermission('canRecon'), async (req, res) => {
  try {
    const { clientId, logSource, iocType, depth: rawDepth } = req.body;

    if (!clientId || !logSource || !iocType || !rawDepth) {
      return res.status(400).json({ error: 'clientId, logSource, iocType, and depth are required' });
    }

    const MAX_DEPTH = 10000;
    const depth = Math.max(1, parseInt(rawDepth, 10) || 1000);
    if (depth > MAX_DEPTH) {
      return res.status(400).json({
        error: `Depth exceeds the maximum allowed value of ${MAX_DEPTH}.`,
        suggestion: `Reduce the depth to ${MAX_DEPTH} or less to avoid overloading the SIEM.`,
        category: 'validation'
      });
    }

    const apiKeyObj = await ApiKey.findByPk(clientId);
    if (!apiKeyObj) return res.status(404).json({ error: 'Client not found' });

    const siemType = (apiKeyObj.siemType || 'logrhythm').toLowerCase();
    const adapter = getSiemAdapter(siemType, {
      ...apiKeyObj.dataValues,
      client: apiKeyObj.client
    });

    console.log(`[RECON] Digging ${depth} logs from ${apiKeyObj.client} (${siemType}) for ${iocType}`);

    const query = adapter.buildReconQuery(logSource, depth);
    const searchResult = await adapter.executeSearch(query, { timeout: 120000 });

    let rawLogs = [];

    if (searchResult.taskId && !searchResult.complete) {
      const pollingInterval = adapter.getPollingInterval ? adapter.getPollingInterval(60) : 5000;
      const maxAttempts = adapter.getRetryLimit ? adapter.getRetryLimit(60) : 60;
      const pollResult = await adapter.pollResults(searchResult.taskId, { pollingInterval, maxAttempts, pageSize: depth });

      if (pollResult.status === 'complete') {
        rawLogs = pollResult.results || [];
      } else {
        console.error(`Recon search failed: ${pollResult.status}: ${pollResult.error || 'unknown'}`);
        return res.status(500).json({ error: `Search failed with status: ${pollResult.status}` });
      }
    } else {
      rawLogs = searchResult.results || [];
    }

    console.log(`[RECON] Retrieved ${rawLogs.length} raw logs, analyzing for ${iocType} fields...`);

    const discoveredFields = analyzeFields(rawLogs, iocType);

    res.json({
      totalLogs: rawLogs.length,
      iocType,
      fields: discoveredFields
    });
  } catch (err) {
    console.error('Recon dig error:', err.message);
    res.status(500).json({
      error: 'Field discovery failed.',
      suggestion: err.suggestion || 'Check the SIEM connection and try again with a smaller depth.',
      category: err.category || 'server'
    });
  }
});

// Approve discovered fields
router.post('/approve', authenticateToken, requirePermission('canRecon'), async (req, res) => {
  try {
    const { clientId, filterType, fields, logSource } = req.body;

    if (!clientId || !filterType || !fields?.length) {
      return res.status(400).json({ error: 'clientId, filterType, and fields are required' });
    }

    const apiKeyObj = await ApiKey.findByPk(clientId);
    if (!apiKeyObj) return res.status(404).json({ error: 'Client not found' });

    const [mapping, created] = await FieldMapping.findOrCreate({
      where: {
        client: apiKeyObj.client,
        siemType: apiKeyObj.siemType,
        filterType
      },
      defaults: {
        fields,
        logSource: logSource || null,
        isApproved: true
      }
    });

    if (!created) {
      const existingFields = mapping.fields || [];
      const merged = [...new Set([...existingFields, ...fields])];
      await mapping.update({ fields: merged, isApproved: true, logSource: logSource || mapping.logSource });
    }

    console.log(`[RECON] Approved ${fields.length} fields for ${apiKeyObj.client} | ${filterType}`);
    res.json({ success: true, mapping: created ? mapping : await FieldMapping.findByPk(mapping.id) });
  } catch (err) {
    console.error('Recon approve error:', err.message);
    res.status(500).json({ error: 'Failed to approve fields' });
  }
});

// Get all field mappings (admin view)
router.get('/mappings', authenticateToken, requirePermission('canManageMappings'), async (req, res) => {
  try {
    const mappings = await FieldMapping.findAll({ order: [['client', 'ASC'], ['filterType', 'ASC']] });
    res.json(mappings);
  } catch (err) {
    console.error('Recon getAllMappings error:', err.message);
    res.status(500).json({ error: 'Failed to fetch mappings' });
  }
});

// Get approved mappings for a client
router.get('/mappings/:clientId', authenticateToken, requirePermission('canManageMappings'), async (req, res) => {
  try {
    const clientId = parseInt(req.params.clientId, 10);
    if (isNaN(clientId)) return res.status(400).json({ error: 'Invalid client ID' });
    const apiKeyObj = await ApiKey.findByPk(clientId);
    if (!apiKeyObj) return res.status(404).json({ error: 'Client not found' });

    const mappings = await FieldMapping.findAll({
      where: { client: apiKeyObj.client, siemType: apiKeyObj.siemType }
    });

    res.json(mappings);
  } catch (err) {
    console.error('Recon getMappings error:', err.message);
    res.status(500).json({ error: 'Failed to fetch mappings' });
  }
});

// Delete a field mapping
router.delete('/mappings/:id', authenticateToken, requirePermission('canManageMappings'), validateIdParam, async (req, res) => {
  try {
    const mapping = await FieldMapping.findByPk(req.params.id);
    if (!mapping) return res.status(404).json({ error: 'Mapping not found' });
    await mapping.destroy();
    res.json({ success: true });
  } catch (err) {
    console.error('Recon delete mapping error:', err.message);
    res.status(500).json({ error: 'Failed to delete mapping' });
  }
});

// Update a field mapping
router.put('/mappings/:id', authenticateToken, requirePermission('canManageMappings'), validateIdParam, async (req, res) => {
  try {
    const { fields, isApproved, logSource } = req.body;
    const mapping = await FieldMapping.findByPk(req.params.id);
    if (!mapping) return res.status(404).json({ error: 'Mapping not found' });

    await mapping.update({
      fields: fields !== undefined ? fields : mapping.fields,
      isApproved: isApproved !== undefined ? isApproved : mapping.isApproved,
      logSource: logSource !== undefined ? logSource : mapping.logSource
    });

    res.json(mapping);
  } catch (err) {
    console.error('Recon update mapping error:', err.message);
    res.status(500).json({ error: 'Failed to update mapping' });
  }
});

module.exports = router;
