/**
 * Field Analyzer — SIEM-agnostic utility for IOC field discovery.
 * Flattens log objects to dot-notation, tests field values against
 * IOC regex patterns, and returns a ranked list of matching fields.
 */

const IOC_PATTERNS = {
  IP: /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/,
  Hash: [
    { name: 'MD5',    regex: /\b[a-fA-F0-9]{32}\b/ },
    { name: 'SHA1',   regex: /\b[a-fA-F0-9]{40}\b/ },
    { name: 'SHA256', regex: /\b[a-fA-F0-9]{64}\b/ }
  ],
  Domain: /\b[a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)*\.[a-zA-Z]{2,}\b/,
  URL: /https?:\/\/\S+/i,
  Email: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/,
  FileName: /[^\s\/\\]+\.\w{1,10}$/
};

// Fields to skip (timestamps, IDs, metadata that produce false positives)
const SKIP_FIELDS = new Set([
  '_time', 'timestamp', '@timestamp', '_raw', '_indextime', '_serial',
  'starttime', 'devicetime', 'endtime', 'createdAt', 'updatedAt',
  '_bkt', '_cd', '_si', 'linecount', 'splunk_server', 'splunk_server_group'
]);

/**
 * Recursively flatten a nested object to dot-notation keys.
 * { source: { ip: "1.2.3.4" } } → { "source.ip": "1.2.3.4" }
 */
function flattenObject(obj, prefix = '', result = {}) {
  if (!obj || typeof obj !== 'object') return result;

  for (const key of Object.keys(obj)) {
    const path = prefix ? `${prefix}.${key}` : key;
    const value = obj[key];

    if (value && typeof value === 'object' && !Array.isArray(value)) {
      flattenObject(value, path, result);
    } else if (Array.isArray(value)) {
      // Store each array element separately for matching
      for (const item of value) {
        if (item && typeof item === 'object') {
          flattenObject(item, path, result);
        } else if (item != null) {
          if (!result[path]) result[path] = [];
          if (Array.isArray(result[path])) {
            result[path].push(String(item));
          }
        }
      }
      // Convert array to joined string if it was simple values
      if (Array.isArray(result[path])) {
        result[path] = result[path].join(', ');
      }
    } else {
      result[path] = value;
    }
  }
  return result;
}

/**
 * Analyze an array of raw log objects for a specific IOC type.
 * Returns discovered fields sorted by match count (descending).
 *
 * @param {Object[]} logs - Array of raw log objects from SIEM
 * @param {string} iocType - One of: IP, Hash, Domain, URL, Email, FileName
 * @returns {Array<{fieldName, matchCount, totalSeen, matchPercent, sampleValues}>}
 */
function analyzeFields(logs, iocType) {
  const fieldStats = {};  // { fieldPath: { matchCount, sampleValues: Set, totalSeen } }

  const isHash = iocType === 'Hash';
  const patterns = isHash
    ? IOC_PATTERNS.Hash
    : [{ name: iocType, regex: IOC_PATTERNS[iocType] }];

  if (!patterns || (!isHash && !IOC_PATTERNS[iocType])) {
    return [];
  }

  for (const log of logs) {
    // Handle both raw objects and Elastic _source wrapper
    const entry = log._source || log;
    const flat = flattenObject(entry);

    for (const [fieldPath, rawValue] of Object.entries(flat)) {
      if (rawValue == null) continue;

      // Skip known metadata fields
      const leafField = fieldPath.split('.').pop();
      if (SKIP_FIELDS.has(leafField) || SKIP_FIELDS.has(fieldPath)) continue;

      const strValue = String(rawValue);
      if (!strValue.trim() || strValue.length < 3) continue;

      // Initialize stats
      if (!fieldStats[fieldPath]) {
        fieldStats[fieldPath] = { matchCount: 0, sampleValues: new Set(), totalSeen: 0 };
      }
      fieldStats[fieldPath].totalSeen++;

      // Test against each pattern
      for (const { regex } of patterns) {
        if (regex.test(strValue)) {
          fieldStats[fieldPath].matchCount++;
          if (fieldStats[fieldPath].sampleValues.size < 5) {
            const match = strValue.match(regex);
            if (match) fieldStats[fieldPath].sampleValues.add(match[0]);
          }
          break; // One match per field per log entry is enough
        }
      }
    }
  }

  // Convert to sorted array, only fields with matches
  return Object.entries(fieldStats)
    .filter(([_, stats]) => stats.matchCount > 0)
    .map(([fieldPath, stats]) => ({
      fieldName: fieldPath,
      matchCount: stats.matchCount,
      totalSeen: stats.totalSeen,
      matchPercent: Math.round((stats.matchCount / stats.totalSeen) * 100),
      sampleValues: Array.from(stats.sampleValues)
    }))
    .sort((a, b) => b.matchCount - a.matchCount);
}

module.exports = { analyzeFields, flattenObject, IOC_PATTERNS };
