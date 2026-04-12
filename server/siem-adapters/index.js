/**
 * SIEM Adapter Factory
 * Routes to the correct adapter implementation based on siemType
 */

const SIEM_TYPES = {
  LOGRHYTHM: 'logrhythm',
  SPLUNK: 'splunk',
  QRADAR: 'qradar',
  MANAGEENGINE: 'manageengine',
  WAZUH: 'wazuh',
  ELASTIC: 'elastic'
};

// Lazy-load adapters to avoid circular dependencies
const adapters = {
  [SIEM_TYPES.LOGRHYTHM]: () => require('./logrhythm.adapter'),
  [SIEM_TYPES.SPLUNK]: () => require('./splunk.adapter'),
  [SIEM_TYPES.QRADAR]: () => require('./qradar.adapter'),
  [SIEM_TYPES.MANAGEENGINE]: () => require('./manageengine.adapter'),
  [SIEM_TYPES.WAZUH]: () => require('./wazuh.adapter'),
  [SIEM_TYPES.ELASTIC]: () => require('./elastic.adapter')
};

/**
 * Get a SIEM adapter instance
 * @param {string} siemType - The SIEM type (logrhythm, splunk, qradar, etc.)
 * @param {Object} config - Configuration object for the adapter
 * @returns {BaseSiemAdapter} - Instance of the appropriate adapter
 * @throws {Error} - If siemType is unknown
 */
function getSiemAdapter(siemType, config) {
  const normalizedType = (siemType || '').toLowerCase().trim();

  if (!adapters[normalizedType]) {
    throw new Error(`Unknown SIEM type: "${siemType}". Supported types: ${Object.values(SIEM_TYPES).join(', ')}`);
  }

  const AdapterClass = adapters[normalizedType]();
  return new AdapterClass(config);
}

/**
 * Get configuration schema for a SIEM type
 * @param {string} siemType - The SIEM type
 * @returns {Array<ConfigField>} - Configuration field definitions
 */
function getConfigSchema(siemType) {
  const normalizedType = (siemType || '').toLowerCase().trim();

  if (!adapters[normalizedType]) {
    throw new Error(`Unknown SIEM type: "${siemType}"`);
  }

  const AdapterClass = adapters[normalizedType]();
  return AdapterClass.getConfigSchema();
}

/**
 * Validate configuration for a SIEM type
 * @param {string} siemType - The SIEM type
 * @param {Object} config - Configuration to validate
 * @returns {{valid: boolean, errors: string[]}}
 */
function validateConfig(siemType, config) {
  const normalizedType = (siemType || '').toLowerCase().trim();

  if (!adapters[normalizedType]) {
    return {
      valid: false,
      errors: [`Unknown SIEM type: "${siemType}"`]
    };
  }

  const AdapterClass = adapters[normalizedType]();
  return AdapterClass.validateConfig(config);
}

/**
 * Get list of supported SIEM types
 * @returns {string[]}
 */
function getSupportedTypes() {
  return Object.values(SIEM_TYPES);
}

/**
 * Check if a SIEM type is supported
 * @param {string} siemType - The SIEM type to check
 * @returns {boolean}
 */
function isSupported(siemType) {
  const normalizedType = (siemType || '').toLowerCase().trim();
  return !!adapters[normalizedType];
}

/**
 * Get display name for a SIEM type
 * @param {string} siemType - The SIEM type
 * @returns {string}
 */
function getDisplayName(siemType) {
  const displayNames = {
    [SIEM_TYPES.LOGRHYTHM]: 'LogRhythm',
    [SIEM_TYPES.SPLUNK]: 'Splunk',
    [SIEM_TYPES.QRADAR]: 'IBM QRadar',
    [SIEM_TYPES.MANAGEENGINE]: 'ManageEngine EventLog Analyzer',
    [SIEM_TYPES.WAZUH]: 'Wazuh',
    [SIEM_TYPES.ELASTIC]: 'Elastic / ELK'
  };

  const normalizedType = (siemType || '').toLowerCase().trim();
  return displayNames[normalizedType] || siemType;
}

/**
 * Get default field mappings and query info for all SIEM types
 */
function getAllDefaultConfigs() {
  const configs = {};
  for (const siemType of Object.values(SIEM_TYPES)) {
    try {
      // Pass dummy apiHost so base constructor doesn't throw
      const adapter = new (adapters[siemType]())({ apiHost: 'https://dummy' });
      configs[siemType] = {
        label: getDisplayName(siemType),
        fieldMappings: adapter.fieldMappings || {},
        queryLanguage: getQueryLanguage(siemType),
        queryExamples: getQueryExamples(siemType)
      };
    } catch (e) { /* skip if adapter fails to instantiate */ }
  }
  return configs;
}

function getQueryLanguage(siemType) {
  const langs = {
    splunk: 'SPL',
    qradar: 'AQL',
    elastic: 'Elasticsearch DSL',
    wazuh: 'Wazuh Query / OpenSearch DSL',
    logrhythm: 'LogRhythm Structured JSON',
    manageengine: 'ManageEngine Query'
  };
  return langs[siemType] || 'Unknown';
}

function getQueryExamples(siemType) {
  const allExamples = {
    splunk: {
      IP: 'search index=* (src_ip IN ("{{values}}") OR dest_ip IN ("{{values}}") OR src IN ("{{values}}") OR dst IN ("{{values}}")) | head 1000',
      Hash: 'search index=* (file_hash IN ("{{values}}") OR md5 IN ("{{values}}") OR sha256 IN ("{{values}}")) | head 1000',
      Domain: 'search index=* (url IN ("{{values}}") OR dest_host IN ("{{values}}") OR domain IN ("{{values}}")) | head 1000',
      URL: 'search index=* (url IN ("{{values}}") OR uri IN ("{{values}}") OR http_url IN ("{{values}}")) | head 1000',
      Email: 'search index=* (sender IN ("{{values}}") OR recipient IN ("{{values}}") OR src_user IN ("{{values}}")) | head 1000',
      FileName: 'search index=* (file_name IN ("{{values}}") OR process_name IN ("{{values}}") OR Image IN ("{{values}}")) | head 1000'
    },
    qradar: {
      IP: "SELECT * FROM events WHERE (sourceip='{{value}}' OR destinationip='{{value}}') LAST {{minutesBack}} MINUTES",
      Hash: "SELECT * FROM events WHERE (LOWER(\"Filename Hash\") LIKE '%{{value}}%' OR LOWER(\"SHA256 Hash\") LIKE '%{{value}}%') LAST {{minutesBack}} MINUTES",
      Domain: "SELECT * FROM events WHERE (LOWER(\"DNS Request Domain\") LIKE '%{{value}}%' OR LOWER(\"URL Host\") LIKE '%{{value}}%') LAST {{minutesBack}} MINUTES",
      URL: "SELECT * FROM events WHERE (LOWER(\"URL\") LIKE '%{{value}}%' OR LOWER(\"URL Path\") LIKE '%{{value}}%') LAST {{minutesBack}} MINUTES",
      Email: "SELECT * FROM events WHERE (LOWER(username) LIKE '%{{value}}%') LAST {{minutesBack}} MINUTES",
      FileName: "SELECT * FROM events WHERE (LOWER(\"Filename\") LIKE '%{{value}}%' OR LOWER(\"Process Path\") LIKE '%{{value}}%') LAST {{minutesBack}} MINUTES"
    },
    elastic: {
      IP: '{"terms":{"source.ip":["{{values}}"]}} OR {"terms":{"destination.ip":["{{values}}"]}}',
      Hash: '{"terms":{"file.hash.md5":["{{values}}"]}} OR {"terms":{"file.hash.sha256":["{{values}}"]}}',
      Domain: '{"wildcard":{"dns.question.name":"*{{value}}*"}} OR {"wildcard":{"url.domain":"*{{value}}*"}}',
      URL: '{"wildcard":{"url.full":"*{{value}}*"}} OR {"wildcard":{"url.original":"*{{value}}*"}}',
      Email: '{"wildcard":{"user.email":"*{{value}}*"}} OR {"wildcard":{"source.user.email":"*{{value}}*"}}',
      FileName: '{"wildcard":{"file.name":"*{{value}}*"}} OR {"wildcard":{"process.name":"*{{value}}*"}}'
    },
    wazuh: {
      IP: '"{{value}}" — matches against data.srcip, data.dstip, agent.ip',
      Hash: '"{{value}}" — matches against syscheck.md5_after, syscheck.sha256_after',
      Domain: '"{{value}}" — matches against data.dns.question.name, data.url',
      URL: '"{{value}}" — matches against data.url, data.http.url',
      Email: '"{{value}}" — matches against data.srcuser, data.dstuser',
      FileName: '"{{value}}" — matches against syscheck.path, data.file, data.process.name'
    },
    logrhythm: {
      IP: 'filterType: IP (17), Direction: External/Outbound, valueType: IPAddress',
      Hash: 'filterType: Hash (138), matchType: Value, valueType: String',
      Domain: 'filterType: Domain (39) + DomainOrigin (137) + HostName + URL, matchType: Value',
      URL: 'filterType: URL (42) + Domain (39) + DomainOrigin (137), matchType: Value',
      Email: 'filterType: Sender (31) + Recipient (32), matchType: Value',
      FileName: 'filterType: ParentProcessName (146) + Process (41) + Object (34) + ObjectName (113), matchType: Value'
    },
    manageengine: {
      IP: '(SOURCE = "{{value}}" OR DESTINATION = "{{value}}" OR REMOTE_HOST_IP = "{{value}}")',
      Hash: '(FILE_HASH = "{{value}}" OR MD5_HASH = "{{value}}" OR SHA256_HASH = "{{value}}")',
      Domain: '(DOMAIN = "{{value}}" OR URL = "{{value}}" OR DNS_DOMAIN = "{{value}}")',
      URL: '(URL = "{{value}}" OR HTTP_URL = "{{value}}")',
      Email: '(USER = "{{value}}" OR CALLER_USER = "{{value}}" OR TARGET_USER = "{{value}}")',
      FileName: '(FILE_NAME = "{{value}}" OR PROCESS_NAME = "{{value}}" OR SERVICE_NAME = "{{value}}")'
    }
  };
  return allExamples[siemType] || {};
}

module.exports = {
  getSiemAdapter,
  getConfigSchema,
  validateConfig,
  getSupportedTypes,
  isSupported,
  getDisplayName,
  getAllDefaultConfigs,
  SIEM_TYPES
};
