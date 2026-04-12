/**
 * TI Adapter Factory
 * Routes to the correct adapter implementation based on platformType.
 * Supports API-based platforms (individual adapters) and
 * direct-download feeds (generic feedlist adapter).
 *
 * 14 Providers / 18 Platform Types:
 * - 3 API-based: OTX, MISP, PhishTank
 * - 15 Feed-based: ThreatFox, URLhaus, MalwareBazaar, Feodo Tracker, SSLBL,
 *   OpenPhish, Blocklist.de, Emerging Threats, Spamhaus DROP, FireHOL,
 *   Cisco Talos, CrowdSec, C2 Intel Feeds, Bambenek C2, DigitalSide
 */

const FeedListAdapter = require('./feedlist.adapter');

// =============================================
// Platform type constants
// =============================================
const TI_PLATFORMS = {
  // --- API-based platforms ---
  OTX: 'otx',
  MISP: 'misp',
  PHISHTANK: 'phishtank',

  // --- Direct-download feed platforms ---
  // abuse.ch ecosystem
  THREATFOX: 'threatfox',
  URLHAUS: 'urlhaus',
  MALWAREBAZAAR: 'malwarebazaar',
  FEODOTRACKER: 'feodotracker',
  SSLBL: 'sslbl',
  // Phishing
  OPENPHISH: 'openphish',
  // IP Blocklists
  BLOCKLIST_DE: 'blocklist_de',
  EMERGINGTHREATS: 'emergingthreats',
  SPAMHAUS_DROP: 'spamhaus_drop',
  FIREHOL_L1: 'firehol_l1',
  TALOS: 'talos',
  CROWDSEC: 'crowdsec',
  // C2 & Malware
  C2INTELFEEDS: 'c2intelfeeds',
  BAMBENEK_C2: 'bambenek_c2',
  DIGITALSIDE: 'digitalside'
};

// =============================================
// Default API URLs for API-based platforms
// =============================================
const DEFAULT_URLS = {
  [TI_PLATFORMS.OTX]: 'https://otx.alienvault.com',
  [TI_PLATFORMS.MISP]: null,
  [TI_PLATFORMS.PHISHTANK]: 'https://data.phishtank.com'
};

// =============================================
// Lazy-load API-based adapters
// =============================================
const apiAdapters = {
  [TI_PLATFORMS.OTX]: () => require('./otx.adapter'),
  [TI_PLATFORMS.MISP]: () => require('./misp.adapter'),
  [TI_PLATFORMS.PHISHTANK]: () => require('./phishtank.adapter')
};

/**
 * Get a TI adapter instance
 * @param {string} platformType
 * @param {Object} config
 * @returns {BaseTiAdapter}
 */
function getTiAdapter(platformType, config) {
  const normalizedType = (platformType || '').toLowerCase().trim();

  // Check API-based adapters first
  if (apiAdapters[normalizedType]) {
    const finalConfig = {
      ...config,
      apiUrl: config.apiUrl || DEFAULT_URLS[normalizedType] || ''
    };
    const AdapterClass = apiAdapters[normalizedType]();
    return new AdapterClass(finalConfig);
  }

  // Check feed-based adapters
  if (FeedListAdapter.isFeedType(normalizedType)) {
    return new FeedListAdapter({
      ...config,
      platformType: normalizedType
    });
  }

  const allTypes = [...Object.keys(apiAdapters), ...FeedListAdapter.getAllFeedTypes()];
  throw new Error(`Unknown TI platform: "${platformType}". Supported: ${allTypes.join(', ')}`);
}

/**
 * Get list of all supported TI platform types
 * @returns {string[]}
 */
function getSupportedPlatforms() {
  return Object.values(TI_PLATFORMS);
}

/**
 * Get display info for all platforms, grouped by category
 * @returns {Array}
 */
function getPlatformInfo() {
  return [
    // --- API-based platforms ---
    { type: 'otx', label: 'AlienVault OTX', category: 'API Platform', requiresAuth: true, defaultUrl: DEFAULT_URLS.otx, supportedTypes: ['IP', 'Hash', 'Domain', 'URL'] },
    { type: 'misp', label: 'MISP', category: 'API Platform', requiresAuth: true, defaultUrl: null, supportedTypes: ['IP', 'Hash', 'Domain', 'URL', 'Email'] },
    { type: 'phishtank', label: 'PhishTank', category: 'API Platform', requiresAuth: false, defaultUrl: DEFAULT_URLS.phishtank, supportedTypes: ['URL', 'Domain'] },

    // --- abuse.ch ecosystem ---
    { type: 'threatfox', label: 'ThreatFox', category: 'abuse.ch', requiresAuth: false, defaultUrl: null, supportedTypes: ['IP', 'Hash', 'Domain', 'URL'] },
    { type: 'urlhaus', label: 'URLhaus', category: 'abuse.ch', requiresAuth: false, defaultUrl: null, supportedTypes: ['URL', 'Domain'] },
    { type: 'malwarebazaar', label: 'MalwareBazaar', category: 'abuse.ch', requiresAuth: false, defaultUrl: null, supportedTypes: ['Hash'] },
    { type: 'feodotracker', label: 'Feodo Tracker', category: 'abuse.ch', requiresAuth: false, defaultUrl: null, supportedTypes: ['IP'] },
    { type: 'sslbl', label: 'SSL Blacklist (SSLBL)', category: 'abuse.ch', requiresAuth: false, defaultUrl: null, supportedTypes: ['IP'] },

    // --- Phishing ---
    { type: 'openphish', label: 'OpenPhish', category: 'Phishing', requiresAuth: false, defaultUrl: null, supportedTypes: ['URL', 'Domain'] },

    // --- IP Blocklists ---
    { type: 'blocklist_de', label: 'Blocklist.de', category: 'IP Blocklist', requiresAuth: false, defaultUrl: null, supportedTypes: ['IP'] },
    { type: 'emergingthreats', label: 'Emerging Threats', category: 'IP Blocklist', requiresAuth: false, defaultUrl: null, supportedTypes: ['IP'] },
    { type: 'spamhaus_drop', label: 'Spamhaus DROP', category: 'IP Blocklist', requiresAuth: false, defaultUrl: null, supportedTypes: ['IP'] },
    { type: 'firehol_l1', label: 'FireHOL Level 1', category: 'IP Blocklist', requiresAuth: false, defaultUrl: null, supportedTypes: ['IP'] },
    { type: 'talos', label: 'Cisco Talos', category: 'IP Blocklist', requiresAuth: false, defaultUrl: null, supportedTypes: ['IP'] },
    { type: 'crowdsec', label: 'CrowdSec', category: 'IP Blocklist', requiresAuth: false, defaultUrl: null, supportedTypes: ['IP'] },

    // --- C2 & Malware ---
    { type: 'c2intelfeeds', label: 'C2 Intel Feeds', category: 'C2 & Malware', requiresAuth: false, defaultUrl: null, supportedTypes: ['IP', 'Domain', 'URL'] },
    { type: 'bambenek_c2', label: 'Bambenek C2', category: 'C2 & Malware', requiresAuth: false, defaultUrl: null, supportedTypes: ['IP', 'Domain'] },
    { type: 'digitalside', label: 'DigitalSide Threat-Intel', category: 'C2 & Malware', requiresAuth: false, defaultUrl: null, supportedTypes: ['IP', 'Domain', 'URL'] }
  ];
}

/**
 * Get default URL for a platform type
 * @param {string} platformType
 * @returns {string|null}
 */
function getDefaultUrl(platformType) {
  return DEFAULT_URLS[(platformType || '').toLowerCase().trim()] || null;
}

module.exports = {
  getTiAdapter,
  getSupportedPlatforms,
  getPlatformInfo,
  getDefaultUrl,
  TI_PLATFORMS
};
