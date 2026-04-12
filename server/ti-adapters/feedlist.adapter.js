const BaseTiAdapter = require('./base.adapter');

/**
 * Generic Feed/Blocklist Adapter
 * Handles direct-download TXT, CSV, and JSON feeds.
 *
 * 14 Providers / 15 feed platform types:
 * abuse.ch: ThreatFox, URLhaus, MalwareBazaar, Feodo Tracker, SSLBL
 * Phishing: OpenPhish
 * IP Blocklists: Blocklist.de, Emerging Threats, Spamhaus DROP, FireHOL, Cisco Talos, CrowdSec
 * C2 & Malware: C2 Intel Feeds, Bambenek C2, DigitalSide Threat-Intel
 *
 * Each platform type has a pre-defined feed config (FEED_CONFIGS).
 */

// Pre-defined feed configurations for each platform type
const FEED_CONFIGS = {
  // --- abuse.ch ecosystem (direct download feeds) ---
  threatfox: {
    label: 'ThreatFox',
    feeds: {
      IP: { url: 'https://threatfox.abuse.ch/export/json/recent/', format: 'json', jsonPath: 'data', jsonValueField: 'ioc', filterField: 'ioc_type', filterValues: ['ip:port'] },
      Hash: { url: 'https://threatfox.abuse.ch/export/json/recent/', format: 'json', jsonPath: 'data', jsonValueField: 'ioc', filterField: 'ioc_type', filterValues: ['md5_hash', 'sha256_hash'] },
      Domain: { url: 'https://threatfox.abuse.ch/export/json/recent/', format: 'json', jsonPath: 'data', jsonValueField: 'ioc', filterField: 'ioc_type', filterValues: ['domain'] },
      URL: { url: 'https://threatfox.abuse.ch/export/json/recent/', format: 'json', jsonPath: 'data', jsonValueField: 'ioc', filterField: 'ioc_type', filterValues: ['url'] }
    },
    supportedTypes: ['IP', 'Hash', 'Domain', 'URL']
  },
  urlhaus: {
    label: 'URLhaus',
    feeds: {
      URL: { url: 'https://urlhaus.abuse.ch/downloads/text_recent/', format: 'txt' },
      Domain: { url: 'https://urlhaus.abuse.ch/downloads/text_recent/', format: 'txt', extractDomain: true }
    },
    supportedTypes: ['URL', 'Domain']
  },
  malwarebazaar: {
    label: 'MalwareBazaar',
    feeds: {
      Hash: { url: 'https://bazaar.abuse.ch/export/txt/sha256/recent/', format: 'txt' }
    },
    supportedTypes: ['Hash']
  },
  feodotracker: {
    label: 'Feodo Tracker',
    feeds: {
      IP: { url: 'https://feodotracker.abuse.ch/downloads/ipblocklist.txt', format: 'txt' }
    },
    supportedTypes: ['IP']
  },
  sslbl: {
    label: 'SSL Blacklist',
    feeds: {
      IP: { url: 'https://sslbl.abuse.ch/blacklist/sslipblacklist.txt', format: 'txt' }
    },
    supportedTypes: ['IP']
  },

  // --- Phishing ---
  openphish: {
    label: 'OpenPhish',
    feeds: {
      URL: { url: 'https://openphish.com/feed.txt', format: 'txt' },
      Domain: { url: 'https://openphish.com/feed.txt', format: 'txt', extractDomain: true }
    },
    supportedTypes: ['URL', 'Domain']
  },

  // --- IP Blocklists ---
  blocklist_de: {
    label: 'Blocklist.de',
    feeds: {
      IP: { url: 'https://www.blocklist.de/downloads/export-ips_all.txt', format: 'txt' }
    },
    supportedTypes: ['IP']
  },
  emergingthreats: {
    label: 'Emerging Threats',
    feeds: {
      IP: { url: 'https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt', format: 'txt' }
    },
    supportedTypes: ['IP']
  },
  spamhaus_drop: {
    label: 'Spamhaus DROP',
    feeds: {
      IP: { url: 'https://www.spamhaus.org/drop/drop.txt', format: 'txt_csv', csvColumn: 0, delimiter: ';' }
    },
    supportedTypes: ['IP']
  },
  firehol_l1: {
    label: 'FireHOL Level 1',
    feeds: {
      IP: { url: 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset', format: 'txt' }
    },
    supportedTypes: ['IP']
  },
  talos: {
    label: 'Cisco Talos',
    feeds: {
      IP: { url: 'https://talosintelligence.com/documents/ip-blacklist', format: 'txt' }
    },
    supportedTypes: ['IP']
  },
  crowdsec: {
    label: 'CrowdSec',
    feeds: {
      IP: { url: 'https://raw.githubusercontent.com/crowdsecurity/crowdsec-cloud-blocklist/main/ips.txt', format: 'txt' }
    },
    supportedTypes: ['IP']
  },

  // --- C2 & Malware ---
  c2intelfeeds: {
    label: 'C2 Intel Feeds',
    feeds: {
      IP: { url: 'https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/IPC2s-30day.csv', format: 'txt' },
      Domain: { url: 'https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/domainC2s-30day-filter-abused.csv', format: 'txt' },
      URL: { url: 'https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/urlC2s-30day-filter-abused.csv', format: 'txt' }
    },
    supportedTypes: ['IP', 'Domain', 'URL']
  },
  bambenek_c2: {
    label: 'Bambenek C2',
    feeds: {
      IP: { url: 'https://osint.bambenekconsulting.com/feeds/c2-ipmasterlist.txt', format: 'txt_csv', csvColumn: 0 },
      Domain: { url: 'https://osint.bambenekconsulting.com/feeds/c2-dommasterlist.txt', format: 'txt_csv', csvColumn: 0 }
    },
    supportedTypes: ['IP', 'Domain']
  },
  digitalside: {
    label: 'DigitalSide Threat-Intel',
    feeds: {
      IP: { url: 'https://raw.githubusercontent.com/davidonzo/Threat-Intel/master/lists/latestips.txt', format: 'txt' },
      Domain: { url: 'https://raw.githubusercontent.com/davidonzo/Threat-Intel/master/lists/latestdomains.txt', format: 'txt' },
      URL: { url: 'https://raw.githubusercontent.com/davidonzo/Threat-Intel/master/lists/latesturls.txt', format: 'txt' }
    },
    supportedTypes: ['IP', 'Domain', 'URL']
  }
};

// In-memory feed cache: { key -> { data, fetchedAt } }
const feedCache = new Map();
const CACHE_TTL_MS = 15 * 60 * 1000; // 15 minutes

class FeedListAdapter extends BaseTiAdapter {
  constructor(config) {
    super(config);
    this.platformType = config.platformType || 'feedlist';
    this.name = this.platformType;

    // Get feed config for this platform type
    this.feedConfig = FEED_CONFIGS[this.platformType];
    if (!this.feedConfig && config.apiUrl) {
      // Custom feed URL - create ad-hoc config
      this.feedConfig = {
        label: 'Custom Feed',
        feeds: {
          IP: { url: config.apiUrl, format: 'txt' }
        },
        supportedTypes: ['IP']
      };
    }
  }

  getSupportedTypes() {
    return this.feedConfig?.supportedTypes || ['IP'];
  }

  async testConnection() {
    if (!this.feedConfig) {
      return { success: false, message: `Unknown feed type: ${this.platformType}` };
    }

    // Try to fetch a small amount from the first available feed
    const firstType = this.feedConfig.supportedTypes[0];
    const feed = this.feedConfig.feeds[firstType];
    if (!feed) {
      return { success: false, message: 'No feed URL configured' };
    }

    try {
      const response = await this.makeRequest({
        method: 'GET',
        url: feed.url,
        timeout: 15000,
        maxContentLength: 50000
      });

      if (response.status === 200) {
        return { success: true, message: `${this.feedConfig.label} feed is accessible` };
      }
      return { success: false, message: `Feed returned status ${response.status}` };
    } catch (err) {
      return { success: false, message: err.message };
    }
  }

  async fetchFeed(iocType, options = {}) {
    if (!this.feedConfig) {
      throw new Error(`Unknown feed type: ${this.platformType}`);
    }

    const feed = this.feedConfig.feeds[iocType];
    if (!feed) {
      throw new Error(`${this.feedConfig.label} does not support ${iocType} IOC type`);
    }

    const { limit = 100 } = options;
    const cacheKey = `${this.platformType}:${iocType}`;

    // Check cache
    const cached = feedCache.get(cacheKey);
    if (cached && (Date.now() - cached.fetchedAt) < CACHE_TTL_MS) {
      return { iocs: cached.data.slice(0, limit), cached: true };
    }

    const response = await this.makeRequest({
      method: 'GET',
      url: feed.url,
      timeout: 30000,
      // Some feeds return text, not JSON
      responseType: feed.format.startsWith('json') ? 'json' : 'text'
    });

    if (response.status !== 200) {
      throw new Error(`${this.feedConfig.label} feed error: ${response.status}`);
    }

    let rawItems = [];

    switch (feed.format) {
      case 'txt':
        rawItems = this._parseTxt(response.data, feed);
        break;
      case 'txt_csv':
        rawItems = this._parseTxtCsv(response.data, feed);
        break;
      case 'csv':
        rawItems = this._parseCsv(response.data, feed);
        break;
      case 'json':
        rawItems = this._parseJson(response.data, feed);
        break;
      case 'json_array':
        rawItems = this._parseJsonArray(response.data, feed);
        break;
      default:
        rawItems = this._parseTxt(response.data, feed);
    }

    const normalized = this.normalizeIOCs(rawItems, iocType, feed);

    // Store in cache (full normalized list, sliced on retrieval)
    feedCache.set(cacheKey, { data: normalized, fetchedAt: Date.now() });

    return { iocs: normalized.slice(0, limit) };
  }

  /**
   * Parse plain text file (one IOC per line, skip comments)
   */
  _parseTxt(data, feed) {
    const text = typeof data === 'string' ? data : JSON.stringify(data);
    return text.split('\n')
      .map(line => line.trim())
      .filter(line => line && !line.startsWith('#') && !line.startsWith('//') && !line.startsWith(';'));
  }

  /**
   * Parse text file where each line has CSV-like fields
   */
  _parseTxtCsv(data, feed) {
    const delimiter = feed.delimiter || ',';
    const column = feed.csvColumn || 0;
    const text = typeof data === 'string' ? data : JSON.stringify(data);

    return text.split('\n')
      .map(line => line.trim())
      .filter(line => line && !line.startsWith('#') && !line.startsWith('//') && !line.startsWith(';'))
      .map(line => {
        const parts = line.split(delimiter);
        return (parts[column] || '').trim();
      })
      .filter(Boolean);
  }

  /**
   * Parse CSV with header row
   */
  _parseCsv(data, feed) {
    const lines = (typeof data === 'string' ? data : '').split('\n').filter(l => l.trim() && !l.startsWith('#'));
    if (lines.length < 2) return [];

    const column = feed.csvColumn || 0;
    // Skip header
    return lines.slice(1)
      .map(line => {
        const parts = line.split(feed.delimiter || ',');
        return (parts[column] || '').trim().replace(/^"|"$/g, '');
      })
      .filter(Boolean);
  }

  /**
   * Parse JSON with nested path (e.g., response.data -> items)
   * Supports filterField/filterValues for filtering by a field (e.g., ThreatFox ioc_type)
   */
  _parseJson(data, feed) {
    let items = data;

    // Navigate JSON path
    if (feed.jsonPath) {
      const paths = feed.jsonPath.split('.');
      for (const p of paths) {
        items = items?.[p];
        if (!items) return [];
      }
    }

    // Handle dict/object responses (e.g., ThreatFox returns {id: {...}, id: {...}})
    if (items && typeof items === 'object' && !Array.isArray(items)) {
      items = Object.values(items);
    }
    if (!Array.isArray(items)) return [];

    // Apply filter if specified (e.g., filter ThreatFox by ioc_type)
    if (feed.filterField && feed.filterValues) {
      items = items.filter(item => feed.filterValues.includes(item[feed.filterField]));
    }

    if (feed.jsonValueField) {
      return items.map(item => item[feed.jsonValueField]).filter(Boolean);
    }

    return items;
  }

  /**
   * Parse JSON array directly
   */
  _parseJsonArray(data, feed) {
    const items = Array.isArray(data) ? data : [];

    if (feed.jsonValueField) {
      return items.map(item => item[feed.jsonValueField]).filter(Boolean);
    }

    return items;
  }

  normalizeIOCs(rawItems, iocType, feed) {
    const normalized = rawItems.map(item => {
      let value = typeof item === 'string' ? item.trim() : String(item || '').trim();

      // Handle domain extraction from URLs
      if (feed?.extractDomain && value.startsWith('http')) {
        try {
          value = new URL(value).hostname;
        } catch {
          // keep as-is
        }
      }

      // Clean IP:port format
      if (iocType === 'IP' && value.includes(':')) {
        value = value.split(':')[0];
      }

      // Keep full CIDR notation for IP ranges (e.g., Spamhaus DROP)
      // Don't strip the /prefix — preserve range info for reference
      if (iocType === 'IP' && value.includes('/')) {
        value = value.trim();
      }

      return {
        value,
        type: iocType,
        confidence: 70,
        tags: [],
        source: this.feedConfig?.label || this.platformType,
        metadata: {}
      };
    }).filter(ioc => ioc.value && ioc.value.length > 0 && ioc.value !== 'undefined');

    // Deduplicate IOCs by type:value
    const seen = new Set();
    const dedupedIocs = normalized.filter(ioc => {
      const key = `${ioc.type}:${ioc.value}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });

    return dedupedIocs;
  }
}

/**
 * Get the feed config for a platform type (used by factory)
 */
FeedListAdapter.getFeedConfig = function(platformType) {
  return FEED_CONFIGS[platformType] || null;
};

/**
 * Check if a platform type is handled by the feedlist adapter
 */
FeedListAdapter.isFeedType = function(platformType) {
  return !!FEED_CONFIGS[platformType];
};

/**
 * Get all available feed platform types
 */
FeedListAdapter.getAllFeedTypes = function() {
  return Object.keys(FEED_CONFIGS);
};

module.exports = FeedListAdapter;
