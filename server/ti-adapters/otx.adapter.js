const BaseTiAdapter = require('./base.adapter');

/**
 * AlienVault OTX Adapter
 * Requires API key (free signup)
 * Docs: https://otx.alienvault.com/api
 */
class OTXAdapter extends BaseTiAdapter {
  constructor(config) {
    super(config);
    this.name = 'otx';
    this.apiUrl = config.apiUrl || 'https://otx.alienvault.com';

    if (!config.apiKey) {
      console.warn('OTX adapter initialized without API key');
    }
  }

  getSupportedTypes() {
    return ['IP', 'Hash', 'Domain', 'URL'];
  }

  async testConnection() {
    if (!this.apiKey) {
      return { success: false, message: 'API key is required for OTX' };
    }

    try {
      const response = await this.makeRequest({
        method: 'GET',
        url: `${this.apiUrl}/api/v1/user/me`,
        headers: {
          'X-OTX-API-KEY': this.apiKey
        }
      });

      if (response.status === 200 && response.data?.username) {
        return { success: true, message: `Connected as ${response.data.username}` };
      }
      if (response.status === 403) {
        return { success: false, message: 'Invalid API key' };
      }
      return { success: false, message: `Unexpected response: ${response.status}` };
    } catch (err) {
      return { success: false, message: err.message };
    }
  }

  async fetchFeed(iocType, options = {}) {
    if (!this.apiKey) {
      throw new Error('API key is required for OTX');
    }

    const { limit = 100, daysBack = 1 } = options;

    // Calculate modified_since date
    const since = new Date();
    since.setDate(since.getDate() - daysBack);
    const modifiedSince = since.toISOString().split('.')[0];

    // Fetch subscribed pulses
    const response = await this.makeRequest({
      method: 'GET',
      url: `${this.apiUrl}/api/v1/pulses/subscribed`,
      params: {
        modified_since: modifiedSince,
        limit: 50
      },
      headers: {
        'X-OTX-API-KEY': this.apiKey
      }
    });

    if (response.status === 403) {
      throw new Error('Invalid OTX API key');
    }

    if (response.status !== 200) {
      throw new Error(`OTX API error: ${response.status}`);
    }

    const pulses = response.data?.results || [];

    // Extract indicators from all pulses
    const allIndicators = [];
    for (const pulse of pulses) {
      const indicators = pulse.indicators || [];
      for (const ind of indicators) {
        ind._pulseName = pulse.name;
        ind._pulseId = pulse.id;
        allIndicators.push(ind);
      }
    }

    // Filter by requested IOC type
    const filtered = this._filterByType(allIndicators, iocType);
    const normalized = this.normalizeIOCs(filtered, iocType);

    return { iocs: normalized.slice(0, limit) };
  }

  /**
   * Map our IOC types to OTX indicator types
   */
  _filterByType(indicators, iocType) {
    const typeMap = {
      'IP': ['IPv4', 'IPv6'],
      'Hash': ['FileHash-MD5', 'FileHash-SHA1', 'FileHash-SHA256'],
      'Domain': ['domain', 'hostname'],
      'URL': ['URL', 'URI']
    };

    const allowedTypes = typeMap[iocType] || [];
    return indicators.filter(ind => allowedTypes.includes(ind.type));
  }

  normalizeIOCs(rawData, iocType) {
    return rawData.map(item => ({
      value: item.indicator || '',
      type: iocType,
      confidence: 70,
      tags: [],
      source: 'OTX',
      metadata: {
        pulseName: item._pulseName || '',
        pulseId: item._pulseId || '',
        title: item.title || '',
        created: item.created || ''
      }
    })).filter(ioc => ioc.value && ioc.value.trim());
  }
}

module.exports = OTXAdapter;
