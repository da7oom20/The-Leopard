const BaseTiAdapter = require('./base.adapter');

/**
 * MISP Adapter
 * Requires API key + user-provided URL (self-hosted instances)
 * Docs: https://www.misp-project.org/openapi/
 */
class MISPAdapter extends BaseTiAdapter {
  constructor(config) {
    super(config);
    this.name = 'misp';

    if (!config.apiUrl) {
      console.warn('MISP adapter initialized without API URL');
    }
    if (!config.apiKey) {
      console.warn('MISP adapter initialized without API key');
    }
  }

  getSupportedTypes() {
    return ['IP', 'Hash', 'Domain', 'URL', 'Email'];
  }

  async testConnection() {
    if (!this.apiUrl) {
      return { success: false, message: 'MISP URL is required' };
    }
    if (!this.apiKey) {
      return { success: false, message: 'API key is required for MISP' };
    }

    try {
      const response = await this.makeRequest({
        method: 'GET',
        url: `${this.apiUrl}/servers/getVersion`,
        headers: {
          'Authorization': this.apiKey,
          'Accept': 'application/json',
          'Content-Type': 'application/json'
        }
      });

      if (response.status === 200 && response.data?.version) {
        return { success: true, message: `MISP version ${response.data.version}` };
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
    if (!this.apiUrl) {
      throw new Error('MISP URL is required');
    }
    if (!this.apiKey) {
      throw new Error('API key is required for MISP');
    }

    const { limit = 1000, daysBack = 1 } = options;

    // Map IOC type to MISP attribute types
    const mispTypes = this._getMispTypes(iocType);

    const response = await this.makeRequest({
      method: 'POST',
      url: `${this.apiUrl}/attributes/restSearch`,
      data: {
        type: mispTypes,
        last: `${daysBack}d`,
        limit: limit,
        page: 1,
        enforceWarninglist: true
      },
      headers: {
        'Authorization': this.apiKey,
        'Accept': 'application/json',
        'Content-Type': 'application/json'
      }
    });

    if (response.status === 403) {
      throw new Error('Invalid MISP API key');
    }

    if (response.status !== 200) {
      throw new Error(`MISP API error: ${response.status}`);
    }

    const attributes = response.data?.response?.Attribute || [];
    const normalized = this.normalizeIOCs(attributes, iocType);

    return { iocs: normalized.slice(0, limit) };
  }

  /**
   * Map our IOC types to MISP attribute types
   */
  _getMispTypes(iocType) {
    const typeMap = {
      'IP': ['ip-src', 'ip-dst'],
      'Hash': ['md5', 'sha1', 'sha256'],
      'Domain': ['domain', 'hostname'],
      'URL': ['url', 'uri'],
      'Email': ['email-src', 'email-dst']
    };

    return typeMap[iocType] || [];
  }

  normalizeIOCs(rawData, iocType) {
    return rawData.map(item => ({
      value: item.value || '',
      type: iocType,
      confidence: 70,
      tags: (item.Tag || []).map(t => t.name),
      source: 'MISP',
      metadata: {
        category: item.category || '',
        eventId: item.event_id || '',
        timestamp: item.timestamp ? new Date(item.timestamp * 1000).toISOString() : '',
        comment: item.comment || ''
      }
    })).filter(ioc => ioc.value && ioc.value.trim());
  }
}

module.exports = MISPAdapter;
