const BaseTiAdapter = require('./base.adapter');

/**
 * PhishTank Adapter
 * API key optional but recommended for faster updates
 * Docs: https://www.phishtank.com/developer_info.php
 */
class PhishTankAdapter extends BaseTiAdapter {
  constructor(config) {
    super(config);
    this.name = 'phishtank';
    this.apiUrl = config.apiUrl || 'https://data.phishtank.com';
  }

  getSupportedTypes() {
    return ['URL', 'Domain'];
  }

  async testConnection() {
    try {
      // Try to fetch a small portion of the feed
      const url = this.apiKey
        ? `${this.apiUrl}/data/${this.apiKey}/online-valid.json`
        : `${this.apiUrl}/data/online-valid.json`;

      const response = await this.makeRequest({
        method: 'GET',
        url,
        timeout: 15000
      });

      if (response.status === 200) {
        return { success: true, message: 'PhishTank feed is accessible' };
      }
      return { success: false, message: `Unexpected response: ${response.status}` };
    } catch (err) {
      return { success: false, message: err.message };
    }
  }

  async fetchFeed(iocType, options = {}) {
    const { limit = 100 } = options;

    const url = this.apiKey
      ? `${this.apiUrl}/data/${this.apiKey}/online-valid.json`
      : `${this.apiUrl}/data/online-valid.json`;

    const response = await this.makeRequest({
      method: 'GET',
      url,
      timeout: 30000,
      maxContentLength: 50 * 1024 * 1024 // 50MB limit
    });

    if (response.status !== 200) {
      throw new Error(`PhishTank feed error: ${response.status}`);
    }

    const rawData = Array.isArray(response.data) ? response.data : [];
    // Slice before normalization to avoid processing the entire feed
    const slicedData = rawData.slice(0, limit);
    return { iocs: this.normalizeIOCs(slicedData, iocType) };
  }

  normalizeIOCs(rawData, iocType) {
    return rawData.map(item => {
      let value = '';

      if (iocType === 'URL') {
        value = item.url || '';
      } else if (iocType === 'Domain') {
        try {
          const urlObj = new URL(item.url || '');
          value = urlObj.hostname;
        } catch {
          value = '';
        }
      }

      return {
        value,
        type: iocType,
        confidence: item.verified === 'yes' ? 90 : 60,
        tags: ['phishing'],
        source: 'PhishTank',
        metadata: {
          phishId: item.phish_id || '',
          target: item.target || '',
          verified: item.verified || '',
          submissionTime: item.submission_time || ''
        }
      };
    }).filter(ioc => ioc.value);
  }
}

module.exports = PhishTankAdapter;
