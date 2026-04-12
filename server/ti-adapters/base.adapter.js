/**
 * Base TI Adapter - Abstract interface for all Threat Intelligence platform implementations
 * All TI adapters must extend this class and implement its methods
 */
class BaseTiAdapter {
  constructor(config) {
    if (new.target === BaseTiAdapter) {
      throw new Error('BaseTiAdapter is abstract and cannot be instantiated directly');
    }

    this.config = config;
    this.name = 'base';
    this.apiUrl = config.apiUrl || '';
    this.apiKey = config.apiKey || '';
  }

  /**
   * Get the platform type identifier
   * @returns {string}
   */
  getType() {
    return this.name;
  }

  /**
   * Get IOC types this platform supports
   * @returns {string[]} e.g. ['IP', 'Hash', 'Domain', 'URL']
   */
  getSupportedTypes() {
    throw new Error('getSupportedTypes() must be implemented by subclass');
  }

  /**
   * Test connectivity to the TI platform
   * @returns {Promise<{success: boolean, message: string}>}
   */
  async testConnection() {
    throw new Error('testConnection() must be implemented by subclass');
  }

  /**
   * Fetch IOC feed from the TI platform
   * @param {string} iocType - IOC type to fetch (IP, Hash, Domain, URL)
   * @param {Object} options - Feed options
   * @param {number} options.limit - Max IOCs to fetch (default 100)
   * @param {number} options.daysBack - How far back to fetch (default 1)
   * @param {number} options.confidenceMin - Minimum confidence score (default 0)
   * @returns {Promise<{iocs: Array<{value: string, type: string, confidence: number, tags: string[], source: string}>}>}
   */
  async fetchFeed(iocType, options = {}) {
    throw new Error('fetchFeed() must be implemented by subclass');
  }

  /**
   * Normalize raw TI data to unified IOC format
   * @param {Array} rawData - Raw data from TI platform
   * @param {string} iocType - The requested IOC type
   * @returns {Array<{value: string, type: string, confidence: number, tags: string[], source: string}>}
   */
  normalizeIOCs(rawData, iocType) {
    throw new Error('normalizeIOCs() must be implemented by subclass');
  }

  /**
   * Helper: Make HTTP request with common error handling
   * Routes through corporate proxy when HTTPS_PROXY / HTTP_PROXY env vars are set
   * @param {Object} axiosConfig - Axios request configuration
   * @returns {Promise<any>}
   */
  async makeRequest(axiosConfig) {
    const axios = require('axios');

    const defaultConfig = {
      timeout: 30000,
      validateStatus: (status) => status < 500,  // accept < 500 — 5xx errors trigger error handler
      proxy: false  // disable axios built-in proxy to use httpsAgent instead
    };

    // Use proxy agent for external TI platform requests
    const proxyUrl = process.env.HTTPS_PROXY || process.env.HTTP_PROXY || process.env.https_proxy || process.env.http_proxy;
    if (proxyUrl) {
      const { HttpsProxyAgent } = require('https-proxy-agent');
      const agent = new HttpsProxyAgent(proxyUrl);
      defaultConfig.httpsAgent = agent;
      defaultConfig.httpAgent = agent;
    }

    try {
      const response = await axios({ ...defaultConfig, ...axiosConfig });
      return response;
    } catch (error) {
      const host = axiosConfig.url || this.apiUrl || 'unknown host';

      if (error.code === 'ECONNREFUSED') {
        const err = new Error(`Connection refused to ${host}. The TI service may not be running or is unreachable.`);
        err.suggestion = 'Verify the TI platform URL is correct and the service is running. Check firewall rules and network connectivity.';
        err.category = 'connection';
        throw err;
      }
      if (error.code === 'ETIMEDOUT' || error.code === 'ECONNABORTED' || error.code === 'ESOCKETTIMEDOUT') {
        const err = new Error(`Connection timed out to ${host}.`);
        err.suggestion = 'The TI platform may be slow or unreachable. Check network connectivity and proxy settings.';
        err.category = 'timeout';
        throw err;
      }
      if (error.code === 'ENOTFOUND' || error.code === 'EAI_AGAIN') {
        const err = new Error(`Could not resolve hostname for ${host}.`);
        err.suggestion = 'Check the TI platform URL for typos. Verify DNS resolution and network connectivity.';
        err.category = 'connection';
        throw err;
      }
      if (error.message && (error.message.includes('certificate') || error.message.includes('SSL') || error.message.includes('CERT'))) {
        const err = new Error(`SSL/TLS certificate error connecting to ${host}.`);
        err.suggestion = 'The TI platform may use a self-signed certificate. Check the URL (http vs https) and certificate validity.';
        err.category = 'connection';
        throw err;
      }
      if (error.response) {
        const status = error.response.status;
        if (status === 401 || status === 403) {
          const err = new Error(`Authentication failed for TI platform at ${host} (HTTP ${status}).`);
          err.suggestion = 'Check that the API key or credentials are correct and have not expired.';
          err.category = 'auth';
          throw err;
        }
      }
      throw error;
    }
  }
}

module.exports = BaseTiAdapter;
