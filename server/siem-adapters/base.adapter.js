/**
 * Base SIEM Adapter - Abstract interface for all SIEM implementations
 * All SIEM adapters must extend this class and implement its methods
 */
class BaseSiemAdapter {
  constructor(config) {
    if (new.target === BaseSiemAdapter) {
      throw new Error('BaseSiemAdapter is abstract and cannot be instantiated directly');
    }

    this.config = config;
    this.name = 'base';
    this.supportedIOCTypes = ['IP', 'Hash', 'Domain', 'URL', 'Email', 'FileName'];

    // Common config validation
    if (!config.apiHost) {
      throw new Error('apiHost is required');
    }

    // Cache https.Agent for connections with SSL verification disabled
    if (config.verifySSL === false) {
      const https = require('https');
      this._httpsAgent = new https.Agent({ rejectUnauthorized: false });
    }
  }

  /**
   * Get the SIEM type identifier
   * @returns {string}
   */
  getType() {
    return this.name;
  }

  /**
   * Test connectivity to the SIEM
   * @returns {Promise<{success: boolean, message: string, data?: any}>}
   */
  async testConnection() {
    throw new Error('testConnection() must be implemented by subclass');
  }

  /**
   * Authenticate and get session/token if needed
   * Some SIEMs require a separate auth step before searches
   * @returns {Promise<{authenticated: boolean, token?: string, expiresAt?: Date}>}
   */
  async authenticate() {
    // Default: no separate auth needed (e.g., Bearer token passed directly)
    return { authenticated: true };
  }

  /**
   * Build a query for the specific SIEM
   * @param {string} filterType - IOC type (IP, Hash, Domain, URL, Email, FileName)
   * @param {string[]} values - Array of IOC values to search for
   * @param {Object} options - Search options
   * @param {number} options.minutesBack - How far back to search
   * @param {Object} options.logSourceConfig - SIEM-specific log source configuration
   * @returns {Object} - SIEM-specific query object
   */
  buildQuery(filterType, values, options = {}) {
    throw new Error('buildQuery() must be implemented by subclass');
  }

  /**
   * Execute a search query
   * @param {Object} query - Query built by buildQuery()
   * @param {Object} options - Execution options
   * @param {number} options.timeout - Request timeout in ms
   * @param {number} options.maxResults - Maximum results to return
   * @returns {Promise<{taskId?: string, status: string, results?: Array, complete: boolean}>}
   */
  async executeSearch(query, options = {}) {
    throw new Error('executeSearch() must be implemented by subclass');
  }

  /**
   * Poll for search results (for async SIEMs like LogRhythm, Splunk, QRadar)
   * @param {string} taskId - Search task identifier from executeSearch
   * @param {Object} options - Polling options
   * @param {number} options.pollingInterval - Time between polls in ms
   * @param {number} options.maxAttempts - Maximum polling attempts
   * @returns {Promise<{status: string, results: Array, complete: boolean}>}
   */
  async pollResults(taskId, options = {}) {
    // Default: synchronous SIEM, no polling needed
    return { status: 'complete', results: [], complete: true };
  }

  /**
   * Get available log sources from the SIEM (for Recon feature)
   * @returns {Promise<Array<{id: string, name: string, type?: string}>>}
   */
  async getLogSources() {
    throw new Error('getLogSources() must be implemented by subclass');
  }

  /**
   * Build a raw log retrieval query with no IOC filter (for Recon feature)
   * @param {Object} logSource - Selected log source identifier
   * @param {number} limit - Number of logs to retrieve
   * @returns {Object} - SIEM-specific query object
   */
  buildReconQuery(logSource, limit = 1000) {
    throw new Error('buildReconQuery() must be implemented by subclass');
  }

  /**
   * Normalize results to unified format
   * @param {Array} rawResults - Raw results from SIEM
   * @param {string} filterType - The IOC type that was searched
   * @param {string[]} searchedValues - The IOC values that were searched
   * @returns {Array<NormalizedResult>}
   */
  normalizeResults(rawResults, filterType, searchedValues) {
    throw new Error('normalizeResults() must be implemented by subclass');
  }

  /**
   * Get required configuration fields for this SIEM type
   * Used by frontend to render dynamic forms
   * @returns {Array<ConfigField>}
   */
  static getConfigSchema() {
    return [
      {
        name: 'apiHost',
        label: 'API Host URL',
        type: 'text',
        required: true,
        placeholder: 'https://siem.example.com'
      },
      {
        name: 'apiKey',
        label: 'API Key (Recommended)',
        type: 'password',
        required: true,
        placeholder: 'Enter API key',
        description: 'Primary authentication method. API key/token is preferred over username/password.'
      }
    ];
  }

  /**
   * Validate SIEM-specific configuration
   * @param {Object} config - Configuration to validate
   * @returns {{valid: boolean, errors: string[]}}
   */
  static validateConfig(config) {
    const errors = [];

    if (!config.apiHost) {
      errors.push('API Host is required');
    }

    if (config.apiHost && !config.apiHost.match(/^https?:\/\/.+/)) {
      errors.push('API Host must be a valid URL');
    }

    return {
      valid: errors.length === 0,
      errors
    };
  }

  /**
   * Get authorization headers for API requests.
   * Child adapters should override this for SIEM-specific auth.
   * Prioritizes API key/token over username/password.
   * @returns {Object} - Headers object
   */
  getAuthHeaders() {
    if (this.config.apiKey) {
      return { 'Authorization': `Bearer ${this.config.apiKey}` };
    }
    if (this.config.username && this.config.password) {
      console.warn(`[${this.constructor.name}] Using basic auth - API key/token recommended`);
      const basic = Buffer.from(`${this.config.username}:${this.config.password}`).toString('base64');
      return { 'Authorization': `Basic ${basic}` };
    }
    return {};
  }

  /**
   * Helper: Make HTTP request with common error handling
   * @param {Object} axiosConfig - Axios request configuration
   * @returns {Promise<any>}
   */
  async makeRequest(axiosConfig) {
    const axios = require('axios');

    const defaultConfig = {
      timeout: 30000,
      validateStatus: (status) => status < 500
    };

    // Reuse cached https.Agent for connections with SSL verification disabled
    if (this._httpsAgent) {
      defaultConfig.httpsAgent = this._httpsAgent;
    }

    try {
      const response = await axios({ ...defaultConfig, ...axiosConfig });
      return response;
    } catch (error) {
      const host = this.config.apiHost || 'unknown host';
      const siemName = (this.name || 'SIEM').charAt(0).toUpperCase() + (this.name || 'siem').slice(1);

      if (error.code === 'ECONNREFUSED') {
        const err = new Error(`Cannot connect to ${siemName} at ${host}. The service may be down or the URL may be incorrect.`);
        err.code = error.code;
        err.suggestion = `Verify that ${siemName} is running and accessible from this server. Check the SIEM URL and port.`;
        err.category = 'connection';
        throw err;
      }
      if (error.code === 'ETIMEDOUT' || error.code === 'ECONNABORTED' || error.code === 'ESOCKETTIMEDOUT') {
        const err = new Error(`Connection timed out to ${siemName} at ${host}. The service may be overloaded or unreachable.`);
        err.code = error.code;
        err.suggestion = `Check network connectivity to ${siemName} and try again.`;
        err.category = 'timeout';
        throw err;
      }
      if (error.code === 'ENOTFOUND' || error.code === 'EAI_AGAIN') {
        const err = new Error(`Cannot resolve hostname for ${siemName}. The URL "${host}" could not be found.`);
        err.code = error.code;
        err.suggestion = `Check that the SIEM URL is correct and that DNS is working properly.`;
        err.category = 'connection';
        throw err;
      }
      if (error.code === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' || error.code === 'DEPTH_ZERO_SELF_SIGNED_CERT' ||
          error.code === 'SELF_SIGNED_CERT_IN_CHAIN' || error.code === 'ERR_TLS_CERT_ALTNAME_INVALID' ||
          (error.message && (error.message.includes('certificate') || error.message.includes('self signed')))) {
        const err = new Error(`SSL certificate error connecting to ${siemName} at ${host}.`);
        err.code = error.code || 'SSL_ERROR';
        err.suggestion = `Enable 'Skip SSL Verification' in the SIEM configuration, or install a valid SSL certificate on ${siemName}.`;
        err.category = 'connection';
        throw err;
      }

      // Preserve response status for auth errors
      if (error.response) {
        const status = error.response.status;
        if (status === 401 || status === 403) {
          const err = new Error(`Authentication failed for ${siemName} at ${host}. Check your API credentials.`);
          err.code = 'AUTH_FAILED';
          err.status = status;
          err.suggestion = `Verify your API token, username, or password for ${siemName}.`;
          err.category = 'auth';
          throw err;
        }
        error.status = status;
      }

      throw error;
    }
  }

  /**
   * Helper: Wait for specified milliseconds
   * @param {number} ms - Milliseconds to wait
   * @returns {Promise<void>}
   */
  wait(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Helper: Get retry limit based on search time range
   * @param {number} minutesBack - Search time range in minutes
   * @returns {number}
   */
  getRetryLimit(minutesBack) {
    if (!minutesBack || isNaN(minutesBack)) return 5;
    if (minutesBack <= 5) return 5;
    if (minutesBack <= 15) return 7;
    if (minutesBack <= 60) return 10;
    if (minutesBack <= 360) return 15;
    if (minutesBack <= 1440) return 20;
    return 25;
  }

  /**
   * Helper: Get polling interval based on search time range
   * @param {number} minutesBack - Search time range in minutes
   * @returns {number} - Polling interval in milliseconds
   */
  getPollingInterval(minutesBack) {
    return minutesBack >= 30 ? 60000 : 30000;
  }
}

/**
 * Normalized Result Format
 * All adapters should return results in this format
 * @typedef {Object} NormalizedResult
 * @property {string} siemType - SIEM type identifier
 * @property {string} client - Client name
 * @property {Date} timestamp - Event timestamp
 * @property {string} sourceIP - Source IP address
 * @property {string} destIP - Destination IP address
 * @property {string} hostname - Hostname
 * @property {string} username - Username if applicable
 * @property {string} eventType - Normalized event type
 * @property {string} rawLog - Original raw log
 * @property {string} matchedIOC - The IOC that triggered this result
 * @property {string} matchedIOCType - Type of matched IOC
 * @property {string} severity - Severity level (low/medium/high/critical)
 * @property {Object} additionalFields - SIEM-specific fields
 */

/**
 * Config Field Definition
 * @typedef {Object} ConfigField
 * @property {string} name - Field name (used in config object)
 * @property {string} label - Display label
 * @property {string} type - Input type (text, password, number, checkbox, select)
 * @property {boolean} required - Whether field is required
 * @property {string} placeholder - Placeholder text
 * @property {any} defaultValue - Default value
 * @property {Array} options - Options for select type
 */

module.exports = BaseSiemAdapter;
