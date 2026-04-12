/**
 * ManageEngine EventLog Analyzer SIEM Adapter
 * Implements IOC search via ManageEngine REST API v2
 * API Docs: https://www.manageengine.com/products/eventlog/api/v2/introduction/
 */
const BaseSiemAdapter = require('./base.adapter');

class ManageEngineAdapter extends BaseSiemAdapter {
  constructor(config) {
    super(config);
    this.name = 'manageengine';

    // Default ManageEngine port
    this.port = config.port || 8400;
    this.baseUrl = this.normalizeUrl(config.apiHost);

    // Field mappings for ManageEngine EventLog Analyzer
    this.fieldMappings = {
      IP: [
        'SOURCE_IP', 'DESTINATION_IP', 'CLIENT_IP', 'HOST_IP',
        'REMOTE_IP', 'LOCAL_IP', 'IP_ADDRESS'
      ],
      Hash: ['FILE_HASH', 'MD5', 'SHA1', 'SHA256', 'HASH_VALUE', 'PROCESS_HASH'],
      Domain: [
        'DOMAIN', 'HOST_NAME', 'URL_DOMAIN', 'DNS_DOMAIN',
        'TARGET_SERVER', 'REMOTE_HOST', 'FQDN'
      ],
      URL: ['URL', 'REQUEST_URL', 'WEB_URL', 'FULL_URL', 'URI'],
      Email: [
        'USER_NAME', 'SOURCE_USER', 'DEST_USER', 'EMAIL_FROM', 'EMAIL_TO',
        'SENDER_ADDRESS', 'RECIPIENT_ADDRESS', 'MAIL_FROM', 'MAIL_TO',
        'FROM_ADDRESS', 'TO_ADDRESS'
      ],
      FileName: [
        'FILE_NAME', 'PROCESS_NAME', 'FILE_PATH', 'PROGRAM_NAME',
        'IMAGE_NAME', 'TARGET_FILE', 'ORIGINAL_FILENAME',
        'PARENT_PROCESS', 'COMMAND_LINE', 'EXECUTABLE'
      ]
    };
  }

  /**
   * Normalize API URL
   */
  normalizeUrl(apiHost) {
    let url = apiHost.replace(/\/$/, '');
    if (!url.match(/:\d+$/)) {
      url = `${url}:${this.port}`;
    }
    return url;
  }

  /**
   * Get authorization headers for ManageEngine API v2
   * Uses Bearer token authentication (OAuth)
   */
  getAuthHeaders() {
    const headers = {
      'Content-Type': 'application/json',
      'Accept': 'application/json'
    };

    if (this.config.apiKey) {
      headers['Authorization'] = `Bearer ${this.config.apiKey}`;
    }

    return headers;
  }

  /**
   * Escape a value for use in ManageEngine search queries
   */
  escapeQueryValue(value) {
    if (!value) return value;
    return String(value)
      .replace(/\\/g, '\\\\')
      .replace(/"/g, '\\"')
      .replace(/'/g, "\\'");
  }

  /**
   * Build a search query string from fields and IOC values
   * ManageEngine v2 uses a query string format for searching
   */
  buildQueryString(filterType, values, customFields) {
    const fields = customFields || this.fieldMappings[filterType] || [];
    if (fields.length === 0 || values.length === 0) return '';

    // Build field OR conditions: (FIELD1 = "val1" OR FIELD1 = "val2") OR (FIELD2 = "val1" ...)
    const fieldConditions = fields.map(field => {
      const valueConditions = values.map(v => `${field} = "${this.escapeQueryValue(v)}"`);
      return `(${valueConditions.join(' OR ')})`;
    });

    return fieldConditions.join(' OR ');
  }

  /**
   * Test connectivity to ManageEngine API v2
   */
  async testConnection() {
    try {
      // Try v2 metadata endpoint first
      const response = await this.makeRequest({
        method: 'GET',
        url: `${this.baseUrl}/api/v2/meta/log-fields`,
        headers: this.getAuthHeaders(),
        timeout: 10000
      });

      if (response.status === 200) {
        const fieldCount = response.data?.data?.length || 0;
        return {
          success: true,
          message: `Connected to ManageEngine EventLog Analyzer (API v2). ${fieldCount} log fields available.`,
          data: { apiVersion: 'v2', fieldCount }
        };
      }

      if (response.status === 401) {
        return {
          success: false,
          message: 'Authentication failed. Check your API key (Bearer token).',
          suggestion: 'Generate a new API key from ManageEngine Admin > Settings > API.',
          category: 'auth'
        };
      }

      return {
        success: false,
        message: `Unexpected response status: ${response.status}`
      };
    } catch (error) {
      const errMsg = error.message || `Connection failed to ManageEngine at ${this.baseUrl}`;
      const errSuggestion = error.suggestion || 'Check the ManageEngine URL, port (default 8400), and Bearer token. Ensure the service is running and API v2 is enabled.';
      return {
        success: false,
        message: errMsg,
        suggestion: errSuggestion,
        category: error.category || 'connection'
      };
    }
  }

  /**
   * ManageEngine uses Bearer token auth (no separate auth step)
   */
  async authenticate() {
    return { authenticated: true };
  }

  /**
   * Get available log sources from ManageEngine v2
   */
  async getLogSources() {
    try {
      // Try v2 log sources endpoint
      const response = await this.makeRequest({
        method: 'GET',
        url: `${this.baseUrl}/api/v2/logsources`,
        headers: this.getAuthHeaders(),
        timeout: 30000
      });

      const sources = response.data?.data || response.data?.devices || response.data || [];
      return (Array.isArray(sources) ? sources : []).map(d => ({
        id: String(d.id || d.host_id || d.DEVICE_ID),
        name: d.name || d.host_name || d.DEVICE_NAME || d.hostname || `Device ${d.id}`,
        type: d.type || d.log_type || 'device'
      }));
    } catch (error) {
      console.warn('[MANAGEENGINE] getLogSources error:', error.message);
      // Fallback to v1 if v2 not available
      try {
        const fallback = await this.makeRequest({
          method: 'GET',
          url: `${this.baseUrl}/api/v1/devices`,
          headers: this.getAuthHeaders(),
          timeout: 30000
        });
        const devices = fallback.data?.devices || fallback.data || [];
        return (Array.isArray(devices) ? devices : []).map(d => ({
          id: String(d.id || d.DEVICE_ID),
          name: d.name || d.DEVICE_NAME || d.hostname || `Device ${d.id}`,
          type: 'device'
        }));
      } catch (fallbackError) {
        console.warn('[MANAGEENGINE] Fallback getLogSources also failed:', fallbackError.message);
        return [];
      }
    }
  }

  /**
   * Discover available log fields from ManageEngine v2
   */
  async getLogFields() {
    try {
      const response = await this.makeRequest({
        method: 'GET',
        url: `${this.baseUrl}/api/v2/meta/log-fields`,
        headers: this.getAuthHeaders(),
        timeout: 15000
      });

      return response.data?.data || [];
    } catch (error) {
      console.warn('[MANAGEENGINE] getLogFields error:', error.message);
      return [];
    }
  }

  /**
   * Build raw log retrieval query for Recon (no IOC filter)
   */
  buildReconQuery(logSource, limit = 1000) {
    const endTime = new Date();
    const startTime = new Date(Date.now() - 60 * 60 * 1000);

    return {
      startTime: startTime.toISOString(),
      endTime: endTime.toISOString(),
      query: '',
      logSourceIds: logSource.id ? [logSource.id] : [],
      limit,
      filterType: 'Recon',
      searchedValues: []
    };
  }

  /**
   * Build ManageEngine v2 search query
   * @param {string} filterType - IOC type
   * @param {string[]} values - IOC values
   * @param {Object} options - Search options
   * @returns {Object} - ManageEngine query parameters
   */
  buildQuery(filterType, values, options = {}) {
    const { minutesBack = 5, customFields, customQueryTemplate } = options;

    const endTime = new Date();
    const startTime = new Date(Date.now() - minutesBack * 60 * 1000);

    // Build the query string using field conditions
    let queryString;
    if (customQueryTemplate) {
      const escapedValues = values.map(v => this.escapeQueryValue(v));
      queryString = customQueryTemplate
        .replace('{{values}}', escapedValues.join(','))
        .replace('{{fieldConditions}}', this.buildQueryString(filterType, values, customFields));
      console.log('[MANAGEENGINE] Using custom query template');
    } else {
      queryString = this.buildQueryString(filterType, values, customFields);
    }

    return {
      startTime: startTime.toISOString(),
      endTime: endTime.toISOString(),
      query: queryString,
      logSourceIds: options.logSourceIds || [],
      logTypes: options.logTypes || [],
      limit: options.limit || 1000,
      filterType,
      searchedValues: values
    };
  }

  /**
   * Execute synchronous search via ManageEngine v2 API
   * POST /api/v2/search
   */
  async executeSearch(query, options = {}) {
    try {
      const requestBody = {
        query: query.query,
        start_time: query.startTime,
        end_time: query.endTime
      };

      // Add optional filters
      if (query.logSourceIds && query.logSourceIds.length > 0) {
        requestBody.log_source_ids = query.logSourceIds;
      }
      if (query.logTypes && query.logTypes.length > 0) {
        requestBody.log_types = query.logTypes;
      }

      const response = await this.makeRequest({
        method: 'POST',
        url: `${this.baseUrl}/api/v2/search`,
        headers: this.getAuthHeaders(),
        data: requestBody,
        timeout: options.timeout || 60000
      });

      if (response.status === 200) {
        const hits = response.data?.data?.hits || [];
        const meta = response.data?.meta || {};
        const cursor = meta.cursor || null;
        const totalItems = meta.total_items || hits.length;

        // If there are more results, fetch additional pages using cursor
        let allHits = [...hits];
        let currentCursor = cursor;
        const maxPages = 10; // Safety limit
        let pageCount = 1;

        while (currentCursor && pageCount < maxPages && allHits.length < totalItems) {
          try {
            const nextResponse = await this.makeRequest({
              method: 'POST',
              url: `${this.baseUrl}/api/v2/search`,
              headers: this.getAuthHeaders(),
              data: { cursor: currentCursor },
              timeout: options.timeout || 60000
            });

            const nextHits = nextResponse.data?.data?.hits || [];
            if (nextHits.length === 0) break;

            allHits = allHits.concat(nextHits);
            currentCursor = nextResponse.data?.meta?.cursor || null;
            pageCount++;
          } catch (pageError) {
            console.warn('[MANAGEENGINE] Pagination error:', pageError.message);
            break;
          }
        }

        return {
          status: 'complete',
          results: allHits,
          complete: true,
          resultCount: totalItems,
          query
        };
      }

      if (response.status === 401) {
        throw new Error('Authentication failed. Check your Bearer token.');
      }

      throw new Error(`ManageEngine search returned status ${response.status}`);
    } catch (error) {
      throw new Error(`ManageEngine search failed: ${error.message}`);
    }
  }

  /**
   * Execute asynchronous search via ManageEngine v2 API
   * POST /api/v2/search/async
   * Returns a request_id for polling
   */
  async executeAsyncSearch(query, options = {}) {
    try {
      const requestBody = {
        query: query.query,
        start_time: query.startTime,
        end_time: query.endTime
      };

      if (query.logSourceIds && query.logSourceIds.length > 0) {
        requestBody.log_source_ids = query.logSourceIds;
      }
      if (query.logTypes && query.logTypes.length > 0) {
        requestBody.log_types = query.logTypes;
      }

      const response = await this.makeRequest({
        method: 'POST',
        url: `${this.baseUrl}/api/v2/search/async`,
        headers: this.getAuthHeaders(),
        data: requestBody,
        timeout: options.timeout || 30000
      });

      if (response.status === 200 && response.data?.data?.request_id) {
        return {
          status: 'searching',
          taskId: response.data.data.request_id,
          complete: false
        };
      }

      throw new Error(`Async search initiation failed: ${response.status}`);
    } catch (error) {
      throw new Error(`ManageEngine async search failed: ${error.message}`);
    }
  }

  /**
   * Poll async search status and retrieve results
   * GET /api/v2/jobs?request_id=...
   * GET /api/v2/jobs/results?request_id=...
   */
  async pollResults(taskId, options = {}) {
    const maxAttempts = options.maxAttempts || 30;
    const pollInterval = options.pollInterval || 3000;

    for (let attempt = 0; attempt < maxAttempts; attempt++) {
      try {
        // Check job status
        const statusResponse = await this.makeRequest({
          method: 'GET',
          url: `${this.baseUrl}/api/v2/jobs`,
          headers: this.getAuthHeaders(),
          params: { request_id: taskId },
          timeout: 15000
        });

        const jobData = statusResponse.data?.data || {};
        const stage = jobData.stage || '';

        if (stage === 'COMPLETED' || stage === 'completed') {
          // Fetch results
          const resultsResponse = await this.makeRequest({
            method: 'GET',
            url: `${this.baseUrl}/api/v2/jobs/results`,
            headers: this.getAuthHeaders(),
            params: { request_id: taskId },
            timeout: 30000
          });

          const hits = resultsResponse.data?.data?.hits || [];
          const totalItems = resultsResponse.data?.meta?.total_items || hits.length;

          return {
            status: 'complete',
            results: hits,
            complete: true,
            resultCount: totalItems
          };
        }

        if (stage === 'FAILED' || stage === 'failed') {
          return {
            status: 'failed',
            results: [],
            complete: true,
            error: jobData.message || 'Search failed'
          };
        }

        // Still running — wait and retry
        if (attempt < maxAttempts - 1) {
          await new Promise(resolve => setTimeout(resolve, pollInterval));
        }
      } catch (error) {
        console.warn(`[MANAGEENGINE] Poll attempt ${attempt + 1} failed:`, error.message);
        if (attempt >= maxAttempts - 1) {
          return {
            status: 'error',
            results: [],
            complete: true,
            error: `Polling failed after ${maxAttempts} attempts: ${error.message}`
          };
        }
        await new Promise(resolve => setTimeout(resolve, pollInterval));
      }
    }

    return {
      status: 'timeout',
      results: [],
      complete: true,
      error: 'Search polling timed out'
    };
  }

  /**
   * Normalize ManageEngine results to unified format
   */
  normalizeResults(rawResults, filterType, searchedValues) {
    if (!Array.isArray(rawResults)) {
      return [];
    }

    return rawResults.map((item) => ({
      siemType: 'manageengine',
      client: this.config.client,
      timestamp: item.EVENT_TIME || item.TIMESTAMP || item.event_time || item.Time || new Date().toISOString(),
      sourceIP: item.SOURCE_IP || item.CLIENT_IP || item.Source || '',
      destIP: item.DESTINATION_IP || item.HOST_IP || item.Destination || '',
      hostname: item.HOST_NAME || item.DEVICE_NAME || item.Device || '',
      username: item.USER_NAME || item.SOURCE_USER || item.User || '',
      eventType: item.EVENT_TYPE || item.LOG_TYPE || item.LogType || item.Type || '',
      rawLog: item.RAW_LOG || item.MESSAGE || item.Message || '',
      matchedIOC: this.findMatchedIOC(item, searchedValues, filterType),
      matchedIOCType: filterType,
      severity: this.mapSeverity(item.SEVERITY || item.Severity || item.PRIORITY),
      additionalFields: {
        eventId: item.EVENT_ID || item.EventID,
        logSource: item.LOG_SOURCE || item.LogSource,
        deviceType: item.DEVICE_TYPE || item.DeviceType,
        action: item.ACTION || item.Action,
        status: item.STATUS || item.Status,
        protocol: item.PROTOCOL || item.Protocol,
        port: item.PORT || item.Port
      }
    }));
  }

  /**
   * Find which IOC matched in the result
   */
  findMatchedIOC(item, searchedValues, filterType) {
    const fields = this.fieldMappings[filterType] || [];

    for (const field of fields) {
      const value = item[field];
      if (value) {
        const valueLower = String(value).toLowerCase();
        for (const ioc of searchedValues) {
          if (valueLower.includes(ioc.toLowerCase())) {
            return ioc;
          }
        }
      }
    }

    // Check raw log / message
    const rawLog = item.RAW_LOG || item.MESSAGE || item.Message || '';
    if (rawLog) {
      const logLower = rawLog.toLowerCase();
      for (const ioc of searchedValues) {
        if (logLower.includes(ioc.toLowerCase())) {
          return ioc;
        }
      }
    }

    return searchedValues[0] || '';
  }

  /**
   * Map ManageEngine severity to standard severity
   */
  mapSeverity(severity) {
    if (!severity) return 'medium';

    const s = String(severity).toLowerCase();
    if (['critical', 'emergency', 'alert'].includes(s)) return 'critical';
    if (['high', 'error', 'err'].includes(s)) return 'high';
    if (['medium', 'warning', 'warn'].includes(s)) return 'medium';
    return 'low';
  }

  /**
   * Get configuration schema for ManageEngine
   */
  static getConfigSchema() {
    return [
      {
        name: 'apiHost',
        label: 'ManageEngine Server URL',
        type: 'text',
        required: true,
        placeholder: 'https://manageengine.example.com',
        description: 'Base URL of your EventLog Analyzer instance'
      },
      {
        name: 'port',
        label: 'Server Port',
        type: 'number',
        required: false,
        defaultValue: 8400,
        placeholder: '8400',
        description: 'Default: 8400'
      },
      {
        name: 'apiKey',
        label: 'API Key / Bearer Token (Required)',
        type: 'password',
        required: true,
        placeholder: 'Bearer token from ManageEngine API settings',
        description: 'OAuth Bearer token. Generate from Admin > Settings > API in EventLog Analyzer.'
      },
      {
        name: 'verifySSL',
        label: 'Verify SSL Certificate',
        type: 'checkbox',
        required: false,
        defaultValue: true
      }
    ];
  }

  /**
   * Validate ManageEngine configuration
   */
  static validateConfig(config) {
    const errors = [];

    if (!config.apiHost) {
      errors.push('ManageEngine Server URL is required');
    }

    if (config.apiHost && !config.apiHost.match(/^https?:\/\/.+/)) {
      errors.push('ManageEngine Server URL must be a valid URL');
    }

    if (!config.apiKey) {
      errors.push('API Key (Bearer Token) is required');
    }

    if (config.port && (isNaN(config.port) || config.port < 1 || config.port > 65535)) {
      errors.push('Port must be a valid port number (1-65535)');
    }

    return {
      valid: errors.length === 0,
      errors
    };
  }
}

module.exports = ManageEngineAdapter;
