/**
 * IBM QRadar SIEM Adapter
 * Implements IOC search via QRadar Ariel REST API using AQL queries
 */
const BaseSiemAdapter = require('./base.adapter');

class QRadarAdapter extends BaseSiemAdapter {
  constructor(config) {
    super(config);
    this.name = 'qradar';

    // QRadar API version (default to 15.0)
    this.apiVersion = config.apiVersion || '15.0';

    // Field mappings for different IOC types in QRadar AQL
    // Includes common QRadar field names and custom properties
    this.fieldMappings = {
      IP: ['sourceip', 'destinationip', 'identityip', 'SourceIP', 'DestinationIP'],
      Hash: ['MD5Hash', 'SHA256Hash', 'SHA1Hash', 'Filename_Hash', 'File_Hash', 'FileHash', 'ProcessHash'],
      Domain: ['UrlHost', 'DomainName', 'DNS_RequestedHost', 'HostName', 'FQDN', 'dns_query'],
      URL: ['URL', 'UrlPath', 'RequestURL', 'FullURL', 'URI', 'http_url'],
      Email: [
        'Sender', 'Recipient', 'EmailAddress', 'MailFrom', 'MailTo',
        'SenderAddress', 'RecipientAddress', 'FromAddress', 'ToAddress',
        'email_sender', 'email_recipient'
      ],
      FileName: [
        'Filename', 'Process_Name', 'Process_Path', 'File_Path',
        'Image', 'TargetFilename', 'ParentImage', 'OriginalFilename',
        'ImagePath', 'ProcessName', 'ParentProcessName', 'CommandLine'
      ]
    };

    // QRadar log source type IDs for reference
    this.logSourceTypes = {
      firewall: 'devicetype=11',
      ids: 'devicetype=12',
      proxy: 'devicetype=14',
      endpoint: 'devicetype=19'
    };
  }

  /**
   * Get authorization headers for QRadar API
   * QRadar uses SEC token in header
   */
  getAuthHeaders() {
    const headers = {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
      'Version': this.apiVersion
    };

    if (this.config.apiKey) {
      // QRadar SEC token (recommended)
      headers['SEC'] = this.config.apiKey;
    } else if (this.config.username && this.config.password) {
      // Basic auth fallback
      console.warn('[QRADAR] Using basic auth - SEC token recommended for production');
      const credentials = Buffer.from(`${this.config.username}:${this.config.password}`).toString('base64');
      headers['Authorization'] = `Basic ${credentials}`;
    }

    return headers;
  }

  /**
   * Test connectivity to QRadar API
   */
  async testConnection() {
    try {
      const response = await this.makeRequest({
        method: 'GET',
        url: `${this.config.apiHost}/api/system/servers`,
        headers: this.getAuthHeaders(),
        timeout: 10000
      });

      if (response.status === 200 && response.data) {
        const servers = response.data;
        return {
          success: true,
          message: 'Successfully connected to QRadar API',
          data: {
            serverCount: Array.isArray(servers) ? servers.length : 1,
            hostname: servers[0]?.hostname || 'unknown'
          }
        };
      }

      if (response.status === 401 || response.status === 403) {
        return {
          success: false,
          message: `Authentication failed for QRadar at ${this.config.apiHost}. Check your SEC token.`,
          suggestion: 'Verify your QRadar SEC authorization token. Ensure it has the required API permissions.',
          category: 'auth'
        };
      }

      return {
        success: false,
        message: `Unexpected response from QRadar (HTTP ${response.status}).`,
        suggestion: 'Verify the QRadar Console URL. Ensure the API is accessible and the API version is correct.',
        category: 'server'
      };
    } catch (error) {
      return {
        success: false,
        message: error.message || `Connection failed to QRadar at ${this.config.apiHost}.`,
        suggestion: error.suggestion || 'Check the QRadar URL and SEC token. Ensure the QRadar console is running and accessible.',
        category: error.category || 'connection'
      };
    }
  }

  /**
   * QRadar uses SEC token auth (no separate auth step)
   */
  async authenticate() {
    return { authenticated: true };
  }

  /**
   * Get available log sources from QRadar (for Recon)
   */
  async getLogSources() {
    try {
      const response = await this.makeRequest({
        method: 'GET',
        url: `${this.config.apiHost}/api/config/event_sources/log_source_management/log_sources`,
        headers: this.getAuthHeaders(),
        params: { fields: 'id,name,type_id,enabled', filter: 'enabled=true' },
        timeout: 30000
      });

      const sources = response.data || [];
      return (Array.isArray(sources) ? sources : []).map(s => ({
        id: String(s.id),
        name: s.name,
        type: 'log_source',
        enabled: s.enabled
      }));
    } catch (error) {
      console.warn('QRadar getLogSources error:', error.message);
      return [];
    }
  }

  /**
   * Build raw log retrieval query for Recon (no IOC filter)
   */
  buildReconQuery(logSource, limit = 1000) {
    // Validate logsourceid and limit are integers to prevent AQL injection
    const safeId = parseInt(logSource.id, 10);
    const safeLimit = Math.min(Math.max(1, parseInt(limit, 10) || 1000), 10000);
    if (isNaN(safeId) || safeId < 0) {
      throw new Error('Invalid log source ID');
    }
    const aql = `SELECT * FROM events WHERE logsourceid=${safeId} LAST 60 MINUTES LIMIT ${safeLimit}`;
    return {
      query_expression: aql,
      filterType: 'Recon',
      searchedValues: []
    };
  }

  /**
   * Build QRadar AQL query
   * @param {string} filterType - IOC type (IP, Hash, Domain, URL, Email, FileName)
   * @param {string[]} values - IOC values to search for
   * @param {Object} options - Search options
   * @returns {Object} - QRadar search configuration
   */
  buildQuery(filterType, values, options = {}) {
    const { minutesBack = 5, customFields, customQueryTemplate } = options;

    // Escape values for AQL
    const escapedValues = values.map(v => this.escapeForAQL(v));

    // Use custom fields from Recon if available, otherwise hardcoded defaults
    const fields = customFields || this.fieldMappings[filterType] || [];

    // Build OR conditions for all fields and values
    const conditions = fields.flatMap(field => {
      return escapedValues.map(value => {
        if (filterType === 'IP') {
          return `${field}='${value}'`;
        } else {
          return `LOWER(${field}) LIKE '%${value.toLowerCase()}%'`;
        }
      });
    }).join(' OR ');

    let aqlQuery;
    if (customQueryTemplate) {
      aqlQuery = customQueryTemplate
        .replace(/\{\{fieldConditions\}\}/g, conditions)
        .replace(/\{\{minutesBack\}\}/g, String(minutesBack))
        .replace(/\{\{values\}\}/g, escapedValues.map(v => `'${v}'`).join(', '));
      console.log(`🔧 [QRADAR] Using custom AQL: ${aqlQuery.substring(0, 200)}`);
    } else {
      aqlQuery = `SELECT * FROM events WHERE (${conditions}) LAST ${minutesBack} MINUTES`;
    }

    return {
      query_expression: aqlQuery,
      filterType,
      searchedValues: values
    };
  }

  /**
   * Escape special characters for AQL
   */
  escapeForAQL(value) {
    if (!value) return value;
    return String(value)
      .replace(/\\/g, '\\\\')
      .replace(/'/g, "\\'")
      .replace(/%/g, '\\%')
      .replace(/_/g, '\\_');
  }

  /**
   * Execute search in QRadar (async - creates an Ariel search)
   */
  async executeSearch(query, options = {}) {
    const searchUrl = `${this.config.apiHost}/api/ariel/searches`;

    try {
      const response = await this.makeRequest({
        method: 'POST',
        url: searchUrl,
        headers: this.getAuthHeaders(),
        params: {
          query_expression: query.query_expression
        },
        timeout: options.timeout || 30000
      });

      const searchId = response.data?.search_id;

      if (!searchId) {
        throw new Error('No search_id returned from QRadar');
      }

      return {
        taskId: searchId,
        status: 'searching',
        complete: false,
        query // Include query info for result normalization
      };
    } catch (error) {
      throw new Error(`QRadar search failed: ${error.message}`);
    }
  }

  /**
   * Poll for QRadar search results
   */
  async pollResults(taskId, options = {}) {
    const {
      pollingInterval = 5000,
      maxAttempts = 60
    } = options;

    // Sanitize taskId to prevent path traversal in URL
    const safeTaskId = encodeURIComponent(String(taskId));
    const statusUrl = `${this.config.apiHost}/api/ariel/searches/${safeTaskId}`;
    const resultsUrl = `${this.config.apiHost}/api/ariel/searches/${safeTaskId}/results`;

    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      try {
        // Check search status
        const statusResponse = await this.makeRequest({
          method: 'GET',
          url: statusUrl,
          headers: this.getAuthHeaders(),
          timeout: 30000
        });

        const status = statusResponse.data?.status;

        if (status === 'COMPLETED') {
          // Fetch results
          const resultsResponse = await this.makeRequest({
            method: 'GET',
            url: resultsUrl,
            headers: {
              ...this.getAuthHeaders(),
              'Range': 'items=0-999' // Get first 1000 results
            },
            timeout: 300000
          });

          const results = resultsResponse.data?.events || resultsResponse.data || [];

          return {
            status: 'complete',
            results: Array.isArray(results) ? results : [],
            complete: true,
            resultCount: statusResponse.data?.record_count || results.length
          };
        }

        if (status === 'ERROR' || status === 'CANCELED') {
          return {
            status: 'failed',
            results: [],
            complete: true,
            error: statusResponse.data?.error_messages?.[0] || `Search ${status.toLowerCase()}`
          };
        }

        // Still running (WAIT, SORTING, EXECUTING)
        console.log(`QRadar poll ${attempt}/${maxAttempts}: ${status} (${statusResponse.data?.progress || 0}%)`);
        await this.wait(pollingInterval);

      } catch (error) {
        console.error(`QRadar poll ${attempt} error:`, error.message);
        await this.wait(pollingInterval);
      }
    }

    return {
      status: 'timeout',
      results: [],
      complete: true,
      error: `Polling timeout after ${maxAttempts} attempts`
    };
  }

  /**
   * Normalize QRadar results to unified format
   */
  normalizeResults(rawResults, filterType, searchedValues) {
    if (!Array.isArray(rawResults)) {
      return [];
    }

    return rawResults.map((item) => ({
      siemType: 'qradar',
      client: this.config.client,
      timestamp: this.parseQRadarTimestamp(item.starttime || item.devicetime),
      sourceIP: item.sourceip || '',
      destIP: item.destinationip || '',
      hostname: item.hostname || item.identityhostname || '',
      username: item.username || item.identityname || '',
      eventType: item.qidname || item.eventname || item.logsourcename || '',
      rawLog: item.utf8_payload || item.payload || '',
      matchedIOC: this.findMatchedIOC(item, searchedValues, filterType),
      matchedIOCType: filterType,
      severity: this.mapSeverity(item.severity || item.magnitude),
      additionalFields: {
        logsourceid: item.logsourceid,
        logsourcename: item.logsourcename,
        qid: item.qid,
        category: item.category,
        credibility: item.credibility,
        relevance: item.relevance,
        magnitude: item.magnitude,
        protocolid: item.protocolid,
        sourceport: item.sourceport,
        destinationport: item.destinationport
      }
    }));
  }

  /**
   * Parse QRadar timestamp (epoch milliseconds)
   */
  parseQRadarTimestamp(timestamp) {
    if (!timestamp) return new Date().toISOString();

    // QRadar timestamps are in epoch milliseconds
    if (typeof timestamp === 'number') {
      return new Date(timestamp).toISOString();
    }

    return timestamp;
  }

  /**
   * Find which IOC matched in the result
   */
  findMatchedIOC(item, searchedValues, filterType) {
    const fields = this.fieldMappings[filterType] || [];
    const allValues = fields
      .map(f => item[f.toLowerCase()] || item[f])
      .filter(Boolean)
      .map(v => String(v).toLowerCase());

    for (const ioc of searchedValues) {
      const lowerIOC = ioc.toLowerCase();
      if (allValues.some(v => v.includes(lowerIOC))) {
        return ioc;
      }
    }

    // Check payload
    const payload = item.utf8_payload || item.payload || '';
    if (payload) {
      const payloadLower = payload.toLowerCase();
      for (const ioc of searchedValues) {
        if (payloadLower.includes(ioc.toLowerCase())) {
          return ioc;
        }
      }
    }

    return searchedValues[0] || '';
  }

  /**
   * Map QRadar severity/magnitude to standard severity
   */
  mapSeverity(value) {
    if (!value) return 'medium';

    const v = parseInt(value, 10);
    if (v >= 8) return 'critical';
    if (v >= 6) return 'high';
    if (v >= 4) return 'medium';
    return 'low';
  }

  /**
   * Get configuration schema for QRadar
   */
  static getConfigSchema() {
    return [
      {
        name: 'apiHost',
        label: 'QRadar Console URL',
        type: 'text',
        required: true,
        placeholder: 'https://qradar.example.com'
      },
      {
        name: 'apiKey',
        label: 'SEC Token (Recommended)',
        type: 'password',
        required: true,
        placeholder: 'QRadar SEC authorization token',
        description: 'Primary authentication method. Generate a SEC token from QRadar Admin > Authorized Services.'
      },
      {
        name: 'apiVersion',
        label: 'API Version',
        type: 'text',
        required: false,
        defaultValue: '15.0',
        placeholder: '15.0'
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
   * Validate QRadar configuration
   */
  static validateConfig(config) {
    const errors = [];

    if (!config.apiHost) {
      errors.push('QRadar Console URL is required');
    }

    if (config.apiHost && !config.apiHost.match(/^https?:\/\/.+/)) {
      errors.push('QRadar Console URL must be a valid URL');
    }

    if (!config.apiKey) {
      errors.push('SEC Token is required');
    }

    return {
      valid: errors.length === 0,
      errors
    };
  }
}

module.exports = QRadarAdapter;
