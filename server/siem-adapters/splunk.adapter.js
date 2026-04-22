/**
 * Splunk SIEM Adapter
 * Implements IOC search via Splunk REST API using SPL queries
 */
const BaseSiemAdapter = require('./base.adapter');

class SplunkAdapter extends BaseSiemAdapter {
  constructor(config) {
    super(config);
    this.name = 'splunk';

    // Default Splunk port is 8089 for management API
    this.port = config.port || 8089;
    this.baseUrl = this.normalizeUrl(config.apiHost);

    // Field mappings for different IOC types in Splunk
    // Includes common field names from various data sources (Sysmon, CrowdStrike, Exchange, O365, etc.)
    this.fieldMappings = {
      IP: ['src_ip', 'dest_ip', 'src', 'dst', 'clientip', 'client_ip', 'source_ip', 'destination_ip'],
      Hash: ['file_hash', 'md5', 'sha1', 'sha256', 'hash', 'FileHash'],
      Domain: ['url', 'dest_host', 'domain', 'host', 'site', 'uri_host', 'dest_dns'],
      URL: ['url', 'uri', 'uri_path', 'http_url', 'request_url', 'dest_url'],
      Email: [
        'sender', 'recipient', 'src_user', 'dest_user', 'email', 'mail_from', 'mail_to',
        // Exchange
        'sender_address', 'recipient_address',
        // O365
        'SenderAddress', 'RecipientAddress',
        // Proofpoint
        'fromAddress', 'toAddress'
      ],
      FileName: [
        'file_name', 'filename', 'process', 'process_name', 'parent_process', 'file_path',
        // Sysmon
        'Image', 'TargetFilename', 'OriginalFileName',
        // CrowdStrike
        'FileName', 'FilePath', 'ImageFileName',
        // Carbon Black
        'process_path', 'parent_path'
      ]
    };
  }

  /**
   * Normalize API URL (ensure proper format with port)
   */
  normalizeUrl(apiHost) {
    let url = apiHost.replace(/\/$/, ''); // Remove trailing slash

    // Add port if not present
    if (!url.match(/:\d+$/)) {
      // Check if it's https (default port 8089) or custom
      const portToUse = this.config.port || 8089;
      url = `${url}:${portToUse}`;
    }

    return url;
  }

  /**
   * Get authorization headers for Splunk API
   * Supports both Bearer token and Basic auth
   */
  getAuthHeaders() {
    const headers = {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Accept': 'application/json'
    };

    if (this.config.apiKey) {
      // Splunk auth token (recommended for production)
      headers['Authorization'] = `Bearer ${this.config.apiKey}`;
    } else if (this.config.username && this.config.password) {
      // Basic auth fallback
      console.warn('[SPLUNK] Using basic auth - API token recommended for production');
      const credentials = Buffer.from(`${this.config.username}:${this.config.password}`).toString('base64');
      headers['Authorization'] = `Basic ${credentials}`;
    }

    return headers;
  }

  /**
   * Test connectivity to Splunk API
   */
  async testConnection() {
    try {
      const response = await this.makeRequest({
        method: 'GET',
        url: `${this.baseUrl}/services/server/info`,
        headers: this.getAuthHeaders(),
        params: { output_mode: 'json' },
        timeout: 10000
      });

      if (response.status === 200 && response.data) {
        const serverInfo = response.data.entry?.[0]?.content || {};
        return {
          success: true,
          message: 'Successfully connected to Splunk API',
          data: {
            serverName: serverInfo.serverName,
            version: serverInfo.version,
            build: serverInfo.build
          }
        };
      }

      if (response.status === 401 || response.status === 403) {
        return {
          success: false,
          message: `Authentication failed for Splunk at ${this.baseUrl}. Check your API token or credentials.`,
          suggestion: 'Verify your Splunk auth token or username/password. The token may have expired.',
          category: 'auth'
        };
      }

      return {
        success: false,
        message: `Unexpected response from Splunk (HTTP ${response.status}).`,
        suggestion: 'Verify the Splunk URL and API port (default 8089). Ensure the Splunk management API is enabled.',
        category: 'server'
      };
    } catch (error) {
      return {
        success: false,
        message: error.message || `Connection failed to Splunk at ${this.baseUrl}.`,
        suggestion: error.suggestion || 'Check the Splunk URL, port, and network connectivity. Ensure the service is running.',
        category: error.category || 'connection'
      };
    }
  }

  /**
   * Splunk uses direct token auth (no separate auth step)
   */
  async authenticate() {
    // If using username/password, we could get a session key here
    // For now, assuming Bearer token is provided
    return { authenticated: true };
  }

  /**
   * Get available sourcetypes from Splunk (for Recon)
   */
  async getLogSources() {
    try {
      const response = await this.makeRequest({
        method: 'POST',
        url: `${this.baseUrl}/services/search/jobs`,
        headers: this.getAuthHeaders(),
        data: new URLSearchParams({
          search: '| metadata type=sourcetypes | table sourcetype totalCount | sort -totalCount',
          earliest_time: '-24h',
          latest_time: 'now',
          output_mode: 'json',
          exec_mode: 'oneshot'
        }).toString(),
        timeout: 60000
      });

      const results = response.data?.results || [];
      return results.map(r => ({
        id: r.sourcetype,
        name: r.sourcetype,
        type: 'sourcetype',
        count: r.totalCount
      }));
    } catch (error) {
      console.warn('Splunk getLogSources error:', error.message);
      return [];
    }
  }

  /**
   * Build raw log retrieval query for Recon (no IOC filter)
   */
  buildReconQuery(logSource, limit = 1000) {
    // Sanitize sourcetype to prevent SPL injection
    const safeSourcetype = logSource.id ? this.escapeForSPL(String(logSource.id)) : '';
    const safeLimit = Math.min(Math.max(1, parseInt(limit, 10) || 1000), 10000);
    const stPart = safeSourcetype ? `sourcetype="${safeSourcetype}"` : '';
    const query = `search index=* ${stPart} | head ${safeLimit}`;

    return {
      search: query,
      earliest_time: '-60m',
      latest_time: 'now',
      output_mode: 'json',
      max_count: limit
    };
  }

  /**
   * Build Splunk SPL query
   * @param {string} filterType - IOC type (IP, Hash, Domain, URL, Email, FileName)
   * @param {string[]} values - IOC values to search for
   * @param {Object} options - Search options
   * @returns {Object} - Splunk search configuration
   */
  buildQuery(filterType, values, options = {}) {
    const { minutesBack = 5, index = '*', logSources, customFields, customQueryTemplate } = options;

    // Escape special characters in values for SPL
    const escapedValues = values.map(v => this.escapeForSPL(v));

    // Use custom fields from Recon if available, otherwise hardcoded defaults
    const fields = customFields || this.fieldMappings[filterType] || [];
    const fieldConditions = fields.map(field => {
      const valueList = escapedValues.map(v => `"${v}"`).join(', ');
      return `${field} IN (${valueList})`;
    }).join(' OR ');

    // Resolve index: explicit `index` option wins; else logSources[].name OR'd; else '*'
    let resolvedIndex = index;
    if ((!index || index === '*') && Array.isArray(logSources) && logSources.length > 0) {
      const indexList = logSources
        .map(ls => (ls?.name ?? ls?.id ?? '').toString().trim())
        .filter(Boolean)
        .map(n => n.replace(/[|`;\[\]{}\s"']/g, ''));
      if (indexList.length > 0) {
        resolvedIndex = indexList.length === 1 ? indexList[0] : `(${indexList.map(i => `index=${i}`).join(' OR ')})`;
      }
    }
    const safeIndex = (resolvedIndex || '*').toString().replace(/[|`;\[\]{}]/g, '');

    let splQuery;
    if (customQueryTemplate) {
      // Use admin-defined custom template with variable substitution
      splQuery = customQueryTemplate
        .replace(/\{\{index\}\}/g, safeIndex)
        .replace(/\{\{fieldConditions\}\}/g, fieldConditions)
        .replace(/\{\{minutesBack\}\}/g, String(minutesBack))
        .replace(/\{\{values\}\}/g, escapedValues.map(v => `"${v}"`).join(', '));
      console.log(`🔧 [SPLUNK] Using custom SPL: ${splQuery.substring(0, 200)}`);
    } else {
      // If safeIndex already contains "index=" (multi-index OR group), use as-is
      const indexClause = safeIndex.startsWith('(') ? safeIndex : `index=${safeIndex}`;
      splQuery = `search ${indexClause} (${fieldConditions}) | head 1000`;
    }

    return {
      search: splQuery,
      earliest_time: `-${minutesBack}m`,
      latest_time: 'now',
      output_mode: 'json',
      max_count: 1000,
      filterType,
      searchedValues: values
    };
  }

  /**
   * Escape special characters for SPL
   */
  escapeForSPL(value) {
    if (!value) return value;
    return String(value)
      .replace(/\\/g, '\\\\')
      .replace(/"/g, '\\"')
      .replace(/'/g, "\\'")
      .replace(/`/g, '\\`')
      .replace(/\|/g, '\\|')
      .replace(/\[/g, '\\[')
      .replace(/\]/g, '\\]');
  }

  /**
   * Execute search in Splunk (async - creates a search job)
   */
  async executeSearch(query, options = {}) {
    const searchUrl = `${this.baseUrl}/services/search/jobs`;
    const timeout = options.timeout || 30000;

    try {
      // Create search job
      const response = await this.makeRequest({
        method: 'POST',
        url: searchUrl,
        headers: this.getAuthHeaders(),
        data: new URLSearchParams({
          search: query.search,
          earliest_time: query.earliest_time,
          latest_time: query.latest_time,
          output_mode: 'json'
        }).toString(),
        timeout
      });

      // Splunk returns SID (Search ID) in response
      const sid = response.data?.sid;

      if (!sid) {
        throw new Error('No search ID (sid) returned from Splunk');
      }

      return {
        taskId: sid,
        status: 'searching',
        complete: false,
        query // Include query info for result normalization
      };
    } catch (error) {
      throw new Error(`Splunk search failed: ${error.message}`);
    }
  }

  /**
   * Poll for Splunk search results
   */
  async pollResults(taskId, options = {}) {
    const {
      pollingInterval = 5000,
      maxAttempts = 24 // 2 minutes max with 5s intervals
    } = options;

    // Sanitize taskId to prevent path traversal in URL
    const safeTaskId = encodeURIComponent(String(taskId));
    const statusUrl = `${this.baseUrl}/services/search/jobs/${safeTaskId}`;
    const resultsUrl = `${this.baseUrl}/services/search/jobs/${safeTaskId}/results`;

    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      try {
        // Check job status
        const statusResponse = await this.makeRequest({
          method: 'GET',
          url: statusUrl,
          headers: this.getAuthHeaders(),
          params: { output_mode: 'json' },
          timeout: 15000
        });

        const jobStatus = statusResponse.data?.entry?.[0]?.content;
        const dispatchState = jobStatus?.dispatchState;

        if (dispatchState === 'DONE') {
          // Fetch results
          const resultsResponse = await this.makeRequest({
            method: 'GET',
            url: resultsUrl,
            headers: this.getAuthHeaders(),
            params: {
              output_mode: 'json',
              count: 1000
            },
            timeout: 300000
          });

          const results = resultsResponse.data?.results || [];

          return {
            status: 'complete',
            results: results,
            complete: true,
            resultCount: results.length
          };
        }

        if (dispatchState === 'FAILED') {
          return {
            status: 'failed',
            results: [],
            complete: true,
            error: jobStatus?.messages?.[0]?.text || 'Search job failed'
          };
        }

        // Still running
        console.log(`Splunk poll ${attempt}/${maxAttempts}: ${dispatchState}`);
        await this.wait(pollingInterval);

      } catch (error) {
        console.error(`Splunk poll ${attempt} error:`, error.message);
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
   * Normalize Splunk results to unified format
   */
  normalizeResults(rawResults, filterType, searchedValues) {
    if (!Array.isArray(rawResults)) {
      return [];
    }

    return rawResults.map((item) => ({
      siemType: 'splunk',
      client: this.config.client,
      timestamp: item._time || item.timestamp || new Date().toISOString(),
      sourceIP: item.src_ip || item.src || item.clientip || '',
      destIP: item.dest_ip || item.dest || '',
      hostname: item.host || item.dest_host || '',
      username: item.user || item.src_user || item.dest_user || '',
      eventType: item.eventtype || item.sourcetype || '',
      rawLog: item._raw || '',
      matchedIOC: this.findMatchedIOC(item, searchedValues, filterType),
      matchedIOCType: filterType,
      severity: this.mapSeverity(item.severity || item.priority),
      additionalFields: {
        source: item.source,
        sourcetype: item.sourcetype,
        index: item.index,
        action: item.action,
        app: item.app,
        url: item.url,
        file_hash: item.file_hash || item.md5 || item.sha256
      }
    }));
  }

  /**
   * Find which IOC matched in the result
   */
  findMatchedIOC(item, searchedValues, filterType) {
    const fields = this.fieldMappings[filterType] || [];
    const allValues = fields
      .map(f => item[f])
      .filter(Boolean)
      .map(v => String(v).toLowerCase());

    for (const ioc of searchedValues) {
      const lowerIOC = ioc.toLowerCase();
      if (allValues.some(v => v.includes(lowerIOC))) {
        return ioc;
      }
    }

    // Also check _raw
    if (item._raw) {
      const rawLower = item._raw.toLowerCase();
      for (const ioc of searchedValues) {
        if (rawLower.includes(ioc.toLowerCase())) {
          return ioc;
        }
      }
    }

    return searchedValues[0] || '';
  }

  /**
   * Map Splunk severity to standard severity
   */
  mapSeverity(severity) {
    if (!severity) return 'unknown';
    const s = String(severity).toLowerCase();
    if (s === 'critical' || s === 'fatal') return 'critical';
    if (s === 'high') return 'high';
    if (s === 'medium' || s === 'warning' || s === 'warn') return 'medium';
    if (s === 'low' || s === 'info' || s === 'informational') return 'low';
    return 'unknown';
  }

  /**
   * Get configuration schema for Splunk
   */
  static getConfigSchema() {
    return [
      {
        name: 'apiHost',
        label: 'Splunk API Host',
        type: 'text',
        required: true,
        placeholder: 'https://splunk.example.com'
      },
      {
        name: 'port',
        label: 'Management Port',
        type: 'number',
        required: false,
        defaultValue: 8089,
        placeholder: '8089'
      },
      {
        name: 'apiKey',
        label: 'Auth Token (Recommended)',
        type: 'password',
        required: false,
        placeholder: 'Splunk auth token (preferred for production)',
        description: 'Primary authentication method. Use a Splunk authentication token for secure API access.'
      },
      {
        name: 'username',
        label: 'Username (Fallback)',
        type: 'text',
        required: false,
        placeholder: 'Splunk username (only if not using token)',
        description: 'Optional fallback. API token is recommended instead.'
      },
      {
        name: 'password',
        label: 'Password (Fallback)',
        type: 'password',
        required: false,
        placeholder: 'Splunk password (only if not using token)',
        description: 'Optional fallback. API token is recommended instead.'
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
   * Validate Splunk configuration
   */
  static validateConfig(config) {
    const errors = [];

    if (!config.apiHost) {
      errors.push('API Host is required');
    }

    if (config.apiHost && !config.apiHost.match(/^https?:\/\/.+/)) {
      errors.push('API Host must be a valid URL');
    }

    // Either apiKey OR (username + password) is required
    if (!config.apiKey && (!config.username || !config.password)) {
      errors.push('Either API Token or Username/Password is required');
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

module.exports = SplunkAdapter;
