/**
 * Wazuh SIEM Adapter
 * Implements IOC search via Wazuh REST API
 * Wazuh uses JWT authentication and Elasticsearch as backend
 */
const BaseSiemAdapter = require('./base.adapter');

class WazuhAdapter extends BaseSiemAdapter {
  constructor(config) {
    super(config);
    this.name = 'wazuh';

    // Default Wazuh API port
    this.port = config.port || 55000;
    this.baseUrl = this.normalizeUrl(config.apiHost);

    // JWT token cache
    this.authToken = null;
    this.tokenExpiry = null;

    // Wazuh Indexer config (OpenSearch backend for log-level searches)
    // If extraConfig has indexerUrl, use it for log-level search instead of alerts API
    this.indexerUrl = config.extraConfig?.indexerUrl || null;
    const extraConfig = config.extraConfig;
    this.indexerUsername = extraConfig?.indexerUsername;
    this.indexerPassword = extraConfig?.indexerPassword;
    if (this.indexerUrl && (!this.indexerUsername || !this.indexerPassword)) {
      console.warn('[WAZUH] Indexer URL is configured but indexerUsername/indexerPassword are missing. Indexer searches will fail without credentials.');
    }
    this.indexerPattern = config.extraConfig?.indexerPattern || 'wazuh-alerts-*';

    // Field mappings for Wazuh alert fields
    // Includes Syscheck, Windows events, and common data fields
    this.fieldMappings = {
      IP: [
        'data.srcip', 'data.dstip', 'agent.ip', 'data.src_ip', 'data.dst_ip',
        'data.win.eventdata.ipAddress', 'data.aws.sourceIPAddress'
      ],
      Hash: [
        'syscheck.md5_after', 'syscheck.sha1_after', 'syscheck.sha256_after',
        'syscheck.md5_before', 'data.md5', 'data.sha256',
        'data.win.eventdata.hashes', 'data.virustotal.sha256'
      ],
      Domain: [
        'data.url', 'data.hostname', 'data.dns.question.name',
        'data.win.eventdata.targetServerName', 'data.win.eventdata.destinationHostname',
        'data.aws.requestParameters.host'
      ],
      URL: ['data.url', 'data.uri', 'data.http.url', 'data.http.request.uri', 'data.full_url'],
      Email: [
        'data.srcuser', 'data.dstuser', 'data.win.eventdata.targetUserName',
        'data.win.eventdata.subjectUserName', 'data.aws.userIdentity.userName',
        'data.office365.SenderAddress', 'data.office365.RecipientAddress',
        'data.mail.from', 'data.mail.to'
      ],
      FileName: [
        'syscheck.path', 'data.filename', 'data.file', 'data.win.eventdata.image',
        // Sysmon via Wazuh
        'data.win.eventdata.targetFilename', 'data.win.eventdata.originalFileName',
        'data.win.eventdata.parentImage', 'data.win.eventdata.commandLine',
        // Audit
        'data.audit.file.name', 'data.audit.exe'
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
   * Get authorization headers for Wazuh API
   */
  getAuthHeaders() {
    const headers = {
      'Content-Type': 'application/json'
    };

    if (this.authToken) {
      headers['Authorization'] = `Bearer ${this.authToken}`;
    }

    return headers;
  }

  /**
   * Test connectivity to Wazuh API
   */
  async testConnection() {
    try {
      // First authenticate
      const authResult = await this.authenticate();
      if (!authResult.authenticated) {
        return {
          success: false,
          message: `Authentication failed for Wazuh at ${this.baseUrl}. Check your username and password.`,
          suggestion: 'Verify the Wazuh API username and password. The default user is "wazuh-wui". Ensure the Wazuh API is running on the configured port (default 55000).',
          category: 'auth'
        };
      }

      // Then test with manager info
      const response = await this.makeRequest({
        method: 'GET',
        url: `${this.baseUrl}/manager/info`,
        headers: this.getAuthHeaders(),
        timeout: 10000
      });

      if (response.status === 200 && response.data) {
        const info = response.data.data?.affected_items?.[0] || response.data;
        return {
          success: true,
          message: 'Successfully connected to Wazuh API',
          data: {
            version: info.version,
            compilationDate: info.compilation_date,
            type: info.type
          }
        };
      }

      return {
        success: false,
        message: `Unexpected response from Wazuh (HTTP ${response.status}).`,
        suggestion: 'Verify the Wazuh Manager URL and API port (default 55000). Ensure the Wazuh API service is running.',
        category: 'server'
      };
    } catch (error) {
      return {
        success: false,
        message: error.message || `Connection failed to Wazuh at ${this.baseUrl}.`,
        suggestion: error.suggestion || 'Check the Wazuh URL, port, and credentials. Ensure the Wazuh API service is running and SSL settings are correct.',
        category: error.category || 'connection'
      };
    }
  }

  /**
   * Authenticate with Wazuh API to get JWT token
   */
  async authenticate() {
    // Check if we have a valid cached token
    if (this.authToken && this.tokenExpiry && new Date() < this.tokenExpiry) {
      return { authenticated: true, token: this.authToken };
    }

    try {
      const authUrl = `${this.baseUrl}/security/user/authenticate`;

      // Wazuh uses Basic auth to get JWT token
      const credentials = Buffer.from(
        `${this.config.username}:${this.config.password}`
      ).toString('base64');

      const response = await this.makeRequest({
        method: 'POST',
        url: authUrl,
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Basic ${credentials}`
        },
        timeout: 10000
      });

      const token = response.data?.data?.token;

      if (!token) {
        throw new Error('No token received from Wazuh');
      }

      // Cache the token (default 15 minutes expiry)
      this.authToken = token;
      this.tokenExpiry = new Date(Date.now() + 14 * 60 * 1000); // 14 minutes

      return {
        authenticated: true,
        token: this.authToken,
        expiresAt: this.tokenExpiry
      };
    } catch (error) {
      this.authToken = null;
      this.tokenExpiry = null;
      return {
        authenticated: false,
        error: error.message
      };
    }
  }

  /**
   * Get available agents from Wazuh (for Recon)
   */
  async getLogSources() {
    try {
      const authResult = await this.authenticate();
      if (!authResult.authenticated) throw new Error('Wazuh auth failed');

      const response = await this.makeRequest({
        method: 'GET',
        url: `${this.baseUrl}/agents`,
        headers: this.getAuthHeaders(),
        params: { limit: 500, select: 'id,name,ip,status', status: 'active' },
        timeout: 30000
      });

      const agents = response.data?.data?.affected_items || [];
      return agents.map(a => ({
        id: a.id,
        name: `${a.name} (${a.ip})`,
        type: 'agent',
        status: a.status
      }));
    } catch (error) {
      console.warn('Wazuh getLogSources error:', error.message);
      return [];
    }
  }

  /**
   * Build raw log retrieval query for Recon (no IOC filter)
   */
  buildReconQuery(logSource, limit = 1000) {
    return {
      search: '',
      agentId: logSource.id,
      limit,
      filterType: 'Recon',
      searchedValues: []
    };
  }

  /**
   * Build Wazuh API query
   * @param {string} filterType - IOC type
   * @param {string[]} values - IOC values
   * @param {Object} options - Search options
   * @returns {Object} - Wazuh query parameters
   */
  buildQuery(filterType, values, options = {}) {
    const { minutesBack = 5, logSources, customFields, customQueryTemplate } = options;

    // Use custom fields from Recon if available, otherwise hardcoded defaults
    const fields = customFields || this.fieldMappings[filterType] || [];

    // Create OR conditions for all values across all fields (escape double quotes in IOC values)
    const escapedValues = values.map(v => `"${String(v).replace(/"/g, '\\"')}"`);
    const searchTerms = escapedValues.join(' OR ');

    // Optional agent scoping (Wazuh's "log sources" are agents)
    const agentIds = Array.isArray(logSources)
      ? logSources.map(ls => String(ls?.id ?? ls?.listId ?? ls?.name ?? '').trim()).filter(Boolean)
      : [];

    let search = searchTerms;
    if (customQueryTemplate) {
      search = customQueryTemplate
        .replace(/\{\{values\}\}/g, values.join(','))
        .replace(/\{\{fieldConditions\}\}/g, searchTerms)
        .replace(/\{\{minutesBack\}\}/g, String(minutesBack));
      console.log(`🔧 [WAZUH] Using custom query: ${search.substring(0, 200)}`);
    }

    return {
      search,
      minutesBack,
      filterType,
      searchedValues: values,
      fields,
      agentIds
    };
  }

  /**
   * Execute search in Wazuh
   * If indexerUrl is configured, searches the Wazuh Indexer (OpenSearch) for log-level results.
   * Otherwise falls back to the Wazuh Manager alerts API.
   */
  async executeSearch(query, options = {}) {
    // Prefer indexer-based search (log-level) if configured
    if (this.indexerUrl) {
      return this.executeIndexerSearch(query, options);
    }
    return this.executeAlertsSearch(query, options);
  }

  /**
   * Search via Wazuh Indexer (OpenSearch) - searches all logs/events
   */
  async executeIndexerSearch(query, options = {}) {
    const fields = query.fields || this.fieldMappings[query.filterType] || [];
    const values = query.searchedValues || [];

    // Build OpenSearch query DSL
    const shouldClauses = fields.flatMap(field => {
      if (query.filterType === 'IP') {
        return [{ terms: { [field]: values } }];
      } else {
        return values.map(value => ({
          wildcard: { [field]: { value: `*${value.toLowerCase()}*`, case_insensitive: true } }
        }));
      }
    });

    const must = [
      { range: { timestamp: { gte: `now-${query.minutesBack || 1440}m`, lte: 'now' } } }
    ];
    if (Array.isArray(query.agentIds) && query.agentIds.length > 0) {
      must.push({ terms: { 'agent.id': query.agentIds } });
    }

    const dslBody = {
      query: {
        bool: {
          must,
          should: shouldClauses,
          minimum_should_match: 1
        }
      },
      size: 1000,
      sort: [{ timestamp: 'desc' }]
    };

    const credentials = Buffer.from(`${this.indexerUsername}:${this.indexerPassword}`).toString('base64');

    try {
      console.log(`🔍 [WAZUH] Searching indexer at ${this.indexerUrl}/${this.indexerPattern}`);
      const response = await this.makeRequest({
        method: 'POST',
        url: `${this.indexerUrl}/${this.indexerPattern}/_search`,
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Basic ${credentials}`
        },
        data: dslBody,
        timeout: options.timeout || 60000
      });

      const hits = response.data?.hits?.hits || [];
      const results = hits.map(hit => hit._source);

      return {
        status: 'complete',
        results,
        complete: true,
        resultCount: response.data?.hits?.total?.value || results.length,
        query
      };
    } catch (error) {
      console.warn(`⚠️ [WAZUH] Indexer search failed, falling back to alerts API: ${error.message}`);
      return this.executeAlertsSearch(query, options);
    }
  }

  /**
   * Search via Wazuh Manager alerts API (alert-level only)
   */
  async executeAlertsSearch(query, options = {}, retried = false) {
    const authResult = await this.authenticate();
    if (!authResult.authenticated) {
      throw new Error('Wazuh authentication failed');
    }

    const alertsUrl = `${this.baseUrl}/alerts`;

    try {
      const response = await this.makeRequest({
        method: 'GET',
        url: alertsUrl,
        headers: this.getAuthHeaders(),
        params: {
          ...(query.search ? { q: query.search } : {}),
          ...(Array.isArray(query.agentIds) && query.agentIds.length > 0 ? { agents_list: query.agentIds.join(',') } : (query.agentId ? { agents_list: query.agentId } : {})),
          limit: query.limit || 1000,
          sort: '-timestamp'
        },
        timeout: options.timeout || 60000
      });

      if (response.status === 401 && !retried) {
        this.authToken = null;
        await this.authenticate();
        return this.executeAlertsSearch(query, options, true);
      }

      const alerts = response.data?.data?.affected_items || [];

      return {
        status: 'complete',
        results: alerts,
        complete: true,
        resultCount: response.data?.data?.total_affected_items || alerts.length,
        query
      };
    } catch (error) {
      throw new Error(`Wazuh search failed: ${error.message}`);
    }
  }

  /**
   * Wazuh API is synchronous, no polling needed
   */
  async pollResults(taskId, options = {}) {
    return {
      status: 'complete',
      results: [],
      complete: true
    };
  }

  /**
   * Normalize Wazuh results to unified format
   */
  normalizeResults(rawResults, filterType, searchedValues) {
    if (!Array.isArray(rawResults)) {
      return [];
    }

    return rawResults.map((item) => ({
      siemType: 'wazuh',
      client: this.config.client,
      timestamp: item.timestamp || item['@timestamp'] || new Date().toISOString(),
      sourceIP: item.data?.srcip || item.data?.src_ip || item.agent?.ip || '',
      destIP: item.data?.dstip || item.data?.dst_ip || '',
      hostname: item.agent?.name || item.manager?.name || '',
      username: item.data?.srcuser || item.data?.dstuser || '',
      eventType: item.rule?.description || item.rule?.id || '',
      rawLog: item.full_log || item.data?.data || JSON.stringify(item.data || {}),
      matchedIOC: this.findMatchedIOC(item, searchedValues, filterType),
      matchedIOCType: filterType,
      severity: this.mapSeverity(item.rule?.level),
      additionalFields: {
        ruleId: item.rule?.id,
        ruleLevel: item.rule?.level,
        ruleGroups: item.rule?.groups,
        agentId: item.agent?.id,
        agentName: item.agent?.name,
        decoderId: item.decoder?.name,
        location: item.location,
        syscheckPath: item.syscheck?.path
      }
    }));
  }

  /**
   * Find which IOC matched in the result
   */
  findMatchedIOC(item, searchedValues, filterType) {
    const fields = this.fieldMappings[filterType] || [];

    for (const field of fields) {
      const value = this.getNestedValue(item, field);
      if (value) {
        const valueLower = String(value).toLowerCase();
        for (const ioc of searchedValues) {
          if (valueLower.includes(ioc.toLowerCase())) {
            return ioc;
          }
        }
      }
    }

    // Check full_log
    if (item.full_log) {
      const logLower = item.full_log.toLowerCase();
      for (const ioc of searchedValues) {
        if (logLower.includes(ioc.toLowerCase())) {
          return ioc;
        }
      }
    }

    return searchedValues[0] || '';
  }

  /**
   * Get nested object value using dot notation
   */
  getNestedValue(obj, path) {
    return path.split('.').reduce((current, key) => current?.[key], obj);
  }

  /**
   * Map Wazuh rule level (0-15) to standard severity
   */
  mapSeverity(level) {
    if (!level) return 'medium';

    const l = parseInt(level, 10);
    if (l >= 12) return 'critical';
    if (l >= 9) return 'high';
    if (l >= 5) return 'medium';
    return 'low';
  }

  /**
   * Get configuration schema for Wazuh
   */
  static getConfigSchema() {
    return [
      {
        name: 'apiHost',
        label: 'Wazuh Manager URL',
        type: 'text',
        required: true,
        placeholder: 'https://wazuh.example.com'
      },
      {
        name: 'port',
        label: 'API Port',
        type: 'number',
        required: false,
        defaultValue: 55000,
        placeholder: '55000'
      },
      {
        name: 'username',
        label: 'API Username',
        type: 'text',
        required: true,
        placeholder: 'wazuh-wui'
      },
      {
        name: 'password',
        label: 'API Password',
        type: 'password',
        required: true,
        placeholder: 'Wazuh API password'
      },
      {
        name: 'verifySSL',
        label: 'Verify SSL Certificate',
        type: 'checkbox',
        required: false,
        defaultValue: false
      }
    ];
  }

  /**
   * Validate Wazuh configuration
   */
  static validateConfig(config) {
    const errors = [];

    if (!config.apiHost) {
      errors.push('Wazuh Manager URL is required');
    }

    if (config.apiHost && !config.apiHost.match(/^https?:\/\/.+/)) {
      errors.push('Wazuh Manager URL must be a valid URL');
    }

    if (!config.username) {
      errors.push('API Username is required');
    }

    if (!config.password) {
      errors.push('API Password is required');
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

module.exports = WazuhAdapter;
