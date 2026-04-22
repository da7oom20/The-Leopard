/**
 * Elastic/ELK SIEM Adapter
 * Implements IOC search via Elasticsearch REST API using DSL queries
 */
const BaseSiemAdapter = require('./base.adapter');

class ElasticAdapter extends BaseSiemAdapter {
  constructor(config) {
    super(config);
    this.name = 'elastic';

    // Default index pattern (check extraConfig first, then top-level)
    this.indexPattern = config.extraConfig?.indexPattern || config.indexPattern || 'logs-*';

    // Field mappings for different IOC types in Elasticsearch (ECS compliant + common variations)
    this.fieldMappings = {
      IP: ['source.ip', 'destination.ip', 'client.ip', 'server.ip', 'host.ip', 'related.ip'],
      Hash: [
        'file.hash.md5', 'file.hash.sha1', 'file.hash.sha256',
        'process.hash.md5', 'process.hash.sha256',
        'related.hash', 'hash.md5', 'hash.sha256'
      ],
      Domain: [
        'url.domain', 'dns.question.name', 'destination.domain', 'source.domain',
        'host.hostname', 'host.name', 'related.hosts', 'dns.resolved_ip'
      ],
      URL: ['url.full', 'url.original', 'url.path', 'http.request.body.content', 'url.query'],
      Email: [
        'email.from.address', 'email.to.address', 'source.user.email', 'destination.user.email', 'user.email',
        // O365 / Exchange
        'o365.audit.SenderAddress', 'o365.audit.RecipientAddress',
        // Generic
        'email.sender', 'email.recipient', 'mail.from', 'mail.to'
      ],
      FileName: [
        'file.name', 'file.path', 'process.name', 'process.executable', 'process.command_line',
        // Sysmon / Winlogbeat
        'winlog.event_data.Image', 'winlog.event_data.TargetFilename', 'winlog.event_data.OriginalFileName',
        // Endpoint agents
        'process.parent.name', 'process.parent.executable', 'file.target_path'
      ]
    };
  }

  /**
   * Get authorization headers for Elasticsearch
   * Supports API Key and Basic auth
   */
  getAuthHeaders() {
    const headers = {
      'Content-Type': 'application/json'
    };

    if (this.config.apiKeyId && this.config.apiKeySecret) {
      // API Key auth: base64(id:api_key) - recommended
      const apiKeyToken = Buffer.from(`${this.config.apiKeyId}:${this.config.apiKeySecret}`).toString('base64');
      headers['Authorization'] = `ApiKey ${apiKeyToken}`;
    } else if (this.config.apiKey) {
      // Pre-encoded API key - recommended
      headers['Authorization'] = `ApiKey ${this.config.apiKey}`;
    } else if (this.config.username && this.config.password) {
      // Basic auth fallback
      console.warn('[ELASTIC] Using basic auth - API key recommended for production');
      const credentials = Buffer.from(`${this.config.username}:${this.config.password}`).toString('base64');
      headers['Authorization'] = `Basic ${credentials}`;
    }

    return headers;
  }

  /**
   * Test connectivity to Elasticsearch
   */
  async testConnection() {
    try {
      const response = await this.makeRequest({
        method: 'GET',
        url: `${this.config.apiHost}`,
        headers: this.getAuthHeaders(),
        timeout: 10000
      });

      if (response.status === 200 && response.data) {
        return {
          success: true,
          message: 'Successfully connected to Elasticsearch',
          data: {
            clusterName: response.data.cluster_name,
            version: response.data.version?.number,
            nodeName: response.data.name
          }
        };
      }

      if (response.status === 401 || response.status === 403) {
        return {
          success: false,
          message: `Authentication failed for Elasticsearch at ${this.config.apiHost}. Check your API key or credentials.`,
          suggestion: 'Verify your Elasticsearch API Key or username/password. Ensure the credentials have sufficient privileges.',
          category: 'auth'
        };
      }

      return {
        success: false,
        message: `Unexpected response from Elasticsearch (HTTP ${response.status}).`,
        suggestion: 'Verify the Elasticsearch URL (default port 9200). Ensure the cluster is healthy and accessible.',
        category: 'server'
      };
    } catch (error) {
      return {
        success: false,
        message: error.message || `Connection failed to Elasticsearch at ${this.config.apiHost}.`,
        suggestion: error.suggestion || 'Check the Elasticsearch URL and network connectivity. Ensure the cluster is running.',
        category: error.category || 'connection'
      };
    }
  }

  /**
   * Elasticsearch uses direct auth (no separate auth step)
   */
  async authenticate() {
    return { authenticated: true };
  }

  /**
   * Get available indices from Elasticsearch (for Recon)
   */
  async getLogSources() {
    try {
      const response = await this.makeRequest({
        method: 'GET',
        url: `${this.config.apiHost}/_cat/indices?format=json&h=index,docs.count,store.size,health`,
        headers: this.getAuthHeaders(),
        timeout: 30000
      });

      const indices = response.data || [];
      return (Array.isArray(indices) ? indices : [])
        .filter(i => !i.index.startsWith('.'))
        .map(i => ({
          id: i.index,
          name: i.index,
          type: 'index',
          docCount: i['docs.count'],
          size: i['store.size']
        }));
    } catch (error) {
      console.warn('Elastic getLogSources error:', error.message);
      return [];
    }
  }

  /**
   * Build raw log retrieval query for Recon (no IOC filter)
   */
  buildReconQuery(logSource, limit = 1000) {
    return {
      index: logSource.id,
      body: {
        query: { match_all: {} },
        size: limit,
        sort: [{ '@timestamp': { order: 'desc', unmapped_type: 'date' } }]
      },
      filterType: 'Recon',
      searchedValues: []
    };
  }

  /**
   * Build Elasticsearch DSL query
   * @param {string} filterType - IOC type
   * @param {string[]} values - IOC values to search for
   * @param {Object} options - Search options
   * @returns {Object} - Elasticsearch query
   */
  buildQuery(filterType, values, options = {}) {
    const { minutesBack = 5, logSources, customFields, customQueryTemplate } = options;
    let indexPattern = options.indexPattern || this.indexPattern;
    if (Array.isArray(logSources) && logSources.length > 0) {
      const names = logSources
        .map(ls => (ls?.name ?? ls?.id ?? '').toString().trim())
        .filter(Boolean);
      if (names.length > 0) indexPattern = names.join(',');
    }

    // Use custom fields from Recon if available, otherwise hardcoded defaults
    const fields = customFields || this.fieldMappings[filterType] || [];

    // Build should clauses for each field
    const shouldClauses = fields.flatMap(field => {
      if (filterType === 'IP' || filterType === 'Hash') {
        // For IP and Hash types, use terms query (exact match)
        return [{
          terms: { [field]: values }
        }];
      } else {
        return values.map(value => ({
          wildcard: {
            [field]: {
              value: `*${value.toLowerCase()}*`,
              case_insensitive: true
            }
          }
        }));
      }
    });

    if (customQueryTemplate) {
      try {
        const rendered = customQueryTemplate
          .replace(/\{\{minutesBack\}\}/g, String(minutesBack))
          .replace(/\{\{fieldConditions\}\}/g, JSON.stringify(shouldClauses))
          .replace(/\{\{values\}\}/g, JSON.stringify(values))
          .replace(/\{\{index\}\}/g, indexPattern);
        const customBody = JSON.parse(rendered);
        console.log(`🔧 [ELASTIC] Using custom DSL template`);
        return {
          index: indexPattern,
          body: customBody,
          filterType,
          searchedValues: values
        };
      } catch (e) {
        console.warn(`⚠️ [ELASTIC] Custom template parse failed, using default: ${e.message}`);
      }
    }

    return {
      index: indexPattern,
      body: {
        query: {
          bool: {
            must: [
              {
                range: {
                  '@timestamp': {
                    gte: `now-${minutesBack}m`,
                    lte: 'now'
                  }
                }
              }
            ],
            should: shouldClauses,
            minimum_should_match: 1
          }
        },
        size: 1000,
        sort: [{ '@timestamp': 'desc' }]
      },
      filterType,
      searchedValues: values
    };
  }

  /**
   * Execute search in Elasticsearch (synchronous)
   */
  async executeSearch(query, options = {}) {
    const searchUrl = `${this.config.apiHost}/${query.index}/_search`;

    try {
      const response = await this.makeRequest({
        method: 'POST',
        url: searchUrl,
        headers: this.getAuthHeaders(),
        data: query.body,
        timeout: options.timeout || 60000
      });

      const hits = response.data?.hits?.hits || [];
      const total = response.data?.hits?.total?.value || hits.length;

      return {
        status: 'complete',
        results: hits.map(hit => hit._source),
        complete: true,
        resultCount: total,
        query // Include for normalization
      };
    } catch (error) {
      throw new Error(`Elasticsearch search failed: ${error.message}`);
    }
  }

  /**
   * Elasticsearch is synchronous, no polling needed
   */
  async pollResults(taskId, options = {}) {
    return {
      status: 'complete',
      results: [],
      complete: true
    };
  }

  /**
   * Normalize Elasticsearch results to unified format (ECS compliant)
   */
  normalizeResults(rawResults, filterType, searchedValues) {
    if (!Array.isArray(rawResults)) {
      return [];
    }

    return rawResults.map((item) => ({
      siemType: 'elastic',
      client: this.config.client,
      timestamp: item['@timestamp'] || item.timestamp || new Date().toISOString(),
      sourceIP: item.source?.ip || item.client?.ip || '',
      destIP: item.destination?.ip || item.server?.ip || '',
      hostname: item.host?.hostname || item.host?.name || '',
      username: item.user?.name || item.source?.user?.name || '',
      eventType: item.event?.action || item.event?.category || '',
      rawLog: item.message || JSON.stringify(item),
      matchedIOC: this.findMatchedIOC(item, searchedValues, filterType),
      matchedIOCType: filterType,
      severity: this.mapSeverity(item.event?.severity),
      additionalFields: {
        eventId: item.event?.id,
        eventCategory: item.event?.category,
        eventDataset: item.event?.dataset,
        agentName: item.agent?.name,
        ruleName: item.rule?.name,
        filePath: item.file?.path,
        processName: item.process?.name,
        url: item.url?.full
      }
    }));
  }

  /**
   * Find which IOC matched in the result (handles nested ECS fields)
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

    // Check message field
    if (item.message) {
      const msgLower = item.message.toLowerCase();
      for (const ioc of searchedValues) {
        if (msgLower.includes(ioc.toLowerCase())) {
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
   * Map Elasticsearch severity to standard severity
   */
  mapSeverity(severity) {
    if (!severity) return 'medium';

    const s = parseInt(severity, 10);
    if (s >= 75) return 'critical';
    if (s >= 50) return 'high';
    if (s >= 25) return 'medium';
    return 'low';
  }

  /**
   * Get configuration schema for Elasticsearch
   */
  static getConfigSchema() {
    return [
      {
        name: 'apiHost',
        label: 'Elasticsearch URL',
        type: 'text',
        required: true,
        placeholder: 'https://elasticsearch.example.com:9200'
      },
      {
        name: 'apiKeyId',
        label: 'API Key ID (Recommended)',
        type: 'text',
        required: false,
        placeholder: 'API key ID (preferred for production)',
        description: 'Primary authentication method. Create an API key via Kibana or Elasticsearch API.'
      },
      {
        name: 'apiKeySecret',
        label: 'API Key Secret',
        type: 'password',
        required: false,
        placeholder: 'API key secret',
        description: 'Used together with API Key ID for secure authentication.'
      },
      {
        name: 'username',
        label: 'Username (Fallback)',
        type: 'text',
        required: false,
        placeholder: 'Elasticsearch username (only if not using API key)',
        description: 'Optional fallback. API key is recommended instead.'
      },
      {
        name: 'password',
        label: 'Password (Fallback)',
        type: 'password',
        required: false,
        placeholder: 'Elasticsearch password (only if not using API key)',
        description: 'Optional fallback. API key is recommended instead.'
      },
      {
        name: 'indexPattern',
        label: 'Index Pattern',
        type: 'text',
        required: false,
        defaultValue: 'logs-*',
        placeholder: 'logs-*, filebeat-*, etc.'
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
   * Validate Elasticsearch configuration
   */
  static validateConfig(config) {
    const errors = [];

    if (!config.apiHost) {
      errors.push('Elasticsearch URL is required');
    }

    if (config.apiHost && !config.apiHost.match(/^https?:\/\/.+/)) {
      errors.push('Elasticsearch URL must be a valid URL');
    }

    // Either API key OR username/password required
    const hasApiKey = config.apiKey || (config.apiKeyId && config.apiKeySecret);
    const hasCredentials = config.username && config.password;

    if (!hasApiKey && !hasCredentials) {
      errors.push('Either API Key or Username/Password is required');
    }

    return {
      valid: errors.length === 0,
      errors
    };
  }
}

module.exports = ElasticAdapter;
