/**
 * LogRhythm SIEM Adapter
 * Implements IOC search via LogRhythm Search API
 */
const BaseSiemAdapter = require('./base.adapter');

class LogRhythmAdapter extends BaseSiemAdapter {
  constructor(config) {
    super(config);
    this.name = 'logrhythm';

    // LogRhythm-specific filter type IDs
    this.filterTypeIds = {
      IP: 17,
      Hash: 138,
      Domain: 39,
      DomainOrigin: 137,
      URL: 42,
      ParentProcessName: 146,
      Process: 41,
      Object: 34,
      ObjectName: 113,
      Sender: 31,
      Recipient: 32
    };

    // Fields to search for each IOC type
    this.searchFields = {
      Email: ['Sender', 'Recipient'],
      Domain: ['Domain', 'DomainOrigin', 'HostName', 'URL'],
      URL: ['URL', 'Domain', 'DomainOrigin', 'HostName'],
      FileName: ['ParentProcessName', 'Process', 'Object', 'ObjectName', 'ThreatName']
    };

    // Expose as fieldMappings for consistency with other adapters
    this.fieldMappings = {
      IP: ['IP (filterType 17, Direction: External/Outbound)'],
      Hash: ['Hash (filterType 138, matchType: Value)'],
      Domain: this.searchFields.Domain,
      URL: this.searchFields.URL,
      Email: this.searchFields.Email,
      FileName: this.searchFields.FileName
    };
  }

  /**
   * Test connectivity to LogRhythm API
   */
  async testConnection() {
    try {
      const response = await this.makeRequest({
        method: 'GET',
        url: `${this.config.apiHost}/lr-admin-api/lists`,
        headers: this.getAuthHeaders(),
        timeout: 10000
      });

      if (response.status === 200) {
        return {
          success: true,
          message: 'Successfully connected to LogRhythm API',
          data: { listCount: Array.isArray(response.data) ? response.data.length : 0 }
        };
      }

      if (response.status === 401 || response.status === 403) {
        return {
          success: false,
          message: `Authentication failed for LogRhythm at ${this.config.apiHost}. Check your API key.`,
          suggestion: 'Verify your LogRhythm Bearer token. Ensure it has not expired and has the required permissions.',
          category: 'auth'
        };
      }

      return {
        success: false,
        message: `Unexpected response from LogRhythm (HTTP ${response.status}).`,
        suggestion: 'Verify the LogRhythm API Host URL. Ensure the API services are running.',
        category: 'server'
      };
    } catch (error) {
      return {
        success: false,
        message: error.message || `Connection failed to LogRhythm at ${this.config.apiHost}.`,
        suggestion: error.suggestion || 'Check the LogRhythm API URL and Bearer token. Ensure the API services are running.',
        category: error.category || 'connection'
      };
    }
  }

  /**
   * LogRhythm uses Bearer token auth directly (no separate auth step)
   */
  async authenticate() {
    return { authenticated: true };
  }

  /**
   * Get available log sources from LogRhythm (for Recon)
   */
  async getLogSources() {
    try {
      const response = await this.makeRequest({
        method: 'GET',
        url: `${this.config.apiHost}/lr-admin-api/logsources`,
        headers: this.getAuthHeaders(),
        params: { count: 500 },
        timeout: 30000
      });

      const sources = response.data || [];
      return (Array.isArray(sources) ? sources : []).map(s => ({
        id: String(s.id),
        name: s.name || `LogSource ${s.id}`,
        type: 'log_source',
        hostName: s.hostName
      }));
    } catch (error) {
      console.warn('LogRhythm getLogSources error:', error.message);
      return [];
    }
  }

  /**
   * Build raw log retrieval query for Recon (no IOC filter)
   */
  buildReconQuery(logSource, limit = 1000) {
    const now = new Date().toISOString();
    const since = new Date(Date.now() - 60 * 60 * 1000).toISOString();

    return {
      maxMsgsToQuery: limit,
      queryTimeout: 120,
      searchMode: 2,              // PagedSortedDateAsc
      queryEventManager: false,
      queryLogSources: logSource.id ? [parseInt(logSource.id)] : [],
      dateCriteria: {
        useInsertedDate: false,
        dateMin: since,
        dateMax: now
      },
      queryFilter: {
        msgFilterType: 2,         // Grouped
        filterGroup: {
          filterItemType: 'Group',
          fieldOperator: 'And',
          filterMode: 'FilterIn',
          filterGroupOperator: 'And',
          filterItems: []
        }
      }
    };
  }

  /**
   * Get authorization headers for LogRhythm API
   */
  getAuthHeaders() {
    return {
      'Authorization': `Bearer ${this.config.apiKey}`,
      'Content-Type': 'application/json'
    };
  }

  /**
   * Build LogRhythm search query
   * @param {string} filterType - IOC type (IP, Hash, Domain, URL, Email, FileName)
   * @param {string[]} values - IOC values to search for
   * @param {Object} options - Search options
   * @returns {Object} - LogRhythm search body
   */
  buildQuery(filterType, values, options = {}) {
    const { minutesBack = 5, logSourceListId, customFields, customQueryTemplate } = options;
    // Use a local copy — never mutate this.searchFields
    const searchFields = {
      ...this.searchFields,
      ...(customFields && customFields.length > 0 ? { [filterType]: customFields } : {})
    };
    if (customQueryTemplate) {
      console.log(`🔧 [LOGRHYTHM] Custom template noted (LogRhythm uses structured JSON filters - fields customizable via Field Mappings)`);
    }

    const now = new Date().toISOString();
    const since = new Date(Date.now() - minutesBack * 60 * 1000).toISOString();

    const base = {
      name: '',
      description: '',
      maxMsgsToQuery: 50,
      logCacheSize: 1000,
      aggregateLogCacheSize: 1000,
      queryTimeout: 60,
      isOriginatedFromWeb: false,
      webLayoutId: 0,
      queryRawLog: true,
      queryEventManager: false,
      useDefaultLogRepositories: true,
      dateCreated: now,
      dateSaved: now,
      dateUsed: now,
      includeDiagnosticEvents: true,
      searchMode: 'PagedSortedDateAsc',
      webResultMode: 'Analyze',
      nextPageToken: '',
      pagedTimeout: 300,
      restrictedUserId: 0,
      createdVia: 'LegacyConsole',
      searchType: 'LogRepository',
      queryOrigin: 'Investigator',
      searchServerIPAddress: '127.0.0.1',
      repositoryPattern: '^logs-.*',
      ownerId: 0,
      searchId: 1000000000,
      queryLogSourceLists: logSourceListId ? [logSourceListId] : [],
      queryLogSources: [],
      logRepositoryIds: [],
      refreshRate: 0,
      isRealTime: false,
      objectSecurity: {
        objectId: 1000000000,
        objectType: 20,
        readPermissions: 0,
        writePermissions: 0,
        entityId: 0,
        ownerId: 0,
        canEdit: false,
        canDelete: false,
        canDeleteObject: false,
        entityName: '',
        ownerName: '',
        isSystemObject: false
      },
      enableIntelligentIndexing: false,
      dateCriteria: {
        useInsertedDate: false,
        dateMin: since
      }
    };

    // Build filter based on IOC type
    const filterGroup = this.buildFilterGroup(filterType, values, searchFields);

    if (!filterGroup) {
      throw new Error(`Unsupported filterType: ${filterType}`);
    }

    base.queryFilter = {
      msgFilterType: 'Grouped',
      isSavedFilter: false,
      name: 'Filter Group',
      filterGroup
    };

    return base;
  }

  /**
   * Build filter group based on IOC type
   */
  buildFilterGroup(filterType, values, searchFields) {
    if (filterType === 'IP') {
      return this.buildIPFilter(values);
    }

    if (filterType === 'Hash') {
      return this.buildHashFilter(values);
    }

    if (filterType === 'Email') {
      return this.buildStringGroupFilter(searchFields.Email, values);
    }

    if (filterType === 'Domain') {
      return this.buildStringGroupFilter(searchFields.Domain, values);
    }

    if (filterType === 'URL') {
      return this.buildStringGroupFilter(searchFields.URL, values);
    }

    if (filterType === 'FileName') {
      return this.buildStringGroupFilter(searchFields.FileName, values);
    }

    return null;
  }

  /**
   * Build IP address filter
   */
  buildIPFilter(values) {
    return {
      filterItemType: 'Group',
      fieldOperator: 'And',
      filterMode: 'FilterIn',
      filterGroupOperator: 'And',
      filterItems: [
        {
          filterItemType: 'Filter',
          fieldOperator: 'And',
          filterMode: 'FilterIn',
          filterType: 'Direction',
          values: [
            { filterType: 'Direction', valueType: 'Int32', value: 3, displayValue: 'External' },
            { filterType: 'Direction', valueType: 'Int32', value: 4, displayValue: 'Outbound' }
          ],
          name: 'Direction'
        },
        {
          filterItemType: 'Group',
          fieldOperator: 'Or',
          filterMode: 'FilterIn',
          filterGroupOperator: 'Or',
          filterItems: values.map((ip) => ({
            filterItemType: 'Filter',
            fieldOperator: 'None',
            filterMode: 'FilterIn',
            filterType: 'IP',
            values: [
              {
                filterType: 'IP',
                valueType: 'IPAddress',
                value: ip,
                displayValue: ip
              }
            ],
            name: 'IP Address (Origin or Impacted)'
          })),
          name: 'Filter Group'
        }
      ],
      name: 'Filter Group'
    };
  }

  /**
   * Build hash filter (MD5, SHA1, SHA256)
   */
  buildHashFilter(values) {
    return {
      filterItemType: 'Group',
      fieldOperator: 'And',
      filterMode: 'FilterIn',
      filterGroupOperator: 'And',
      filterItems: [
        {
          filterItemType: 'Filter',
          fieldOperator: 'And',
          filterMode: 'FilterIn',
          filterType: 'Hash',
          values: values.map((h) => ({
            filterType: 'Hash',
            valueType: 'String',
            value: { value: h, matchType: 'Value' },
            displayValue: h
          })),
          name: 'Hash'
        }
      ]
    };
  }

  /**
   * Build string group filter (for Email, Domain, URL, FileName)
   */
  buildStringGroupFilter(fields, values) {
    return {
      filterItemType: 'Group',
      fieldOperator: 'And',
      filterMode: 'FilterIn',
      filterGroupOperator: 'And',
      filterItems: [
        {
          filterItemType: 'Group',
          fieldOperator: 'Or',
          filterMode: 'FilterIn',
          filterGroupOperator: 'Or',
          filterItems: fields.map((field) => ({
            filterItemType: 'Filter',
            fieldOperator: 'Or',
            filterMode: 'FilterIn',
            filterType: field,
            values: values.map((v) => ({
              filterType: field,
              valueType: 'String',
              value: { value: `%${v}%`, matchType: 'SQLPattern' },
              displayValue: `%${v}% (SQL PATTERN)`
            })),
            name: field
          })),
          name: 'Filter Group'
        }
      ],
      name: 'Filter Group'
    };
  }

  /**
   * Execute search in LogRhythm (async - returns taskId)
   */
  async executeSearch(query, options = {}) {
    const searchUrl = `${this.config.apiHost}/lr-search-api/actions/search-task`;

    try {
      const response = await this.makeRequest({
        method: 'POST',
        url: searchUrl,
        headers: this.getAuthHeaders(),
        data: query,
        timeout: options.timeout || 30000
      });

      const data = response.data;
      console.log(`[LR] search-task status=${response.status}, statusCode=${data?.statusCode}, taskStatus=${data?.taskStatus}`);

      // Handle non-success HTTP status (makeRequest accepts < 500)
      if (response.status >= 400) {
        throw new Error(`HTTP ${response.status}: ${data?.responseMessage || data?.statusMessage || JSON.stringify(data)}`);
      }

      // Handle LR-level error in response body
      if (data?.statusCode && data.statusCode >= 400) {
        throw new Error(`LR ${data.statusCode}: ${data.responseMessage || data.statusMessage || 'Unknown error'}`);
      }

      // API docs: response has taskId (camelCase), existing LR may use TaskId (PascalCase)
      const taskId = data?.TaskId || data?.taskId
        || (typeof data === 'string' ? data : null);

      if (!taskId) {
        console.error('[LR] Full response data:', JSON.stringify(data, null, 2));
        throw new Error(`No TaskId returned. taskStatus=${data?.taskStatus}, responseMessage=${data?.responseMessage}`);
      }

      return {
        taskId,
        status: 'searching',
        complete: false
      };
    } catch (error) {
      throw new Error(`LogRhythm search failed: ${error.message}`);
    }
  }

  /**
   * Poll for search results
   */
  async pollResults(taskId, options = {}) {
    const {
      pollingInterval = 30000,
      maxAttempts = 10,
      pageSize = 50
    } = options;

    const resultUrl = `${this.config.apiHost}/lr-search-api/actions/search-result`;

    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      await this.wait(pollingInterval);

      try {
        const response = await this.makeRequest({
          method: 'POST',
          url: resultUrl,
          headers: this.getAuthHeaders(),
          timeout: 300000,
          data: {
            data: {
              searchGuid: taskId,
              search: { sort: [] },
              paginator: { origin: 0, page_size: pageSize }
            }
          }
        });

        const result = response.data;

        // API docs: taskStatus values — Searching, First Results, Queued, Completed, Failed, Cancelled
        const status = result.TaskStatus || result.taskStatus || '';

        if (['Searching', 'Queued', 'First Results'].includes(status)) {
          console.log(`LogRhythm poll ${attempt}/${maxAttempts}: ${status}...`);
          continue;
        }

        if (['Failed', 'Search Failed', 'Cancelled'].includes(status)) {
          return {
            status: 'failed',
            results: [],
            complete: true,
            error: result.responseMessage || result.statusMessage || `Search ${status}`
          };
        }

        // API docs: items (lowercase), existing LR may use Items (PascalCase)
        const items = result.Items || result.items || [];

        if (Array.isArray(items)) {
          return {
            status: 'complete',
            results: items,
            complete: true,
            resultCount: result.allLogsCount || result.filteredLogsCount || items.length,
            taskStatus: status
          };
        }
      } catch (error) {
        console.error(`LogRhythm poll ${attempt} error:`, error.message);
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
   * Normalize LogRhythm results to unified format
   */
  normalizeResults(rawResults, filterType, searchedValues) {
    if (!Array.isArray(rawResults)) {
      return [];
    }

    return rawResults.map((item) => ({
      siemType: 'logrhythm',
      client: this.config.client,
      timestamp: item.normalDate || item.logDate || new Date().toISOString(),
      sourceIP: item.originIp || item.sip || '',
      destIP: item.impactedIp || item.dip || '',
      hostname: item.originHostName || item.impactedHostName || '',
      username: item.account || item.login || '',
      eventType: item.classificationName || item.commonEventName || '',
      rawLog: item.normalMsgSummary || item.logMessage || '',
      matchedIOC: this.findMatchedIOC(item, searchedValues),
      matchedIOCType: filterType,
      severity: this.mapSeverity(item.priority || item.riskRating),
      additionalFields: {
        logSourceName: item.logSourceName,
        direction: item.direction,
        protocolName: item.protocolName,
        mpeRuleName: item.mpeRuleName,
        objectName: item.objectName,
        hash: item.hash,
        url: item.url,
        sender: item.sender,
        recipient: item.recipient
      }
    }));
  }

  /**
   * Find which IOC matched in the result
   */
  findMatchedIOC(item, searchedValues) {
    const searchableFields = [
      item.originIp, item.impactedIp, item.sip, item.dip,
      item.hash, item.url, item.sender, item.recipient,
      item.originHostName, item.impactedHostName, item.objectName
    ].filter(Boolean).map(v => String(v).toLowerCase());

    for (const ioc of searchedValues) {
      const lowerIOC = ioc.toLowerCase();
      if (searchableFields.some(field => field.includes(lowerIOC))) {
        return ioc;
      }
    }

    return searchedValues[0] || '';
  }

  /**
   * Map LogRhythm priority/risk to standard severity
   */
  mapSeverity(priority) {
    if (!priority) return 'medium';
    const p = parseInt(priority, 10);
    if (p >= 80) return 'critical';
    if (p >= 60) return 'high';
    if (p >= 40) return 'medium';
    return 'low';
  }

  /**
   * Get configuration schema for LogRhythm
   */
  static getConfigSchema() {
    return [
      {
        name: 'apiHost',
        label: 'API Host URL',
        type: 'text',
        required: true,
        placeholder: 'https://logrhythm.example.com'
      },
      {
        name: 'apiKey',
        label: 'API Key (Bearer Token)',
        type: 'password',
        required: true,
        placeholder: 'Enter LogRhythm API key'
      }
    ];
  }

  /**
   * Validate LogRhythm configuration
   */
  static validateConfig(config) {
    const errors = [];

    if (!config.apiHost) {
      errors.push('API Host is required');
    }

    if (config.apiHost && !config.apiHost.match(/^https?:\/\/.+/)) {
      errors.push('API Host must be a valid URL');
    }

    if (!config.apiKey) {
      errors.push('API Key is required');
    }

    return {
      valid: errors.length === 0,
      errors
    };
  }
}

module.exports = LogRhythmAdapter;
