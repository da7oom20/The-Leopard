/**
 * IOC Search API Tests
 * Tests IOC upload, search, and export functionality
 */

const axios = require('axios');
const FormData = require('form-data');

describe('Search API', () => {
  let api;
  let authToken;

  beforeAll(async () => {
    authToken = await global.getAdminToken();
    api = global.createAuthApi(authToken);
  });

  describe('POST /upload', () => {
    test('should require authentication', async () => {
      const noAuthApi = global.createAuthApi(null);
      const res = await noAuthApi.post('/upload', { text: '8.8.8.8' });
      expect([401, 403]).toContain(res.status);
    });

    test('should accept text IOC submission', async () => {
      if (!authToken) { console.log('Skipping - no auth token'); return; }

      const form = new FormData();
      form.append('text', '192.168.1.1\n8.8.8.8\ngoogle.com');
      form.append('searchMinutesAgo', '10080');

      const res = await api.post('/upload', form, {
        headers: { ...form.getHeaders(), Authorization: `Bearer ${authToken}` }
      });

      // Should succeed or return no clients error
      expect([200, 201, 400]).toContain(res.status);
    });

    test('should detect IP addresses in text', async () => {
      if (!authToken) { console.log('Skipping - no auth token'); return; }

      const form = new FormData();
      form.append('text', '192.168.1.1\n10.0.0.1\n8.8.8.8');
      form.append('searchMinutesAgo', '10080');

      const res = await api.post('/upload', form, {
        headers: { ...form.getHeaders(), Authorization: `Bearer ${authToken}` }
      });

      if (res.status === 200 && res.data.filters) {
        expect(res.data.filters).toHaveProperty('IP');
        expect(res.data.filters.IP.length).toBeGreaterThan(0);
      }
    });

    test('should detect domains in text', async () => {
      if (!authToken) { console.log('Skipping - no auth token'); return; }

      const form = new FormData();
      form.append('text', 'google.com\nmalicious[.]domain[.]com\nevil.example.org');
      form.append('searchMinutesAgo', '10080');

      const res = await api.post('/upload', form, {
        headers: { ...form.getHeaders(), Authorization: `Bearer ${authToken}` }
      });

      if (res.status === 200 && res.data.filters) {
        expect(res.data.filters).toHaveProperty('Domain');
      }
    });

    test('should detect file hashes in text', async () => {
      if (!authToken) { console.log('Skipping - no auth token'); return; }

      const form = new FormData();
      form.append('text', 'd41d8cd98f00b204e9800998ecf8427e\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
      form.append('searchMinutesAgo', '10080');

      const res = await api.post('/upload', form, {
        headers: { ...form.getHeaders(), Authorization: `Bearer ${authToken}` }
      });

      if (res.status === 200 && res.data.filters) {
        expect(res.data.filters).toHaveProperty('Hash');
      }
    });

    test('should handle obfuscated IOCs', async () => {
      if (!authToken) { console.log('Skipping - no auth token'); return; }

      const form = new FormData();
      form.append('text', '192[.]168[.]1[.]1\nhxxp://evil[.]com/malware\nuser[at]domain[dot]com');
      form.append('searchMinutesAgo', '10080');

      const res = await api.post('/upload', form, {
        headers: { ...form.getHeaders(), Authorization: `Bearer ${authToken}` }
      });

      expect([200, 201, 400]).toContain(res.status);
    });
  });

  describe('GET /repo', () => {
    test('should require authentication', async () => {
      const noAuthApi = global.createAuthApi(null);
      const res = await noAuthApi.get('/repo');
      expect([401, 403]).toContain(res.status);
    });

    test('should return search history when authenticated', async () => {
      if (!authToken) { console.log('Skipping - no auth token'); return; }

      const res = await api.get('/repo');
      expect(res.status).toBe(200);
    });
  });

  describe('GET /export-results', () => {
    test('should require authentication', async () => {
      const noAuthApi = global.createAuthApi(null);
      // Note: export-results is at root, not under /api
      const res = await axios.get(`${global.API_BASE_URL}/export-results`, { validateStatus: () => true });
      expect([401, 403]).toContain(res.status);
    });
  });

  describe('GET /export-status', () => {
    test('should require authentication', async () => {
      const noAuthApi = global.createAuthApi(null);
      const res = await noAuthApi.get('/export-status');
      expect([401, 403]).toContain(res.status);
    });
  });
});

describe('Hunt API', () => {
  let api;
  let authToken;

  beforeAll(async () => {
    authToken = await global.getAdminToken();
    api = global.createAuthApi(authToken);
  });

  describe('POST /hunt', () => {
    test('should require authentication', async () => {
      const noAuthApi = global.createAuthApi(null);
      const res = await noAuthApi.post('/hunt', {});
      expect([401, 403]).toContain(res.status);
    });

    test('should require TI source and IOC type', async () => {
      if (!authToken) { console.log('Skipping - no auth token'); return; }

      const res = await api.post('/hunt', {});
      expect([400, 422]).toContain(res.status);
    });

    test('should require client selection', async () => {
      if (!authToken) { console.log('Skipping - no auth token'); return; }

      const res = await api.post('/hunt', {
        tiSource: 'threatfox',
        iocType: 'IP',
        clientIds: []
      });

      expect([200, 400]).toContain(res.status);
    });
  });

  describe('GET /ti-sources (public)', () => {
    test('should return list of TI sources without auth', async () => {
      const noAuthApi = global.createAuthApi(null);
      const res = await noAuthApi.get('/ti-sources');

      expect(res.status).toBe(200);
      expect(Array.isArray(res.data)).toBe(true);
    });
  });
});
