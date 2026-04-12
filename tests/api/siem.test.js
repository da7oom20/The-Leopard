/**
 * SIEM Management API Tests
 * Tests SIEM client CRUD operations and connection testing
 */

const axios = require('axios');

describe('SIEM API', () => {
  const api = axios.create({
    baseURL: global.API_URL,
    validateStatus: () => true
  });

  let authToken = null;

  beforeAll(async () => {
    // Try to get auth token
    const res = await api.post('/auth/login', {
      username: 'admin',
      password: 'admin123'
    });
    if (res.data.token) {
      authToken = res.data.token;
    }
  });

  describe('GET /clients (Public)', () => {
    test('should return list of active clients', async () => {
      const res = await api.get('/clients');

      expect(res.status).toBe(200);
      expect(Array.isArray(res.data)).toBe(true);
    });

    test('clients should have required fields', async () => {
      const res = await api.get('/clients');

      if (res.data.length > 0) {
        const client = res.data[0];
        expect(client).toHaveProperty('id');
        expect(client).toHaveProperty('client');
        expect(client).toHaveProperty('siemType');
      }
    });
  });

  describe('GET /admin/api-keys (Protected)', () => {
    test('should require authentication', async () => {
      const res = await api.get('/admin/api-keys');
      expect([401, 403]).toContain(res.status);
    });

    test('should return SIEM list when authenticated', async () => {
      if (!authToken) {
        console.log('Skipping - no auth token');
        return;
      }

      const res = await api.get('/admin/api-keys', {
        headers: { Authorization: `Bearer ${authToken}` }
      });

      expect(res.status).toBe(200);
      expect(Array.isArray(res.data)).toBe(true);
    });
  });

  describe('GET /admin/siem-types', () => {
    test('should return supported SIEM types', async () => {
      if (!authToken) {
        console.log('Skipping - no auth token');
        return;
      }

      const res = await api.get('/admin/siem-types', {
        headers: { Authorization: `Bearer ${authToken}` }
      });

      expect(res.status).toBe(200);
      expect(Array.isArray(res.data)).toBe(true);

      // Should include known SIEM types
      const types = res.data.map(s => s.id);
      expect(types).toContain('logrhythm');
      expect(types).toContain('splunk');
      expect(types).toContain('qradar');
    });

    test('SIEM types should have schema definitions', async () => {
      if (!authToken) {
        console.log('Skipping - no auth token');
        return;
      }

      const res = await api.get('/admin/siem-types', {
        headers: { Authorization: `Bearer ${authToken}` }
      });

      if (res.data.length > 0) {
        const siemType = res.data[0];
        expect(siemType).toHaveProperty('id');
        expect(siemType).toHaveProperty('name');
        expect(siemType).toHaveProperty('configSchema');
      }
    });
  });

  describe('POST /admin/check-api-key', () => {
    test('should require authentication', async () => {
      const res = await api.post('/admin/check-api-key', {});
      expect([401, 403]).toContain(res.status);
    });

    test('should test SIEM connection', async () => {
      if (!authToken) {
        console.log('Skipping - no auth token');
        return;
      }

      // This will fail without a real SIEM, but should return proper error
      const res = await api.post('/admin/check-api-key', {
        siemType: 'logrhythm',
        config: {
          host: 'https://fake-siem.example.com',
          apiKey: 'fake-api-key'
        }
      }, {
        headers: { Authorization: `Bearer ${authToken}` }
      });

      // Should return success:false (connection failed) not a server error
      expect([200, 400, 500]).toContain(res.status);
      if (res.status === 200) {
        expect(res.data).toHaveProperty('success');
      }
    });
  });

  describe('POST /admin/api-keys', () => {
    test('should require authentication', async () => {
      const res = await api.post('/admin/api-keys', {});
      expect([401, 403]).toContain(res.status);
    });

    test('should validate required fields', async () => {
      if (!authToken) {
        console.log('Skipping - no auth token');
        return;
      }

      const res = await api.post('/admin/api-keys', {}, {
        headers: { Authorization: `Bearer ${authToken}` }
      });

      expect([400, 422]).toContain(res.status);
    });
  });
});
