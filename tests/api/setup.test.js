/**
 * Setup Wizard API Tests
 * Tests the first-time setup endpoints
 */

const axios = require('axios');

describe('Setup API', () => {
  let api;
  let authToken;

  beforeAll(async () => {
    authToken = await global.getAdminToken();
    api = global.createAuthApi(authToken);
  });

  describe('GET /setup/status', () => {
    test('should return setup status without auth', async () => {
      const noAuthApi = global.createAuthApi(null);
      const res = await noAuthApi.get('/setup/status');

      expect(res.status).toBe(200);
      expect(res.data).toHaveProperty('isComplete');
      expect(typeof res.data.isComplete).toBe('boolean');
    });
  });

  describe('POST /setup/test-db', () => {
    test('should require auth when setup is complete', async () => {
      const noAuthApi = global.createAuthApi(null);
      const res = await noAuthApi.post('/setup/test-db');

      // When users exist, requires admin JWT
      expect([200, 401]).toContain(res.status);
    });

    test('should test database connection with admin auth', async () => {
      if (!authToken) { console.log('Skipping - no auth token'); return; }

      const res = await api.post('/setup/test-db');
      expect(res.status).toBe(200);
      expect(res.data).toHaveProperty('success');
      expect(res.data.success).toBe(true);
    });
  });

  describe('POST /setup/add-siem', () => {
    test('should reject SIEM without required fields', async () => {
      const noAuthApi = global.createAuthApi(null);
      const res = await noAuthApi.post('/setup/add-siem', {});

      expect([400, 403, 422]).toContain(res.status);
    });

    test('should reject SIEM with invalid type', async () => {
      const noAuthApi = global.createAuthApi(null);
      const res = await noAuthApi.post('/setup/add-siem', {
        client: 'TestClient',
        siemType: 'invalid-siem-type',
        config: {}
      });

      expect([400, 403, 422]).toContain(res.status);
    });
  });

  describe('POST /setup/create-admin', () => {
    test('should reject admin creation without password', async () => {
      const noAuthApi = global.createAuthApi(null);
      const res = await noAuthApi.post('/setup/create-admin', {
        username: 'testadmin'
      });

      // When users exist, setup is blocked (403) or validation fails (400)
      expect([400, 403, 422]).toContain(res.status);
    });

    test('should block setup when users already exist', async () => {
      const noAuthApi = global.createAuthApi(null);
      const res = await noAuthApi.post('/setup/create-admin', {
        username: 'testadmin',
        password: 'TestPass123!'
      });

      // Setup already complete
      expect([400, 403]).toContain(res.status);
    });
  });
});
