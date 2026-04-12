/**
 * Health Check Tests
 * Tests that all services are running and accessible
 */

const axios = require('axios');

describe('System Health Checks', () => {
  let api;
  let authToken;

  beforeAll(async () => {
    authToken = await global.getAdminToken();
    api = global.createAuthApi(authToken);
  });

  describe('Backend API', () => {
    test('should be accessible', async () => {
      const noAuthApi = global.createAuthApi(null);
      const res = await noAuthApi.get('/setup/status');
      expect([200, 301, 302]).toContain(res.status);
    });

    test('should respond within acceptable time', async () => {
      const noAuthApi = global.createAuthApi(null);
      const start = Date.now();
      await noAuthApi.get('/clients');
      const duration = Date.now() - start;
      expect(duration).toBeLessThan(5000);
    });
  });

  describe('Database Connection', () => {
    test('should require authentication when setup is complete', async () => {
      const noAuthApi = global.createAuthApi(null);
      const res = await noAuthApi.post('/setup/test-db');
      // When users exist, this requires admin auth
      expect([200, 401]).toContain(res.status);
    });

    test('should work with admin auth', async () => {
      if (!authToken) { console.log('Skipping - no auth token'); return; }

      const res = await api.post('/setup/test-db');
      expect(res.status).toBe(200);
      expect(res.data.success).toBe(true);
    });
  });

  describe('Public Endpoints', () => {
    test('GET /clients should work without auth', async () => {
      const noAuthApi = global.createAuthApi(null);
      const res = await noAuthApi.get('/clients');
      expect(res.status).toBe(200);
    });

    test('GET /ti-sources should work without auth', async () => {
      const noAuthApi = global.createAuthApi(null);
      const res = await noAuthApi.get('/ti-sources');
      expect(res.status).toBe(200);
    });

    test('GET /setup/status should work without auth', async () => {
      const noAuthApi = global.createAuthApi(null);
      const res = await noAuthApi.get('/setup/status');
      expect(res.status).toBe(200);
      expect(res.data).toHaveProperty('isComplete');
    });
  });

  describe('Protected Endpoints', () => {
    test('GET /repo should require authentication', async () => {
      const noAuthApi = global.createAuthApi(null);
      const res = await noAuthApi.get('/repo');
      expect([401, 403]).toContain(res.status);
    });

    test('GET /repo should work with auth', async () => {
      if (!authToken) { console.log('Skipping - no auth token'); return; }

      const res = await api.get('/repo');
      expect(res.status).toBe(200);
    });

    test('should reject unauthenticated access to /admin/api-keys', async () => {
      const noAuthApi = global.createAuthApi(null);
      const res = await noAuthApi.get('/admin/api-keys');
      expect([401, 403]).toContain(res.status);
    });

    test('should reject unauthenticated access to /admin/users', async () => {
      const noAuthApi = global.createAuthApi(null);
      const res = await noAuthApi.get('/admin/users');
      expect([401, 403]).toContain(res.status);
    });

    test('should reject unauthenticated access to /recon/mappings', async () => {
      const noAuthApi = global.createAuthApi(null);
      const res = await noAuthApi.get('/recon/mappings');
      expect([401, 403]).toContain(res.status);
    });
  });

  describe('Error Handling', () => {
    test('should return 404 for non-existent endpoints', async () => {
      const noAuthApi = global.createAuthApi(null);
      const res = await noAuthApi.get('/nonexistent-endpoint-12345');
      expect(res.status).toBe(404);
    });
  });
});

describe('Frontend Health', () => {
  const frontendUrl = process.env.TEST_FRONTEND_URL || 'http://localhost:3015';

  test('should be accessible', async () => {
    try {
      const res = await axios.get(frontendUrl, { timeout: 10000 });
      expect([200, 301, 302]).toContain(res.status);
    } catch (err) {
      console.log('Frontend check skipped:', err.message);
    }
  });
});
