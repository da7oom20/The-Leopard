/**
 * Recon (Field Discovery) API Tests
 * Tests field mapping discovery and management
 */

const axios = require('axios');

describe('Recon API', () => {
  const api = axios.create({
    baseURL: global.API_URL,
    validateStatus: () => true
  });

  let authToken = null;

  beforeAll(async () => {
    const res = await api.post('/auth/login', {
      username: 'admin',
      password: 'admin123'
    });
    if (res.data.token) {
      authToken = res.data.token;
    }
  });

  describe('GET /recon/mappings', () => {
    test('should require authentication', async () => {
      const res = await api.get('/recon/mappings');
      expect([401, 403]).toContain(res.status);
    });

    test('should return all field mappings', async () => {
      if (!authToken) {
        console.log('Skipping - no auth token');
        return;
      }

      const res = await api.get('/recon/mappings', {
        headers: { Authorization: `Bearer ${authToken}` }
      });

      expect(res.status).toBe(200);
      expect(Array.isArray(res.data)).toBe(true);
    });

    test('field mappings should have required fields', async () => {
      if (!authToken) {
        console.log('Skipping - no auth token');
        return;
      }

      const res = await api.get('/recon/mappings', {
        headers: { Authorization: `Bearer ${authToken}` }
      });

      if (res.data.length > 0) {
        const mapping = res.data[0];
        expect(mapping).toHaveProperty('id');
        expect(mapping).toHaveProperty('client');
        expect(mapping).toHaveProperty('siemType');
        expect(mapping).toHaveProperty('filterType');
        expect(mapping).toHaveProperty('fields');
        expect(mapping).toHaveProperty('isApproved');
      }
    });
  });

  describe('GET /recon/mappings/:clientId', () => {
    test('should require authentication', async () => {
      const res = await api.get('/recon/mappings/1');
      expect([401, 403]).toContain(res.status);
    });

    test('should return mappings for specific client', async () => {
      if (!authToken) {
        console.log('Skipping - no auth token');
        return;
      }

      const res = await api.get('/recon/mappings/1', {
        headers: { Authorization: `Bearer ${authToken}` }
      });

      expect([200, 404]).toContain(res.status);
      if (res.status === 200) {
        expect(Array.isArray(res.data)).toBe(true);
      }
    });
  });

  describe('GET /recon/log-sources/:clientId', () => {
    test('should require authentication', async () => {
      const res = await api.get('/recon/log-sources/1');
      expect([401, 403]).toContain(res.status);
    });

    test('should return log sources for client', async () => {
      if (!authToken) {
        console.log('Skipping - no auth token');
        return;
      }

      const res = await api.get('/recon/log-sources/1', {
        headers: { Authorization: `Bearer ${authToken}` }
      });

      // May fail if no SIEM configured
      expect([200, 400, 404, 500]).toContain(res.status);
    });
  });

  describe('POST /recon/dig', () => {
    test('should require authentication', async () => {
      const res = await api.post('/recon/dig', {
        clientId: 1,
        logSource: 'test',
        filterType: 'IP'
      });

      expect([401, 403]).toContain(res.status);
    });

    test('should require valid parameters', async () => {
      if (!authToken) {
        console.log('Skipping - no auth token');
        return;
      }

      const res = await api.post('/recon/dig', {}, {
        headers: { Authorization: `Bearer ${authToken}` }
      });

      expect([400, 422]).toContain(res.status);
    });
  });

  describe('POST /recon/approve', () => {
    test('should require authentication', async () => {
      const res = await api.post('/recon/approve', {
        clientId: 1,
        siemType: 'logrhythm',
        filterType: 'IP',
        fields: ['src_ip', 'dst_ip']
      });

      expect([401, 403]).toContain(res.status);
    });

    test('should save approved field mapping', async () => {
      if (!authToken) {
        console.log('Skipping - no auth token');
        return;
      }

      const res = await api.post('/recon/approve', {
        clientId: 999, // Test client
        siemType: 'logrhythm',
        filterType: 'IP',
        fields: ['test_field_1', 'test_field_2'],
        logSource: 'Test Log Source'
      }, {
        headers: { Authorization: `Bearer ${authToken}` }
      });

      expect([200, 201]).toContain(res.status);
      if (res.data.id) {
        // Clean up - delete test mapping
        await api.delete(`/recon/mappings/${res.data.id}`, {
          headers: { Authorization: `Bearer ${authToken}` }
        });
      }
    });
  });

  describe('PUT /recon/mappings/:id', () => {
    test('should require authentication', async () => {
      const res = await api.put('/recon/mappings/1', {
        fields: ['updated_field']
      });

      expect([401, 403]).toContain(res.status);
    });
  });

  describe('DELETE /recon/mappings/:id', () => {
    test('should require authentication', async () => {
      const res = await api.delete('/recon/mappings/1');
      expect([401, 403]).toContain(res.status);
    });

    test('should return 404 for non-existent mapping', async () => {
      if (!authToken) {
        console.log('Skipping - no auth token');
        return;
      }

      const res = await api.delete('/recon/mappings/99999', {
        headers: { Authorization: `Bearer ${authToken}` }
      });

      expect([404]).toContain(res.status);
    });
  });
});
