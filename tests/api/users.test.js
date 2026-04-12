/**
 * User Management API Tests
 * Tests user CRUD and permission management
 */

const axios = require('axios');

describe('User Management API', () => {
  const api = axios.create({
    baseURL: global.API_URL,
    validateStatus: () => true
  });

  let authToken = null;
  let testUserId = null;

  beforeAll(async () => {
    const res = await api.post('/auth/login', {
      username: 'admin',
      password: 'admin123'
    });
    if (res.data.token) {
      authToken = res.data.token;
    }
  });

  describe('GET /admin/users', () => {
    test('should require authentication', async () => {
      const res = await api.get('/admin/users');
      expect([401, 403]).toContain(res.status);
    });

    test('should return user list when authenticated', async () => {
      if (!authToken) {
        console.log('Skipping - no auth token');
        return;
      }

      const res = await api.get('/admin/users', {
        headers: { Authorization: `Bearer ${authToken}` }
      });

      expect(res.status).toBe(200);
      expect(Array.isArray(res.data)).toBe(true);
    });

    test('users should have permission fields', async () => {
      if (!authToken) {
        console.log('Skipping - no auth token');
        return;
      }

      const res = await api.get('/admin/users', {
        headers: { Authorization: `Bearer ${authToken}` }
      });

      if (res.data.length > 0) {
        const user = res.data[0];
        // Feature permissions
        expect(user).toHaveProperty('canSearch');
        expect(user).toHaveProperty('canHunt');
        expect(user).toHaveProperty('canExport');
        expect(user).toHaveProperty('canViewRepo');
        // Admin permissions
        expect(user).toHaveProperty('canRecon');
        expect(user).toHaveProperty('canManageSIEM');
        expect(user).toHaveProperty('canManageTI');
        expect(user).toHaveProperty('canManageMappings');
        expect(user).toHaveProperty('canManageUsers');
        expect(user).toHaveProperty('canManageSecurity');
      }
    });

    test('users should not expose password hash', async () => {
      if (!authToken) {
        console.log('Skipping - no auth token');
        return;
      }

      const res = await api.get('/admin/users', {
        headers: { Authorization: `Bearer ${authToken}` }
      });

      if (res.data.length > 0) {
        const user = res.data[0];
        expect(user).not.toHaveProperty('passwordHash');
        expect(user).not.toHaveProperty('password');
        expect(user).not.toHaveProperty('mfaSecret');
        expect(user).not.toHaveProperty('mfaBackupCodes');
      }
    });
  });

  describe('POST /admin/users', () => {
    test('should require authentication', async () => {
      const res = await api.post('/admin/users', {
        username: 'testuser',
        password: 'testpass123',
        role: 'analyst'
      });

      expect([401, 403]).toContain(res.status);
    });

    test('should create user with default permissions', async () => {
      if (!authToken) {
        console.log('Skipping - no auth token');
        return;
      }

      const timestamp = Date.now();
      const res = await api.post('/admin/users', {
        username: `testuser_${timestamp}`,
        password: 'TestPass123!',
        role: 'analyst'
      }, {
        headers: { Authorization: `Bearer ${authToken}` }
      });

      if (res.status === 201 || res.status === 200) {
        testUserId = res.data.id;
        expect(res.data).toHaveProperty('id');
        expect(res.data.username).toBe(`testuser_${timestamp}`);
        // Analyst should have feature permissions enabled
        expect(res.data.canSearch).toBe(true);
        expect(res.data.canHunt).toBe(true);
        // But not admin permissions
        expect(res.data.canManageUsers).toBe(false);
      }
    });

    test('should reject duplicate username', async () => {
      if (!authToken) {
        console.log('Skipping - no auth token');
        return;
      }

      // Try to create user with same username as admin
      const res = await api.post('/admin/users', {
        username: 'admin',
        password: 'TestPass123!',
        role: 'analyst'
      }, {
        headers: { Authorization: `Bearer ${authToken}` }
      });

      expect([400, 409, 422]).toContain(res.status);
    });
  });

  describe('PUT /admin/users/:id', () => {
    test('should require authentication', async () => {
      const res = await api.put('/admin/users/1', {
        role: 'viewer'
      });

      expect([401, 403]).toContain(res.status);
    });

    test('should update user permissions', async () => {
      if (!authToken || !testUserId) {
        console.log('Skipping - no auth token or test user');
        return;
      }

      const res = await api.put(`/admin/users/${testUserId}`, {
        canRecon: true,
        canManageSIEM: true
      }, {
        headers: { Authorization: `Bearer ${authToken}` }
      });

      expect(res.status).toBe(200);
      expect(res.data.canRecon).toBe(true);
      expect(res.data.canManageSIEM).toBe(true);
    });

    test('should update user password', async () => {
      if (!authToken || !testUserId) {
        console.log('Skipping - no auth token or test user');
        return;
      }

      const res = await api.put(`/admin/users/${testUserId}`, {
        password: 'NewPassword456!'
      }, {
        headers: { Authorization: `Bearer ${authToken}` }
      });

      expect(res.status).toBe(200);
    });
  });

  describe('DELETE /admin/users/:id', () => {
    test('should require authentication', async () => {
      const res = await api.delete('/admin/users/999');
      expect([401, 403]).toContain(res.status);
    });

    test('should delete test user', async () => {
      if (!authToken || !testUserId) {
        console.log('Skipping - no auth token or test user');
        return;
      }

      const res = await api.delete(`/admin/users/${testUserId}`, {
        headers: { Authorization: `Bearer ${authToken}` }
      });

      expect([200, 204]).toContain(res.status);
    });

    test('should prevent deleting own account', async () => {
      if (!authToken) {
        console.log('Skipping - no auth token');
        return;
      }

      // Get current user's ID
      const usersRes = await api.get('/admin/users', {
        headers: { Authorization: `Bearer ${authToken}` }
      });

      const adminUser = usersRes.data.find(u => u.username === 'admin');
      if (!adminUser) return;

      const res = await api.delete(`/admin/users/${adminUser.id}`, {
        headers: { Authorization: `Bearer ${authToken}` }
      });

      // Should prevent self-deletion
      expect([400, 403]).toContain(res.status);
    });
  });
});
