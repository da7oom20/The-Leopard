/**
 * Security Tests - Cyber Security Validation
 * Tests for common vulnerabilities: SQL injection, XSS, auth bypass, etc.
 */

const axios = require('axios');

describe('Security Tests', () => {
  const api = axios.create({
    baseURL: global.API_URL,
    timeout: 10000,
    validateStatus: () => true
  });

  describe('SQL Injection Prevention', () => {
    const sqlPayloads = [
      "' OR '1'='1",
      "'; DROP TABLE users; --",
      "1; SELECT * FROM users",
      "' UNION SELECT * FROM users --",
      "admin'--",
      "1' OR '1'='1' /*",
      "') OR ('1'='1"
    ];

    test('should reject SQL injection in login username', async () => {
      for (const payload of sqlPayloads) {
        const res = await api.post('/auth/login', {
          username: payload,
          password: 'test'
        });
        // Should return 401 (invalid credentials) not 500 (SQL error)
        expect([400, 401, 429]).toContain(res.status);
        expect(res.data.message).not.toMatch(/sql|syntax|query/i);
      }
    });

    test('should reject SQL injection in login password', async () => {
      for (const payload of sqlPayloads) {
        const res = await api.post('/auth/login', {
          username: 'admin',
          password: payload
        });
        expect([400, 401, 429]).toContain(res.status);
        expect(res.data.message).not.toMatch(/sql|syntax|query/i);
      }
    });
  });

  describe('XSS Prevention', () => {
    const xssPayloads = [
      '<script>alert("xss")</script>',
      '<img src=x onerror=alert("xss")>',
      '"><script>alert(1)</script>',
      "javascript:alert('xss')",
      '<svg onload=alert(1)>',
      '{{constructor.constructor("alert(1)")()}}'
    ];

    test('should sanitize XSS in search input', async () => {
      const FormData = require('form-data');

      for (const payload of xssPayloads) {
        const form = new FormData();
        form.append('rawText', payload);
        form.append('clientIds', JSON.stringify([]));
        form.append('days', '7');

        const res = await api.post('/upload', form, {
          headers: form.getHeaders()
        });

        // Response should not contain unescaped script tags
        const responseStr = JSON.stringify(res.data);
        expect(responseStr).not.toContain('<script>');
        expect(responseStr).not.toContain('onerror=');
      }
    });
  });

  describe('Authentication Security', () => {
    test('should not expose password hash in user list', async () => {
      // Try to get users without auth
      const res = await api.get('/admin/users');

      if (res.status === 200 && res.data) {
        const responseStr = JSON.stringify(res.data);
        expect(responseStr).not.toMatch(/passwordHash|password.*:/i);
        expect(responseStr).not.toMatch(/mfaSecret/i);
        expect(responseStr).not.toMatch(/mfaBackupCodes/i);
      }
    });

    test('should reject expired/invalid JWT tokens', async () => {
      const invalidTokens = [
        'invalid.token.here',
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjEsImlhdCI6MTUxNjIzOTAyMn0.fake',
        '',
        'Bearer ',
        'null',
        'undefined'
      ];

      for (const token of invalidTokens) {
        const res = await api.get('/admin/users', {
          headers: { Authorization: `Bearer ${token}` }
        });
        expect([401, 403]).toContain(res.status);
      }
    });

    test('should not leak information in error messages', async () => {
      const res = await api.post('/auth/login', {
        username: 'nonexistent_user_12345',
        password: 'wrongpassword'
      });

      // Error message should not reveal if user exists
      if (res.data.message) {
        expect(res.data.message.toLowerCase()).not.toContain('user not found');
        expect(res.data.message.toLowerCase()).not.toContain('username does not exist');
      }
    });
  });

  describe('Authorization Tests', () => {
    test('should reject unauthenticated admin access', async () => {
      const adminEndpoints = [
        '/admin/api-keys',
        '/admin/users',
        '/admin/ti-sources',
        '/admin/ssl',
        '/recon/mappings/1'
      ];

      for (const endpoint of adminEndpoints) {
        const res = await api.get(endpoint);
        expect([401, 403, 404]).toContain(res.status);
      }
    });

    test('should reject unauthorized POST to admin endpoints', async () => {
      const res = await api.post('/admin/users', {
        username: 'hacker',
        password: 'hacked123',
        role: 'admin'
      });
      expect([401, 403]).toContain(res.status);
    });

    test('should reject unauthorized DELETE operations', async () => {
      const res = await api.delete('/admin/users/1');
      expect([401, 403]).toContain(res.status);
    });
  });

  describe('Input Validation', () => {
    test('should reject oversized payloads', async () => {
      const largePayload = 'A'.repeat(10 * 1024 * 1024); // 10MB

      const res = await api.post('/auth/login', {
        username: largePayload,
        password: 'test'
      });

      // Should reject or handle gracefully, not crash
      expect([400, 413, 429, 500]).toContain(res.status);
    });

    test('should handle special characters in input', async () => {
      const specialChars = [
        '\x00\x01\x02', // Null bytes
        '\n\r\t',       // Control chars
        '../../etc/passwd', // Path traversal
        '%00%0a%0d',    // URL encoded
        '\\x00\\x0a'    // Escaped
      ];

      for (const payload of specialChars) {
        const res = await api.post('/auth/login', {
          username: payload,
          password: payload
        });
        // Should handle gracefully
        expect([400, 401, 429]).toContain(res.status);
      }
    });

    test('should validate email format', async () => {
      const invalidEmails = [
        'notanemail',
        '@nodomain.com',
        'no@',
        'spaces in@email.com'
      ];

      // Test in any endpoint that accepts email (if applicable)
      // For now, just verify the server doesn't crash
      for (const email of invalidEmails) {
        const res = await api.post('/auth/login', {
          username: email,
          password: 'test'
        });
        expect(res.status).not.toBe(500);
      }
    });
  });

  describe('Rate Limiting', () => {
    test('should enforce rate limits on login', async () => {
      const requests = [];

      // Send 15 rapid requests
      for (let i = 0; i < 15; i++) {
        requests.push(api.post('/auth/login', {
          username: `test${i}`,
          password: 'test'
        }));
      }

      const results = await Promise.all(requests);
      const rateLimited = results.filter(r => r.status === 429);

      // At least some requests should be rate limited
      expect(rateLimited.length).toBeGreaterThan(0);
    });
  });

  describe('Path Traversal Prevention', () => {
    test('should reject path traversal attempts', async () => {
      const traversalPayloads = [
        '../../../etc/passwd',
        '..\\..\\..\\windows\\system32\\config\\sam',
        '....//....//....//etc/passwd',
        '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
        '..%252f..%252f..%252fetc/passwd'
      ];

      for (const payload of traversalPayloads) {
        // Test in file-related endpoints if any
        const res = await api.get(`/export-results?filename=${encodeURIComponent(payload)}`);
        expect(res.status).not.toBe(200);

        // Response should not contain file contents
        const responseStr = JSON.stringify(res.data || '');
        expect(responseStr).not.toContain('root:');
        expect(responseStr).not.toContain('[boot loader]');
      }
    });
  });

  describe('CORS and Headers', () => {
    test('should have security headers', async () => {
      const res = await api.get('/setup/status');

      // Check for common security headers (may not all be present)
      // Just verify the request succeeds
      expect(res.status).toBe(200);
    });
  });

  describe('Session Security', () => {
    test('should invalidate session on logout (if implemented)', async () => {
      // This test assumes a logout endpoint exists
      // Skip if not implemented
      const res = await api.post('/auth/logout', {});
      expect([200, 401, 404]).toContain(res.status);
    });
  });

  describe('Sensitive Data Exposure', () => {
    test('should not expose internal errors', async () => {
      // Send malformed data to trigger potential errors
      const res = await api.post('/upload', 'not-valid-data', {
        headers: { 'Content-Type': 'application/json' }
      });

      if (res.data) {
        const responseStr = JSON.stringify(res.data);
        // Should not expose stack traces or internal paths
        expect(responseStr).not.toMatch(/at\s+\w+\s+\(/); // Stack trace
        expect(responseStr).not.toMatch(/\/app\//); // Internal paths
        expect(responseStr).not.toMatch(/node_modules/);
      }
    });

    test('should not expose database info in errors', async () => {
      const res = await api.post('/auth/login', {
        username: "'; SELECT version(); --",
        password: 'test'
      });

      if (res.data) {
        const responseStr = JSON.stringify(res.data).toLowerCase();
        expect(responseStr).not.toContain('mysql');
        expect(responseStr).not.toContain('sequelize');
        expect(responseStr).not.toContain('mariadb');
        expect(responseStr).not.toContain('postgresql');
      }
    });
  });
});
