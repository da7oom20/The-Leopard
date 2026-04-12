// Test setup file
const path = require('path');

// Set test environment variables
process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'test-jwt-secret-for-testing';

// API base URL - use port 4000 inside container, 3005 from host
const API_BASE_URL = process.env.TEST_API_URL || 'http://localhost:4000';

// Export for use in tests
global.API_BASE_URL = API_BASE_URL;
global.API_URL = `${API_BASE_URL}/api`;

// Default test credentials
global.TEST_ADMIN_USER = process.env.TEST_ADMIN_USER || 'admin';
global.TEST_ADMIN_PASS = process.env.TEST_ADMIN_PASS || 'admin123';

// Helper to get admin auth token
global.getAdminToken = async () => {
  const axios = require('axios');
  try {
    const res = await axios.post(`${global.API_URL}/auth/login`, {
      username: global.TEST_ADMIN_USER,
      password: global.TEST_ADMIN_PASS
    }, { validateStatus: () => true });
    return res.data?.token || null;
  } catch {
    return null;
  }
};

// Helper to create authenticated axios instance
global.createAuthApi = (token) => {
  const axios = require('axios');
  return axios.create({
    baseURL: global.API_URL,
    validateStatus: () => true,
    headers: token ? { Authorization: `Bearer ${token}` } : {}
  });
};

// Test timeouts
jest.setTimeout(30000);

// Console logging for test debugging
if (process.env.DEBUG_TESTS) {
  console.log('Test Configuration:');
  console.log(`  API_BASE_URL: ${API_BASE_URL}`);
  console.log(`  API_URL: ${global.API_URL}`);
}
