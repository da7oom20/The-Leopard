module.exports = {
  testEnvironment: 'node',
  testMatch: ['**/api/**/*.test.js'],
  setupFilesAfterEnv: ['./setup.js'],
  testTimeout: 30000,
  verbose: true,
  collectCoverageFrom: [
    '../server/**/*.js',
    '!../server/node_modules/**'
  ],
  coverageDirectory: './coverage',
  coverageReporters: ['text', 'lcov', 'html']
};
