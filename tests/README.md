# The Leopard - Test Suite

Comprehensive testing for The Leopard IOC Search App.

## Quick Start

```bash
# Install test dependencies
npm install

# Run all API tests
npm test

# Run E2E tests (requires running app)
npm run test:e2e
```

## Test Structure

```
tests/
├── api/                    # Backend API tests (Jest + Axios)
│   ├── auth.test.js        # Authentication & MFA
│   ├── health.test.js      # System health checks
│   ├── recon.test.js       # Field discovery
│   ├── search.test.js      # IOC search & hunt
│   ├── setup.test.js       # Setup wizard
│   ├── siem.test.js        # SIEM management
│   └── users.test.js       # User & permission management
│
├── e2e/                    # End-to-end tests (Cypress)
│   ├── admin.cy.js         # Admin panel flows
│   ├── login.cy.js         # Login & MFA flows
│   ├── search.cy.js        # IOC search flows
│   └── support.js          # Cypress helpers
│
├── fixtures/               # Test data
│   └── sample-iocs.txt     # Sample IOC file
│
├── cypress.config.js       # Cypress configuration
├── jest.config.js          # Jest configuration
├── setup.js                # Jest setup
└── package.json            # Test dependencies
```

## Available Scripts

| Script | Description |
|--------|-------------|
| `npm test` | Run API tests |
| `npm run test:api` | Run API tests |
| `npm run test:api:watch` | Run API tests in watch mode |
| `npm run test:api:coverage` | Run tests with coverage report |
| `npm run test:e2e` | Run Cypress E2E tests (headless) |
| `npm run test:e2e:open` | Open Cypress UI |
| `npm run test:all` | Run all tests (API + E2E) |
| `npm run test:health` | Run health checks only |
| `npm run test:auth` | Run auth tests only |
| `npm run test:search` | Run search tests only |
| `npm run test:users` | Run user tests only |

## Prerequisites

Before running tests:

1. **Application must be running:**
   ```bash
   docker-compose up -d
   ```

2. **Default test credentials:**
   - Username: `admin`
   - Password: `admin123`

3. **Environment variables (optional):**
   ```bash
   export TEST_API_URL=http://localhost:3005
   export TEST_FRONTEND_URL=http://localhost:3015
   ```

## API Tests (Jest)

API tests use Jest with Axios for HTTP requests.

### Running Specific Tests

```bash
# Run a single test file
npx jest api/auth.test.js

# Run tests matching a pattern
npx jest --testNamePattern="login"

# Run with verbose output
npx jest --verbose
```

### Test Configuration

Edit `jest.config.js` to modify:
- Test timeout (default: 30s)
- Coverage settings
- Test patterns

## E2E Tests (Cypress)

E2E tests simulate real user interactions.

### Running E2E Tests

```bash
# Headless mode
npm run test:e2e

# Interactive mode (recommended for debugging)
npm run test:e2e:open
```

### E2E Configuration

Edit `cypress.config.js` to modify:
- Base URL
- Viewport size
- Timeouts
- Video recording

## Writing New Tests

### API Test Example

```javascript
// tests/api/my-feature.test.js
const axios = require('axios');

describe('My Feature', () => {
  const api = axios.create({
    baseURL: global.API_URL,
    validateStatus: () => true
  });

  test('should do something', async () => {
    const res = await api.get('/my-endpoint');
    expect(res.status).toBe(200);
  });
});
```

### E2E Test Example

```javascript
// tests/e2e/my-flow.cy.js
describe('My Flow', () => {
  it('should complete user flow', () => {
    cy.visit('/');
    cy.get('button').click();
    cy.contains('Success').should('be.visible');
  });
});
```

## Troubleshooting

### Tests fail with connection errors
- Ensure Docker containers are running
- Check port bindings (3005 for API, 3015 for frontend)
- Verify network connectivity

### Authentication tests fail
- Create admin user via Setup Wizard
- Check default credentials match
- Disable MFA for testing if needed

### E2E tests timeout
- Increase timeout in `cypress.config.js`
- Check if frontend is responsive
- Look for JavaScript errors in browser console

### Coverage report not generated
```bash
npm run test:api:coverage
# Report saved to tests/coverage/
```

## CI/CD Integration

Example GitHub Actions workflow:

```yaml
name: Tests
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Start services
        run: docker-compose up -d
      - name: Wait for services
        run: sleep 30
      - name: Install test deps
        run: cd tests && npm install
      - name: Run tests
        run: cd tests && npm test
```
