// Cypress E2E Support File

// Custom commands for common operations

// Login command
Cypress.Commands.add('login', (username = 'admin', password = 'admin123') => {
  cy.visit('/login');
  cy.get('input[name="username"]').type(username);
  cy.get('input[name="password"]').type(password);
  cy.get('button[type="submit"]').click();
  // Wait for redirect or MFA prompt
  cy.url().should('not.include', '/login');
});

// API login (get JWT token)
Cypress.Commands.add('apiLogin', (username = 'admin', password = 'admin123') => {
  return cy.request({
    method: 'POST',
    url: `${Cypress.env('apiUrl')}/auth/login`,
    body: { username, password },
    failOnStatusCode: false
  }).then((response) => {
    if (response.body.token) {
      Cypress.env('authToken', response.body.token);
      window.localStorage.setItem('token', response.body.token);
    }
    return response;
  });
});

// Check if element exists without failing
Cypress.Commands.add('ifExists', (selector, callback) => {
  cy.get('body').then(($body) => {
    if ($body.find(selector).length > 0) {
      callback();
    }
  });
});

// Wait for API call to complete
Cypress.Commands.add('waitForApi', (alias, timeout = 30000) => {
  cy.wait(alias, { timeout });
});

// Upload file helper
Cypress.Commands.add('uploadFile', (selector, filePath, mimeType) => {
  cy.get(selector).selectFile(filePath, { mimeType });
});

// Suppress uncaught exceptions from the app
Cypress.on('uncaught:exception', (err, runnable) => {
  // Returning false prevents Cypress from failing the test
  console.log('Uncaught exception:', err.message);
  return false;
});

// Log test name on start
beforeEach(() => {
  const testName = Cypress.currentTest.title;
  cy.log(`Running: ${testName}`);
});
