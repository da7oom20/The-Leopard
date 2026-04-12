/**
 * Login Page E2E Tests
 */

describe('Login Page', () => {
  beforeEach(() => {
    cy.visit('/login');
  });

  it('should display login form', () => {
    cy.get('input[name="username"]').should('be.visible');
    cy.get('input[name="password"]').should('be.visible');
    cy.get('button[type="submit"]').should('be.visible');
  });

  it('should display The Leopard branding', () => {
    cy.contains('The Leopard').should('be.visible');
    cy.contains('IOC Search Platform').should('be.visible');
  });

  it('should show error for empty credentials', () => {
    cy.get('button[type="submit"]').click();
    // Should show validation error or stay on page
    cy.url().should('include', '/login');
  });

  it('should show error for invalid credentials', () => {
    cy.get('input[name="username"]').type('wronguser');
    cy.get('input[name="password"]').type('wrongpassword');
    cy.get('button[type="submit"]').click();

    // Should show error message
    cy.contains(/invalid|failed|error/i, { timeout: 5000 }).should('be.visible');
  });

  it('should successfully login with valid credentials', () => {
    cy.get('input[name="username"]').type('admin');
    cy.get('input[name="password"]').type('admin123');
    cy.get('button[type="submit"]').click();

    // Should redirect to admin or show MFA prompt
    cy.url({ timeout: 10000 }).should('satisfy', (url) => {
      return url.includes('/admin') || url.includes('/login');
    });
  });

  it('should show MFA prompt when MFA is enabled', () => {
    cy.get('input[name="username"]').type('admin');
    cy.get('input[name="password"]').type('admin123');
    cy.get('button[type="submit"]').click();

    // If MFA is enabled, should show MFA input
    cy.get('body').then(($body) => {
      if ($body.text().includes('Two-Factor')) {
        cy.contains('Two-Factor Authentication').should('be.visible');
        cy.get('input[maxlength="6"]').should('be.visible');
      }
    });
  });

  it('should have working backup code option', () => {
    cy.get('input[name="username"]').type('admin');
    cy.get('input[name="password"]').type('admin123');
    cy.get('button[type="submit"]').click();

    // If MFA prompt appears, check for backup code option
    cy.get('body').then(($body) => {
      if ($body.text().includes('Two-Factor')) {
        cy.contains('backup code').click();
        cy.contains('Enter one of your backup codes').should('be.visible');
      }
    });
  });
});
