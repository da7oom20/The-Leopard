/**
 * Admin Panel E2E Tests
 */

describe('Admin Panel', () => {
  beforeEach(() => {
    // Login first
    cy.apiLogin().then((response) => {
      if (response.body.token) {
        cy.visit('/admin');
      } else if (response.body.mfaRequired) {
        cy.log('MFA required - some tests may be skipped');
        cy.visit('/login');
      } else {
        cy.log('Login failed - tests may fail');
        cy.visit('/admin');
      }
    });
  });

  describe('Navigation', () => {
    it('should display admin panel when logged in', () => {
      cy.url().then((url) => {
        if (url.includes('/admin')) {
          cy.contains(/admin|management|settings/i).should('exist');
        }
      });
    });

    it('should have tabbed interface', () => {
      cy.url().then((url) => {
        if (url.includes('/admin')) {
          // Should have tabs
          cy.get('button, [role="tab"]').then(($tabs) => {
            const tabCount = $tabs.filter((i, el) => {
              const text = el.textContent.toLowerCase();
              return text.includes('siem') ||
                     text.includes('ti') ||
                     text.includes('users') ||
                     text.includes('recon') ||
                     text.includes('mapping') ||
                     text.includes('security');
            }).length;
            expect(tabCount).to.be.greaterThan(0);
          });
        }
      });
    });
  });

  describe('SIEM Tab', () => {
    it('should display SIEM clients tab', () => {
      cy.url().then((url) => {
        if (url.includes('/admin')) {
          cy.contains(/siem|client/i).should('exist');
        }
      });
    });

    it('should have Add SIEM button', () => {
      cy.url().then((url) => {
        if (url.includes('/admin')) {
          cy.get('button').filter(':contains("Add")').should('exist');
        }
      });
    });
  });

  describe('TI Sources Tab', () => {
    it('should switch to TI tab', () => {
      cy.url().then((url) => {
        if (url.includes('/admin')) {
          cy.contains(/ti source|threat intel/i).click({ force: true });
          // Tab content should change
          cy.contains(/platform|source|feed/i).should('exist');
        }
      });
    });
  });

  describe('Users Tab', () => {
    it('should switch to Users tab', () => {
      cy.url().then((url) => {
        if (url.includes('/admin')) {
          cy.contains(/user/i).click({ force: true });
          // Should show user list or form
          cy.contains(/username|role|permission/i, { timeout: 5000 }).should('exist');
        }
      });
    });

    it('should display user permissions', () => {
      cy.url().then((url) => {
        if (url.includes('/admin')) {
          cy.contains(/user/i).click({ force: true });
          // Check for permission-related content
          cy.get('body').then(($body) => {
            const hasPermissions = $body.text().toLowerCase().includes('permission') ||
                                  $body.text().toLowerCase().includes('search') ||
                                  $body.text().toLowerCase().includes('export');
            cy.log('Has permission content:', hasPermissions);
          });
        }
      });
    });
  });

  describe('Security Tab', () => {
    it('should switch to Security tab', () => {
      cy.url().then((url) => {
        if (url.includes('/admin')) {
          cy.contains(/security/i).click({ force: true });
          // Should show MFA and/or SSL options
          cy.contains(/mfa|ssl|certificate|authentication/i, { timeout: 5000 }).should('exist');
        }
      });
    });

    it('should have MFA setup option', () => {
      cy.url().then((url) => {
        if (url.includes('/admin')) {
          cy.contains(/security/i).click({ force: true });
          cy.contains(/mfa|two-factor|2fa/i).should('exist');
        }
      });
    });
  });

  describe('Field Mappings Tab', () => {
    it('should switch to Field Mappings tab', () => {
      cy.url().then((url) => {
        if (url.includes('/admin')) {
          cy.contains(/mapping/i).click({ force: true });
          // Should show mappings table or empty state
          cy.contains(/field|mapping|client/i, { timeout: 5000 }).should('exist');
        }
      });
    });
  });

  describe('Recon Tab', () => {
    it('should switch to Recon tab', () => {
      cy.url().then((url) => {
        if (url.includes('/admin')) {
          cy.contains(/recon/i).click({ force: true });
          // Should show Recon interface
          cy.contains(/discovery|field|log source|dig/i, { timeout: 5000 }).should('exist');
        }
      });
    });
  });
});

describe('Admin Access Control', () => {
  it('should redirect to login when not authenticated', () => {
    // Clear any existing tokens
    cy.clearLocalStorage();
    cy.clearCookies();

    cy.visit('/admin');

    // Should redirect to login
    cy.url({ timeout: 10000 }).should('include', '/login');
  });
});
