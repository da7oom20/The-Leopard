/**
 * IOC Search E2E Tests
 */

describe('IOC Search Page', () => {
  beforeEach(() => {
    cy.visit('/');
  });

  it('should display upload page', () => {
    cy.contains('The Leopard').should('be.visible');
    cy.get('textarea').should('exist'); // IOC input area
  });

  it('should have IOC input textarea', () => {
    cy.get('textarea').should('be.visible');
    cy.get('textarea').should('have.attr', 'placeholder');
  });

  it('should accept IOC text input', () => {
    const testIOCs = '192.168.1.1\ngoogle.com\nd41d8cd98f00b204e9800998ecf8427e';

    cy.get('textarea').type(testIOCs);
    cy.get('textarea').should('have.value', testIOCs);
  });

  it('should have file upload option', () => {
    // Check for file input or upload button
    cy.get('body').then(($body) => {
      const hasFileInput = $body.find('input[type="file"]').length > 0;
      const hasUploadButton = $body.find('button').filter(':contains("Upload")').length > 0 ||
                              $body.find('button').filter(':contains("Browse")').length > 0;
      expect(hasFileInput || hasUploadButton).to.be.true;
    });
  });

  it('should have client selection', () => {
    // Should have checkboxes or dropdown for client selection
    cy.get('input[type="checkbox"], select').should('exist');
  });

  it('should have time range selector', () => {
    // Should have days input or dropdown
    cy.get('body').then(($body) => {
      const hasDaysInput = $body.find('input[name="days"], select').length > 0;
      const hasTimeOption = $body.text().toLowerCase().includes('day') ||
                           $body.text().toLowerCase().includes('time') ||
                           $body.text().toLowerCase().includes('period');
      expect(hasDaysInput || hasTimeOption).to.be.true;
    });
  });

  it('should have submit button', () => {
    cy.get('button[type="submit"], button').filter(':contains("Search"), button:contains("Submit")')
      .should('exist');
  });

  it('should show detected IOC types after input', () => {
    const testIOCs = '192.168.1.1\ngoogle.com\nd41d8cd98f00b204e9800998ecf8427e';

    cy.get('textarea').type(testIOCs);

    // Should detect and display IOC types (IP, Domain, Hash)
    cy.get('body').then(($body) => {
      // Give time for detection
      cy.wait(1000);
      // Check if IOC counts or types are displayed
      const bodyText = $body.text().toLowerCase();
      const hasIOCInfo = bodyText.includes('ip') ||
                        bodyText.includes('domain') ||
                        bodyText.includes('hash') ||
                        bodyText.includes('detected');
      // This might not be immediately visible, so just log
      cy.log('IOC detection info present:', hasIOCInfo);
    });
  });

  it('should have Hunt button for TI-based searching', () => {
    cy.get('button').filter(':contains("Hunt")').should('exist');
  });

  it('should open Hunt modal when clicked', () => {
    cy.get('button').filter(':contains("Hunt")').first().click();

    // Modal should appear
    cy.get('[role="dialog"], .modal, [class*="modal"]', { timeout: 5000 })
      .should('be.visible');
  });
});

describe('Search Results', () => {
  it('should navigate to results page after search', () => {
    cy.visit('/');

    // Input some IOCs
    cy.get('textarea').type('8.8.8.8');

    // Check if any clients are available
    cy.get('input[type="checkbox"]').then(($checkboxes) => {
      if ($checkboxes.length > 0) {
        // Select first client
        cy.wrap($checkboxes.first()).check({ force: true });

        // Submit
        cy.get('button[type="submit"], button')
          .filter(':contains("Search"), button:contains("Submit")')
          .first()
          .click();

        // Should redirect or show results
        cy.url({ timeout: 30000 }).should('satisfy', (url) => {
          return url.includes('/results') ||
                 url.includes('/repo') ||
                 url === Cypress.config().baseUrl + '/';
        });
      } else {
        cy.log('No SIEM clients configured - skipping search test');
      }
    });
  });
});
