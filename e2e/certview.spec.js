const { test, expect } = require('@playwright/test');

const baseURL = process.env.CERTVIEW_E2E_BASE_URL || 'http://127.0.0.1:18080';
const siteHost = process.env.CERTVIEW_E2E_HOST || 'www.gosuslugi.ru';
const unresolvedHost = process.env.CERTVIEW_E2E_UNRESOLVED_HOST || 'не-существует.invalid';

async function waitIdle(page) {
  await page.waitForFunction(() => !document.querySelector('#loading').classList.contains('active'));
}

async function expectReady(page) {
  await waitIdle(page);
  await expect(page.locator('#error-box')).not.toHaveClass(/active/);
  await expect(page.locator('#results')).toHaveClass(/active/);
  await expect(page.locator('#chain-tree .chain-node').first()).toBeVisible();
}

test.describe('certview site links', () => {
  test.beforeEach(async ({ page }) => {
    page.on('dialog', dialog => {
      throw new Error(`Unexpected dialog: ${dialog.type()} ${dialog.message()}`);
    });
  });

  test('analyzes site without hash and copied links round-trip', async ({ page, context }) => {
    await context.grantPermissions(['clipboard-read', 'clipboard-write'], { origin: baseURL });

    await page.goto(baseURL + '/');
    await page.fill('#pem-input', siteHost);
    await page.click('#pem-btn');
    await expectReady(page);

    const analyzedURL = new URL(page.url());
    expect(analyzedURL.hash).toBe('');
    expect(analyzedURL.pathname).not.toBe('/');

    const linkButtons = page.locator('#chain-tree > .chain-node > .cert-actions button', { hasText: 'Link' });
    const count = await linkButtons.count();
    expect(count).toBeGreaterThan(0);

    const copied = [];
    for (let i = 0; i < count; i++) {
      await linkButtons.nth(i).click();
      const href = await page.evaluate(() => navigator.clipboard.readText());
      copied.push(href);
    }

    expect(new URL(copied[0]).pathname).toBe(analyzedURL.pathname);
    for (const href of copied.slice(1)) {
      expect(new URL(href).pathname).toBe('/');
    }

    for (const href of copied) {
      await page.goto(href);
      await expectReady(page);
    }
  });

  test('shows in-page error without dialog for unresolved host', async ({ page }) => {
    await page.goto(baseURL + '/');
    await page.fill('#pem-input', unresolvedHost);
    await page.click('#pem-btn');
    await waitIdle(page);

    await expect(page.locator('#error-box')).toHaveClass(/active/);
    await expect(page.locator('#error-box')).toContainText('Site fetch failed');
    await expect(page.locator('#results')).not.toHaveClass(/active/);
  });
});

test.describe('certificate links', () => {
  const b64url = b64 => b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  let chain;

  test.beforeAll(async ({ request }) => {
    const resp = await request.post(baseURL + '/api/site', { data: { url: siteHost } });
    expect(resp.ok()).toBeTruthy();
    const site = await resp.json();
    chain = site.results.find(r => r.ok).analysis.chain.map(c => b64url(c.der_b64));
    expect(chain.length).toBeGreaterThan(1);
  });

  test('opens the certificate of a link and keeps the link on reload', async ({ page }) => {
    const link = baseURL + '/#cert=' + chain[0];
    await page.goto(link);
    await expectReady(page);
    await expect(page.locator('#chain-tree > .chain-node').first()).toContainText('LEAF');
    expect(page.url()).toBe(link);

    await page.reload();
    await expectReady(page);
    expect(page.url()).toBe(link);
  });

  test('builds the whole chain from a link', async ({ page }) => {
    const link = baseURL + '/#' + chain.map(c => 'cert=' + c).join('&');
    await page.goto(link);
    await expectReady(page);
    await expect(page.locator('#chain-tree > .chain-node')).toHaveCount(chain.length);
    expect(page.url()).toBe(link);
  });

  test('reports a bad link', async ({ page }) => {
    for (const hash of ['#cert=not*base64', '#cert=' + chain[0] + '&cert=MAMCAQE']) {
      await page.goto('about:blank');
      await page.goto(baseURL + '/' + hash);
      await waitIdle(page);
      await expect(page.locator('#error-box')).toHaveClass(/active/);
      await expect(page.locator('#error-box')).toContainText('Bad link');
    }
  });
});

test.describe('revocation details', () => {
  const revokedAt = '2026-10-01T12:00:00Z';
  const cert = (cn, extra) => ({
    subject: 'CN = ' + cn, issuer: 'CN = Test Root', serial: '0A', path_len: -1,
    not_before: '2026-01-01T00:00:00Z', not_after: '2027-01-01T00:00:00Z',
    is_ca: false, is_self_signed: false, is_cross_signed: false, trusted: false,
    thumbprint_sha1: 'AA', thumbprint_sha256: 'BB', stored: false, ...extra,
  });
  const analysis = {
    chain: [
      cert('Revoked Leaf', {
        ocsp_urls: ['http://ocsp.test/'],
        revocation: { status: 'revoked', via: 'OCSP', revoked_at: revokedAt, revoke_reason: 'keyCompromise' },
      }),
      cert('Test Root', {
        is_ca: true, is_self_signed: true, serial: '01',
        issued_ocsps: [{
          url: 'http://ocsp.test/', status: 'revoked', verified: true,
          this_update: '2026-10-20T00:00:00Z', next_update: '2026-10-30T00:00:00Z',
          revoked_at: revokedAt, revoke_reason: 'keyCompromise',
          cert_subject: 'CN = Revoked Leaf', cert_serial: '0A', source: 'fetched',
        }],
      }),
    ],
    verify: { status: 'error', message: 'Certificate is revoked', trusted: false, revocation_status: 'revoked' },
    is_admin: false,
  };

  test('shows OCSP revocation date and reason', async ({ page }) => {
    await page.route('**/api/analyze', route => route.fulfill({ json: analysis }));
    await page.goto(baseURL + '/');
    await page.fill('#pem-input', '-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----');
    await page.click('#pem-btn');
    await expectReady(page);

    const details = page.locator('#cert-details');
    await expect(details).toContainText(revokedAt);
    await expect(details).toContainText('keyCompromise');

    const ocspNode = page.locator('#chain-tree .crl-inline', { hasText: 'OCSP' });
    await expect(ocspNode).toContainText(revokedAt);
    await ocspNode.click();
    await expect(details).toContainText('Revoked At');
    await expect(details).toContainText(revokedAt);
    await expect(details).toContainText('Revocation Reason');
    await expect(details).toContainText('keyCompromise');
  });
});
