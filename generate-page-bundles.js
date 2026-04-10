/*
  Generate page-specific app bundles from app.js.
  This keeps app.js as source-of-truth while cutting unrelated sections per entry page.

  Usage:
    node generate-page-bundles.js
*/

const fs = require('fs');
const path = require('path');

const ROOT = __dirname;
const SOURCE = path.join(ROOT, 'app.js');

const OUT_REQUEST = path.join(ROOT, 'app-request.js');
const OUT_WORKFLOWS = path.join(ROOT, 'app-workflows.js');
const OUT_SETTINGS = path.join(ROOT, 'app-settings.js');
const OUT_ITEMIZE = path.join(ROOT, 'app-itemize.js');
const OUT_BANKING = path.join(ROOT, 'app-banking.js');
const OUT_TRANSFERS = path.join(ROOT, 'app-transfers.js');
const OUT_OPERATIONS = path.join(ROOT, 'app-operations.js');
const OUT_BUDGET = path.join(ROOT, 'app-budget.js');

const M_RECON = '// ---- Payment Orders Reconciliation (year-scoped) ----';
const M_SETTINGS = '// ---- Roles / Users (settings page) ----';
const M_INCOME = '// ---- Income (year-scoped) ----';
const M_PAYMENT_ORDERS = 'const PAYMENT_ORDERS_COL_TYPES = {';
const M_BACKUP_FN = 'function initBackupPage() {';
const M_ITEMIZE = '// ---- Itemize page logic ----';
const M_MT_LIST = '// ---- Money Transfers list page ----';
const M_INCOME_COL_TYPES = 'const INCOME_COL_TYPES = {';
const M_LOAD_INCOME_FN = 'function loadIncome(year) {';
const M_BUDGET_EDITOR_FN = 'function initBudgetEditor() {';
const M_ARCHIVE_FN = 'function initArchivePage() {';
const M_CATCH = '\n})().catch((err) => {';
const M_REQUEST_BLOCK = '\n  if (form) {';
const M_KEYDOWN = "\n  document.addEventListener('keydown', (e) => {";

const INCOME_KEY_HELPER_FALLBACK = `

  // [bundle-fix:income-key-helper] Income section is stripped in this bundle,
  // but dev seeding still references this helper during startup.
  function getIncomeKeyForYear(year) {
    const y = Number(year);
    if (!Number.isInteger(y)) return null;
    return \`payment_order_income_\${y}_v1\`;
  }
`;

function assertFound(haystack, needle, label) {
  const idx = haystack.indexOf(needle);
  if (idx < 0) throw new Error(`Missing marker (${label}): ${needle}`);
  return idx;
}

function removeBetween(text, startMarker, endMarker, label) {
  const start = assertFound(text, startMarker, `${label}:start`);
  const end = assertFound(text, endMarker, `${label}:end`);
  if (end <= start) throw new Error(`Invalid marker order for ${label}`);

  const before = text.slice(0, start);
  const after = text.slice(end);
  return `${before}\n  // [bundle-strip:${label}] removed in page-specific build.\n${after}`;
}

function insertBeforeMarker(text, marker, insertText, label) {
  const idx = assertFound(text, marker, `${label}:marker`);
  const before = text.slice(0, idx);
  const after = text.slice(idx);
  return `${before}${insertText}${after}`;
}

function banner(name) {
  return `/* Generated from app.js by generate-page-bundles.js: ${name}. Do not edit manually. */\n`;
}

function writeBundle(filePath, content) {
  fs.writeFileSync(filePath, content, 'utf8');
  const bytes = fs.statSync(filePath).size;
  console.log(`${path.basename(filePath)}: ${bytes} bytes`);
}

function buildRequestBundle(source) {
  let out = source;
  out = removeBetween(out, M_RECON, M_SETTINGS, 'request-remove-reconciliation');
  out = removeBetween(out, M_SETTINGS, M_INCOME, 'request-remove-settings');
  out = removeBetween(out, M_INCOME, M_REQUEST_BLOCK, 'request-remove-workflows');
  out = removeBetween(out, M_ITEMIZE, M_CATCH, 'request-remove-itemize');
  out = insertBeforeMarker(out, M_CATCH, INCOME_KEY_HELPER_FALLBACK, 'request-insert-income-key-helper');
  out = insertBeforeMarker(
    out,
    M_CATCH,
    `

  // [bundle-fix:request-auth-wiring] The request bundle strips workflow wiring
  // above, but index page still needs header auth and popout link handlers.
  if (authHeaderBtn) {
    syncAuthHeaderBtn();
    if (!authHeaderBtn.dataset.bound) {
      authHeaderBtn.dataset.bound = 'true';
      authHeaderBtn.addEventListener('click', (e) => {
        e.preventDefault();
        openAuthLoginOverlay();
      });
    }
  }

  // Populate the side-nav tree (stripped with workflow wiring block).
  initBudgetYearNav();

  // Ensure the request-page nav toggle is shown/hidden based on auth state.
  syncRequestFormHamburgerVisibility();

  if (appShell && navToggleBtn && !navToggleBtn.dataset.requestNavBound) {
    navToggleBtn.dataset.requestNavBound = '1';
    updateNavToggleUi();
    navToggleBtn.addEventListener('click', () => {
      appShell.classList.toggle('appShell--navClosed');
      updateNavToggleUi();
    });
  }

  for (const popoutLink of requestHeaderPopoutLinks) {
    if (!popoutLink || popoutLink.dataset.bound) continue;
    popoutLink.dataset.bound = 'true';
    popoutLink.addEventListener('click', (e) => {
      e.preventDefault();

      const rawHref = String(popoutLink.getAttribute('href') || '').trim();
      if (!rawHref) return;

      const isExternal = popoutLink.getAttribute('data-popout-external') === '1';
      const href = isExternal ? rawHref : withWpEmbedParams(rawHref);
      const winName = String(popoutLink.getAttribute('data-popout-name') || 'acglInfoPopout').trim() || 'acglInfoPopout';

      const w = 1120;
      const h = 820;
      const screenLeft = Number(window.screenLeft ?? window.screenX ?? 0) || 0;
      const screenTop = Number(window.screenTop ?? window.screenY ?? 0) || 0;
      const screenH = Number(window.screen?.height) || window.outerHeight || h;
      const left = screenLeft + 20;
      const top = Math.max(0, Math.round(screenTop + (screenH - h) / 2));
      const features = 
        'popup=yes,toolbar=no,location=yes,status=no,menubar=no,scrollbars=yes,resizable=yes'
        + ',width=' + w + ',height=' + h + ',left=' + left + ',top=' + top;

      const win = window.open(href, winName, features);
      if (win && typeof win.focus === 'function') win.focus();
    });
  }
`,
    'request-insert-auth-wiring'
  );
  return banner('request') + out;
}

function buildWorkflowBundle(source) {
  let out = source;
  out = removeBetween(out, M_SETTINGS, M_INCOME, 'workflows-remove-settings');
  out = removeBetween(out, M_REQUEST_BLOCK, M_KEYDOWN, 'workflows-remove-request-form');
  out = removeBetween(out, M_ITEMIZE, M_CATCH, 'workflows-remove-itemize');
  out = removeBetween(out, M_MT_LIST, M_LOAD_INCOME_FN, 'workflows-remove-money-transfers');
  return banner('workflows') + out;
}

function buildSettingsBundle(source) {
  let out = source;
  out = removeBetween(out, M_PAYMENT_ORDERS, M_SETTINGS, 'settings-remove-payment-orders-and-reconciliation');
  out = removeBetween(out, M_INCOME, M_BACKUP_FN, 'settings-remove-workflows');
  out = removeBetween(out, M_REQUEST_BLOCK, M_KEYDOWN, 'settings-remove-request-form');
  out = removeBetween(out, M_ITEMIZE, M_CATCH, 'settings-remove-itemize');
  out = insertBeforeMarker(out, M_CATCH, INCOME_KEY_HELPER_FALLBACK, 'settings-insert-income-key-helper');
  return banner('settings') + out;
}

function buildItemizeBundle(source) {
  let out = source;
  out = removeBetween(out, M_SETTINGS, M_INCOME, 'itemize-remove-settings');
  out = removeBetween(out, M_INCOME, M_ITEMIZE, 'itemize-remove-non-itemize-workflows');
  return banner('itemize') + out;
}

function buildBankingBundle(source) {
  let out = source;
  out = removeBetween(out, M_SETTINGS, M_INCOME, 'banking-remove-settings');
  out = removeBetween(out, M_REQUEST_BLOCK, M_KEYDOWN, 'banking-remove-request-form');
  out = removeBetween(out, M_ITEMIZE, M_CATCH, 'banking-remove-itemize');
  out = removeBetween(out, M_MT_LIST, M_LOAD_INCOME_FN, 'banking-remove-money-transfers');
  return banner('banking') + out;
}

function buildTransfersBundle(source) {
  let out = source;
  out = removeBetween(out, M_SETTINGS, M_INCOME, 'transfers-remove-settings');
  out = removeBetween(out, M_REQUEST_BLOCK, M_KEYDOWN, 'transfers-remove-request-form');
  out = removeBetween(out, M_ITEMIZE, M_CATCH, 'transfers-remove-itemize');
  out = removeBetween(out, M_INCOME_COL_TYPES, M_BACKUP_FN, 'transfers-remove-income-and-banking-pages');
  return banner('transfers') + out;
}

function buildOperationsBundle(source) {
  let out = source;
  out = removeBetween(out, M_SETTINGS, M_INCOME, 'operations-remove-settings');
  out = removeBetween(out, M_REQUEST_BLOCK, M_KEYDOWN, 'operations-remove-request-form');
  out = removeBetween(out, M_ITEMIZE, M_CATCH, 'operations-remove-itemize');
  out = removeBetween(out, M_MT_LIST, M_LOAD_INCOME_FN, 'operations-remove-money-transfers');
  out = removeBetween(out, M_BUDGET_EDITOR_FN, M_ARCHIVE_FN, 'operations-remove-budget-editor');
  return banner('operations') + out;
}

function buildBudgetBundle(source) {
  let out = source;
  out = removeBetween(out, M_SETTINGS, M_INCOME, 'budget-remove-settings');
  out = removeBetween(out, M_REQUEST_BLOCK, M_KEYDOWN, 'budget-remove-request-form');
  out = removeBetween(out, M_ITEMIZE, M_CATCH, 'budget-remove-itemize');
  out = removeBetween(out, M_MT_LIST, M_LOAD_INCOME_FN, 'budget-remove-money-transfers');
  out = removeBetween(out, M_ARCHIVE_FN, M_BACKUP_FN, 'budget-remove-archive-and-backup');
  return banner('budget') + out;
}

function main() {
  const source = fs.readFileSync(SOURCE, 'utf8');

  const request = buildRequestBundle(source);
  const workflows = buildWorkflowBundle(source);
  const settings = buildSettingsBundle(source);
  const itemize = buildItemizeBundle(source);
  const banking = buildBankingBundle(source);
  const transfers = buildTransfersBundle(source);
  const operations = buildOperationsBundle(source);
  const budget = buildBudgetBundle(source);

  writeBundle(OUT_REQUEST, request);
  writeBundle(OUT_WORKFLOWS, workflows);
  writeBundle(OUT_SETTINGS, settings);
  writeBundle(OUT_ITEMIZE, itemize);
  writeBundle(OUT_BANKING, banking);
  writeBundle(OUT_TRANSFERS, transfers);
  writeBundle(OUT_OPERATIONS, operations);
  writeBundle(OUT_BUDGET, budget);

  console.log('Page bundles generated successfully.');
}

main();
