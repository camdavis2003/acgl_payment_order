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
const OUT_SETTINGS = path.join(ROOT, 'app-settings.js');
const OUT_ITEMIZE = path.join(ROOT, 'app-itemize.js');
const OUT_INCOME = path.join(ROOT, 'app-income.js');
const OUT_GS_LEDGER = path.join(ROOT, 'app-gs-ledger.js');
const OUT_WISE_EUR = path.join(ROOT, 'app-wise-eur.js');
const OUT_WISE_USD = path.join(ROOT, 'app-wise-usd.js');
const OUT_TRANSFERS = path.join(ROOT, 'app-transfers.js');
const OUT_MENU = path.join(ROOT, 'app-menu.js');
const OUT_ARCHIVE = path.join(ROOT, 'app-archive.js');
const OUT_RECONCILIATION = path.join(ROOT, 'app-reconciliation.js');
const OUT_BUDGET_EDITOR = path.join(ROOT, 'app-budget-editor.js');
const OUT_BUDGET_DASHBOARD = path.join(ROOT, 'app-budget-dashboard.js');

const M_RECON = '// ---- Payment Orders Reconciliation (year-scoped) ----';
const M_SETTINGS = '// ---- Roles / Users (settings page) ----';
const M_INCOME = '// ---- Income (year-scoped) ----';
const M_PAYMENT_ORDERS = 'const PAYMENT_ORDERS_COL_TYPES = {';
const M_BACKUP_FN = 'function initBackupPage() {';
const M_ITEMIZE = '// ---- Itemize page logic ----';
const M_MT_LIST = '// ---- Money Transfers list page ----';
const M_INCOME_COL_TYPES = 'const INCOME_COL_TYPES = {';
const M_LOAD_INCOME_FN = 'function loadIncome(year) {';
const M_GS_LEDGER_INIT_FN = 'function initGsLedgerListPage() {';
const M_INCOME_INIT_FN = 'function initIncomeListPage() {';
const M_WISE_EUR_INIT_FN = 'function initWiseEurListPage() {';
const M_WISE_USD_INIT_FN = 'function initWiseUsdListPage() {';
const M_BUDGET_EDITOR_FN = 'function initBudgetEditor() {';
const M_BUDGET_DASHBOARD_FN = 'function initBudgetDashboard() {';
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

function buildIncomeBundle(source) {
  let out = source;
  out = removeBetween(out, M_SETTINGS, M_INCOME, 'income-remove-settings');
  out = removeBetween(out, M_REQUEST_BLOCK, M_KEYDOWN, 'income-remove-request-form');
  out = removeBetween(out, M_ITEMIZE, M_CATCH, 'income-remove-itemize');
  out = removeBetween(out, M_MT_LIST, M_LOAD_INCOME_FN, 'income-remove-money-transfers');
  out = removeBetween(out, M_GS_LEDGER_INIT_FN, M_INCOME_INIT_FN, 'income-remove-gs-ledger-page');
  out = removeBetween(out, M_WISE_EUR_INIT_FN, M_BUDGET_EDITOR_FN, 'income-remove-wise-pages');
  return banner('income') + out;
}

function buildGsLedgerBundle(source) {
  let out = source;
  out = removeBetween(out, M_SETTINGS, M_INCOME, 'gs-ledger-remove-settings');
  out = removeBetween(out, M_REQUEST_BLOCK, M_KEYDOWN, 'gs-ledger-remove-request-form');
  out = removeBetween(out, M_ITEMIZE, M_CATCH, 'gs-ledger-remove-itemize');
  out = removeBetween(out, M_MT_LIST, M_LOAD_INCOME_FN, 'gs-ledger-remove-money-transfers');
  out = removeBetween(out, M_INCOME_INIT_FN, M_WISE_EUR_INIT_FN, 'gs-ledger-remove-income-page');
  out = removeBetween(out, M_WISE_EUR_INIT_FN, M_BUDGET_EDITOR_FN, 'gs-ledger-remove-wise-pages');
  return banner('gs-ledger') + out;
}

function buildWiseEurBundle(source) {
  let out = source;
  out = removeBetween(out, M_SETTINGS, M_INCOME, 'wise-eur-remove-settings');
  out = removeBetween(out, M_REQUEST_BLOCK, M_KEYDOWN, 'wise-eur-remove-request-form');
  out = removeBetween(out, M_ITEMIZE, M_CATCH, 'wise-eur-remove-itemize');
  out = removeBetween(out, M_MT_LIST, M_LOAD_INCOME_FN, 'wise-eur-remove-money-transfers');
  out = removeBetween(out, M_GS_LEDGER_INIT_FN, M_INCOME_INIT_FN, 'wise-eur-remove-ledger-page');
  out = removeBetween(out, M_INCOME_INIT_FN, M_WISE_EUR_INIT_FN, 'wise-eur-remove-income-page');
  out = removeBetween(out, M_WISE_USD_INIT_FN, M_BUDGET_EDITOR_FN, 'wise-eur-remove-wise-usd-page');
  out = removeBetween(out, M_BUDGET_EDITOR_FN, M_ARCHIVE_FN, 'wise-eur-remove-budget-editor');
  return banner('wise-eur') + out;
}

function buildWiseUsdBundle(source) {
  let out = source;
  out = removeBetween(out, M_SETTINGS, M_INCOME, 'wise-usd-remove-settings');
  out = removeBetween(out, M_REQUEST_BLOCK, M_KEYDOWN, 'wise-usd-remove-request-form');
  out = removeBetween(out, M_ITEMIZE, M_CATCH, 'wise-usd-remove-itemize');
  out = removeBetween(out, M_MT_LIST, M_LOAD_INCOME_FN, 'wise-usd-remove-money-transfers');
  out = removeBetween(out, M_GS_LEDGER_INIT_FN, M_INCOME_INIT_FN, 'wise-usd-remove-ledger-page');
  out = removeBetween(out, M_INCOME_INIT_FN, M_WISE_EUR_INIT_FN, 'wise-usd-remove-income-page');
  out = removeBetween(out, M_WISE_EUR_INIT_FN, M_WISE_USD_INIT_FN, 'wise-usd-remove-wise-eur-page');
  out = removeBetween(out, M_BUDGET_EDITOR_FN, M_ARCHIVE_FN, 'wise-usd-remove-budget-editor');
  return banner('wise-usd') + out;
}

function buildTransfersBundle(source) {
  let out = source;
  out = removeBetween(out, M_SETTINGS, M_INCOME, 'transfers-remove-settings');
  out = removeBetween(out, M_REQUEST_BLOCK, M_KEYDOWN, 'transfers-remove-request-form');
  out = removeBetween(out, M_ITEMIZE, M_CATCH, 'transfers-remove-itemize');
  out = removeBetween(out, M_INCOME_COL_TYPES, M_BACKUP_FN, 'transfers-remove-income-and-banking-pages');
  return banner('transfers') + out;
}

function buildMenuBundle(source) {
  let out = source;
  out = removeBetween(out, M_RECON, M_SETTINGS, 'menu-remove-reconciliation-page');
  out = removeBetween(out, M_SETTINGS, M_INCOME, 'menu-remove-settings');
  out = removeBetween(out, M_REQUEST_BLOCK, M_KEYDOWN, 'menu-remove-request-form');
  out = removeBetween(out, M_ITEMIZE, M_CATCH, 'menu-remove-itemize');
  out = removeBetween(out, M_MT_LIST, M_LOAD_INCOME_FN, 'menu-remove-money-transfers');
  out = removeBetween(out, M_BUDGET_EDITOR_FN, M_ARCHIVE_FN, 'menu-remove-budget-editor');
  out = removeBetween(out, M_ARCHIVE_FN, M_BACKUP_FN, 'menu-remove-archive-page');
  return banner('menu') + out;
}

function buildArchiveBundle(source) {
  let out = source;
  out = removeBetween(out, M_PAYMENT_ORDERS, M_SETTINGS, 'archive-remove-orders-and-reconciliation');
  out = removeBetween(out, M_SETTINGS, M_INCOME, 'archive-remove-settings');
  out = removeBetween(out, M_REQUEST_BLOCK, M_KEYDOWN, 'archive-remove-request-form');
  out = removeBetween(out, M_ITEMIZE, M_CATCH, 'archive-remove-itemize');
  out = removeBetween(out, M_MT_LIST, M_LOAD_INCOME_FN, 'archive-remove-money-transfers');
  out = removeBetween(out, M_BUDGET_EDITOR_FN, M_ARCHIVE_FN, 'archive-remove-budget-editor');
  return banner('archive') + out;
}

function buildReconciliationBundle(source) {
  let out = source;
  out = removeBetween(out, M_SETTINGS, M_INCOME, 'reconciliation-remove-settings');
  out = removeBetween(out, M_REQUEST_BLOCK, M_KEYDOWN, 'reconciliation-remove-request-form');
  out = removeBetween(out, M_ITEMIZE, M_CATCH, 'reconciliation-remove-itemize');
  out = removeBetween(out, M_MT_LIST, M_LOAD_INCOME_FN, 'reconciliation-remove-money-transfers');
  out = removeBetween(out, M_BUDGET_EDITOR_FN, M_ARCHIVE_FN, 'reconciliation-remove-budget-editor');
  out = removeBetween(out, M_ARCHIVE_FN, M_BACKUP_FN, 'reconciliation-remove-archive-page');
  return banner('reconciliation') + out;
}

function buildBudgetEditorBundle(source) {
  let out = source;
  out = removeBetween(out, M_SETTINGS, M_INCOME, 'budget-remove-settings');
  out = removeBetween(out, M_REQUEST_BLOCK, M_KEYDOWN, 'budget-remove-request-form');
  out = removeBetween(out, M_ITEMIZE, M_CATCH, 'budget-remove-itemize');
  out = removeBetween(out, M_MT_LIST, M_LOAD_INCOME_FN, 'budget-remove-money-transfers');
  out = removeBetween(out, M_BUDGET_DASHBOARD_FN, M_ARCHIVE_FN, 'budget-remove-dashboard');
  out = removeBetween(out, M_ARCHIVE_FN, M_BACKUP_FN, 'budget-remove-archive-and-backup');
  return banner('budget-editor') + out;
}

function buildBudgetDashboardBundle(source) {
  let out = source;
  out = removeBetween(out, M_SETTINGS, M_INCOME, 'budget-dashboard-remove-settings');
  out = removeBetween(out, M_REQUEST_BLOCK, M_KEYDOWN, 'budget-dashboard-remove-request-form');
  out = removeBetween(out, M_ITEMIZE, M_CATCH, 'budget-dashboard-remove-itemize');
  out = removeBetween(out, M_MT_LIST, M_LOAD_INCOME_FN, 'budget-dashboard-remove-money-transfers');
  out = removeBetween(out, M_BUDGET_EDITOR_FN, M_BUDGET_DASHBOARD_FN, 'budget-dashboard-remove-editor');
  out = removeBetween(out, M_ARCHIVE_FN, M_BACKUP_FN, 'budget-dashboard-remove-archive-and-backup');
  return banner('budget-dashboard') + out;
}

function main() {
  const source = fs.readFileSync(SOURCE, 'utf8');

  const request = buildRequestBundle(source);
  const settings = buildSettingsBundle(source);
  const itemize = buildItemizeBundle(source);
  const income = buildIncomeBundle(source);
  const gsLedger = buildGsLedgerBundle(source);
  const wiseEur = buildWiseEurBundle(source);
  const wiseUsd = buildWiseUsdBundle(source);
  const transfers = buildTransfersBundle(source);
  const menu = buildMenuBundle(source);
  const archive = buildArchiveBundle(source);
  const reconciliation = buildReconciliationBundle(source);
  const budgetEditor = buildBudgetEditorBundle(source);
  const budgetDashboard = buildBudgetDashboardBundle(source);

  writeBundle(OUT_REQUEST, request);
  writeBundle(OUT_SETTINGS, settings);
  writeBundle(OUT_ITEMIZE, itemize);
  writeBundle(OUT_INCOME, income);
  writeBundle(OUT_GS_LEDGER, gsLedger);
  writeBundle(OUT_WISE_EUR, wiseEur);
  writeBundle(OUT_WISE_USD, wiseUsd);
  writeBundle(OUT_TRANSFERS, transfers);
  writeBundle(OUT_MENU, menu);
  writeBundle(OUT_ARCHIVE, archive);
  writeBundle(OUT_RECONCILIATION, reconciliation);
  writeBundle(OUT_BUDGET_EDITOR, budgetEditor);
  writeBundle(OUT_BUDGET_DASHBOARD, budgetDashboard);

  console.log('Page bundles generated successfully.');
}

main();
