/*
  One-way sync from root app files -> wp-plugin/acgl-fms/app.
  This makes the plugin app folder a generated mirror to prevent
  recurring "fixed then came back" issues caused by dual editing.

  Run:
    node sync-wp-app.js
*/

const fs = require('fs');
const path = require('path');

const ROOT = __dirname;
const PLUGIN_APP_DIR = path.join(ROOT, 'wp-plugin', 'acgl-fms', 'app');
const MARKER_FILE = path.join(PLUGIN_APP_DIR, '.generated-from-root');

const FILES = [
  'index.html',
  'about.html',
  'help.html',
  'user_guide.html',
  'archive.html',
  'menu.html',
  'budget.html',
  'budget_dashboard.html',
  'income.html',
  'wise_eur.html',
  'wise_usd.html',
  'reconciliation.html',
  'grand_secretary_ledger.html',
  'settings.html',
  'google_backup_setup.html',
  'itemize.html',
  'money_transfer.html',
  'money_transfers.html',
  'loading.html',
  'user-roles.js',
  'iban.js',
  'bic.js',
  'table-enhancements.js',
  'pdf-lib.min.js',
  'datastore.js',
  'app.js',
  'app-request.js',
  'app-settings.js',
  'app-itemize.js',
  'app-transfers.js',
  'app-operations.js',
  'app-budget-editor.js',
  'app-budget-dashboard.js',
  'app-income-ledger.js',
  'app-wise.js',
  'app-shell.js',
  'styles.css',
  'hoverPopup.css',
  'hoverPopup.js',
  'wise_eur_2026_seed.csv',
  'wise_usd_2026_seed.csv',
  'payment_order_template.pdf',
];

const OPTIONAL_FILES = new Set(['payment_order_template.pdf']);

function ensureDir(p) {
  fs.mkdirSync(p, { recursive: true });
}

function sameFileContent(src, dest) {
  if (!fs.existsSync(dest)) return false;
  const a = fs.readFileSync(src);
  const b = fs.readFileSync(dest);
  return a.length === b.length && a.equals(b);
}

function syncFile(rel) {
  const src = path.join(ROOT, rel);
  const dest = path.join(PLUGIN_APP_DIR, rel);

  if (!fs.existsSync(src)) {
    if (OPTIONAL_FILES.has(rel)) return { rel, status: 'optional-missing' };
    throw new Error(`Missing source file: ${rel}`);
  }

  if (sameFileContent(src, dest)) return { rel, status: 'unchanged' };

  fs.copyFileSync(src, dest);
  return { rel, status: 'copied' };
}

function writeMarker() {
  const marker = [
    'Generated mirror of root app files.',
    'Do not edit files in this folder directly.',
    'Edit root files, then run: npm run sync:wp',
    `Last sync: ${new Date().toISOString()}`,
    '',
  ].join('\n');
  fs.writeFileSync(MARKER_FILE, marker, 'utf8');
}

function main() {
  ensureDir(PLUGIN_APP_DIR);

  const results = FILES.map(syncFile);
  writeMarker();

  const copied = results.filter((r) => r.status === 'copied').length;
  const unchanged = results.filter((r) => r.status === 'unchanged').length;
  const optionalMissing = results.filter((r) => r.status === 'optional-missing').length;

  console.log(`Synced WP app mirror: ${PLUGIN_APP_DIR}`);
  console.log(`Copied: ${copied}, Unchanged: ${unchanged}, Optional missing: ${optionalMissing}`);
}

main();
