/*
  Builds the WordPress plugin app assets by copying the static app files into:
    wp-plugin/acgl-fms/app/

  Run:
    node build-wp-plugin.js
*/

const fs = require('fs');
const path = require('path');

const ROOT = __dirname;
const PLUGIN_APP_DIR = path.join(ROOT, 'wp-plugin', 'acgl-fms', 'app');

const FILES = [
  'index.html',
  'about.html',
  'menu.html',
  'budget.html',
  'budget_dashboard.html',
  'income.html',
  'reconciliation.html',
  'grand_secretary_ledger.html',
  'settings.html',
  'itemize.html',
  'loading.html',
  'iban.js',
  'bic.js',
  'app.js',
  'styles.css',
];

function ensureDir(p) {
  fs.mkdirSync(p, { recursive: true });
}

function copyFile(src, dest) {
  fs.copyFileSync(src, dest);
}

function main() {
  ensureDir(PLUGIN_APP_DIR);

  for (const rel of FILES) {
    const src = path.join(ROOT, rel);
    const dest = path.join(PLUGIN_APP_DIR, rel);
    if (!fs.existsSync(src)) {
      throw new Error(`Missing source file: ${rel}`);
    }
    copyFile(src, dest);
  }

  // Remove placeholder file if it exists.
  const keep = path.join(PLUGIN_APP_DIR, '.gitkeep');
  if (fs.existsSync(keep)) fs.unlinkSync(keep);

  console.log('Built WP plugin app assets into:', PLUGIN_APP_DIR);
}

main();
