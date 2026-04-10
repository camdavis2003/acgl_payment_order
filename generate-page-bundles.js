/*
  Generate page-specific bundles from module-first sources under src/bundles/.

  Usage:
    node generate-page-bundles.js
*/

const fs = require('fs');
const path = require('path');

const ROOT = __dirname;
const SRC_DIR = path.join(ROOT, 'src', 'bundles');

const BUNDLES = [
  'app-request.js',
  'app-admin-settings.js',
  'app-itemize.js',
  'app-income.js',
  'app-gs-ledger.js',
  'app-wise-eur.js',
  'app-wise-usd.js',
  'app-money-transfer-list.js',
  'app-money-transfer-builder.js',
  'app-menu.js',
  'app-archive.js',
  'app-reconciliation.js',
  'app-budget-editor.js',
  'app-budget-dashboard.js',
];

function ensureSourceExists(fileName) {
  const src = path.join(SRC_DIR, fileName);
  if (!fs.existsSync(src)) {
    throw new Error(`Missing source bundle: ${src}`);
  }
  return src;
}

function copyBundle(fileName) {
  const src = ensureSourceExists(fileName);
  const dest = path.join(ROOT, fileName);
  fs.copyFileSync(src, dest);
  const bytes = fs.statSync(dest).size;
  console.log(`${fileName}: ${bytes} bytes`);
}

function main() {
  if (!fs.existsSync(SRC_DIR)) {
    throw new Error(`Missing source directory: ${SRC_DIR}`);
  }

  for (const fileName of BUNDLES) {
    copyBundle(fileName);
  }

  console.log('Page bundles generated successfully (module-first sources).');
}

main();
