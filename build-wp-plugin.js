/*
  Builds the WordPress plugin app assets by copying the static app files into:
    wp-plugin/acgl-fms/app/

  Source of truth is the project root app files.
  The plugin app folder is a generated mirror (synced by sync-wp-app.js).

  Run:
    node build-wp-plugin.js
*/

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const ROOT = __dirname;
const PLUGIN_APP_DIR = path.join(ROOT, 'wp-plugin', 'acgl-fms', 'app');
const SYNC_SCRIPT = path.join(ROOT, 'sync-wp-app.js');

function tryGetGitHash() {
  try {
    const res = spawnSync('git', ['rev-parse', '--short', 'HEAD'], {
      cwd: ROOT,
      stdio: ['ignore', 'pipe', 'ignore'],
      shell: false,
      windowsHide: true,
    });
    if (res && res.status === 0) {
      const out = String(res.stdout || '').trim();
      return out || '';
    }
  } catch {
    // ignore
  }
  return '';
}

function assetVersion() {
  const forced = String(process.env.ACGL_ASSET_VERSION || '').trim();
  if (forced) return forced;
  const git = tryGetGitHash();
  const ts = new Date().toISOString().replace(/[-:.TZ]/g, '').slice(0, 14);
  return git ? `${git}-${ts}` : ts;
}

function patchAssetUrlsInHtml(html, version) {
  const v = encodeURIComponent(String(version || '').trim());
  if (!v) return html;

  // Append ?v=... to our local asset URLs to avoid stale browser/WP caches.
  // Only patch exact filenames and skip if a query string is already present.
  const assets = [
    'styles.css',
    'hoverPopup.css',
    'hoverPopup.js',
    'user-roles.js',
    'datastore.js',
    'app-request.js',
    'app-admin-settings.js',
    'app-shell.js',
    'app-itemize.js',
    'app-money-transfers.js',
    'app-money-transfer.js',
    'app-menu.js',
    'app-archive.js',
    'app-reconciliation.js',
    'app-budget-editor.js',
    'app-budget-dashboard.js',
    'app-income.js',
    'app-gs-ledger.js',
    'app-wise-eur.js',
    'app-wise-usd.js',
    'iban.js',
    'bic.js',
    'table-enhancements.js',
    'pdf-lib.min.js',
  ];
  let out = String(html || '');
  for (const a of assets) {
    // href="styles.css"  /  src="app.js"
    out = out.replace(new RegExp(`(href|src)=("|')${a}\\2`, 'g'), `$1=$2${a}?v=${v}$2`);
  }
  return out;
}

function copyHtmlWithCacheBusting(src, dest, version) {
  const raw = fs.readFileSync(src, 'utf8');
  const patched = patchAssetUrlsInHtml(raw, version);
  fs.writeFileSync(dest, patched, 'utf8');
}

function runSyncMirror() {
  const res = spawnSync(process.execPath, [SYNC_SCRIPT], {
    cwd: ROOT,
    stdio: 'inherit',
    shell: false,
    windowsHide: true,
  });
  if (res.error) throw res.error;
  if (typeof res.status === 'number' && res.status !== 0) {
    throw new Error(`sync-wp-app.js failed with exit code ${res.status}`);
  }
}

function main() {
  runSyncMirror();

  const ver = assetVersion();

  const entries = fs.readdirSync(PLUGIN_APP_DIR, { withFileTypes: true });
  for (const e of entries) {
    if (!e.isFile()) continue;
    const rel = String(e.name || '');
    if (!rel.endsWith('.html')) continue;
    const src = path.join(PLUGIN_APP_DIR, rel);
    copyHtmlWithCacheBusting(src, src, ver);
  }

  // Remove placeholder file if it exists.
  const keep = path.join(PLUGIN_APP_DIR, '.gitkeep');
  if (fs.existsSync(keep)) fs.unlinkSync(keep);

  console.log('Built WP plugin app assets into:', PLUGIN_APP_DIR);
  console.log('Asset version:', ver);
}

main();
