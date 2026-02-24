/*
  Builds the WordPress plugin app assets by copying the static app files into:
    wp-plugin/acgl-fms/app/

  Run:
    node build-wp-plugin.js
*/

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

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
  const assets = ['styles.css', 'app.js', 'iban.js', 'bic.js'];
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

function main() {
  ensureDir(PLUGIN_APP_DIR);

  const ver = assetVersion();

  for (const rel of FILES) {
    const src = path.join(ROOT, rel);
    const dest = path.join(PLUGIN_APP_DIR, rel);
    if (!fs.existsSync(src)) {
      throw new Error(`Missing source file: ${rel}`);
    }

    if (rel.endsWith('.html')) {
      copyHtmlWithCacheBusting(src, dest, ver);
    } else {
      copyFile(src, dest);
    }
  }

  // Remove placeholder file if it exists.
  const keep = path.join(PLUGIN_APP_DIR, '.gitkeep');
  if (fs.existsSync(keep)) fs.unlinkSync(keep);

  console.log('Built WP plugin app assets into:', PLUGIN_APP_DIR);
  console.log('Asset version:', ver);
}

main();
