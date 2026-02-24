/*
  Packages the WordPress plugin into a ZIP suitable for upload in WP Admin.

  IMPORTANT:
  - The ZIP MUST use forward slashes in entry names so Linux/WordPress extracts
    into real folders ("includes/db.php"), not literal backslash filenames.

  Output:
    dist/acgl-fms.zip

  Run:
    npm run package:wp
*/

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

let archiver;
try {
  archiver = require('archiver');
} catch {
  // Keep error message actionable.
  console.error('Missing dependency: archiver');
  console.error('Run: npm install');
  process.exit(1);
}

const ROOT = __dirname;
const PLUGIN_DIR = path.join(ROOT, 'wp-plugin', 'acgl-fms');
const DIST_DIR = path.join(ROOT, 'dist');

function readArg(name) {
  const idx = process.argv.indexOf(name);
  if (idx === -1) return null;
  const val = process.argv[idx + 1];
  if (!val || val.startsWith('--')) return null;
  return String(val);
}

// Allows creating a zip that installs into a different folder name in WP,
// which is useful when WP says "Destination folder already exists".
const ZIP_SLUG = (readArg('--slug') || process.env.WP_PLUGIN_SLUG || 'acgl-fms').trim() || 'acgl-fms';
const OUT_NAME = (readArg('--out') || process.env.WP_PLUGIN_ZIP || `${ZIP_SLUG}.zip`).trim() || `${ZIP_SLUG}.zip`;
const OUT_ZIP = path.join(DIST_DIR, OUT_NAME);

function ensureDir(p) {
  fs.mkdirSync(p, { recursive: true });
}

function rmIfExists(p) {
  try {
    fs.rmSync(p, { force: true });
  } catch {
    // ignore
  }
}

function run(cmd, args, options = {}) {
  const res = spawnSync(cmd, args, {
    cwd: options.cwd || ROOT,
    stdio: 'inherit',
    shell: false,
  });
  if (res.error) throw res.error;
  if (typeof res.status === 'number' && res.status !== 0) {
    throw new Error(`Command failed (${res.status}): ${cmd} ${args.join(' ')}`);
  }
}

function walkFiles(rootDir) {
  const out = [];
  const stack = [rootDir];
  while (stack.length) {
    const current = stack.pop();
    const entries = fs.readdirSync(current, { withFileTypes: true });
    for (const e of entries) {
      const abs = path.join(current, e.name);
      if (e.isDirectory()) {
        stack.push(abs);
      } else if (e.isFile()) {
        out.push(abs);
      }
    }
  }
  return out;
}

function toPosixPath(p) {
  return String(p).split(path.sep).join('/');
}

async function zipPlugin() {
  ensureDir(DIST_DIR);
  rmIfExists(OUT_ZIP);

  const output = fs.createWriteStream(OUT_ZIP);
  const archive = archiver('zip', { zlib: { level: 9 } });

  const done = new Promise((resolve, reject) => {
    output.on('close', resolve);
    output.on('error', reject);
    archive.on('warning', (err) => {
      // Treat warnings as errors for packaging reliability.
      reject(err);
    });
    archive.on('error', reject);
  });

  archive.pipe(output);

  const allFiles = walkFiles(PLUGIN_DIR);

  for (const abs of allFiles) {
    const rel = path.relative(PLUGIN_DIR, abs);
    if (!rel) continue;
    // Don’t include dev placeholders.
    if (rel === '.gitkeep') continue;

    // Put everything under a top-level folder so WP extracts to wp-content/plugins/<slug>/
    const entryName = toPosixPath(path.posix.join(ZIP_SLUG, rel.split(path.sep).join('/')));
    archive.file(abs, { name: entryName });
  }

  await archive.finalize();
  await done;
}

(async function main() {
  if (!fs.existsSync(PLUGIN_DIR)) {
    throw new Error('Missing plugin folder: wp-plugin/acgl-fms');
  }

  // Build/copy the latest app assets into the plugin.
  run(process.execPath, ['build-wp-plugin.js']);

  await zipPlugin();

  const stats = fs.statSync(OUT_ZIP);
  console.log(`\nCreated: ${OUT_ZIP}`);
  console.log(`Size: ${stats.size} bytes`);
})();
