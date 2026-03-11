/*
  Packages a DEMO copy of the WordPress plugin into a ZIP suitable for upload in WP Admin,
  designed to be installed AND activated alongside production without collisions.

  Key differences vs the production plugin:
  - Different plugin folder slug inside the zip: acgl-fms-demo/
  - Different main plugin file name: acgl-fms-demo.php
  - Different PHP symbol prefixes:
      ACGL_FMS_*    -> ACGL_FMS_DEMO_*
      acgl_fms_*    -> acgl_fms_demo_*
      shortcode tag -> acgl_fms_demo
  - Different REST namespace:
      acgl-fms/v1   -> acgl-fms-demo/v1
  - Different full-page route slug:
      /acgl-fms/    -> /acgl-fms-demo/

  Output:
    dist/acgl-fms-demo.zip

  Run:
    npm run package:demo
*/

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

let archiver;
try {
  archiver = require('archiver');
} catch {
  console.error('Missing dependency: archiver');
  console.error('Run: npm install');
  process.exit(1);
}

const ROOT = __dirname;
const PLUGIN_DIR = path.join(ROOT, 'wp-plugin', 'acgl-fms');
const DIST_DIR = path.join(ROOT, 'dist');

// Folder name *inside* the zip (i.e. wp-content/plugins/<this>/...).
// Keep this distinct from production to avoid WP "replace existing" behavior.
const ZIP_SLUG = 'acgl-fms-demo-plugin';
const OUT_NAME = 'acgl-fms-demo.zip';
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

function replaceAll(haystack, needle, replacement) {
  return String(haystack).split(String(needle)).join(String(replacement));
}

function transformPhp(srcText) {
  let out = String(srcText);

  // Make it visually obvious in WP Admin.
  out = out.replace(/\*\s*Plugin Name:\s*(.*)$/m, '* Plugin Name: ACGL Financial Management System (FMS) — DEMO');
  out = out.replace(/\*\s*Description:\s*(.*)$/m, '* Description: DEMO copy of the ACGL FMS plugin (safe to run alongside production).');

  // Namespacing / isolation.
  out = replaceAll(out, 'ACGL_FMS_', 'ACGL_FMS_DEMO_');
  out = replaceAll(out, 'acgl_fms_', 'acgl_fms_demo_');

  // Make the full-page wrapper tab title clearly DEMO.
  out = replaceAll(out, ' — FMS</title>', ' — FMS (DEMO)</title>');

  // Shortcode tag and other exact matches without trailing underscore.
  out = replaceAll(out, "'acgl_fms'", "'acgl_fms_demo'");
  out = replaceAll(out, '"acgl_fms"', '"acgl_fms_demo"');

  // REST namespace and full-page route slug.
  // NOTE: Do a single replacement so "acgl-fms/v1" becomes "acgl-fms-demo/v1"
  // and we don't accidentally turn it into "acgl-fms-demo-demo/v1".
  out = replaceAll(out, 'acgl-fms', 'acgl-fms-demo');

  return out;
}

function transformHtml(srcText) {
  let out = String(srcText);
  // Update the in-app tab title when the HTML is opened directly.
  out = out.replace(/<title>\s*ACGL\s*-\s*FMS\s*<\/title>/i, '<title>ACGL - FMS (DEMO)</title>');
  return out;
}

function transformAppJs(srcText) {
  let out = String(srcText);

  // Make demo tab title obvious even after JS overrides document.title.
  out = replaceAll(out, "const APP_TAB_TITLE = 'ACGL - FMS';", "const APP_TAB_TITLE = 'ACGL - FMS (DEMO)';");

  // Separate browser state between production and demo.
  out = replaceAll(out, 'acgl_fms_', 'acgl_fms_demo_');

  // Point demo app at demo REST namespace.
  out = replaceAll(out, 'acgl-fms/v1', 'acgl-fms-demo/v1');

  return out;
}

async function zipDemoPlugin() {
  ensureDir(DIST_DIR);
  rmIfExists(OUT_ZIP);

  const output = fs.createWriteStream(OUT_ZIP);
  const archive = archiver('zip', { zlib: { level: 9 } });

  const done = new Promise((resolve, reject) => {
    output.on('close', resolve);
    output.on('error', reject);
    archive.on('warning', reject);
    archive.on('error', reject);
  });

  archive.pipe(output);

  const allFiles = walkFiles(PLUGIN_DIR);
  for (const abs of allFiles) {
    const rel = path.relative(PLUGIN_DIR, abs);
    if (!rel) continue;
    if (rel === '.gitkeep') continue;

    let entryRel = rel.split(path.sep).join('/');

    // Rename main plugin file for clarity and unique identity.
    if (entryRel === 'acgl-fms.php') {
      entryRel = 'acgl-fms-demo.php';
    }

    const entryName = toPosixPath(path.posix.join(ZIP_SLUG, entryRel));

    if (entryRel.endsWith('.php')) {
      const raw = fs.readFileSync(abs, 'utf8');
      const transformed = transformPhp(raw);
      archive.append(transformed, { name: entryName });
      continue;
    }

    if (entryRel.endsWith('.html')) {
      const raw = fs.readFileSync(abs, 'utf8');
      const transformed = transformHtml(raw);
      archive.append(transformed, { name: entryName });
      continue;
    }

    if (entryRel === 'app/app.js') {
      const raw = fs.readFileSync(abs, 'utf8');
      const transformed = transformAppJs(raw);
      archive.append(transformed, { name: entryName });
      continue;
    }

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

  await zipDemoPlugin();

  const stats = fs.statSync(OUT_ZIP);
  console.log(`\nCreated: ${OUT_ZIP}`);
  console.log(`Size: ${stats.size} bytes`);
})();
