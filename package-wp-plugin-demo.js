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
const RELAX_DEMO_SETTINGS_CARD_VISIBILITY = String(process.env.DEMO_RELAX_SETTINGS_CARD_VISIBILITY || '').trim() === '1';
const DEMO_BRAND_UI = String(process.env.DEMO_BRAND_UI || '').trim() === '1';
const DEMO_LEGACY_DATA_MIGRATION = String(process.env.DEMO_LEGACY_DATA_MIGRATION || '1').trim() !== '0';
// Data-key isolation is ON by default so demo and prod never share localStorage keys
// when both plugins are active on the same WordPress site.
// Set DEMO_ISOLATE_BROWSER_DATA_KEYS=0 to disable (not recommended for co-install).
const DEMO_ISOLATE_BROWSER_DATA_KEYS = String(process.env.DEMO_ISOLATE_BROWSER_DATA_KEYS || '1').trim() !== '0';

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

  // When data-key isolation is on, the demo app uses payment_order_demo_* keys in
  // localStorage and in WP REST calls.  The PHP key-to-module auth helper must strip
  // that infix so it can resolve the correct permission module for each key.
  // This replacement runs AFTER the acgl_fms_* rename so the function is already named
  // acgl_fms_demo_key_to_module in the transformed source.
  if (DEMO_ISOLATE_BROWSER_DATA_KEYS) {
    out = out.replace(
      /function acgl_fms_demo_key_to_module\(\$key\) \{(\r?\n)([ \t]+)\$k = \(string\) \$key;/,
      (_, nl, indent) =>
        `function acgl_fms_demo_key_to_module($key) {${nl}${indent}$k = (string) $key;${nl}` +
        `${indent}// Strip demo data-key infix for canonical module lookup.${nl}` +
        `${indent}$k = preg_replace('/^payment_order_demo_/', 'payment_order_', $k);${nl}` +
        `${indent}$k = preg_replace('/^payment_orders_demo_/', 'payment_orders_', $k);${nl}` +
        `${indent}$k = preg_replace('/^money_transfers_demo_/', 'money_transfers_', $k);`
    );
  }

  // Optional UI branding so demo and prod can be visually distinguished.
  if (DEMO_BRAND_UI) {
    out = replaceAll(out, ' — FMS</title>', ' — FMS (DEMO)</title>');
  }

  // Shortcode tag and other exact matches without trailing underscore.
  out = replaceAll(out, "'acgl_fms'", "'acgl_fms_demo'");
  out = replaceAll(out, '"acgl_fms"', '"acgl_fms_demo"');

  // REST namespace and full-page route slug.
  // NOTE: Do a single replacement so "acgl-fms/v1" becomes "acgl-fms-demo/v1"
  // and we don't accidentally turn it into "acgl-fms-demo-demo/v1".
  out = replaceAll(out, 'acgl-fms', 'acgl-fms-demo');

      // Demo activation: one-time snapshot copy from production KV table into demo KV
      // for settings datasets used in testing.
      out = out.replace(
        /register_activation_hook\(__FILE__, function \(\) \{\r?\n\s*acgl_fms_demo_db_install\(\);/,
      `register_activation_hook(__FILE__, function () {
        acgl_fms_demo_db_install();

      // DEMO one-time seed: copy selected settings data from production storage.
      // This is activation-only and marker-gated (no recurring runtime sync).
      try {
        global $wpdb;
        $demo_table = acgl_fms_demo_kv_table_name();
        $prod_table = $wpdb->prefix . implode('_', ['acgl', 'fms', 'kv']);
        $seed_marker_key = 'payment_order_demo_seed_marker_v1';
        $seed_marker = acgl_fms_demo_kv_get_raw($seed_marker_key);

        if (
          (!is_string($seed_marker) || trim($seed_marker) === '') &&
          is_string($prod_table) &&
          $prod_table !== '' &&
          $prod_table !== $demo_table
        ) {
          $exists = $wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $prod_table));
          if (is_string($exists) && $exists === $prod_table) {
            // target_key = key stored in demo table (demo-prefixed, matches demo JS)
            // source_key = key read from prod table (canonical name)
            $seed_map = [
              'payment_order_demo_users_v1'           => 'payment_order_users_v1',
              'payment_order_demo_backlog_v1'          => 'payment_order_backlog_v1',
              'payment_order_demo_grand_lodge_info_v1' => 'payment_order_grand_lodge_info_v1',
            ];

            foreach ($seed_map as $target_key => $source_key) {
              $target_key = (string) $target_key;
              $source_key = (string) $source_key;
              if ($target_key === '' || $source_key === '') continue;

              $current = acgl_fms_demo_kv_get_raw($target_key);
              if (is_string($current) && trim($current) !== '') continue;

              $source = $wpdb->get_var($wpdb->prepare("SELECT v FROM {$prod_table} WHERE k = %s", $source_key));
              if (!is_string($source) || trim($source) === '') continue;

              acgl_fms_demo_kv_set_raw($target_key, $source);
            }

            acgl_fms_demo_kv_set_raw($seed_marker_key, wp_json_encode([
              'seeded_at' => time(),
              'source' => 'activation',
            ]));
          }
        }
      } catch (Throwable $e) {
        // ignore
      }`
      );

  return out;
}

function transformHtml(srcText) {
  let out = String(srcText);
  // Optional UI branding so demo and prod can be visually distinguished.
  if (DEMO_BRAND_UI) {
    out = out.replace(/<title>\s*ACGL\s*-\s*FMS\s*<\/title>/i, '<title>ACGL - FMS (DEMO)</title>');
  }
  return out;
}

function transformAppJs(srcText) {
  let out = String(srcText);

  const legacyMigrationBootstrap = `
/* DEMO one-time legacy key migration (prod remains untouched).
   Copies old shared browser keys into demo-prefixed keys so existing demo/mock data survives isolation. */
(() => {
  try {
    const MIGRATION_KEY = 'acgl_fms_legacy_keys_migrated_v1';
    if (localStorage.getItem(MIGRATION_KEY) === '1') return;

    const oldPoPrefix = ['payment', 'order', ''].join('_');
    const oldPosPrefix = ['payment', 'orders', ''].join('_');
    const oldMtPrefix = ['money', 'transfers', ''].join('_');
    const demoPoPrefix = ['payment', 'order', 'demo', ''].join('_');
    const demoPosPrefix = ['payment', 'orders', 'demo', ''].join('_');
    const demoMtPrefix = ['money', 'transfers', 'demo', ''].join('_');
    const prefixes = [oldPoPrefix, oldPosPrefix, oldMtPrefix];
    const keys = [];
    for (let i = 0; i < localStorage.length; i += 1) {
      const k = localStorage.key(i);
      if (!k) continue;
      if (k.startsWith(demoPoPrefix) || k.startsWith(demoPosPrefix) || k.startsWith(demoMtPrefix)) continue;
      if (prefixes.some((p) => k.startsWith(p))) keys.push(k);
    }

    for (const oldKey of keys) {
      let newKey = oldKey;
      if (oldKey.startsWith(oldPosPrefix)) {
        newKey = demoPosPrefix + oldKey.slice(oldPosPrefix.length);
      } else if (oldKey.startsWith(oldPoPrefix)) {
        newKey = demoPoPrefix + oldKey.slice(oldPoPrefix.length);
      } else if (oldKey.startsWith(oldMtPrefix)) {
        newKey = demoMtPrefix + oldKey.slice(oldMtPrefix.length);
      }

      if (newKey === oldKey) continue;
      if (localStorage.getItem(newKey) !== null) continue;

      const value = localStorage.getItem(oldKey);
      if (value !== null) localStorage.setItem(newKey, value);
    }

    localStorage.setItem(MIGRATION_KEY, '1');
  } catch {
    // ignore
  }

})();
`;

  if (DEMO_LEGACY_DATA_MIGRATION) {
    out = `${legacyMigrationBootstrap}\n${out}`;
  }

  // Optional UI branding so demo and prod can be visually distinguished.
  if (DEMO_BRAND_UI) {
    out = replaceAll(out, "const APP_TAB_TITLE = 'ACGL - FMS';", "const APP_TAB_TITLE = 'ACGL - FMS (DEMO)';");
  }

  // Keep session/auth state separate between production and demo.
  out = replaceAll(out, 'acgl_fms_', 'acgl_fms_demo_');

  // Optional standalone-mode data-key isolation.
  if (DEMO_ISOLATE_BROWSER_DATA_KEYS) {
    out = replaceAll(out, 'payment_order_', 'payment_order_demo_');
    out = replaceAll(out, 'payment_orders_', 'payment_orders_demo_');
    out = replaceAll(out, 'money_transfers_', 'money_transfers_demo_');
  }

  // Point demo app at demo REST namespace.
  out = replaceAll(out, 'acgl-fms/v1', 'acgl-fms-demo/v1');

  if (RELAX_DEMO_SETTINGS_CARD_VISIBILITY) {
    // Optional demo-only UX mode: keep major Admin Settings cards visible for
    // users that can access the Settings page, even if legacy role rows miss
    // newer child keys.
    out = replaceAll(out, "roles: 'settings_roles',", "roles: 'settings',");
    out = replaceAll(out, "backlog: 'settings_backlog',", "backlog: 'settings',");
    out = replaceAll(out, "grandlodge: 'settings_grandlodge',", "grandlodge: 'settings',");
    out = replaceAll(out, "backup: 'settings_backup',", "backup: 'settings',");
  }

  return out;
}

function transformAppShellJs(srcText) {
  let out = String(srcText);

  // Optional UI branding so demo and prod can be visually distinguished.
  if (DEMO_BRAND_UI) {
    out = replaceAll(out, "const APP_TAB_TITLE = 'ACGL - FMS';", "const APP_TAB_TITLE = 'ACGL - FMS (DEMO)';");
  }

  // Keep session/auth state separate between production and demo.
  out = replaceAll(out, 'acgl_fms_', 'acgl_fms_demo_');

  // Optional standalone-mode data-key isolation.
  if (DEMO_ISOLATE_BROWSER_DATA_KEYS) {
    out = replaceAll(out, 'payment_order_', 'payment_order_demo_');
    out = replaceAll(out, 'payment_orders_', 'payment_orders_demo_');
    out = replaceAll(out, 'money_transfers_', 'money_transfers_demo_');
  }

  return out;
}

function transformDatastoreJs(srcText) {
  let out = String(srcText);

  // Point demo store at demo REST namespace.
  out = replaceAll(out, 'acgl-fms/v1', 'acgl-fms-demo/v1');

  // Optional standalone-mode data-key isolation.
  if (DEMO_ISOLATE_BROWSER_DATA_KEYS) {
    out = replaceAll(out, 'payment_order_', 'payment_order_demo_');
    out = replaceAll(out, 'payment_orders_', 'payment_orders_demo_');
    out = replaceAll(out, 'money_transfers_', 'money_transfers_demo_');
  }

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

    if (
      entryRel === 'app/app.js'
      || entryRel === 'app/app-request.js'
      || entryRel === 'app/app-workflows.js'
      || entryRel === 'app/app-settings.js'
    ) {
      const raw = fs.readFileSync(abs, 'utf8');
      const transformed = transformAppJs(raw);
      archive.append(transformed, { name: entryName });
      continue;
    }

    if (entryRel === 'app/app-shell.js') {
      const raw = fs.readFileSync(abs, 'utf8');
      const transformed = transformAppShellJs(raw);
      archive.append(transformed, { name: entryName });
      continue;
    }

    if (entryRel === 'app/datastore.js') {
      const raw = fs.readFileSync(abs, 'utf8');
      const transformed = transformDatastoreJs(raw);
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
  console.log(`Demo settings visibility mode: ${RELAX_DEMO_SETTINGS_CARD_VISIBILITY ? 'relaxed (demo-only)' : 'strict (prod parity)'}`);
  console.log(`Demo UI branding: ${DEMO_BRAND_UI ? 'enabled' : 'disabled (prod parity)'}`);
  console.log(`Demo legacy localStorage migration: ${DEMO_LEGACY_DATA_MIGRATION ? 'enabled' : 'disabled (prod parity)'}`);
  console.log(`Demo browser data-key isolation: ${DEMO_ISOLATE_BROWSER_DATA_KEYS ? 'enabled' : 'disabled (prod parity)'}`);
  run(process.execPath, ['build-wp-plugin.js']);

  await zipDemoPlugin();

  const stats = fs.statSync(OUT_ZIP);
  console.log(`\nCreated: ${OUT_ZIP}`);
  console.log(`Size: ${stats.size} bytes`);
})();
