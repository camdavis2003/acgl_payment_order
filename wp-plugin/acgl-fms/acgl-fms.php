<?php
/**
 * Plugin Name: ACGL Financial Management System (FMS)
 * Description: Embeds the ACGL FMS app and provides shared storage via WordPress (custom DB tables + REST API).
 * Version: 0.1.0
 * Author: Cameron Davis
 */

if (!defined('ABSPATH')) {
    exit;
}

define('ACGL_FMS_PLUGIN_FILE', __FILE__);
define('ACGL_FMS_PLUGIN_DIR', plugin_dir_path(__FILE__));

define('ACGL_FMS_CAP_ACCESS', 'acgl_fms_access');
define('ACGL_FMS_CAP_WRITE', 'acgl_fms_write');

define('ACGL_FMS_TABLE_KV', 'acgl_fms_kv');

// Standalone (no-theme) app route slug. Visiting https://example.com/<slug>/
// will render only the app in a full-page iframe.
define('ACGL_FMS_FULLPAGE_SLUG', 'acgl-fms');

define('ACGL_FMS_OPTION_FULLPAGE_SLUG', 'acgl_fms_fullpage_slug_v1');

require_once ACGL_FMS_PLUGIN_DIR . 'includes/db.php';
require_once ACGL_FMS_PLUGIN_DIR . 'includes/auth.php';
require_once ACGL_FMS_PLUGIN_DIR . 'includes/rest.php';
require_once ACGL_FMS_PLUGIN_DIR . 'includes/shortcode.php';

function acgl_fms_register_fullpage_route() {
    $slug = trim((string) ACGL_FMS_FULLPAGE_SLUG);
    if ($slug === '') {
        return;
    }

    // e.g. /acgl-fms/
    add_rewrite_rule('^' . preg_quote($slug, '/') . '/?$', 'index.php?acgl_fms_fullpage=1', 'top');
}

function acgl_fms_maybe_flush_rewrite_rules_on_slug_change() {
    $desired = trim((string) ACGL_FMS_FULLPAGE_SLUG);
    if ($desired === '') return;

    $prev = (string) get_option(ACGL_FMS_OPTION_FULLPAGE_SLUG, '');
    if ($prev === $desired) return;

    // Ensure our rewrite rule is registered before flushing.
    acgl_fms_register_fullpage_route();
    flush_rewrite_rules();
    update_option(ACGL_FMS_OPTION_FULLPAGE_SLUG, $desired);
}

function acgl_fms_render_fullpage() {
    // Start with a lightweight loading page; it will redirect to index.html.
    $app_url = plugins_url('app/loading.html', ACGL_FMS_PLUGIN_FILE);

    $rest_url = rest_url();
    $nonce = wp_create_nonce('wp_rest');

    $src = add_query_arg([
        'restUrl' => $rest_url,
        'restNonce' => $nonce,
        'wp' => '1',
    ], $app_url);

    // Minimal shell (no wp_head/wp_footer) to avoid theme chrome.
    status_header(200);
    header('Content-Type: text/html; charset=' . get_bloginfo('charset'));

    echo '<!doctype html>';
    echo '<html lang="' . esc_attr(get_locale()) . '">';
    echo '<head>';
    echo '<meta charset="' . esc_attr(get_bloginfo('charset')) . '">';
    echo '<meta name="viewport" content="width=device-width, initial-scale=1">';
    echo '<title>' . esc_html(get_bloginfo('name')) . ' — FMS</title>';
    echo '<style>html,body{height:100%;margin:0;padding:0;}iframe{position:fixed;inset:0;width:100%;height:100%;border:0;}</style>';
    echo '</head>';
    echo '<body>';
    echo '<iframe src="' . esc_url($src) . '" allow="clipboard-read; clipboard-write"></iframe>';
    echo '</body>';
    echo '</html>';

    exit;
}

register_activation_hook(__FILE__, function () {
    acgl_fms_db_install();

    // Seed a default internal admin into shared storage if users are not set yet.
    // This supports the "public app (no WP login)" mode where the app handles its own roles.
    try {
        $existing_users = acgl_fms_kv_get_raw('payment_order_users_v1');
        if (!is_string($existing_users) || trim($existing_users) === '') {
            $now = gmdate('c');
            $salt = 'acgl_fms_admin_v1';
            // Match the app's legacy reversible format used for the hard-coded admin.
            $pwHash = 'pw:' . base64_encode($salt . ':' . 'acgl1962ADM');
            $admin = [
                'id' => 'user_admin_pass_v1',
                'createdAt' => $now,
                'updatedAt' => $now,
                'username' => 'admin.pass',
                'email' => '',
                'salt' => $salt,
                'passwordHash' => $pwHash,
                'passwordPlain' => '',
                'permissions' => [ 'budget' => 'write', 'income' => 'write', 'orders' => 'write', 'ledger' => 'write', 'settings' => 'write' ],
            ];
            acgl_fms_kv_set_raw('payment_order_users_v1', wp_json_encode([ $admin ]));
        }
    } catch (Throwable $e) {
        // ignore
    }

    // Grant capabilities to admins by default.
    $role = get_role('administrator');
    if ($role) {
        $role->add_cap(ACGL_FMS_CAP_ACCESS);
        $role->add_cap(ACGL_FMS_CAP_WRITE);
    }

    // Ensure our rewrite rule is registered before flushing.
    acgl_fms_register_fullpage_route();
    flush_rewrite_rules();

    // Track the current slug so upgrades can flush when it changes.
    update_option(ACGL_FMS_OPTION_FULLPAGE_SLUG, trim((string) ACGL_FMS_FULLPAGE_SLUG));
});

register_deactivation_hook(__FILE__, function () {
    flush_rewrite_rules();
});

add_action('rest_api_init', function () {
    acgl_fms_register_rest_routes();
});

add_action('init', function () {
    // Ensure the KV table exists even if activation hooks didn't run.
    acgl_fms_db_ensure_installed();

    // Ensure the bootstrap internal admin user exists in shared storage.
    if (function_exists('acgl_fms_ensure_default_admin_pass_user_exists')) {
        acgl_fms_ensure_default_admin_pass_user_exists();
    }

    // Ensure base uploads folder exists for attachment organization.
    $uploads = wp_upload_dir();
    if (is_array($uploads) && !empty($uploads['basedir'])) {
        $base = trailingslashit((string) $uploads['basedir']) . 'acgl-fms';
        if (!file_exists($base)) {
            wp_mkdir_p($base);
        }
    }

    acgl_fms_register_fullpage_route();
    acgl_fms_register_shortcodes();

    // If the slug changed between plugin versions, flush once.
    acgl_fms_maybe_flush_rewrite_rules_on_slug_change();
});

add_filter('query_vars', function ($vars) {
    $vars[] = 'acgl_fms_fullpage';
    return $vars;
});

add_action('template_redirect', function () {
    if ((string) get_query_var('acgl_fms_fullpage') === '1') {
        acgl_fms_render_fullpage();
    }
});
