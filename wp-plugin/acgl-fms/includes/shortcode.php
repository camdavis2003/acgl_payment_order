<?php

if (!defined('ABSPATH')) {
    exit;
}

function acgl_fms_register_shortcodes() {
    add_shortcode('acgl_fms', 'acgl_fms_shortcode');
}

function acgl_fms_shortcode($atts = []) {
    // We embed the existing static app as an iframe, and pass the REST base + nonce
    // as query parameters so the app can use WP shared storage.
    $app_url = plugins_url('app/index.html', ACGL_FMS_PLUGIN_FILE);

    $rest_url = rest_url(); // usually https://example.com/wp-json/
    $nonce = wp_create_nonce('wp_rest');

    $src = add_query_arg([
        'restUrl' => $rest_url,
        'restNonce' => $nonce,
        'wp' => '1',
        'v' => defined('ACGL_FMS_APP_VERSION') ? ACGL_FMS_APP_VERSION : '0',
    ], $app_url);

    $height = isset($atts['height']) ? preg_replace('/[^0-9]/', '', (string)$atts['height']) : '';
    if ($height === '') $height = '950';

    // Prefer showing the app name in the browser tab even when embedded inside
    // a WordPress/portal page.
    $tab_title = 'ACGL - FMS';
    $title_script = sprintf(
        '<script>(function(){try{document.title=%s;}catch(e){}})();</script>',
        wp_json_encode($tab_title)
    );

    $html = sprintf(
        '<iframe src="%s" style="width:100%%;height:%spx;border:0;" loading="lazy" referrerpolicy="no-referrer-when-downgrade"></iframe>',
        esc_url($src),
        esc_attr($height)
    );

    return $title_script . $html;
}
