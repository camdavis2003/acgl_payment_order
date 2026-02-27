<?php

if (!defined('ABSPATH')) {
    exit;
}

define('ACGL_FMS_GDRIVE_FOLDER_OPTION', 'acgl_fms_gdrive_folder_id_v1');
define('ACGL_FMS_GDRIVE_JSON_OPTION', 'acgl_fms_gdrive_service_account_json_v1');

function acgl_fms_admin_get_crypto_key() {
    // Derive an encryption key from WP salts. This keeps the secret out of code and
    // makes it different per site.
    $salt = function_exists('wp_salt') ? (string) wp_salt('auth') : '';
    if ($salt === '') {
        $salt = function_exists('wp_salt') ? (string) wp_salt() : '';
    }
    if ($salt === '') {
        $salt = defined('AUTH_KEY') ? (string) AUTH_KEY : 'acgl-fms';
    }

    return hash('sha256', $salt, true); // 32 bytes
}

function acgl_fms_admin_encrypt($plaintext) {
    $text = (string) $plaintext;
    if ($text === '') return '';

    if (!function_exists('openssl_encrypt') || !function_exists('openssl_random_pseudo_bytes')) {
        // Fallback: store plaintext (still avoids Media Library). Mark format.
        return 'plain:' . $text;
    }

    $key = acgl_fms_admin_get_crypto_key();
    $iv = openssl_random_pseudo_bytes(16);
    $cipher = openssl_encrypt($text, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
    if ($cipher === false) {
        return 'plain:' . $text;
    }

    return 'enc:' . base64_encode($iv . $cipher);
}

function acgl_fms_admin_decrypt($stored) {
    $raw = (string) $stored;
    if ($raw === '') return '';

    if (strpos($raw, 'plain:') === 0) {
        return substr($raw, strlen('plain:'));
    }

    if (strpos($raw, 'enc:') !== 0) {
        // Back-compat: treat as plaintext.
        return $raw;
    }

    if (!function_exists('openssl_decrypt')) {
        return '';
    }

    $b64 = substr($raw, strlen('enc:'));
    $bin = base64_decode($b64, true);
    if ($bin === false || strlen($bin) < 17) {
        return '';
    }

    $iv = substr($bin, 0, 16);
    $cipher = substr($bin, 16);
    $key = acgl_fms_admin_get_crypto_key();

    $plain = openssl_decrypt($cipher, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
    return $plain === false ? '' : (string) $plain;
}

function acgl_fms_admin_get_gdrive_folder_id() {
    return trim((string) get_option(ACGL_FMS_GDRIVE_FOLDER_OPTION, ''));
}

function acgl_fms_admin_get_gdrive_json() {
    $stored = (string) get_option(ACGL_FMS_GDRIVE_JSON_OPTION, '');
    return trim((string) acgl_fms_admin_decrypt($stored));
}

function acgl_fms_admin_set_option_no_autoload($name, $value) {
    // update_option's $autoload parameter exists in modern WP; if missing, WP will ignore it.
    if (function_exists('update_option')) {
        @update_option($name, $value, false);
    }
}

function acgl_fms_admin_save_gdrive_settings($folderId, $jsonText) {
    $folderId = trim((string) $folderId);
    $jsonText = trim((string) $jsonText);

    if ($folderId === '') {
        return [ 'ok' => false, 'error' => 'Folder ID is required.' ];
    }

    if ($jsonText === '') {
        return [ 'ok' => false, 'error' => 'Service account JSON is required.' ];
    }

    $parsed = json_decode($jsonText, true);
    if (!is_array($parsed)) {
        $msg = function_exists('json_last_error_msg') ? json_last_error_msg() : 'Invalid JSON.';
        return [ 'ok' => false, 'error' => 'Service account JSON is not valid JSON (' . $msg . ').' ];
    }

    $email = isset($parsed['client_email']) ? trim((string) $parsed['client_email']) : '';
    $privateKey = isset($parsed['private_key']) ? (string) $parsed['private_key'] : '';
    if ($email === '' || $privateKey === '') {
        return [ 'ok' => false, 'error' => 'JSON must include client_email and private_key.' ];
    }

    acgl_fms_admin_set_option_no_autoload(ACGL_FMS_GDRIVE_FOLDER_OPTION, $folderId);
    acgl_fms_admin_set_option_no_autoload(ACGL_FMS_GDRIVE_JSON_OPTION, acgl_fms_admin_encrypt($jsonText));

    return [ 'ok' => true, 'clientEmail' => $email ];
}

function acgl_fms_register_admin_pages() {
    if (!function_exists('add_options_page')) return;

    add_action('admin_menu', function () {
        add_options_page(
            'ACGL FMS',
            'ACGL FMS',
            'manage_options',
            'acgl-fms',
            'acgl_fms_render_admin_settings_page'
        );
    });
}

acgl_fms_register_admin_pages();

function acgl_fms_render_admin_settings_page() {
    if (!current_user_can('manage_options') || (defined('ACGL_FMS_CAP_WRITE') && !current_user_can(ACGL_FMS_CAP_WRITE))) {
        wp_die('Insufficient permissions.');
    }

    $messages = [];
    $errors = [];
    $runResults = null;

    $action = isset($_POST['acgl_fms_action']) ? (string) $_POST['acgl_fms_action'] : '';
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && $action !== '') {
        check_admin_referer('acgl_fms_admin_settings');

        if ($action === 'save_gdrive') {
            $folderId = isset($_POST['acgl_fms_gdrive_folder_id']) ? (string) $_POST['acgl_fms_gdrive_folder_id'] : '';
            $jsonText = isset($_POST['acgl_fms_gdrive_json']) ? (string) $_POST['acgl_fms_gdrive_json'] : '';

            // WP adds slashes to all input (including textarea). Undo that before parsing.
            if (function_exists('wp_unslash')) {
                $folderId = wp_unslash($folderId);
                $jsonText = wp_unslash($jsonText);
            } else {
                $folderId = stripslashes($folderId);
                $jsonText = stripslashes($jsonText);
            }

            // Normalize BOM and newlines to reduce paste issues.
            $jsonText = preg_replace('/^\xEF\xBB\xBF/', '', (string) $jsonText);
            $res = acgl_fms_admin_save_gdrive_settings($folderId, $jsonText);
            if (!empty($res['ok'])) {
                $messages[] = 'Saved Google Drive settings for ' . esc_html((string) $res['clientEmail']) . '.';
            } else {
                $errors[] = isset($res['error']) ? (string) $res['error'] : 'Failed to save settings.';
            }
        } elseif ($action === 'run_gdrive') {
            if (function_exists('acgl_fms_gdrive_run_backup_upload')) {
                $res = acgl_fms_gdrive_run_backup_upload('manual');
                $runResults = is_array($res) ? $res : null;

                $uploaded = is_array($res) && isset($res['uploaded']) ? (int) $res['uploaded'] : null;
                $failed = is_array($res) && isset($res['failed']) ? (int) $res['failed'] : null;

                if (is_array($res) && !empty($res['ok'])) {
                    $messages[] = 'Google Drive backup upload ran successfully.';
                } else {
                    $suffix = '';
                    if (is_int($uploaded) && is_int($failed)) {
                        $suffix = ' (uploaded ' . $uploaded . ', failed ' . $failed . ')';
                    }
                    $errors[] = 'Upload did not fully succeed' . $suffix . '. See results below.';
                }
            } else {
                $errors[] = 'Drive backup module is not available.';
            }
        }
    }

    $folderId = acgl_fms_admin_get_gdrive_folder_id();
    $json = acgl_fms_admin_get_gdrive_json();
    $clientEmail = '';
    if ($json !== '') {
        $parsed = json_decode($json, true);
        if (is_array($parsed) && !empty($parsed['client_email'])) {
            $clientEmail = trim((string) $parsed['client_email']);
        }
    }

    echo '<div class="wrap">';
    echo '<h1>ACGL FMS</h1>';

    foreach ($messages as $m) {
        echo '<div class="notice notice-success is-dismissible"><p>' . esc_html($m) . '</p></div>';
    }
    foreach ($errors as $e) {
        echo '<div class="notice notice-error"><p>' . esc_html($e) . '</p></div>';
    }

    echo '<h2>Google Drive Backups</h2>';
    echo '<p>Use this if you cannot edit <code>wp-config.php</code> or upload files to the server. The service account JSON is stored in the WordPress database (encrypted when OpenSSL is available).</p>';
    echo '<p><strong>Configured folder:</strong> ' . ($folderId !== '' ? esc_html($folderId) : '<em>not set</em>') . '</p>';
    echo '<p><strong>Service account:</strong> ' . ($clientEmail !== '' ? esc_html($clientEmail) : '<em>not set</em>') . '</p>';

    echo '<form method="post" action="">';
    wp_nonce_field('acgl_fms_admin_settings');
    echo '<input type="hidden" name="acgl_fms_action" value="save_gdrive">';

    echo '<table class="form-table" role="presentation">';
    echo '<tr>';
    echo '<th scope="row"><label for="acgl_fms_gdrive_folder_id">Drive folder ID</label></th>';
    echo '<td><input name="acgl_fms_gdrive_folder_id" id="acgl_fms_gdrive_folder_id" type="text" class="regular-text" value="' . esc_attr($folderId) . '" required></td>';
    echo '</tr>';

    echo '<tr>';
    echo '<th scope="row"><label for="acgl_fms_gdrive_json">Service account JSON</label></th>';
    echo '<td>';
    echo '<textarea name="acgl_fms_gdrive_json" id="acgl_fms_gdrive_json" class="large-text code" rows="12" placeholder="Paste the full JSON here (including private_key)." required></textarea>';
    echo '<p class="description">For safety, the saved JSON is not shown. Pasting a new JSON here will replace the stored key.</p>';
    echo '</td>';
    echo '</tr>';
    echo '</table>';

    submit_button('Save Google Drive Settings');
    echo '</form>';

    echo '<form method="post" action="" style="margin-top:12px;">';
    wp_nonce_field('acgl_fms_admin_settings');
    echo '<input type="hidden" name="acgl_fms_action" value="run_gdrive">';
    submit_button('Run Test Upload Now', 'secondary');
    echo '</form>';

    if (is_array($runResults) && !empty($runResults['results']) && is_array($runResults['results'])) {
        echo '<h3>Last test upload results</h3>';
        echo '<table class="widefat striped" style="max-width:1100px;">';
        echo '<thead><tr><th>Year</th><th>Status</th><th>File</th><th>File ID</th><th>Error</th><th>Reason</th><th>Message</th></tr></thead>';
        echo '<tbody>';
        foreach ($runResults['results'] as $r) {
            if (!is_array($r)) continue;
            $year = isset($r['year']) ? (string) $r['year'] : '';
            $ok = !empty($r['ok']);
            $status = $ok ? 'OK' : 'FAILED';
            $fileName = isset($r['fileName']) ? (string) $r['fileName'] : '';
            $fileId = isset($r['fileId']) ? (string) $r['fileId'] : '';
            $err = isset($r['error']) ? (string) $r['error'] : '';
            $reason = isset($r['reason']) ? (string) $r['reason'] : '';
            $msg = isset($r['message']) ? (string) $r['message'] : '';
            if ($err === '' && !$ok) {
                $err = 'unknown';
            }
            echo '<tr>';
            echo '<td>' . esc_html($year) . '</td>';
            echo '<td>' . esc_html($status) . '</td>';
            echo '<td>' . esc_html($fileName) . '</td>';
            echo '<td>' . esc_html($fileId) . '</td>';
            echo '<td>' . esc_html($ok ? '' : $err) . '</td>';
            echo '<td>' . esc_html($ok ? '' : $reason) . '</td>';
            echo '<td>' . esc_html($ok ? '' : $msg) . '</td>';
            echo '</tr>';
        }
        echo '</tbody>';
        echo '</table>';

        echo '<p class="description">If uploads fail with permission errors, confirm the Drive folder is shared with the service account email as Editor.</p>';
    }

    echo '</div>';
}
