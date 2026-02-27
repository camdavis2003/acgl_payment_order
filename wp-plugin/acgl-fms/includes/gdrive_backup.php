<?php

if (!defined('ABSPATH')) {
    exit;
}

// ---- Google Drive automated backups (service account) ----

// Bump version to force a new token if scopes/config change.
define('ACGL_FMS_GDRIVE_TOKEN_TRANSIENT', 'acgl_fms_gdrive_token_v2');

define('ACGL_FMS_GDRIVE_LAST_RUN_OPTION', 'acgl_fms_gdrive_last_run_v1');
define('ACGL_FMS_GDRIVE_LAST_ERROR_OPTION', 'acgl_fms_gdrive_last_error_v1');

define('ACGL_FMS_GDRIVE_SCHEMA', 'acgl-fms-year-backup');
define('ACGL_FMS_GDRIVE_VERSION', 1);

function acgl_fms_gdrive_now_backup_id() {
    // Match the app's UTC ID format: YYYYMMDDTHHMMSSZ
    return gmdate('Ymd\THis\Z');
}

function acgl_fms_gdrive_base64url($data) {
    $b64 = base64_encode($data);
    $b64 = str_replace([ '+', '/', '=' ], [ '-', '_', '' ], $b64);
    return $b64;
}

function acgl_fms_gdrive_get_config() {
    $folderId = defined('ACGL_FMS_GDRIVE_FOLDER_ID') ? trim((string) ACGL_FMS_GDRIVE_FOLDER_ID) : '';
    $json = defined('ACGL_FMS_GDRIVE_SERVICE_ACCOUNT_JSON') ? trim((string) ACGL_FMS_GDRIVE_SERVICE_ACCOUNT_JSON) : '';

    // Fallback: if wp-config.php constants are not available, allow config from WP Admin settings.
    if (($folderId === '' || $json === '') && function_exists('acgl_fms_admin_get_gdrive_folder_id') && function_exists('acgl_fms_admin_get_gdrive_json')) {
        if ($folderId === '') $folderId = trim((string) acgl_fms_admin_get_gdrive_folder_id());
        if ($json === '') $json = trim((string) acgl_fms_admin_get_gdrive_json());
    }

    if ($folderId === '' || $json === '') {
        return null;
    }

    $parsed = json_decode($json, true);
    if (!is_array($parsed)) {
        return null;
    }

    $email = isset($parsed['client_email']) ? trim((string) $parsed['client_email']) : '';
    $privateKey = isset($parsed['private_key']) ? (string) $parsed['private_key'] : '';

    if ($email === '' || $privateKey === '') {
        return null;
    }

    return [
        'folderId' => $folderId,
        'clientEmail' => $email,
        'privateKey' => $privateKey,
    ];
}

function acgl_fms_gdrive_get_access_token($config) {
    $cached = get_transient(ACGL_FMS_GDRIVE_TOKEN_TRANSIENT);
    if (is_string($cached) && trim($cached) !== '') {
        return trim($cached);
    }

    $now = time();
    $header = [ 'alg' => 'RS256', 'typ' => 'JWT' ];
    $payload = [
        'iss' => (string) $config['clientEmail'],
        // drive.file can be too restrictive for creating files in folders the app hasn't created.
        // Use full drive scope for service-account backups.
        'scope' => 'https://www.googleapis.com/auth/drive',
        'aud' => 'https://oauth2.googleapis.com/token',
        'iat' => $now,
        'exp' => $now + 3600,
    ];

    $segments = [
        acgl_fms_gdrive_base64url(wp_json_encode($header)),
        acgl_fms_gdrive_base64url(wp_json_encode($payload)),
    ];
    $signingInput = implode('.', $segments);

    $signature = '';
    $pkey = openssl_get_privatekey((string) $config['privateKey']);
    if (!$pkey) {
        return null;
    }

    $ok = openssl_sign($signingInput, $signature, $pkey, 'sha256');
    openssl_free_key($pkey);
    if (!$ok) {
        return null;
    }

    $jwt = $signingInput . '.' . acgl_fms_gdrive_base64url($signature);

    $res = wp_remote_post('https://oauth2.googleapis.com/token', [
        'timeout' => 30,
        'headers' => [ 'Content-Type' => 'application/x-www-form-urlencoded' ],
        'body' => http_build_query([
            'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer',
            'assertion' => $jwt,
        ]),
    ]);

    if (is_wp_error($res)) {
        return null;
    }

    $code = (int) wp_remote_retrieve_response_code($res);
    $body = (string) wp_remote_retrieve_body($res);
    if ($code < 200 || $code >= 300) {
        return null;
    }

    $parsed = json_decode($body, true);
    if (!is_array($parsed) || empty($parsed['access_token'])) {
        return null;
    }

    $token = trim((string) $parsed['access_token']);
    if ($token === '') {
        return null;
    }

    // Cache slightly under the real expiry.
    set_transient(ACGL_FMS_GDRIVE_TOKEN_TRANSIENT, $token, 55 * 60);

    return $token;
}

function acgl_fms_gdrive_upload_json($token, $folderId, $fileName, $jsonText) {
    $boundary = 'acgl_fms_' . wp_generate_password(12, false, false);

    $meta = [
        'name' => $fileName,
        'parents' => [ $folderId ],
        'mimeType' => 'application/json',
    ];

    $body = '';
    $body .= "--{$boundary}\r\n";
    $body .= "Content-Type: application/json; charset=UTF-8\r\n\r\n";
    $body .= wp_json_encode($meta);
    $body .= "\r\n";

    $body .= "--{$boundary}\r\n";
    $body .= "Content-Type: application/json; charset=UTF-8\r\n\r\n";
    $body .= $jsonText;
    $body .= "\r\n";

    $body .= "--{$boundary}--\r\n";

    // supportsAllDrives allows uploads into Shared Drives / shared folders reliably.
    $url = 'https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart&supportsAllDrives=true';

    $res = wp_remote_post($url, [
        'timeout' => 60,
        'headers' => [
            'Authorization' => 'Bearer ' . $token,
            'Content-Type' => 'multipart/related; boundary=' . $boundary,
        ],
        'body' => $body,
    ]);

    if (is_wp_error($res)) {
        return [ 'ok' => false, 'error' => $res->get_error_message() ];
    }

    $code = (int) wp_remote_retrieve_response_code($res);
    $respBody = (string) wp_remote_retrieve_body($res);

    if ($code < 200 || $code >= 300) {
        $msg = '';
        $reason = '';
        $parsedErr = json_decode($respBody, true);
        if (is_array($parsedErr) && isset($parsedErr['error']) && is_array($parsedErr['error'])) {
            $errObj = $parsedErr['error'];
            if (isset($errObj['message'])) $msg = (string) $errObj['message'];
            if (!empty($errObj['errors']) && is_array($errObj['errors']) && is_array($errObj['errors'][0] ?? null)) {
                $reason = isset($errObj['errors'][0]['reason']) ? (string) $errObj['errors'][0]['reason'] : '';
            }
        }

        return [
            'ok' => false,
            'error' => 'http_' . $code,
            'reason' => $reason,
            'message' => $msg,
            'body' => $respBody,
        ];
    }

    $parsed = json_decode($respBody, true);
    $id = is_array($parsed) && !empty($parsed['id']) ? (string) $parsed['id'] : '';

    return [ 'ok' => true, 'fileId' => $id, 'raw' => $parsed ];
}

function acgl_fms_gdrive_list_backup_files($token, $folderId, $pageSize) {
    $n = (int) $pageSize;
    if ($n < 1) $n = 20;
    if ($n > 100) $n = 100;

    // List recent JSON backups in the folder.
    $q = sprintf("'%s' in parents and mimeType='application/json' and name contains 'acgl-fms-backup-'", str_replace("'", "\\'", (string) $folderId));

    $url = add_query_arg([
        'q' => $q,
        'pageSize' => (string) $n,
        'orderBy' => 'createdTime desc',
        'fields' => 'files(id,name,createdTime,size,webViewLink)',
        'spaces' => 'drive',
        'supportsAllDrives' => 'true',
        'includeItemsFromAllDrives' => 'true',
    ], 'https://www.googleapis.com/drive/v3/files');

    $res = wp_remote_get($url, [
        'timeout' => 30,
        'headers' => [
            'Authorization' => 'Bearer ' . $token,
        ],
    ]);

    if (is_wp_error($res)) {
        return [ 'ok' => false, 'error' => 'request_failed', 'message' => $res->get_error_message() ];
    }

    $code = (int) wp_remote_retrieve_response_code($res);
    $body = (string) wp_remote_retrieve_body($res);
    if ($code < 200 || $code >= 300) {
        $msg = '';
        $reason = '';
        $parsedErr = json_decode($body, true);
        if (is_array($parsedErr) && isset($parsedErr['error']) && is_array($parsedErr['error'])) {
            $errObj = $parsedErr['error'];
            if (isset($errObj['message'])) $msg = (string) $errObj['message'];
            if (!empty($errObj['errors']) && is_array($errObj['errors']) && is_array($errObj['errors'][0] ?? null)) {
                $reason = isset($errObj['errors'][0]['reason']) ? (string) $errObj['errors'][0]['reason'] : '';
            }
        }
        return [ 'ok' => false, 'error' => 'http_' . $code, 'reason' => $reason, 'message' => $msg, 'body' => $body ];
    }

    $parsed = json_decode($body, true);
    if (!is_array($parsed)) {
        return [ 'ok' => false, 'error' => 'invalid_json' ];
    }

    $files = isset($parsed['files']) && is_array($parsed['files']) ? $parsed['files'] : [];
    return [ 'ok' => true, 'files' => $files ];
}

function acgl_fms_gdrive_list_backups($pageSize) {
    $config = acgl_fms_gdrive_get_config();
    if (!$config) {
        return [ 'ok' => false, 'error' => 'missing_config' ];
    }

    $token = acgl_fms_gdrive_get_access_token($config);
    if (!$token) {
        return [ 'ok' => false, 'error' => 'token_failed' ];
    }

    return acgl_fms_gdrive_list_backup_files($token, (string) $config['folderId'], $pageSize);
}

function acgl_fms_gdrive_get_file_meta($token, $fileId) {
    $id = trim((string) $fileId);
    if ($id === '') return [ 'ok' => false, 'error' => 'invalid_id' ];

    $url = add_query_arg([
        'fields' => 'id,name,createdTime,parents,mimeType,size',
        'supportsAllDrives' => 'true',
    ], 'https://www.googleapis.com/drive/v3/files/' . rawurlencode($id));

    $res = wp_remote_get($url, [
        'timeout' => 30,
        'headers' => [
            'Authorization' => 'Bearer ' . $token,
        ],
    ]);

    if (is_wp_error($res)) {
        return [ 'ok' => false, 'error' => 'request_failed', 'message' => $res->get_error_message() ];
    }

    $code = (int) wp_remote_retrieve_response_code($res);
    $body = (string) wp_remote_retrieve_body($res);
    if ($code < 200 || $code >= 300) {
        return [ 'ok' => false, 'error' => 'http_' . $code, 'body' => $body ];
    }

    $parsed = json_decode($body, true);
    if (!is_array($parsed)) {
        return [ 'ok' => false, 'error' => 'invalid_json' ];
    }

    return [ 'ok' => true, 'file' => $parsed ];
}

function acgl_fms_gdrive_download_file_media($token, $fileId) {
    $id = trim((string) $fileId);
    if ($id === '') return [ 'ok' => false, 'error' => 'invalid_id' ];

    $url = add_query_arg([
        'alt' => 'media',
        'supportsAllDrives' => 'true',
    ], 'https://www.googleapis.com/drive/v3/files/' . rawurlencode($id));

    $res = wp_remote_get($url, [
        'timeout' => 60,
        'headers' => [
            'Authorization' => 'Bearer ' . $token,
        ],
    ]);

    if (is_wp_error($res)) {
        return [ 'ok' => false, 'error' => 'request_failed', 'message' => $res->get_error_message() ];
    }

    $code = (int) wp_remote_retrieve_response_code($res);
    $body = (string) wp_remote_retrieve_body($res);
    if ($code < 200 || $code >= 300) {
        return [ 'ok' => false, 'error' => 'http_' . $code, 'body' => $body ];
    }

    return [ 'ok' => true, 'text' => $body ];
}

function acgl_fms_gdrive_get_backup_payload_by_file_id($fileId) {
    $id = trim((string) $fileId);
    if ($id === '' || strlen($id) > 200) {
        return [ 'ok' => false, 'error' => 'invalid_id' ];
    }

    $config = acgl_fms_gdrive_get_config();
    if (!$config) {
        return [ 'ok' => false, 'error' => 'missing_config' ];
    }

    $token = acgl_fms_gdrive_get_access_token($config);
    if (!$token) {
        return [ 'ok' => false, 'error' => 'token_failed' ];
    }

    $metaRes = acgl_fms_gdrive_get_file_meta($token, $id);
    if (!is_array($metaRes) || empty($metaRes['ok']) || !is_array($metaRes['file'] ?? null)) {
        return is_array($metaRes) ? $metaRes : [ 'ok' => false, 'error' => 'meta_failed' ];
    }

    $file = $metaRes['file'];
    $name = isset($file['name']) ? (string) $file['name'] : '';
    $mime = isset($file['mimeType']) ? (string) $file['mimeType'] : '';
    $parents = isset($file['parents']) && is_array($file['parents']) ? $file['parents'] : [];

    if ($mime !== '' && $mime !== 'application/json') {
        return [ 'ok' => false, 'error' => 'not_json' ];
    }

    // Restrict to expected naming pattern.
    if ($name === '' || strpos($name, 'acgl-fms-backup-') !== 0) {
        return [ 'ok' => false, 'error' => 'not_a_backup' ];
    }

    // Restrict access to the configured folder.
    $folderId = (string) $config['folderId'];
    $inFolder = false;
    foreach ($parents as $p) {
        if ((string) $p === $folderId) {
            $inFolder = true;
            break;
        }
    }
    if (!$inFolder) {
        return [ 'ok' => false, 'error' => 'wrong_folder' ];
    }

    $dl = acgl_fms_gdrive_download_file_media($token, $id);
    if (!is_array($dl) || empty($dl['ok']) || !is_string($dl['text'] ?? null)) {
        return is_array($dl) ? $dl : [ 'ok' => false, 'error' => 'download_failed' ];
    }

    $text = (string) $dl['text'];
    $payload = json_decode($text, true);
    if (!is_array($payload)) {
        return [ 'ok' => false, 'error' => 'invalid_payload' ];
    }

    return [
        'ok' => true,
        'file' => [
            'id' => isset($file['id']) ? (string) $file['id'] : $id,
            'name' => $name,
            'createdTime' => isset($file['createdTime']) ? (string) $file['createdTime'] : '',
            'size' => isset($file['size']) ? (string) $file['size'] : '',
        ],
        'payload' => $payload,
    ];
}

function acgl_fms_gdrive_backup_year_payload($year, $kind) {
    $y = (int) $year;
    if ($y < 1900 || $y > 3000) {
        return null;
    }

    $keys = [
        'payment_orders_' . $y . '_v1',
        'payment_orders_reconciliation_' . $y . '_v1',
        'payment_order_income_' . $y . '_v1',
        'payment_order_budget_table_html_' . $y . '_v1',
        'payment_order_wise_eur_' . $y . '_v1',
        'payment_order_wise_usd_' . $y . '_v1',
        'payment_order_gs_ledger_verified_' . $y . '_v1',
    ];

    $bag = [];
    foreach ($keys as $k) {
        $bag[$k] = acgl_fms_kv_get_raw($k);
    }

    $id = acgl_fms_gdrive_now_backup_id();
    $createdAt = gmdate('c');

    return [
        'schema' => ACGL_FMS_GDRIVE_SCHEMA,
        'version' => ACGL_FMS_GDRIVE_VERSION,
        'year' => $y,
        'id' => $id,
        'createdAt' => $createdAt,
        'kind' => $kind === 'auto' ? 'auto' : 'manual',
        'keys' => $bag,
        'source' => 'wordpress',
    ];
}

function acgl_fms_gdrive_backup_get_known_years() {
    $years = [];

    $raw = acgl_fms_kv_get_raw('payment_order_budget_years_v1');
    if (is_string($raw) && trim($raw) !== '') {
        $parsed = json_decode($raw, true);
        if (is_array($parsed)) {
            foreach ($parsed as $v) {
                $y = (int) $v;
                if ($y >= 1900 && $y <= 3000) $years[] = $y;
            }
        }
    }

    $activeRaw = acgl_fms_kv_get_raw('payment_order_active_budget_year_v1');
    if (is_string($activeRaw) && preg_match('/^\d{4}$/', trim($activeRaw))) {
        $y = (int) trim($activeRaw);
        if ($y >= 1900 && $y <= 3000) $years[] = $y;
    }

    $years = array_values(array_unique($years));
    rsort($years);
    return $years;
}

function acgl_fms_gdrive_run_backup_upload($kind) {
    $config = acgl_fms_gdrive_get_config();
    if (!$config) {
        return [ 'ok' => false, 'error' => 'missing_config' ];
    }

    $token = acgl_fms_gdrive_get_access_token($config);
    if (!$token) {
        return [ 'ok' => false, 'error' => 'token_failed' ];
    }

    $years = acgl_fms_gdrive_backup_get_known_years();
    if (count($years) === 0) {
        return [ 'ok' => false, 'error' => 'no_years' ];
    }

    $results = [];
    foreach ($years as $year) {
        $payload = acgl_fms_gdrive_backup_year_payload($year, $kind);
        if (!$payload) {
            $results[] = [ 'year' => $year, 'ok' => false, 'error' => 'invalid_year' ];
            continue;
        }

        $fileName = 'acgl-fms-backup-' . $year . '-' . (string) $payload['id'] . '.json';
        $text = wp_json_encode($payload, JSON_PRETTY_PRINT);
        $up = acgl_fms_gdrive_upload_json($token, (string) $config['folderId'], $fileName, (string) $text);
        $results[] = array_merge([ 'year' => $year, 'fileName' => $fileName ], $up);
    }

    $uploaded = 0;
    $failed = 0;
    foreach ($results as $r) {
        if (!is_array($r)) continue;
        if (!empty($r['ok'])) $uploaded++;
        else $failed++;
    }

    return [
        'ok' => $uploaded > 0 && $failed === 0,
        'uploaded' => $uploaded,
        'failed' => $failed,
        'results' => $results,
    ];
}

function acgl_fms_gdrive_backup_daily_handler() {
    // Run as a background cron task. If not configured, silently skip.
    $config = acgl_fms_gdrive_get_config();
    if (!$config) {
        return;
    }

    $res = acgl_fms_gdrive_run_backup_upload('auto');

    update_option(ACGL_FMS_GDRIVE_LAST_RUN_OPTION, gmdate('c'), false);

    if (!$res || !is_array($res) || empty($res['ok'])) {
        update_option(ACGL_FMS_GDRIVE_LAST_ERROR_OPTION, wp_json_encode($res), false);
    } else {
        delete_option(ACGL_FMS_GDRIVE_LAST_ERROR_OPTION);
    }
}
