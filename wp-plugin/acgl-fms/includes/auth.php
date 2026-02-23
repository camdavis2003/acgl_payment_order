<?php

if (!defined('ABSPATH')) {
    exit;
}

// ---- Token format ----
// token = base64url(json_payload) + '.' + base64url(hmac_sha256(payload_b64, wp_salt('auth')))

function acgl_fms_base64url_encode($bytes) {
    $b64 = base64_encode($bytes);
    $b64 = str_replace(['+', '/', '='], ['-', '_', ''], $b64);
    return $b64;
}

function acgl_fms_base64url_decode($b64url) {
    $b64 = str_replace(['-', '_'], ['+', '/'], (string) $b64url);
    $pad = strlen($b64) % 4;
    if ($pad > 0) {
        $b64 .= str_repeat('=', 4 - $pad);
    }
    return base64_decode($b64);
}

function acgl_fms_get_bearer_token() {
    $auth = '';

    if (function_exists('getallheaders')) {
        $headers = getallheaders();
        if (is_array($headers)) {
            foreach ($headers as $k => $v) {
                if (strtolower((string) $k) === 'authorization') {
                    $auth = (string) $v;
                    break;
                }
            }
        }
    }

    if ($auth === '' && isset($_SERVER['HTTP_AUTHORIZATION'])) {
        $auth = (string) $_SERVER['HTTP_AUTHORIZATION'];
    }

    $auth = trim($auth);
    if ($auth === '') return null;

    if (stripos($auth, 'bearer ') === 0) {
        return trim(substr($auth, 7));
    }

    return null;
}

function acgl_fms_sign_token_payload_b64($payloadB64) {
    $secret = wp_salt('auth');
    $sig = hash_hmac('sha256', (string) $payloadB64, $secret, true);
    return acgl_fms_base64url_encode($sig);
}

function acgl_fms_issue_token($username, $permissions, $ttlSeconds = 43200) {
    $now = time();
    $payload = [
        'v' => 1,
        'iat' => $now,
        'exp' => $now + (int) $ttlSeconds,
        'u' => (string) $username,
        'p' => is_array($permissions) ? $permissions : [],
    ];

    $json = wp_json_encode($payload);
    $payloadB64 = acgl_fms_base64url_encode($json);
    $sigB64 = acgl_fms_sign_token_payload_b64($payloadB64);

    return $payloadB64 . '.' . $sigB64;
}

function acgl_fms_verify_token($token) {
    $t = trim((string) $token);
    if ($t === '') return null;

    $parts = explode('.', $t);
    if (count($parts) !== 2) return null;

    [$payloadB64, $sigB64] = $parts;
    if ($payloadB64 === '' || $sigB64 === '') return null;

    $expected = acgl_fms_sign_token_payload_b64($payloadB64);
    if (!hash_equals($expected, $sigB64)) return null;

    $json = acgl_fms_base64url_decode($payloadB64);
    if (!is_string($json) || $json === '') return null;

    $payload = json_decode($json, true);
    if (!is_array($payload)) return null;

    $exp = isset($payload['exp']) ? (int) $payload['exp'] : 0;
    if ($exp <= time()) return null;

    return $payload;
}

function acgl_fms_normalize_perm_level($value) {
    if ($value === true) return 'write';
    if ($value === false || $value === null) return 'none';
    $v = strtolower(trim((string) $value));
    if ($v === 'write' || $v === 'full' || $v === 'fullaccess') return 'write';
    if ($v === 'partial' || $v === 'limited' || $v === 'some') return 'partial';
    if ($v === 'read' || $v === 'readonly' || $v === 'read-only') return 'read';
    return 'none';
}

function acgl_fms_normalize_permissions($perms) {
    $p = is_array($perms) ? $perms : [];
    return [
        'budget' => acgl_fms_normalize_perm_level($p['budget'] ?? null),
        'income' => acgl_fms_normalize_perm_level($p['income'] ?? null),
        'orders' => acgl_fms_normalize_perm_level($p['orders'] ?? null),
        'ledger' => acgl_fms_normalize_perm_level($p['ledger'] ?? null),
        'settings' => acgl_fms_normalize_perm_level($p['settings'] ?? null),
    ];
}

function acgl_fms_key_to_module($key) {
    $k = (string) $key;

    if ($k === 'payment_order_users_v1') return 'settings';
    if ($k === 'payment_order_auth_audit_v1') return 'settings';

    if ($k === 'payment_order_budget_years_v1') return 'budget';
    if ($k === 'payment_order_active_budget_year_v1') return 'budget';
    if (str_starts_with($k, 'payment_order_budget_table_html_')) return 'budget';
    if ($k === 'payment_order_budget_table_html_v1') return 'budget';

    if ($k === 'payment_order_numbering') return 'orders';
    if (str_starts_with($k, 'payment_orders_')) return 'orders';

    if (str_starts_with($k, 'payment_order_income_')) return 'income';

    if (str_starts_with($k, 'payment_order_gs_ledger_verified_')) return 'ledger';

    // Default: treat as settings/sensitive.
    return 'settings';
}

function acgl_fms_token_allows_key($tokenPayload, $key, $isWrite) {
    if (!is_array($tokenPayload)) return false;

    $username = strtolower(trim((string) ($tokenPayload['u'] ?? '')));
    if ($username === '') return false;

    $perms = acgl_fms_normalize_permissions($tokenPayload['p'] ?? []);
    $module = acgl_fms_key_to_module($key);
    $level = $perms[$module] ?? 'none';

    if ($level === 'none') return false;

    if ($isWrite) {
        return $level === 'write' || $level === 'partial';
    }

    return true;
}

function acgl_fms_get_client_ip() {
    // Best-effort (won't be perfect behind proxies).
    if (!empty($_SERVER['REMOTE_ADDR'])) return (string) $_SERVER['REMOTE_ADDR'];
    return 'unknown';
}

function acgl_fms_rate_limit_key($username) {
    $ip = acgl_fms_get_client_ip();
    $u = strtolower(trim((string) $username));
    return 'acgl_fms_login_' . md5($ip . '|' . $u);
}

function acgl_fms_rate_limit_check($username) {
    $k = acgl_fms_rate_limit_key($username);
    $count = (int) get_transient($k);
    if ($count >= 15) return false;
    return true;
}

function acgl_fms_rate_limit_bump($username) {
    $k = acgl_fms_rate_limit_key($username);
    $count = (int) get_transient($k);
    $count++;
    // 10 minute window.
    set_transient($k, $count, 10 * 60);
}

function acgl_fms_rate_limit_clear($username) {
    delete_transient(acgl_fms_rate_limit_key($username));
}

function acgl_fms_kv_get_raw($key) {
    global $wpdb;
    $table = acgl_fms_kv_table_name();
    $row = $wpdb->get_row($wpdb->prepare("SELECT v FROM {$table} WHERE k = %s", $key), ARRAY_A);
    if (!$row) return null;
    return $row['v'];
}

function acgl_fms_kv_set_raw($key, $value) {
    global $wpdb;
    $table = acgl_fms_kv_table_name();
    $now = current_time('mysql');
    $wpdb->query(
        $wpdb->prepare(
            "INSERT INTO {$table} (k, v, updated_at) VALUES (%s, %s, %s)
             ON DUPLICATE KEY UPDATE v = VALUES(v), updated_at = VALUES(updated_at)",
            $key,
            $value,
            $now
        )
    );
}

function acgl_fms_verify_user_password($userRow, $password) {
    $salt = isset($userRow['salt']) ? (string) $userRow['salt'] : '';
    $stored = isset($userRow['passwordHash']) ? (string) $userRow['passwordHash'] : '';
    $pw = (string) $password;

    if ($salt === '' || $stored === '') return false;

    if (str_starts_with($stored, 'sha256:')) {
        $input = $salt . ':' . $pw;
        $raw = hash('sha256', $input, true);
        $b64 = base64_encode($raw);
        return hash_equals('sha256:' . $b64, $stored);
    }

    if (str_starts_with($stored, 'pw:')) {
        $b64 = substr($stored, 3);
        $decoded = base64_decode($b64, true);
        if ($decoded === false) return false;
        return hash_equals($salt . ':' . $pw, $decoded);
    }

    // Unknown format.
    return false;
}

function acgl_fms_load_users_from_kv() {
    $raw = acgl_fms_kv_get_raw('payment_order_users_v1');
    if (!is_string($raw) || trim($raw) === '') return [];

    $parsed = json_decode($raw, true);
    if (!is_array($parsed)) return [];

    // Expect an array of user objects.
    return array_values(array_filter($parsed, function ($u) {
        return is_array($u) && isset($u['username']);
    }));
}

function acgl_fms_ensure_default_admin_pass_user_exists() {
    // Ensure the built-in bootstrap admin exists, without overwriting other users.
    try {
        $raw = acgl_fms_kv_get_raw('payment_order_users_v1');
        $users = [];

        if (is_string($raw) && trim($raw) !== '') {
            $parsed = json_decode($raw, true);
            if (is_array($parsed)) {
                $users = array_values(array_filter($parsed, function ($u) {
                    return is_array($u) && isset($u['username']);
                }));
            }
        }

        $adminU = 'admin.pass';
        foreach ($users as $row) {
            $ru = strtolower(trim((string) ($row['username'] ?? '')));
            if ($ru === $adminU) {
                return;
            }
        }

        $now = gmdate('c');
        $salt = 'acgl_fms_admin_v1';
        $pwHash = 'pw:' . base64_encode($salt . ':' . 'acgl1962ADM');
        $admin = [
            'id' => 'user_admin_pass_v1',
            'createdAt' => $now,
            'updatedAt' => $now,
            'username' => $adminU,
            'email' => '',
            'salt' => $salt,
            'passwordHash' => $pwHash,
            'passwordPlain' => '',
            'permissions' => [ 'budget' => 'write', 'income' => 'write', 'orders' => 'write', 'ledger' => 'write', 'settings' => 'write' ],
        ];

        $users[] = $admin;
        acgl_fms_kv_set_raw('payment_order_users_v1', wp_json_encode($users));
    } catch (Throwable $e) {
        // ignore
    }
}

function acgl_fms_find_user_by_username($users, $username) {
    $u = strtolower(trim((string) $username));
    foreach ($users as $row) {
        $ru = strtolower(trim((string) ($row['username'] ?? '')));
        if ($ru !== '' && $ru === $u) return $row;
    }
    return null;
}

function acgl_fms_authorize_kv($request, $keyOrNull, $isWrite) {
    // Allow WordPress users with caps (admin/internal WP usage).
    if ($isWrite) {
        if (acgl_fms_require_write()) return true;
    } else {
        if (acgl_fms_require_access()) return true;
    }

    // Public mode: require a valid bearer token.
    $token = acgl_fms_get_bearer_token();
    if (!$token) return false;
    $payload = acgl_fms_verify_token($token);
    if (!$payload) return false;

    // List endpoint: allow if token has ANY non-none module.
    if ($keyOrNull === null) {
        $perms = acgl_fms_normalize_permissions($payload['p'] ?? []);
        foreach ($perms as $lvl) {
            if ($lvl !== 'none') return true;
        }
        return false;
    }

    return acgl_fms_token_allows_key($payload, $keyOrNull, $isWrite);
}
