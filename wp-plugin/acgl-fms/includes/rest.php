<?php

if (!defined('ABSPATH')) {
    exit;
}

function acgl_fms_require_access() {
    return is_user_logged_in() && current_user_can(ACGL_FMS_CAP_ACCESS);
}

function acgl_fms_require_write() {
    return is_user_logged_in() && current_user_can(ACGL_FMS_CAP_WRITE);
}

function acgl_fms_sanitize_kv_key($key) {
    $k = is_string($key) ? $key : '';
    $k = trim($k);
    // Only allow characters we expect from localStorage keys.
    if ($k === '' || !preg_match('/^[A-Za-z0-9_\-\.]+$/', $k)) {
        return null;
    }
    return $k;
}

function acgl_fms_authorize_attachments($isWrite) {
    // Allow WordPress users with caps.
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

    $perms = acgl_fms_normalize_permissions($payload['p'] ?? []);
    $lvl = $perms['orders'] ?? 'none';
    if ($lvl === 'none') return false;
    if ($isWrite) return $lvl === 'write' || $lvl === 'partial';
    return true;
}

function acgl_fms_sanitize_target_key($targetKey) {
    $t = is_string($targetKey) ? trim($targetKey) : '';
    if ($t === '') return null;
    // Keep it reasonably bounded.
    if (strlen($t) > 200) $t = substr($t, 0, 200);
    return $t;
}

function acgl_fms_sanitize_year_folder($year) {
    $y = is_string($year) ? trim($year) : '';
    if ($y === '') return '';
    if (!preg_match('/^\d{4}$/', $y)) return '';
    return $y;
}

function acgl_fms_sanitize_po_folder($paymentOrderNo) {
    $raw = is_string($paymentOrderNo) ? trim($paymentOrderNo) : '';
    if ($raw === '') return '';
    // Keep folder names stable; allow PO 26-01, PO-26-01, PO26-01 etc.
    $s = strtoupper($raw);
    $s = preg_replace('/\s+/', '-', $s);
    $s = preg_replace('/[^A-Z0-9\-_.]/', '', $s);
    $s = trim($s, '-. _');
    if ($s === '') return '';
    // Avoid extremely long paths.
    if (strlen($s) > 80) $s = substr($s, 0, 80);
    return $s;
}

function acgl_fms_attachment_to_payload($id) {
    $post = get_post((int) $id);
    if (!$post || $post->post_type !== 'attachment') return null;

    $url = wp_get_attachment_url((int) $id);
    $file = get_attached_file((int) $id);
    $size = is_string($file) && file_exists($file) ? filesize($file) : null;
    $fileName = is_string($file) && $file !== '' ? basename($file) : '';

    return [
        'id' => (int) $id,
        'name' => $fileName !== '' ? (string) $fileName : (string) get_the_title((int) $id),
        'type' => (string) ($post->post_mime_type ?? ''),
        'size' => is_int($size) ? $size : null,
        'createdAt' => (string) ($post->post_date_gmt ?? ''),
        'url' => is_string($url) ? $url : '',
        'targetKey' => (string) get_post_meta((int) $id, 'acgl_fms_target_key', true),
        'year' => (string) get_post_meta((int) $id, 'acgl_fms_year', true),
        'paymentOrderNo' => (string) get_post_meta((int) $id, 'acgl_fms_payment_order_no', true),
    ];
}

function acgl_fms_register_rest_routes() {
    register_rest_route('acgl-fms/v1', '/auth/login', [
        'methods' => 'POST',
        'permission_callback' => '__return_true',
        'callback' => function (WP_REST_Request $request) {
            $username = strtolower(trim((string) $request->get_param('username')));
            $password = (string) $request->get_param('password');

            if ($username === '' || $password === '') {
                return new WP_REST_Response([ 'error' => 'missing_credentials' ], 400);
            }

            if (!acgl_fms_rate_limit_check($username)) {
                return new WP_REST_Response([ 'error' => 'rate_limited' ], 429);
            }

            $users = acgl_fms_load_users_from_kv();
            $user = acgl_fms_find_user_by_username($users, $username);
            if (!$user) {
                // Safety net: ensure the bootstrap admin user exists.
                if ($username === 'admin.pass') {
                    acgl_fms_ensure_default_admin_pass_user_exists();
                    $users = acgl_fms_load_users_from_kv();
                    $user = acgl_fms_find_user_by_username($users, $username);
                }
            }
            if (!$user) {
                acgl_fms_rate_limit_bump($username);
                return new WP_REST_Response([ 'error' => 'invalid_credentials' ], 401);
            }

            if (!acgl_fms_verify_user_password($user, $password)) {
                acgl_fms_rate_limit_bump($username);
                return new WP_REST_Response([ 'error' => 'invalid_credentials' ], 401);
            }

            acgl_fms_rate_limit_clear($username);

            $perms = acgl_fms_normalize_permissions($user['permissions'] ?? []);
            $token = acgl_fms_issue_token($username, $perms);

            return [
                'ok' => true,
                'token' => $token,
                'user' => [
                    'username' => (string) ($user['username'] ?? $username),
                    'permissions' => $perms,
                ],
            ];
        },
    ]);

    register_rest_route('acgl-fms/v1', '/kv', [
        'methods'  => 'GET',
        'permission_callback' => function () {
            return acgl_fms_authorize_kv(null, null, false);
        },
        'callback' => function (WP_REST_Request $request) {
            global $wpdb;
            $table = acgl_fms_kv_table_name();

            $prefixes = $request->get_param('prefix');
            $items = [];

            if (is_array($prefixes) && count($prefixes) > 0) {
                // Multiple prefixes.
                $clauses = [];
                $params = [];
                foreach ($prefixes as $p) {
                    $p = is_string($p) ? $p : '';
                    $p = trim($p);
                    if ($p === '') continue;
                    $clauses[] = 'k LIKE %s';
                    $params[] = $wpdb->esc_like($p) . '%';
                }
                if (count($clauses) === 0) {
                    return [ 'items' => [] ];
                }
                $where = implode(' OR ', $clauses);
                $rows = $wpdb->get_results($wpdb->prepare("SELECT k, v FROM {$table} WHERE {$where}", ...$params), ARRAY_A);
                foreach ($rows as $r) {
                    $items[] = [ 'k' => $r['k'], 'v' => $r['v'] ];
                }
                return [ 'items' => $items ];
            }

            // Single prefix or no prefix.
            $prefix = $request->get_param('prefix');
            if (is_string($prefix) && trim($prefix) !== '') {
                $p = trim($prefix);
                $like = $wpdb->esc_like($p) . '%';
                $rows = $wpdb->get_results($wpdb->prepare("SELECT k, v FROM {$table} WHERE k LIKE %s", $like), ARRAY_A);
            } else {
                $rows = $wpdb->get_results("SELECT k, v FROM {$table}", ARRAY_A);
            }

            foreach ($rows as $r) {
                $items[] = [ 'k' => $r['k'], 'v' => $r['v'] ];
            }

            // If this is a bearer-token request, filter items to only what the token can access.
            $token = acgl_fms_get_bearer_token();
            $payload = $token ? acgl_fms_verify_token($token) : null;
            if ($payload) {
                $items = array_values(array_filter($items, function ($item) use ($payload) {
                    $k = is_array($item) ? (string) ($item['k'] ?? '') : '';
                    return $k !== '' && acgl_fms_token_allows_key($payload, $k, false);
                }));
            }

            return [ 'items' => $items ];
        },
    ]);

    register_rest_route('acgl-fms/v1', '/kv/(?P<key>[A-Za-z0-9_\-\.]+)', [
        [
            'methods'  => 'GET',
            'permission_callback' => function (WP_REST_Request $request) {
                $key = acgl_fms_sanitize_kv_key($request['key']);
                if (!$key) return false;
                return acgl_fms_authorize_kv($request, $key, false);
            },
            'callback' => function (WP_REST_Request $request) {
                global $wpdb;
                $table = acgl_fms_kv_table_name();
                $key = acgl_fms_sanitize_kv_key($request['key']);
                if (!$key) {
                    return new WP_REST_Response([ 'error' => 'invalid_key' ], 400);
                }

                $row = $wpdb->get_row($wpdb->prepare("SELECT v FROM {$table} WHERE k = %s", $key), ARRAY_A);
                if (!$row) {
                    return new WP_REST_Response([ 'k' => $key, 'v' => null ], 200);
                }
                return [ 'k' => $key, 'v' => $row['v'] ];
            },
        ],
        [
            'methods'  => 'POST',
            'permission_callback' => function (WP_REST_Request $request) {
                $key = acgl_fms_sanitize_kv_key($request['key']);
                if (!$key) return false;
                return acgl_fms_authorize_kv($request, $key, true);
            },
            'callback' => function (WP_REST_Request $request) {
                global $wpdb;
                $table = acgl_fms_kv_table_name();
                $key = acgl_fms_sanitize_kv_key($request['key']);
                if (!$key) {
                    return new WP_REST_Response([ 'error' => 'invalid_key' ], 400);
                }

                $value = $request->get_param('value');
                if (!is_string($value) && $value !== null) {
                    return new WP_REST_Response([ 'error' => 'invalid_value' ], 400);
                }

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

                return [ 'ok' => true, 'k' => $key ];
            },
        ],
        [
            'methods'  => 'DELETE',
            'permission_callback' => function (WP_REST_Request $request) {
                $key = acgl_fms_sanitize_kv_key($request['key']);
                if (!$key) return false;
                return acgl_fms_authorize_kv($request, $key, true);
            },
            'callback' => function (WP_REST_Request $request) {
                global $wpdb;
                $table = acgl_fms_kv_table_name();
                $key = acgl_fms_sanitize_kv_key($request['key']);
                if (!$key) {
                    return new WP_REST_Response([ 'error' => 'invalid_key' ], 400);
                }
                $wpdb->delete($table, [ 'k' => $key ], [ '%s' ]);
                return [ 'ok' => true, 'k' => $key ];
            },
        ],
    ]);

    // ---- Attachments (Media Library) ----

    register_rest_route('acgl-fms/v1', '/attachments', [
        [
            'methods' => 'GET',
            'permission_callback' => function (WP_REST_Request $request) {
                return acgl_fms_authorize_attachments(false);
            },
            'callback' => function (WP_REST_Request $request) {
                $targetKey = acgl_fms_sanitize_target_key($request->get_param('targetKey'));
                if (!$targetKey) {
                    return new WP_REST_Response([ 'error' => 'missing_target_key' ], 400);
                }

                $ids = get_posts([
                    'post_type' => 'attachment',
                    'post_status' => 'inherit',
                    'posts_per_page' => 250,
                    'orderby' => 'date',
                    'order' => 'DESC',
                    'fields' => 'ids',
                    'meta_query' => [
                        [
                            'key' => 'acgl_fms_target_key',
                            'value' => $targetKey,
                            'compare' => '=',
                        ],
                    ],
                ]);

                $items = [];
                foreach ($ids as $id) {
                    $payload = acgl_fms_attachment_to_payload($id);
                    if ($payload) $items[] = $payload;
                }

                return [ 'items' => $items ];
            },
        ],
        [
            'methods' => 'DELETE',
            'permission_callback' => function (WP_REST_Request $request) {
                return acgl_fms_authorize_attachments(true);
            },
            'callback' => function (WP_REST_Request $request) {
                $targetKey = acgl_fms_sanitize_target_key($request->get_param('targetKey'));
                if (!$targetKey) {
                    return new WP_REST_Response([ 'error' => 'missing_target_key' ], 400);
                }

                $ids = get_posts([
                    'post_type' => 'attachment',
                    'post_status' => 'inherit',
                    'posts_per_page' => 500,
                    'fields' => 'ids',
                    'meta_query' => [
                        [
                            'key' => 'acgl_fms_target_key',
                            'value' => $targetKey,
                            'compare' => '=',
                        ],
                    ],
                ]);

                $count = 0;
                foreach ($ids as $id) {
                    $id = (int) $id;
                    if ($id <= 0) continue;
                    $deleted = wp_delete_attachment($id, true);
                    if ($deleted) $count++;
                }

                return [ 'ok' => true, 'deleted' => $count ];
            },
        ],
    ]);

    register_rest_route('acgl-fms/v1', '/attachments/(?P<id>\d+)', [
        [
            'methods' => 'GET',
            'permission_callback' => function (WP_REST_Request $request) {
                return acgl_fms_authorize_attachments(false);
            },
            'callback' => function (WP_REST_Request $request) {
                $id = (int) $request['id'];
                if ($id <= 0) return new WP_REST_Response([ 'error' => 'invalid_id' ], 400);
                $targetKey = (string) get_post_meta($id, 'acgl_fms_target_key', true);
                if (trim($targetKey) === '') {
                    return new WP_REST_Response([ 'error' => 'not_found' ], 404);
                }
                $payload = acgl_fms_attachment_to_payload($id);
                if (!$payload) return new WP_REST_Response([ 'error' => 'not_found' ], 404);
                return $payload;
            },
        ],
        [
            'methods' => 'DELETE',
            'permission_callback' => function (WP_REST_Request $request) {
                return acgl_fms_authorize_attachments(true);
            },
            'callback' => function (WP_REST_Request $request) {
                $id = (int) $request['id'];
                if ($id <= 0) return new WP_REST_Response([ 'error' => 'invalid_id' ], 400);
                $targetKey = (string) get_post_meta($id, 'acgl_fms_target_key', true);
                if (trim($targetKey) === '') {
                    return new WP_REST_Response([ 'error' => 'not_found' ], 404);
                }

                $deleted = wp_delete_attachment($id, true);
                if (!$deleted) {
                    return new WP_REST_Response([ 'error' => 'delete_failed' ], 500);
                }
                return [ 'ok' => true, 'id' => $id ];
            },
        ],
    ]);

    register_rest_route('acgl-fms/v1', '/attachments/upload', [
        'methods' => 'POST',
        'permission_callback' => function (WP_REST_Request $request) {
            return acgl_fms_authorize_attachments(true);
        },
        'callback' => function (WP_REST_Request $request) {
            $targetKey = acgl_fms_sanitize_target_key($request->get_param('targetKey'));
            if (!$targetKey) {
                return new WP_REST_Response([ 'error' => 'missing_target_key' ], 400);
            }

            $year = acgl_fms_sanitize_year_folder((string) $request->get_param('year'));
            $po = acgl_fms_sanitize_po_folder((string) $request->get_param('paymentOrderNo'));
            $orderId = (string) $request->get_param('orderId');
            $orderId = trim($orderId);
            if ($orderId !== '') {
                $orderId = preg_replace('/[^A-Za-z0-9\-_.]/', '', $orderId);
            }

            $fileParams = $request->get_file_params();
            $file = is_array($fileParams) && isset($fileParams['file']) ? $fileParams['file'] : null;
            if (!is_array($file) || !isset($file['tmp_name'])) {
                return new WP_REST_Response([ 'error' => 'missing_file' ], 400);
            }

            // Determine upload subdir: /acgl-fms/<year>/<po-or-orderId>
            $bucket = $po !== '' ? $po : ($orderId !== '' ? $orderId : 'order');
            $subdir = '/acgl-fms';
            if ($year !== '') $subdir .= '/' . $year;
            $subdir .= '/' . $bucket;

            // Ensure WP upload helpers are available.
            require_once ABSPATH . 'wp-admin/includes/file.php';
            require_once ABSPATH . 'wp-admin/includes/media.php';
            require_once ABSPATH . 'wp-admin/includes/image.php';

            $filter = function ($dirs) use ($subdir) {
                $dirs['subdir'] = $subdir;
                $dirs['path'] = $dirs['basedir'] . $dirs['subdir'];
                $dirs['url'] = $dirs['baseurl'] . $dirs['subdir'];
                return $dirs;
            };

            add_filter('upload_dir', $filter);
            try {
                $overrides = [ 'test_form' => false ];
                $upload = wp_handle_upload($file, $overrides);
            } finally {
                remove_filter('upload_dir', $filter);
            }

            if (!is_array($upload) || isset($upload['error'])) {
                $msg = is_array($upload) && isset($upload['error']) ? (string) $upload['error'] : 'upload_failed';
                return new WP_REST_Response([ 'error' => 'upload_failed', 'message' => $msg ], 500);
            }

            $filePath = (string) ($upload['file'] ?? '');
            $fileUrl = (string) ($upload['url'] ?? '');
            $type = (string) ($upload['type'] ?? 'application/octet-stream');
            $name = isset($file['name']) ? (string) $file['name'] : '';
            $title = $name !== '' ? preg_replace('/\.[^.]+$/', '', $name) : basename($filePath);

            $attachment = [
                'post_mime_type' => $type,
                'post_title' => sanitize_text_field($title),
                'post_content' => '',
                'post_status' => 'inherit',
            ];

            $attachId = wp_insert_attachment($attachment, $filePath);
            if (!$attachId || is_wp_error($attachId)) {
                return new WP_REST_Response([ 'error' => 'insert_failed' ], 500);
            }

            $meta = wp_generate_attachment_metadata($attachId, $filePath);
            if (is_array($meta)) {
                wp_update_attachment_metadata($attachId, $meta);
            }

            update_post_meta($attachId, 'acgl_fms_target_key', $targetKey);
            if ($year !== '') update_post_meta($attachId, 'acgl_fms_year', $year);
            if ($po !== '') update_post_meta($attachId, 'acgl_fms_payment_order_no', $po);
            if ($orderId !== '') update_post_meta($attachId, 'acgl_fms_order_id', $orderId);

            $payload = acgl_fms_attachment_to_payload($attachId);
            if (!$payload) {
                return new WP_REST_Response([ 'error' => 'insert_failed' ], 500);
            }

            // Ensure the URL is included even if title differs.
            if ($payload['url'] === '' && $fileUrl !== '') $payload['url'] = $fileUrl;

            return [ 'ok' => true, 'item' => $payload ];
        },
    ]);
}
