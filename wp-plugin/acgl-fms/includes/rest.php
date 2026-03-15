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

function acgl_fms_authorize_settings_write() {
    // Allow WordPress users with caps.
    if (acgl_fms_require_write()) return true;

    // Token mode: require settings write/partial.
    $token = acgl_fms_get_bearer_token();
    if (!$token) return false;
    $payload = acgl_fms_verify_token($token);
    if (!$payload) return false;

    $perms = acgl_fms_normalize_permissions($payload['p'] ?? []);
    $lvl = $perms['settings'] ?? 'none';
    return acgl_fms_level_allows_write($lvl);
}

function acgl_fms_authorize_settings_notifications($isWrite) {
    // Allow WordPress users with caps.
    if ($isWrite) {
        if (acgl_fms_require_write()) return true;
    } else {
        if (acgl_fms_require_access()) return true;
    }

    // Token mode: require email notifications permission.
    $token = acgl_fms_get_bearer_token();
    if (!$token) return false;
    $payload = acgl_fms_verify_token($token);
    if (!$payload) return false;

    $perms = acgl_fms_normalize_permissions($payload['p'] ?? []);
    $lvl = $perms['settings_email_notifications'] ?? 'none';
    if ($lvl === 'none') return false;
    if ($isWrite) return acgl_fms_level_allows_write($lvl);
    return true;
}

function acgl_fms_notifications_is_valid_email($value) {
    $email = trim((string) $value);
    if ($email === '') return false;
    if (function_exists('sanitize_email')) {
        $email = (string) sanitize_email($email);
    }
    if ($email === '') return false;
    if (function_exists('is_email') && !is_email($email)) return false;
    return true;
}

function acgl_fms_notifications_normalize_runtime_settings($baseSettings, $overrides) {
    $base = is_array($baseSettings) ? $baseSettings : [];
    $ov = is_array($overrides) ? $overrides : [];
    $defaults = function_exists('acgl_fms_admin_notification_defaults') ? acgl_fms_admin_notification_defaults() : [];
    $defaultTypes = isset($defaults['types_config']) && is_array($defaults['types_config']) ? $defaults['types_config'] : [];

    $pick = function ($key, $default = '') use ($ov, $base) {
        if (array_key_exists($key, $ov)) return $ov[$key];
        if (array_key_exists($key, $base)) return $base[$key];
        return $default;
    };

    $mode = (string) $pick('recipients_mode', 'all_users_with_email');
    if ($mode !== 'manual_list' && $mode !== 'all_users_with_email') {
        if (strpos($mode, 'user:') === 0) {
            $username = strtolower(trim((string) substr($mode, strlen('user:'))));
            if ($username !== '' && preg_match('/^[a-z0-9._\-]+$/', $username)) {
                $mode = 'user:' . $username;
            } else {
                $mode = 'all_users_with_email';
            }
        } else {
            $mode = 'all_users_with_email';
        }
    }

    $typesRaw = $pick('types_config', []);
    $typesMap = is_array($typesRaw) ? $typesRaw : [];
    $typesConfig = [];
    foreach ($defaultTypes as $typeId => $typeDefault) {
        $rawType = isset($typesMap[$typeId]) && is_array($typesMap[$typeId]) ? $typesMap[$typeId] : [];
        $enabledRaw = isset($rawType['enabled']) ? (string) $rawType['enabled'] : (string) ($typeDefault['enabled'] ?? '1');
        $subject = isset($rawType['subject']) ? trim((string) $rawType['subject']) : '';
        $body = isset($rawType['body']) ? trim((string) $rawType['body']) : '';
        $typesConfig[$typeId] = [
            'enabled' => ($enabledRaw === '1' || $enabledRaw === 'true' || $enabledRaw === 'yes') ? '1' : '0',
            'subject' => $subject !== '' ? (string) $rawType['subject'] : (string) ($typeDefault['subject'] ?? ''),
            'body' => $body !== '' ? (string) $rawType['body'] : (string) ($typeDefault['body'] ?? ''),
            'recipients_mode' => isset($rawType['recipients_mode']) ? trim((string) $rawType['recipients_mode']) : '',
            'manual_to' => isset($rawType['manual_to']) ? trim((string) $rawType['manual_to']) : '',
        ];
    }

    return [
        'recipients_mode' => $mode,
        'manual_to' => trim((string) $pick('manual_to', '')),
        'reply_to' => trim((string) $pick('reply_to', '')),
        'signature' => trim((string) $pick('signature', 'ACGL Financial Management System')),
        'types_config' => $typesConfig,
    ];
}

function acgl_fms_notifications_get_type_config($settings, $typeId) {
    $sid = trim((string) $typeId);
    if ($sid === '') return null;

    $defaults = function_exists('acgl_fms_admin_notification_type_defaults')
        ? acgl_fms_admin_notification_type_defaults()
        : [];
    if (!isset($defaults[$sid]) || !is_array($defaults[$sid])) {
        return null;
    }

    $typesConfig = is_array($settings) && isset($settings['types_config']) && is_array($settings['types_config'])
        ? $settings['types_config']
        : [];
    $rawType = isset($typesConfig[$sid]) && is_array($typesConfig[$sid]) ? $typesConfig[$sid] : [];
    $default = $defaults[$sid];

    $enabledRaw = isset($rawType['enabled']) ? (string) $rawType['enabled'] : (string) ($default['enabled'] ?? '1');
    $subject = isset($rawType['subject']) ? trim((string) $rawType['subject']) : '';
    $body = isset($rawType['body']) ? trim((string) $rawType['body']) : '';

    return [
        'enabled' => ($enabledRaw === '1' || $enabledRaw === 'true' || $enabledRaw === 'yes') ? '1' : '0',
        'subject' => $subject !== '' ? (string) $rawType['subject'] : (string) ($default['subject'] ?? ''),
        'body' => $body !== '' ? (string) $rawType['body'] : (string) ($default['body'] ?? ''),
        'recipients_mode' => isset($rawType['recipients_mode']) ? trim((string) $rawType['recipients_mode']) : '',
        'manual_to' => isset($rawType['manual_to']) ? trim((string) $rawType['manual_to']) : '',
    ];
}

function acgl_fms_notifications_resolve_recipients($settings, $forcedTo) {
    $recipients = [];

    $to = trim((string) $forcedTo);
    if ($to !== '' && acgl_fms_notifications_is_valid_email($to)) {
        return [ strtolower($to) ];
    }

    $mode = is_array($settings) ? (string) ($settings['recipients_mode'] ?? '') : '';
    if ($mode === 'manual_list') {
        $raw = is_array($settings) ? (string) ($settings['manual_to'] ?? '') : '';
        if (function_exists('acgl_fms_admin_parse_notification_emails')) {
            $list = acgl_fms_admin_parse_notification_emails($raw);
            if (is_array($list)) {
                foreach ($list as $email) {
                    $e = strtolower(trim((string) $email));
                    if ($e !== '' && acgl_fms_notifications_is_valid_email($e)) $recipients[$e] = true;
                }
            }
        }
    } elseif (strpos($mode, 'user:') === 0) {
        $targetUsername = strtolower(trim((string) substr($mode, strlen('user:'))));
        if ($targetUsername !== '' && function_exists('acgl_fms_load_users_from_kv')) {
            $users = acgl_fms_load_users_from_kv();
            if (is_array($users)) {
                foreach ($users as $u) {
                    if (!is_array($u)) continue;
                    $username = strtolower(trim((string) ($u['username'] ?? '')));
                    if ($username !== $targetUsername) continue;

                    $email = strtolower(trim((string) ($u['email'] ?? '')));
                    if ($email !== '' && acgl_fms_notifications_is_valid_email($email)) {
                        $recipients[$email] = true;
                    }
                    break;
                }
            }
        }
    } else {
        if (function_exists('acgl_fms_load_users_from_kv')) {
            $users = acgl_fms_load_users_from_kv();
            if (is_array($users)) {
                foreach ($users as $u) {
                    if (!is_array($u)) continue;
                    $email = strtolower(trim((string) ($u['email'] ?? '')));
                    if ($email !== '' && acgl_fms_notifications_is_valid_email($email)) {
                        $recipients[$email] = true;
                    }
                }
            }
        }
    }

    if (count($recipients) === 0) {
        $adminEmail = trim((string) get_option('admin_email', ''));
        if ($adminEmail !== '' && acgl_fms_notifications_is_valid_email($adminEmail)) {
            $recipients[strtolower($adminEmail)] = true;
        }
    }

    return array_keys($recipients);
}

function acgl_fms_notifications_apply_placeholders($text, $vars) {
    $out = (string) $text;
    $map = is_array($vars) ? $vars : [];
    foreach ($map as $k => $v) {
        $key = '{{' . trim((string) $k) . '}}';
        $out = str_replace($key, (string) $v, $out);
    }
    return $out;
}

function acgl_fms_notifications_build_body_html($bodyTpl, $vars, $signature) {
    // URL-type placeholders rendered as HTML anchors instead of raw URLs.
    $urlPlaceholders = [
        'directLink'      => 'Open Action',
        'paymentOrderLink' => 'View payment order',
    ];

    $map = is_array($vars) ? $vars : [];

    // HTML-encode the template text so it is safe to emit inside an HTML email.
    $out = htmlspecialchars((string) $bodyTpl, ENT_QUOTES, 'UTF-8');

    // Replace URL placeholders with HTML anchor tags.
    foreach ($urlPlaceholders as $k => $label) {
        $placeholder = htmlspecialchars('{{' . $k . '}}', ENT_QUOTES, 'UTF-8');
        $rawUrl = isset($map[$k]) ? trim((string) $map[$k]) : '';
        if ($rawUrl !== '' && function_exists('esc_url')) {
            $safeUrl = esc_url($rawUrl);
            $anchorLabel = htmlspecialchars($label, ENT_QUOTES, 'UTF-8');
            $out = str_replace($placeholder, '<a href="' . $safeUrl . '">' . $anchorLabel . '</a>', $out);
        } else {
            $out = str_replace($placeholder, '', $out);
        }
    }

    // Replace remaining text placeholders with HTML-encoded values.
    foreach ($map as $k => $v) {
        if (isset($urlPlaceholders[$k])) continue;
        $placeholder = htmlspecialchars('{{' . $k . '}}', ENT_QUOTES, 'UTF-8');
        $out = str_replace($placeholder, htmlspecialchars((string) $v, ENT_QUOTES, 'UTF-8'), $out);
    }

    // Convert newlines to <br> tags.
    $out = nl2br($out);

    // Append signature.
    $sig = trim((string) $signature);
    if ($sig !== '') {
        $out .= '<br><br>' . htmlspecialchars($sig, ENT_QUOTES, 'UTF-8');
    }

    return $out;
}

function acgl_fms_notifications_build_order_link($year, $orderId) {
    if (!defined('ACGL_FMS_PLUGIN_FILE')) return '';

    $y = is_string($year) ? trim($year) : (string) $year;
    if ($y === '' || !preg_match('/^\d{4}$/', $y)) {
        $y = (string) gmdate('Y');
    }

    $id = trim((string) $orderId);
    if ($id === '') return '';

    $url = plugins_url('app/menu.html', ACGL_FMS_PLUGIN_FILE);
    $params = [
        'year' => $y,
        'orderId' => $id,
        'restUrl' => rest_url(),
        'wp' => '1',
        'v' => defined('ACGL_FMS_APP_VERSION') ? ACGL_FMS_APP_VERSION : '0',
    ];

    if (function_exists('wp_create_nonce')) {
        $nonce = (string) wp_create_nonce('wp_rest');
        if ($nonce !== '') $params['restNonce'] = $nonce;
    }

    return (string) add_query_arg($params, $url);
}

function acgl_fms_notifications_send_public_submit($year, $order) {
    if (!function_exists('acgl_fms_admin_get_notification_settings')) {
        return [ 'ok' => false, 'error' => 'not_available' ];
    }

    $saved = acgl_fms_admin_get_notification_settings();
    if (!is_array($saved)) {
        return [ 'ok' => false, 'error' => 'settings_unavailable' ];
    }

    $settings = acgl_fms_notifications_normalize_runtime_settings($saved, []);
    $typeConfig = acgl_fms_notifications_get_type_config($settings, 'new_payment_order');
    if (!is_array($typeConfig)) {
        return [ 'ok' => false, 'error' => 'event_unknown' ];
    }
    if ((string) ($typeConfig['enabled'] ?? '0') !== '1') {
        return [ 'ok' => false, 'error' => 'event_disabled' ];
    }

    $to = acgl_fms_notifications_resolve_recipients($settings, '');
    if (!is_array($to) || count($to) === 0) {
        return [ 'ok' => false, 'error' => 'no_recipients' ];
    }

    $orderArr = is_array($order) ? $order : [];
    $orderId = isset($orderArr['id']) ? (string) $orderArr['id'] : '';
    $createdAt = isset($orderArr['createdAt']) ? (string) $orderArr['createdAt'] : gmdate('c');
    $poNo = isset($orderArr['paymentOrderNo']) ? (string) $orderArr['paymentOrderNo'] : '';
    $orderLink = acgl_fms_notifications_build_order_link($year, $orderId);

    $vars = [
        'paymentOrderNo' => $poNo,
        'year' => (string) $year,
        'createdAt' => $createdAt,
        'id' => $orderId,
        'paymentOrderLink' => $orderLink,
    ];

    $subjectTpl = trim((string) ($typeConfig['subject'] ?? ''));
    if ($subjectTpl === '') $subjectTpl = '[ACGL FMS] New Payment Order {{paymentOrderNo}}';

    $bodyTpl = trim((string) ($typeConfig['body'] ?? ''));
    if ($bodyTpl === '') {
        $bodyTpl = "A new payment order has been submitted.\n\nPayment Order: {{paymentOrderNo}}\nYear: {{year}}\nCreated: {{createdAt}}\nID: {{id}}\nLink: {{paymentOrderLink}}";
    }

    $signature = trim((string) ($settings['signature'] ?? ''));
    $subject = acgl_fms_notifications_apply_placeholders($subjectTpl, $vars);
    $body = acgl_fms_notifications_build_body_html($bodyTpl, $vars, $signature);

    $headers = [ 'Content-Type: text/html; charset=UTF-8' ];
    $replyTo = trim((string) ($settings['reply_to'] ?? ''));
    if ($replyTo !== '' && acgl_fms_notifications_is_valid_email($replyTo)) {
        $headers[] = 'Reply-To: ' . $replyTo;
    }

    $ok = wp_mail($to, $subject, $body, $headers);
    if (!$ok) {
        return [ 'ok' => false, 'error' => 'mail_send_failed' ];
    }

    return [
        'ok' => true,
        'sent' => count($to),
        'to' => $to,
        'subject' => $subject,
        'paymentOrderLink' => $orderLink,
    ];
}

function acgl_fms_public_year2_from_budget_year($budgetYear) {
    $y = is_string($budgetYear) ? trim($budgetYear) : '';
    if ($y === '' || !preg_match('/^\d{4}$/', $y)) return null;
    $n = (int) $y;
    $yy = (($n % 100) + 100) % 100;
    return str_pad((string) $yy, 2, '0', STR_PAD_LEFT);
}

function acgl_fms_public_infer_next_seq_from_orders_json($ordersRaw, $year2) {
    $y2 = is_string($year2) ? trim($year2) : '';
    if ($y2 === '' || !preg_match('/^\d{2}$/', $y2)) return 1;

    if (!is_string($ordersRaw) || trim($ordersRaw) === '') return 1;
    $decoded = json_decode($ordersRaw, true);
    if (!is_array($decoded)) return 1;

    $maxSeq = 0;
    foreach ($decoded as $o) {
        if (!is_array($o)) continue;
        $raw = isset($o['paymentOrderNo']) ? (string) $o['paymentOrderNo'] : '';
        $s = strtoupper(trim($raw));
        if ($s === '') continue;
        $noSpaces = preg_replace('/\s+/', '', $s);
        $canon = preg_replace('/^PO-/', 'PO', $noSpaces);
        if (!preg_match('/^PO(\d{2})-(\d+)$/', $canon, $m)) continue;
        if ((string) $m[1] !== $y2) continue;
        $seq = (int) $m[2];
        if ($seq > $maxSeq) $maxSeq = $seq;
    }

    $next = $maxSeq + 1;
    return $next < 1 ? 1 : $next;
}

function acgl_fms_public_format_po_no($year2, $seq) {
    $y2 = is_string($year2) ? trim($year2) : '';
    if (!preg_match('/^\d{2}$/', $y2)) $y2 = '00';
    $n = (int) $seq;
    if ($n < 1) $n = 1;
    $seqText = $n < 100 ? str_pad((string) $n, 2, '0', STR_PAD_LEFT) : (string) $n;
    return 'PO ' . $y2 . '-' . $seqText;
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
    if ($isWrite) return acgl_fms_level_allows_write($lvl);
    return true;
}

function acgl_fms_authorize_backlog_attachments($isWrite) {
    // Allow WordPress users with caps.
    if ($isWrite) {
        if (acgl_fms_require_write()) return true;
    } else {
        if (acgl_fms_require_access()) return true;
    }

    // Token mode: use Settings permission.
    $token = acgl_fms_get_bearer_token();
    if (!$token) return false;
    $payload = acgl_fms_verify_token($token);
    if (!$payload) return false;

    $perms = acgl_fms_normalize_permissions($payload['p'] ?? []);
    $lvl = $perms['settings'] ?? 'none';
    if ($lvl === 'none') return false;
    if ($isWrite) return acgl_fms_level_allows_write($lvl);
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

function acgl_fms_public_submit_rate_limit_key() {
    $ip = acgl_fms_get_client_ip();
    return 'acgl_fms_public_submit_' . md5((string) $ip);
}

function acgl_fms_public_submit_rate_limit_check() {
    $k = acgl_fms_public_submit_rate_limit_key();
    $count = (int) get_transient($k);
    // Simple anti-spam throttle: 30 submissions per hour per IP.
    return $count < 30;
}

function acgl_fms_public_submit_rate_limit_bump() {
    $k = acgl_fms_public_submit_rate_limit_key();
    $count = (int) get_transient($k);
    $count++;
    set_transient($k, $count, 60 * 60);
}

function acgl_fms_public_sum_items($items) {
    $sumEur = 0.0;
    $sumUsd = 0.0;
    $hasEur = false;
    $hasUsd = false;
    if (!is_array($items)) return [ 'ok' => false, 'error' => 'invalid_items' ];
    foreach ($items as $it) {
        if (!is_array($it)) continue;
        if (isset($it['euro']) && $it['euro'] !== null && $it['euro'] !== '') {
            $hasEur = true;
            $sumEur += (float) $it['euro'];
        }
        if (isset($it['usd']) && $it['usd'] !== null && $it['usd'] !== '') {
            $hasUsd = true;
            $sumUsd += (float) $it['usd'];
        }
    }
    if ($hasEur && $hasUsd) return [ 'ok' => false, 'error' => 'mixed_currency' ];
    if (!$hasEur && !$hasUsd) return [ 'ok' => false, 'error' => 'missing_currency' ];
    return [
        'ok' => true,
        'mode' => $hasEur ? 'EUR' : 'USD',
        'euro' => $hasEur ? round($sumEur, 2) : null,
        'usd' => $hasUsd ? round($sumUsd, 2) : null,
    ];
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

function acgl_fms_find_po_folder_for_order($year, $orderId) {
    $y = acgl_fms_sanitize_year_folder((string) $year);
    $oid = is_string($orderId) ? trim($orderId) : '';
    if ($y === '' || $oid === '') return '';

    // Orders are stored under keys like payment_orders_2026_v1.
    $raw = acgl_fms_kv_get_raw('payment_orders_' . $y . '_v1');
    if (!is_string($raw) || trim($raw) === '') return '';

    $decoded = json_decode($raw, true);
    if (!is_array($decoded)) return '';

    $poRaw = '';
    foreach ($decoded as $o) {
        if (!is_array($o)) continue;
        $id = isset($o['id']) ? (string) $o['id'] : '';
        $id = trim($id);
        if ($id === '' || $id !== $oid) continue;
        $poRaw = isset($o['paymentOrderNo']) ? (string) $o['paymentOrderNo'] : '';
        break;
    }

    $poRaw = trim((string) $poRaw);
    if ($poRaw === '') return '';

    $title = acgl_fms_format_payment_order_title($poRaw, '');
    return acgl_fms_sanitize_po_folder($title);
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

function acgl_fms_orders_year_from_kv_key($key) {
    $k = is_string($key) ? trim($key) : '';
    if ($k === '') return null;
    if (preg_match('/^payment_orders_(\d{4})_v1$/', $k, $m)) {
        return (string) $m[1];
    }
    return null;
}

function acgl_fms_format_payment_order_title($paymentOrderNo, $fallbackId = '') {
    $raw = is_string($paymentOrderNo) ? trim($paymentOrderNo) : '';
    if ($raw === '') {
        $id = is_string($fallbackId) ? trim($fallbackId) : '';
        return $id !== '' ? $id : 'Payment Order';
    }

    // Match the app's display normalization: "PO 26-01" etc.
    if (preg_match('/^PO(?:\s+|-)?(\d{2})-(\d+)$/i', $raw, $m)) {
        $seq = (int) $m[2];
        $seqText = $seq < 100 ? str_pad((string) $seq, 2, '0', STR_PAD_LEFT) : (string) $seq;
        return 'PO ' . $m[1] . '-' . $seqText;
    }

    // Normalize "PO-" to "PO ".
    $normalized = preg_replace('/^PO-\s*/i', 'PO ', $raw);
    $normalized = preg_replace('/^PO\s+/i', 'PO ', $normalized);
    return trim((string) $normalized);
}

function acgl_fms_docs_find_existing_attachment_id($kind, $year, $orderId = null) {
    $kind = is_string($kind) ? trim($kind) : '';
    $year = is_string($year) ? trim($year) : '';
    if ($kind === '' || $year === '') return 0;

    $meta = [
        [ 'key' => 'acgl_fms_doc_kind', 'value' => $kind, 'compare' => '=' ],
        [ 'key' => 'acgl_fms_year', 'value' => $year, 'compare' => '=' ],
    ];
    if ($orderId !== null) {
        $oid = is_string($orderId) ? trim($orderId) : '';
        if ($oid !== '') {
            $meta[] = [ 'key' => 'acgl_fms_order_id', 'value' => $oid, 'compare' => '=' ];
        }
    }

    $ids = get_posts([
        'post_type' => 'attachment',
        'post_status' => 'inherit',
        'posts_per_page' => 1,
        'fields' => 'ids',
        'meta_query' => $meta,
    ]);

    if (is_array($ids) && count($ids) > 0) {
        $id = (int) $ids[0];
        return $id > 0 ? $id : 0;
    }
    return 0;
}

function acgl_fms_docs_write_json_attachment($kind, $year, $title, $subdir, $filename, $payload, $orderId = null) {
    $kind = is_string($kind) ? trim($kind) : '';
    $year = acgl_fms_sanitize_year_folder((string) $year);
    $title = is_string($title) ? trim($title) : '';
    $subdir = is_string($subdir) ? trim($subdir) : '';
    $filename = is_string($filename) ? trim($filename) : '';
    if ($kind === '' || $year === '' || $title === '' || $subdir === '' || $filename === '') return 0;

    $uploads = wp_upload_dir(null, false);
    $basedir = is_array($uploads) ? (string) ($uploads['basedir'] ?? '') : '';
    $baseurl = is_array($uploads) ? (string) ($uploads['baseurl'] ?? '') : '';
    if ($basedir === '' || $baseurl === '') return 0;

    $sub = '/' . ltrim($subdir, '/');
    $sub = rtrim($sub, '/');
    $relative = ltrim($sub, '/') . '/' . $filename;
    $fullPath = rtrim($basedir, '/\\') . $sub . '/' . $filename;
    $fullDir = dirname($fullPath);
    if (!wp_mkdir_p($fullDir)) return 0;

    $json = wp_json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
    if (!is_string($json)) $json = '';
    $written = @file_put_contents($fullPath, $json);
    if ($written === false) return 0;

    $existingId = acgl_fms_docs_find_existing_attachment_id($kind, $year, $orderId);

    $attachmentPost = [
        'post_mime_type' => 'application/json',
        'post_title' => sanitize_text_field($title),
        'post_content' => '',
        'post_status' => 'inherit',
    ];

    $attachId = 0;
    if ($existingId > 0) {
        $attachId = $existingId;
        $attachmentPost['ID'] = $attachId;
        wp_update_post($attachmentPost);
        update_attached_file($attachId, $fullPath);
    } else {
        $attachId = wp_insert_attachment($attachmentPost, $fullPath);
        if (!$attachId || is_wp_error($attachId)) return 0;
    }

    // Ensure the URL and file are stable.
    $guid = rtrim($baseurl, '/') . $sub . '/' . rawurlencode($filename);
    wp_update_post([ 'ID' => $attachId, 'guid' => $guid ]);

    update_post_meta($attachId, 'acgl_fms_doc_kind', $kind);
    update_post_meta($attachId, 'acgl_fms_year', $year);
    if ($orderId !== null) {
        $oid = is_string($orderId) ? trim($orderId) : '';
        if ($oid !== '') update_post_meta($attachId, 'acgl_fms_order_id', $oid);
    }

    return (int) $attachId;
}

function acgl_fms_docs_sync_for_orders_year($year, $ordersJson) {
    $y = acgl_fms_sanitize_year_folder((string) $year);
    if ($y === '') return;
    if (!is_string($ordersJson) || trim($ordersJson) === '') return;

    $decoded = json_decode($ordersJson, true);
    if (!is_array($decoded)) return;

    // Build a stable list of orders.
    $orders = [];
    foreach ($decoded as $o) {
        if (!is_array($o)) continue;
        $id = isset($o['id']) ? (string) $o['id'] : '';
        $id = trim($id);
        if ($id === '') continue;
        $orders[] = $o;
    }

    // 1) Budget year file (index)
    acgl_fms_docs_write_json_attachment(
        'budget_year',
        $y,
        $y . ' Payment Orders',
        '/acgl-fms/' . $y,
        'payment-orders-' . $y . '.json',
        [
            'generatedAt' => gmdate('c'),
            'year' => $y,
            'orders' => $orders,
        ]
    );

    // 2) Per-order files
    $seenIds = [];
    foreach ($orders as $o) {
        $id = (string) ($o['id'] ?? '');
        $id = trim($id);
        if ($id === '') continue;
        $seenIds[$id] = true;

        $poNo = isset($o['paymentOrderNo']) ? (string) $o['paymentOrderNo'] : '';
        $title = acgl_fms_format_payment_order_title($poNo, $id);
        $fileBase = acgl_fms_sanitize_po_folder($title);
        if ($fileBase === '') {
            $fileBase = preg_replace('/[^A-Za-z0-9\-_.]/', '', $id);
            if ($fileBase === '') $fileBase = 'order';
        }

        acgl_fms_docs_write_json_attachment(
            'payment_order',
            $y,
            $title,
            '/acgl-fms/' . $y . '/payment-orders',
            $fileBase . '.json',
            [
                'generatedAt' => gmdate('c'),
                'year' => $y,
                'title' => $title,
                'order' => $o,
            ],
            $id
        );
    }

    // 3) Cleanup: delete per-order docs that no longer exist.
    $existingDocIds = get_posts([
        'post_type' => 'attachment',
        'post_status' => 'inherit',
        'posts_per_page' => -1,
        'fields' => 'ids',
        'meta_query' => [
            [ 'key' => 'acgl_fms_doc_kind', 'value' => 'payment_order', 'compare' => '=' ],
            [ 'key' => 'acgl_fms_year', 'value' => $y, 'compare' => '=' ],
        ],
    ]);

    if (is_array($existingDocIds) && count($existingDocIds) > 0) {
        foreach ($existingDocIds as $aid) {
            $aid = (int) $aid;
            if ($aid <= 0) continue;
            $oid = (string) get_post_meta($aid, 'acgl_fms_order_id', true);
            $oid = trim($oid);
            if ($oid !== '' && !isset($seenIds[$oid])) {
                // Deletes both the attachment and the underlying file.
                wp_delete_attachment($aid, true);
            }
        }
    }
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

    // Public (unauthenticated) helper: return only the computed next Payment Order No.
    // This avoids exposing orders/users data, but allows the request form to display
    // the correct next number even before the user signs into the app.
    register_rest_route('acgl-fms/v1', '/public/next-po', [
        'methods' => 'GET',
        'permission_callback' => '__return_true',
        'callback' => function (WP_REST_Request $request) {
            // Ensure KV storage exists even if activation hook didn't run.
            if (function_exists('acgl_fms_db_ensure_installed')) {
                try {
                    acgl_fms_db_ensure_installed();
                } catch (Throwable $e) {
                    return new WP_REST_Response([ 'ok' => false, 'error' => 'server_error', 'message' => $e->getMessage() ], 500);
                }
            }

            $yearParam = $request->get_param('year');
            $year = is_string($yearParam) ? trim($yearParam) : '';

            if ($year === '') {
                // Try active budget year from KV (safe to reveal).
                $activeRaw = acgl_fms_kv_get_raw('payment_order_active_budget_year_v1');
                $active = is_string($activeRaw) ? trim($activeRaw) : '';
                if (preg_match('/^\d{4}$/', $active)) $year = $active;
            }

            if ($year === '' || !preg_match('/^\d{4}$/', $year)) {
                $fallback = (string) (int) gmdate('Y');
                $year = preg_match('/^\d{4}$/', $fallback) ? $fallback : '2000';
            }

            $year2 = acgl_fms_public_year2_from_budget_year($year);
            if ($year2 === null) return new WP_REST_Response([ 'ok' => false, 'error' => 'invalid_year' ], 400);

            // Next sequence from orders in this budget year.
            $ordersKey = 'payment_orders_' . $year . '_v1';
            $ordersRaw = acgl_fms_kv_get_raw($ordersKey);
            $nextFromOrders = acgl_fms_public_infer_next_seq_from_orders_json($ordersRaw, $year2);

            // Next sequence from stored numbering settings.
            $numRaw = acgl_fms_kv_get_raw('payment_order_numbering');
            $num = is_string($numRaw) ? json_decode($numRaw, true) : null;
            $storedYear2 = is_array($num) && isset($num['year2']) ? (string) $num['year2'] : '';
            $storedYear2 = preg_match('/^\d{2}$/', trim($storedYear2)) ? trim($storedYear2) : $year2;
            $storedNextSeq = is_array($num) && isset($num['nextSeq']) ? (int) $num['nextSeq'] : 1;
            if ($storedNextSeq < 1) $storedNextSeq = 1;

            // Mirror app behavior: if stored year2 doesn't match this budget year, ignore stored nextSeq.
            $nextSeq = ($storedYear2 === $year2) ? max($storedNextSeq, $nextFromOrders) : $nextFromOrders;
            $po = acgl_fms_public_format_po_no($year2, $nextSeq);

            return [
                'ok' => true,
                'year' => $year,
                'year2' => $year2,
                'nextSeq' => $nextSeq,
                'paymentOrderNo' => $po,
            ];
        },
    ]);

    // Admin helper: trigger an immediate Google Drive backup upload (service account).
    // Requires WP write capability (server-side cron jobs run without a user).
    register_rest_route('acgl-fms/v1', '/admin/gdrive-backup/run', [
        'methods' => 'POST',
        'permission_callback' => function () {
            return acgl_fms_authorize_settings_write();
        },
        'callback' => function (WP_REST_Request $request) {
            if (!function_exists('acgl_fms_gdrive_run_backup_upload')) {
                return new WP_REST_Response([ 'ok' => false, 'error' => 'not_available' ], 500);
            }

            // Ensure KV exists.
            if (function_exists('acgl_fms_db_ensure_installed')) {
                try {
                    acgl_fms_db_ensure_installed();
                } catch (Throwable $e) {
                    return new WP_REST_Response([ 'ok' => false, 'error' => 'server_error', 'message' => $e->getMessage() ], 500);
                }
            }

            $res = acgl_fms_gdrive_run_backup_upload('manual');
            if (!is_array($res)) {
                return new WP_REST_Response([ 'ok' => false, 'error' => 'server_error' ], 500);
            }
            return $res;
        },
    ]);

    // Admin helper: list recent Google Drive backup files in the configured folder.
    register_rest_route('acgl-fms/v1', '/admin/gdrive-backup/list', [
        'methods' => 'GET',
        'permission_callback' => function () {
            return acgl_fms_authorize_settings_write();
        },
        'callback' => function (WP_REST_Request $request) {
            if (!function_exists('acgl_fms_gdrive_list_backups')) {
                return new WP_REST_Response([ 'ok' => false, 'error' => 'not_available' ], 500);
            }

            $n = (int) $request->get_param('n');
            if ($n < 1) $n = 20;

            $res = acgl_fms_gdrive_list_backups($n);
            if (!is_array($res)) {
                return new WP_REST_Response([ 'ok' => false, 'error' => 'server_error' ], 500);
            }
            return $res;
        },
    ]);

    // Admin helper: fetch a specific Drive backup JSON by file id.
    register_rest_route('acgl-fms/v1', '/admin/gdrive-backup/file', [
        'methods' => 'GET',
        'permission_callback' => function () {
            return acgl_fms_authorize_settings_write();
        },
        'callback' => function (WP_REST_Request $request) {
            if (!function_exists('acgl_fms_gdrive_get_backup_payload_by_file_id')) {
                return new WP_REST_Response([ 'ok' => false, 'error' => 'not_available' ], 500);
            }

            $id = (string) $request->get_param('id');
            if (function_exists('sanitize_text_field')) {
                $id = sanitize_text_field($id);
            }
            $id = trim($id);
            if ($id === '' || !preg_match('/^[A-Za-z0-9_\-]+$/', $id)) {
                return new WP_REST_Response([ 'ok' => false, 'error' => 'invalid_id' ], 400);
            }

            $res = acgl_fms_gdrive_get_backup_payload_by_file_id($id);
            if (!is_array($res)) {
                return new WP_REST_Response([ 'ok' => false, 'error' => 'server_error' ], 500);
            }
            return $res;
        },
    ]);

    // Admin helper: get email notification settings.
    register_rest_route('acgl-fms/v1', '/admin/notifications-settings', [
        [
            'methods' => 'GET',
            'permission_callback' => function () {
                return acgl_fms_authorize_settings_notifications(false);
            },
            'callback' => function () {
                if (!function_exists('acgl_fms_admin_get_notification_settings')) {
                    return new WP_REST_Response([ 'ok' => false, 'error' => 'not_available' ], 500);
                }
                $settings = acgl_fms_admin_get_notification_settings();
                if (!is_array($settings)) {
                    return new WP_REST_Response([ 'ok' => false, 'error' => 'server_error' ], 500);
                }
                return [
                    'ok' => true,
                    'settings' => $settings,
                ];
            },
        ],
        [
            'methods' => 'POST',
            'permission_callback' => function () {
                return acgl_fms_authorize_settings_notifications(true);
            },
            'callback' => function (WP_REST_Request $request) {
                if (!function_exists('acgl_fms_admin_save_notification_settings') || !function_exists('acgl_fms_admin_get_notification_settings')) {
                    return new WP_REST_Response([ 'ok' => false, 'error' => 'not_available' ], 500);
                }

                $data = $request->get_json_params();
                if (!is_array($data)) {
                    $data = $request->get_params();
                }
                if (!is_array($data)) {
                    return new WP_REST_Response([ 'ok' => false, 'error' => 'invalid_payload' ], 400);
                }

                $res = acgl_fms_admin_save_notification_settings($data);
                if (!is_array($res) || empty($res['ok'])) {
                    return new WP_REST_Response([
                        'ok' => false,
                        'error' => isset($res['error']) ? (string) $res['error'] : 'save_failed',
                    ], 400);
                }

                $settings = acgl_fms_admin_get_notification_settings();
                return [
                    'ok' => true,
                    'settings' => is_array($settings) ? $settings : [],
                ];
            },
        ],
    ]);

    // Admin helper: send a test notification email without saving settings.
    register_rest_route('acgl-fms/v1', '/admin/notifications-settings/test', [
        'methods' => 'POST',
        'permission_callback' => function () {
            return acgl_fms_authorize_settings_notifications(true);
        },
        'callback' => function (WP_REST_Request $request) {
            if (!function_exists('acgl_fms_admin_get_notification_settings')) {
                return new WP_REST_Response([ 'ok' => false, 'error' => 'not_available' ], 500);
            }

            $saved = acgl_fms_admin_get_notification_settings();
            if (!is_array($saved)) {
                return new WP_REST_Response([ 'ok' => false, 'error' => 'server_error' ], 500);
            }

            $data = $request->get_json_params();
            if (!is_array($data)) {
                $data = $request->get_params();
            }
            $settingsOverride = is_array($data) && isset($data['settings']) && is_array($data['settings'])
                ? $data['settings']
                : [];
            $typeId = is_array($data) ? trim((string) ($data['type'] ?? 'new_payment_order')) : 'new_payment_order';
            if ($typeId === '') $typeId = 'new_payment_order';

            $settings = acgl_fms_notifications_normalize_runtime_settings($saved, $settingsOverride);
            $typeConfig = acgl_fms_notifications_get_type_config($settings, $typeId);
            if (!is_array($typeConfig)) {
                return new WP_REST_Response([ 'ok' => false, 'error' => 'event_unknown' ], 400);
            }

            $forcedTo = is_array($data) ? (string) ($data['to'] ?? '') : '';
            $typeRecipMode = trim((string) ($typeConfig['recipients_mode'] ?? ''));
            $typeManualTo = trim((string) ($typeConfig['manual_to'] ?? ''));
            $effectiveSettingsForTest = $settings;
            if ($typeRecipMode !== '') {
                $effectiveSettingsForTest['recipients_mode'] = $typeRecipMode;
                $effectiveSettingsForTest['manual_to'] = $typeManualTo;
            }
            $to = acgl_fms_notifications_resolve_recipients($effectiveSettingsForTest, $forcedTo);
            if (count($to) === 0) {
                return new WP_REST_Response([ 'ok' => false, 'error' => 'no_recipients' ], 400);
            }

            $vars = [
                'paymentOrderNo' => 'PO 00-00',
                'year' => (string) gmdate('Y'),
                'createdAt' => gmdate('c'),
                'id' => 'test-' . (string) wp_rand(100000, 999999),
                'paymentOrderLink' => acgl_fms_notifications_build_order_link((string) gmdate('Y'), 'test-' . (string) wp_rand(100000, 999999)),
                'user' => function_exists('wp_get_current_user') ? (string) (wp_get_current_user()->user_login ?? '') : '',
                'date' => gmdate('Y-m-d'),
                'description' => 'Test description',
                'amount' => '123.45',
                'party' => 'Test party',
                'moneyTransferNo' => 'MT 00-00',
                'comments' => 'Test comments',
                'directLink' => 'https://example.org/fms',
                'refNo' => '12345',
                'subject' => 'Test subject',
                'priority' => 'normal',
                'createdBy' => function_exists('wp_get_current_user') ? (string) (wp_get_current_user()->user_login ?? '') : '',
            ];

            $subjectTpl = trim((string) ($typeConfig['subject'] ?? ''));
            if ($subjectTpl === '') $subjectTpl = '[ACGL FMS] Test Email {{id}}';
            $bodyTpl = trim((string) ($typeConfig['body'] ?? ''));
            if ($bodyTpl === '') $bodyTpl = 'This is a test email from ACGL FMS.';
            $signature = trim((string) ($settings['signature'] ?? ''));

            $subject = acgl_fms_notifications_apply_placeholders($subjectTpl, $vars);
            $body = acgl_fms_notifications_build_body_html($bodyTpl, $vars, $signature);

            $headers = [ 'Content-Type: text/html; charset=UTF-8' ];
            $replyTo = trim((string) ($settings['reply_to'] ?? ''));
            if ($replyTo !== '' && acgl_fms_notifications_is_valid_email($replyTo)) {
                $headers[] = 'Reply-To: ' . $replyTo;
            }

            $ok = wp_mail($to, $subject, $body, $headers);
            if (!$ok) {
                return new WP_REST_Response([ 'ok' => false, 'error' => 'mail_send_failed' ], 500);
            }

            return [
                'ok' => true,
                'sent' => count($to),
                'to' => $to,
                'subject' => $subject,
                'type' => $typeId,
            ];
        },
    ]);

    // Admin helper: send a configured notification event by type.
    register_rest_route('acgl-fms/v1', '/admin/notifications-send-event', [
        'methods' => 'POST',
        'permission_callback' => function () {
            return acgl_fms_authorize_settings_notifications(true);
        },
        'callback' => function (WP_REST_Request $request) {
            if (!function_exists('acgl_fms_admin_get_notification_settings')) {
                return new WP_REST_Response([ 'ok' => false, 'error' => 'not_available' ], 500);
            }

            $saved = acgl_fms_admin_get_notification_settings();
            if (!is_array($saved)) {
                return new WP_REST_Response([ 'ok' => false, 'error' => 'server_error' ], 500);
            }

            $data = $request->get_json_params();
            if (!is_array($data)) {
                $data = $request->get_params();
            }
            if (!is_array($data)) {
                return new WP_REST_Response([ 'ok' => false, 'error' => 'invalid_payload' ], 400);
            }

            $typeId = isset($data['type']) ? trim((string) $data['type']) : '';
            if ($typeId === '') {
                return new WP_REST_Response([ 'ok' => false, 'error' => 'missing_type' ], 400);
            }

            $settings = acgl_fms_notifications_normalize_runtime_settings($saved, []);
            $typeConfig = acgl_fms_notifications_get_type_config($settings, $typeId);
            if (!is_array($typeConfig)) {
                return new WP_REST_Response([ 'ok' => false, 'error' => 'event_unknown' ], 400);
            }
            if ((string) ($typeConfig['enabled'] ?? '0') !== '1') {
                return new WP_REST_Response([ 'ok' => false, 'error' => 'event_disabled' ], 400);
            }

            $typeRecipMode = trim((string) ($typeConfig['recipients_mode'] ?? ''));
            $typeManualTo = trim((string) ($typeConfig['manual_to'] ?? ''));
            $effectiveSettings = $settings;
            if ($typeRecipMode !== '') {
                $effectiveSettings['recipients_mode'] = $typeRecipMode;
                $effectiveSettings['manual_to'] = $typeManualTo;
            }
            $to = acgl_fms_notifications_resolve_recipients($effectiveSettings, '');
            if (count($to) === 0) {
                return new WP_REST_Response([ 'ok' => false, 'error' => 'no_recipients' ], 400);
            }

            $vars = isset($data['vars']) && is_array($data['vars']) ? $data['vars'] : [];
            $subjectTpl = trim((string) ($typeConfig['subject'] ?? ''));
            $bodyTpl = trim((string) ($typeConfig['body'] ?? ''));
            if ($subjectTpl === '') {
                $subjectTpl = '[ACGL FMS] Notification';
            }
            if ($bodyTpl === '') {
                $bodyTpl = 'This is a notification from ACGL FMS.';
            }

            $subject = acgl_fms_notifications_apply_placeholders($subjectTpl, $vars);
            $signature = trim((string) ($settings['signature'] ?? ''));
            $body = acgl_fms_notifications_build_body_html($bodyTpl, $vars, $signature);

            $headers = [ 'Content-Type: text/html; charset=UTF-8' ];
            $replyTo = trim((string) ($settings['reply_to'] ?? ''));
            if ($replyTo !== '' && acgl_fms_notifications_is_valid_email($replyTo)) {
                $headers[] = 'Reply-To: ' . $replyTo;
            }

            $ok = wp_mail($to, $subject, $body, $headers);
            if (!$ok) {
                return new WP_REST_Response([ 'ok' => false, 'error' => 'mail_send_failed' ], 500);
            }

            return [
                'ok' => true,
                'sent' => count($to),
                'to' => $to,
                'subject' => $subject,
                'type' => $typeId,
            ];
        },
    ]);

    // Public (unauthenticated) submission endpoint: persist a new Payment Order.
    // Used when the app is embedded in WP shared mode and the viewer has not signed in yet.
    register_rest_route('acgl-fms/v1', '/public/submit-po', [
        'methods' => 'POST',
        'permission_callback' => '__return_true',
        'callback' => function (WP_REST_Request $request) {
            try {
                // Ensure KV storage exists even if activation hook didn't run.
                if (function_exists('acgl_fms_db_ensure_installed')) {
                    acgl_fms_db_ensure_installed();
                }

                if (!acgl_fms_public_submit_rate_limit_check()) {
                    return new WP_REST_Response([ 'ok' => false, 'error' => 'rate_limited' ], 429);
                }
                $body = $request->get_json_params();
                if (!is_array($body)) {
                    return new WP_REST_Response([ 'ok' => false, 'error' => 'invalid_json' ], 400);
                }
                $year = isset($body['year']) ? trim((string) $body['year']) : '';
                if ($year === '' || !preg_match('/^\d{4}$/', $year)) {
                    // Default to current year if missing.
                    $year = (string) (int) gmdate('Y');
                }
                $year2 = acgl_fms_public_year2_from_budget_year($year);
                if ($year2 === null) {
                    return new WP_REST_Response([ 'ok' => false, 'error' => 'invalid_year' ], 400);
                }
                $values = isset($body['values']) && is_array($body['values']) ? $body['values'] : [];
                $items = isset($body['items']) ? $body['items'] : [];
                // Basic required fields. (Keep aligned with the JS form.)
                $requiredKeys = [ 'date', 'name', 'address', 'purpose' ];
                foreach ($requiredKeys as $k) {
                    $v = isset($values[$k]) ? trim((string) $values[$k]) : '';
                    if ($v === '') {
                        return new WP_REST_Response([ 'ok' => false, 'error' => 'missing_required', 'field' => $k ], 400);
                    }
                }
                $sum = acgl_fms_public_sum_items($items);
                if (!is_array($sum) || !($sum['ok'] ?? false)) {
                    $err = is_array($sum) && isset($sum['error']) ? (string) $sum['error'] : 'invalid_items';
                    return new WP_REST_Response([ 'ok' => false, 'error' => $err ], 400);
                }
                // Compute the next PO number and ensure uniqueness.
                $ordersKey = 'payment_orders_' . $year . '_v1';
                $ordersRaw = acgl_fms_kv_get_raw($ordersKey);
                $orders = [];
                if (is_string($ordersRaw) && trim($ordersRaw) !== '') {
                    $parsed = json_decode($ordersRaw, true);
                    if (is_array($parsed)) $orders = $parsed;
                }
                $nextFromOrders = acgl_fms_public_infer_next_seq_from_orders_json($ordersRaw, $year2);
                $numRaw = acgl_fms_kv_get_raw('payment_order_numbering');
                $num = is_string($numRaw) ? json_decode($numRaw, true) : null;
                $storedYear2 = is_array($num) && isset($num['year2']) ? (string) $num['year2'] : '';
                $storedYear2 = preg_match('/^\d{2}$/', trim($storedYear2)) ? trim($storedYear2) : $year2;
                $storedNextSeq = is_array($num) && isset($num['nextSeq']) ? (int) $num['nextSeq'] : 1;
                if ($storedNextSeq < 1) $storedNextSeq = 1;
                $nextSeq = ($storedYear2 === $year2) ? max($storedNextSeq, $nextFromOrders) : $nextFromOrders;
                $po = acgl_fms_public_format_po_no($year2, $nextSeq);
                if ($po === null) return new WP_REST_Response([ 'ok' => false, 'error' => 'format_failed' ], 500);
                // Ensure uniqueness (in case of concurrent submissions).
                $canon = strtolower(preg_replace('/[^a-z0-9]/', '', $po));
                $existingCanon = [];
                foreach ($orders as $o) {
                    if (!is_array($o)) continue;
                    $raw = isset($o['paymentOrderNo']) ? (string) $o['paymentOrderNo'] : '';
                    $c = strtolower(preg_replace('/[^a-z0-9]/', '', $raw));
                    if ($c !== '') $existingCanon[$c] = true;
                }
                $guard = 0;
                while (isset($existingCanon[$canon]) && $guard < 10) {
                    $nextSeq++;
                    $po2 = acgl_fms_public_format_po_no($year2, $nextSeq);
                    if ($po2 === null) break;
                    $po = $po2;
                    $canon = strtolower(preg_replace('/[^a-z0-9]/', '', $po));
                    $guard++;
                }
                if (isset($existingCanon[$canon])) {
                    return new WP_REST_Response([ 'ok' => false, 'error' => 'po_conflict' ], 409);
                }
                $now = gmdate('c');
                $id = function_exists('wp_generate_uuid4') ? wp_generate_uuid4() : ('po_' . time() . '_' . wp_rand(1000, 9999));
                $order = [
                    'id' => $id,
                    'createdAt' => $now,
                    'updatedAt' => $now,
                    'paymentOrderNo' => $po,
                    'date' => trim((string) ($values['date'] ?? '')),
                    'name' => trim((string) ($values['name'] ?? '')),
                    'address' => trim((string) ($values['address'] ?? '')),
                    'iban' => trim((string) ($values['iban'] ?? '')),
                    'bic' => trim((string) ($values['bic'] ?? '')),
                    'usAccountType' => trim((string) ($values['usAccountType'] ?? '')),
                    'specialInstructions' => trim((string) ($values['specialInstructions'] ?? '')),
                    'bankDetailsMode' => trim((string) ($values['bankDetailsMode'] ?? '')),
                    'budgetNumber' => trim((string) ($values['budgetNumber'] ?? '')),
                    'purpose' => trim((string) ($values['purpose'] ?? '')),
                    'euro' => $sum['euro'],
                    'usd' => $sum['usd'],
                    'items' => is_array($items) ? array_values($items) : [],
                    // Default status fields; UI can normalize/display.
                    'status' => 'Submitted',
                    'with' => '',
                ];
                // Save newest first
                array_unshift($orders, $order);
                acgl_fms_kv_set_raw($ordersKey, wp_json_encode($orders));
                // Increment numbering for next time.
                acgl_fms_kv_set_raw('payment_order_numbering', wp_json_encode([ 'year2' => $year2, 'nextSeq' => $nextSeq + 1 ]));
                // Bump rate limit after successful persistence.
                acgl_fms_public_submit_rate_limit_bump();

                // Best-effort submit notification. Do not fail order creation if mail fails.
                try {
                    acgl_fms_notifications_send_public_submit($year, $order);
                } catch (Throwable $mailErr) {
                    // ignore
                }

                return [ 'ok' => true, 'year' => $year, 'paymentOrderNo' => $po, 'id' => $id ];
            } catch (Throwable $e) {
                return new WP_REST_Response([ 'ok' => false, 'error' => 'server_error', 'message' => $e->getMessage() ], 500);
            }
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

                // Auto-create a Budget Year file and per-Order files in the Media Library.
                // Triggered when the app saves the per-year Payment Orders dataset.
                $ordersYear = acgl_fms_orders_year_from_kv_key($key);
                if ($ordersYear && is_string($value)) {
                    try {
                        acgl_fms_docs_sync_for_orders_year($ordersYear, $value);
                    } catch (Throwable $e) {
                        // Ignore doc-generation errors so KV save still succeeds.
                    }
                }

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

            // If the client doesn't send paymentOrderNo, try deriving it from the saved orders.
            // This keeps uploads consistently grouped under the Payment Order folder.
            if ($po === '' && $orderId !== '' && $year !== '') {
                $derived = acgl_fms_find_po_folder_for_order($year, $orderId);
                if ($derived !== '') $po = $derived;
            }

            // Enforce folder naming by Payment Order No.
            if ($po === '') {
                return new WP_REST_Response([
                    'error' => 'missing_payment_order_no',
                    'message' => 'Payment Order No. is required before uploading documents.'
                ], 400);
            }

            $fileParams = $request->get_file_params();
            $file = is_array($fileParams) && isset($fileParams['file']) ? $fileParams['file'] : null;
            if (!is_array($file) || !isset($file['tmp_name'])) {
                return new WP_REST_Response([ 'error' => 'missing_file' ], 400);
            }

            // Determine upload subdir: /acgl-fms/<year>/<paymentOrderNo>
            $bucket = $po;
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

            // NOTE: wp_upload_dir() caches results per request. If anything has called it
            // earlier in the request (before we add this filter), wp_handle_upload() may
            // reuse the cached default path and ignore our custom subdir. Force-refresh the
            // cache while the filter is active.
            add_filter('upload_dir', $filter, 999);
            try {
                $dirs = wp_upload_dir(null, false, true);
                if (is_array($dirs)) {
                    $p = (string) ($dirs['path'] ?? '');
                    if ($p !== '') {
                        // Ensure nested folders like /uploads/acgl-fms/<year>/<bucket>/ exist.
                        wp_mkdir_p($p);
                    }
                }
                $overrides = [ 'test_form' => false ];
                $upload = wp_handle_upload($file, $overrides);
            } finally {
                remove_filter('upload_dir', $filter, 999);
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

    register_rest_route('acgl-fms/v1', '/backlog-attachments/upload', [
        'methods' => 'POST',
        'permission_callback' => function (WP_REST_Request $request) {
            return acgl_fms_authorize_backlog_attachments(true);
        },
        'callback' => function (WP_REST_Request $request) {
            $itemId = (string) $request->get_param('itemId');
            $itemId = trim($itemId);
            if ($itemId !== '') {
                $itemId = preg_replace('/[^A-Za-z0-9\-_.]/', '', $itemId);
            }
            if ($itemId === '') {
                return new WP_REST_Response([ 'error' => 'missing_item_id' ], 400);
            }

            $fileParams = $request->get_file_params();
            $file = is_array($fileParams) && isset($fileParams['file']) ? $fileParams['file'] : null;
            if (!is_array($file) || !isset($file['tmp_name'])) {
                return new WP_REST_Response([ 'error' => 'missing_file' ], 400);
            }

            // Upload subdir: /acgl-fms/backlog/<itemId>
            $subdir = '/acgl-fms/backlog/' . $itemId;

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

            add_filter('upload_dir', $filter, 999);
            try {
                $dirs = wp_upload_dir(null, false, true);
                if (is_array($dirs)) {
                    $p = (string) ($dirs['path'] ?? '');
                    if ($p !== '') {
                        wp_mkdir_p($p);
                    }
                }
                $overrides = [ 'test_form' => false ];
                $upload = wp_handle_upload($file, $overrides);
            } finally {
                remove_filter('upload_dir', $filter, 999);
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

            $targetKey = 'backlog:' . $itemId;
            update_post_meta($attachId, 'acgl_fms_target_key', $targetKey);
            update_post_meta($attachId, 'acgl_fms_backlog_id', $itemId);

            $payload = acgl_fms_attachment_to_payload($attachId);
            if (!$payload) {
                return new WP_REST_Response([ 'error' => 'insert_failed' ], 500);
            }

            if ($payload['url'] === '' && $fileUrl !== '') $payload['url'] = $fileUrl;

            return [ 'ok' => true, 'item' => $payload ];
        },
    ]);
}
