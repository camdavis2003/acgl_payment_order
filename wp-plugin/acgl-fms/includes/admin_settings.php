<?php

if (!defined('ABSPATH')) {
    exit;
}

define('ACGL_FMS_GDRIVE_FOLDER_OPTION', 'acgl_fms_gdrive_folder_id_v1');
define('ACGL_FMS_GDRIVE_JSON_OPTION', 'acgl_fms_gdrive_service_account_json_v1');
define('ACGL_FMS_NOTIFY_ENABLED_OPTION', 'acgl_fms_notify_enabled_v1');
define('ACGL_FMS_NOTIFY_ON_PUBLIC_SUBMIT_OPTION', 'acgl_fms_notify_on_public_submit_v1');
define('ACGL_FMS_NOTIFY_RECIPIENTS_MODE_OPTION', 'acgl_fms_notify_recipients_mode_v1');
define('ACGL_FMS_NOTIFY_MANUAL_TO_OPTION', 'acgl_fms_notify_manual_to_v1');
define('ACGL_FMS_NOTIFY_REPLY_TO_OPTION', 'acgl_fms_notify_reply_to_v1');
define('ACGL_FMS_NOTIFY_REPLY_TO_CLEARED_OPTION', 'acgl_fms_notify_reply_to_cleared_v1');
define('ACGL_FMS_NOTIFY_SUBJECT_OPTION', 'acgl_fms_notify_subject_v1');
define('ACGL_FMS_NOTIFY_BODY_OPTION', 'acgl_fms_notify_body_v1');
define('ACGL_FMS_NOTIFY_SIGNATURE_OPTION', 'acgl_fms_notify_signature_v1');
define('ACGL_FMS_NOTIFY_INSTANCES_OPTION', 'acgl_fms_notify_instances_v1');
define('ACGL_FMS_NOTIFY_TYPES_CONFIG_OPTION', 'acgl_fms_notify_types_config_v1');
define('ACGL_FMS_NOTIFY_ACTIVE_TYPES_OPTION', 'acgl_fms_notify_active_type_ids_v1');

function acgl_fms_admin_notification_type_defaults() {
    return [
        'new_payment_order' => [
            'enabled' => '1',
            'subject' => '[ACGL FMS] New Payment Order {{paymentOrderNo}}',
            'body' => "A new payment order has been submitted.\n\nPayment Order: {{paymentOrderNo}}\nYear: {{year}}\nCreated: {{createdAt}}\nID: {{id}}\nLink: {{paymentOrderLink}}",
        ],
        'gs_review' => [
            'enabled' => '1',
            'subject' => '[ACGL FMS] Payment Order Awaiting Grand Secretary Review',
            'body' => "Payment Order {{paymentOrderNo}} is awaiting Grand Secretary review.\n\nPayment Order: {{paymentOrderNo}}\nYear: {{year}}\nLink: {{paymentOrderLink}}\nDirect link: {{directLink}}",
        ],
        'gm_review' => [
            'enabled' => '1',
            'subject' => '[ACGL FMS] Payment Order Awaiting Grand Master Review',
            'body' => "Payment Order {{paymentOrderNo}} is awaiting Grand Master review.\n\nPayment Order: {{paymentOrderNo}}\nYear: {{year}}\nLink: {{paymentOrderLink}}\nDirect link: {{directLink}}",
        ],
        'gt_processing' => [
            'enabled' => '1',
            'subject' => '[ACGL FMS] Payment Order Approved for Grand Treasurer Processing',
            'body' => "Payment Order {{paymentOrderNo}} has been approved and is ready for Grand Treasurer processing.\n\nPayment Order: {{paymentOrderNo}}\nYear: {{year}}\nLink: {{paymentOrderLink}}\nDirect link: {{directLink}}",
        ],
        'budget_update' => [
            'enabled' => '1',
            'subject' => '[ACGL FMS] Budget Updated',
            'body' => 'The budget for {{year}} has been updated by {{user}}.\nDirect link: {{directLink}}',
        ],
        'new_bank_eur' => [
            'enabled' => '1',
            'subject' => '[ACGL FMS] New BankEUR Entry',
            'body' => "A new BankEUR entry has been added.\n\nDate: {{date}}\nDescription: {{description}}\nAmount: {{amount}} EUR\nYear: {{year}}\nDirect link: {{directLink}}",
        ],
        'new_wise_eur' => [
            'enabled' => '1',
            'subject' => '[ACGL FMS] New wiseEUR Entry',
            'body' => "A new wiseEUR entry has been added.\n\nDate: {{date}}\nParty: {{party}}\nYear: {{year}}\nDirect link: {{directLink}}",
        ],
        'new_wise_usd' => [
            'enabled' => '1',
            'subject' => '[ACGL FMS] New wiseUSD Entry',
            'body' => "A new wiseUSD entry has been added.\n\nDate: {{date}}\nParty: {{party}}\nYear: {{year}}\nDirect link: {{directLink}}",
        ],
        'mt_gs_verification' => [
            'enabled' => '1',
            'subject' => '[ACGL FMS] New Money Transfer Created',
            'body' => "A new Money Transfer has been created and is awaiting GS verification.\n\nMoney Transfer No: {{moneyTransferNo}}\nDate: {{date}}\nComments: {{comments}}\nYear: {{year}}\nDirect link: {{directLink}}",
        ],
        'mt_gt_verification' => [
            'enabled' => '1',
            'subject' => '[ACGL FMS] Money Transfer GS Verified',
            'body' => "A Money Transfer has been marked as GS Verified.\n\nDate: {{date}}\nDescription: {{description}}\nYear: {{year}}\nDirect link: {{directLink}}",
        ],
        'new_backlog' => [
            'enabled' => '1',
            'subject' => '[ACGL FMS] New Backlog Item',
            'body' => "A new backlog item has been created.\n\nRef: {{refNo}}\nSubject: {{subject}}\nPriority: {{priority}}\nCreated by: {{createdBy}}\nDirect link: {{directLink}}",
        ],
    ];
}

function acgl_fms_admin_normalize_notification_type_config($typeId, $raw) {
    $defaultsMap = acgl_fms_admin_notification_type_defaults();
    $default = isset($defaultsMap[$typeId]) && is_array($defaultsMap[$typeId]) ? $defaultsMap[$typeId] : [
        'enabled' => '1',
        'subject' => '',
        'body' => '',
    ];
    $data = is_array($raw) ? $raw : [];

    $enabledRaw = isset($data['enabled']) ? (string) $data['enabled'] : (string) ($default['enabled'] ?? '1');
    $subject = isset($data['subject']) ? trim((string) $data['subject']) : '';
    $body = isset($data['body']) ? trim((string) $data['body']) : '';

    return [
        'enabled' => ($enabledRaw === '1' || $enabledRaw === 'true' || $enabledRaw === 'yes') ? '1' : '0',
        'subject' => $subject !== '' ? (string) $data['subject'] : (string) ($default['subject'] ?? ''),
        'body' => $body !== '' ? (string) $data['body'] : (string) ($default['body'] ?? ''),
        'recipients_mode' => isset($data['recipients_mode']) ? trim((string) $data['recipients_mode']) : '',
        'manual_to' => isset($data['manual_to']) ? trim((string) $data['manual_to']) : '',
    ];
}

function acgl_fms_admin_normalize_notification_types_config($rawMap) {
    $map = is_array($rawMap) ? $rawMap : [];
    $defaultsMap = acgl_fms_admin_notification_type_defaults();
    $out = [];
    foreach ($defaultsMap as $typeId => $defaultConfig) {
        $raw = isset($map[$typeId]) && is_array($map[$typeId]) ? $map[$typeId] : [];
        $out[$typeId] = acgl_fms_admin_normalize_notification_type_config($typeId, $raw);
    }
    return $out;
}

function acgl_fms_admin_sanitize_notification_instance_id($rawInstanceId) {
    $instanceId = trim((string) $rawInstanceId);
    if ($instanceId === '') return '';
    return preg_match('/^[a-z0-9._:-]+$/i', $instanceId) ? $instanceId : '';
}

function acgl_fms_admin_generate_notification_instance_id($typeId) {
    $base = strtolower(trim((string) $typeId));
    $base = preg_replace('/[^a-z0-9._:-]+/i', '_', $base);
    if (!is_string($base) || $base === '') {
        $base = 'notification';
    }

    if (function_exists('wp_generate_uuid4')) {
        $uuid = str_replace('-', '', (string) wp_generate_uuid4());
        return $base . ':' . substr($uuid, 0, 12);
    }

    return $base . ':' . str_replace('.', '', uniqid('', true));
}

function acgl_fms_admin_notification_instance_defaults($typeId, $instanceId = '') {
    $defaultsMap = acgl_fms_admin_notification_type_defaults();
    $resolvedTypeId = isset($defaultsMap[$typeId]) && is_array($defaultsMap[$typeId]) ? (string) $typeId : 'new_payment_order';
    $default = isset($defaultsMap[$resolvedTypeId]) && is_array($defaultsMap[$resolvedTypeId]) ? $defaultsMap[$resolvedTypeId] : [
        'enabled' => '1',
        'subject' => '',
        'body' => '',
    ];
    $resolvedInstanceId = acgl_fms_admin_sanitize_notification_instance_id($instanceId);
    if ($resolvedInstanceId === '') {
        $resolvedInstanceId = acgl_fms_admin_generate_notification_instance_id($resolvedTypeId);
    }

    return [
        'instance_id' => $resolvedInstanceId,
        'type_id' => $resolvedTypeId,
        'enabled' => (string) ($default['enabled'] ?? '1') === '1' ? '1' : '0',
        'subject' => (string) ($default['subject'] ?? ''),
        'body' => (string) ($default['body'] ?? ''),
        'recipients_mode' => '',
        'manual_to' => '',
    ];
}

function acgl_fms_admin_normalize_notification_instance($raw, $fallbackTypeId = 'new_payment_order', $fallbackInstanceId = '') {
    $data = is_array($raw) ? $raw : [];
    $defaultsMap = acgl_fms_admin_notification_type_defaults();
    $typeId = isset($data['type_id']) ? trim((string) $data['type_id']) : '';
    if ($typeId === '' && isset($data['type'])) {
        $typeId = trim((string) $data['type']);
    }
    if ($typeId === '' || !isset($defaultsMap[$typeId]) || !is_array($defaultsMap[$typeId])) {
        $typeId = isset($defaultsMap[$fallbackTypeId]) && is_array($defaultsMap[$fallbackTypeId]) ? (string) $fallbackTypeId : 'new_payment_order';
    }

    $instanceId = isset($data['instance_id']) ? (string) $data['instance_id'] : '';
    if ($instanceId === '' && isset($data['id'])) {
        $instanceId = (string) $data['id'];
    }
    if ($instanceId === '') {
        $instanceId = (string) $fallbackInstanceId;
    }

    $default = acgl_fms_admin_notification_instance_defaults($typeId, $instanceId);
    $enabledRaw = isset($data['enabled']) ? (string) $data['enabled'] : (string) ($default['enabled'] ?? '1');
    $subject = isset($data['subject']) ? trim((string) $data['subject']) : '';
    $body = isset($data['body']) ? trim((string) $data['body']) : '';
    $recipientsMode = isset($data['recipients_mode']) ? trim((string) $data['recipients_mode']) : '';

    if ($recipientsMode !== '') {
        $recipientsMode = acgl_fms_admin_normalize_notification_recipients_mode($recipientsMode);
    }

    return [
        'instance_id' => acgl_fms_admin_sanitize_notification_instance_id($instanceId) ?: (string) $default['instance_id'],
        'type_id' => $typeId,
        'enabled' => ($enabledRaw === '1' || $enabledRaw === 'true' || $enabledRaw === 'yes') ? '1' : '0',
        'subject' => $subject !== '' ? (string) $data['subject'] : (string) ($default['subject'] ?? ''),
        'body' => $body !== '' ? (string) $data['body'] : (string) ($default['body'] ?? ''),
        'recipients_mode' => $recipientsMode,
        'manual_to' => isset($data['manual_to']) ? trim((string) $data['manual_to']) : '',
    ];
}

function acgl_fms_admin_legacy_notification_instances_from_settings($rawSettings) {
    $settings = is_array($rawSettings) ? $rawSettings : [];
    $typesConfig = acgl_fms_admin_normalize_notification_types_config(isset($settings['types_config']) ? $settings['types_config'] : []);
    $activeTypeIds = acgl_fms_admin_normalize_notification_active_type_ids(isset($settings['active_type_ids']) ? $settings['active_type_ids'] : [], $typesConfig);

    $instances = [];
    foreach ($activeTypeIds as $typeId) {
        $typeKey = trim((string) $typeId);
        if ($typeKey === '') continue;
        $rawType = isset($typesConfig[$typeKey]) && is_array($typesConfig[$typeKey]) ? $typesConfig[$typeKey] : [];
        $instances[] = acgl_fms_admin_normalize_notification_instance(array_merge($rawType, [
            'instance_id' => $typeKey,
            'type_id' => $typeKey,
        ]), $typeKey, $typeKey);
    }

    if (count($instances) > 0) return $instances;
    return [acgl_fms_admin_notification_instance_defaults('new_payment_order', 'new_payment_order')];
}

function acgl_fms_admin_normalize_notification_instances($rawList, $legacySettings = null) {
    if (!is_array($rawList)) {
        return acgl_fms_admin_legacy_notification_instances_from_settings($legacySettings);
    }

    if (count($rawList) === 0) {
        return [];
    }

    $out = [];
    $seen = [];
    foreach (array_values($rawList) as $entry) {
        if (!is_array($entry)) continue;
        $fallbackTypeId = isset($entry['type_id']) ? (string) $entry['type_id'] : 'new_payment_order';
        $instance = acgl_fms_admin_normalize_notification_instance($entry, $fallbackTypeId);
        $instanceId = (string) ($instance['instance_id'] ?? '');
        while ($instanceId === '' || isset($seen[$instanceId])) {
            $instanceId = acgl_fms_admin_generate_notification_instance_id((string) ($instance['type_id'] ?? 'notification'));
        }
        $instance['instance_id'] = $instanceId;
        $seen[$instanceId] = true;
        $out[] = $instance;
    }

    return $out;
}

function acgl_fms_admin_notification_defaults() {
    $types = acgl_fms_admin_notification_type_defaults();
    return [
        'recipients_mode' => 'all_users_with_email',
        'manual_to' => '',
        'reply_to' => '',
        'signature' => "ACGL Financial Management System",
        'instances' => [acgl_fms_admin_notification_instance_defaults('new_payment_order', 'new_payment_order')],
        'types_config' => $types,
        'active_type_ids' => array_values(array_keys($types)),
    ];
}

function acgl_fms_admin_normalize_notification_active_type_ids($rawIds, $typesConfig) {
    $defaultsMap = is_array($typesConfig) && count($typesConfig) > 0
        ? $typesConfig
        : acgl_fms_admin_notification_type_defaults();
    $known = array_keys($defaultsMap);
    $knownSet = [];
    foreach ($known as $id) {
        $knownSet[(string) $id] = true;
    }

    $src = is_array($rawIds) ? $rawIds : [];
    $out = [];
    foreach ($src as $v) {
        $id = trim((string) $v);
        if ($id === '' || !isset($knownSet[$id]) || in_array($id, $out, true)) continue;
        $out[] = $id;
    }

    if (count($out) > 0) return $out;

    $fallback = [];
    foreach ($known as $id) {
        $cfg = isset($defaultsMap[$id]) && is_array($defaultsMap[$id]) ? $defaultsMap[$id] : [];
        if ((string) ($cfg['enabled'] ?? '0') === '1') {
            $fallback[] = (string) $id;
        }
    }
    return $fallback;
}

function acgl_fms_admin_parse_notification_emails($rawText) {
    $raw = str_replace(["\r\n", "\r", ';'], ["\n", "\n", ','], (string) $rawText);
    $parts = preg_split('/[\n,]+/', $raw);
    $emails = [];
    if (!is_array($parts)) return $emails;

    foreach ($parts as $part) {
        $email = trim((string) $part);
        if ($email === '') continue;
        $email = strtolower($email);
        if (function_exists('sanitize_email')) {
            $email = (string) sanitize_email($email);
        }
        if ($email === '') continue;
        if (function_exists('is_email') && !is_email($email)) continue;
        $emails[$email] = true;
    }

    return array_keys($emails);
}

function acgl_fms_admin_normalize_notification_recipients_mode($modeRaw) {
    $mode = trim((string) $modeRaw);
    if ($mode === 'all_users_with_email' || $mode === 'manual_list') {
        return $mode;
    }

    if (strpos($mode, 'user:') === 0) {
        $username = strtolower(trim((string) substr($mode, strlen('user:'))));
        if ($username !== '' && preg_match('/^[a-z0-9._\-]+$/', $username)) {
            return 'user:' . $username;
        }
    }

    return 'all_users_with_email';
}

function acgl_fms_admin_get_notification_settings() {
    $defaults = acgl_fms_admin_notification_defaults();

    $recipientsMode = (string) get_option(ACGL_FMS_NOTIFY_RECIPIENTS_MODE_OPTION, $defaults['recipients_mode']);
    $manualTo = (string) get_option(ACGL_FMS_NOTIFY_MANUAL_TO_OPTION, $defaults['manual_to']);
    $replyToFromDb = get_option(ACGL_FMS_NOTIFY_REPLY_TO_OPTION);
    $replyToIsDefault = ($replyToFromDb === false);
    $replyTo = $replyToIsDefault ? $defaults['reply_to'] : (string) $replyToFromDb;
    $signature = (string) get_option(ACGL_FMS_NOTIFY_SIGNATURE_OPTION, $defaults['signature']);
    $instancesRawStored = get_option(ACGL_FMS_NOTIFY_INSTANCES_OPTION, null);
    $typesRawStored = get_option(ACGL_FMS_NOTIFY_TYPES_CONFIG_OPTION, null);
    $activeTypesRawStored = get_option(ACGL_FMS_NOTIFY_ACTIVE_TYPES_OPTION, null);

    $recipientsMode = acgl_fms_admin_normalize_notification_recipients_mode($recipientsMode);

    $instancesRaw = null;
    if (is_array($instancesRawStored)) {
        $instancesRaw = $instancesRawStored;
    } elseif (is_string($instancesRawStored) && trim($instancesRawStored) !== '') {
        $decoded = json_decode($instancesRawStored, true);
        if (is_array($decoded)) {
            $instancesRaw = $decoded;
        }
    }

    $typesConfigRaw = null;
    if (is_array($typesRawStored)) {
        $typesConfigRaw = $typesRawStored;
    } elseif (is_string($typesRawStored) && trim($typesRawStored) !== '') {
        $decoded = json_decode($typesRawStored, true);
        if (is_array($decoded)) {
            $typesConfigRaw = $decoded;
        }
    }

    if (!is_array($typesConfigRaw)) {
        // Backward compatibility: migrate old single-event settings into new_payment_order.
        $legacyEnabled = (string) get_option(ACGL_FMS_NOTIFY_ENABLED_OPTION, '0');
        $legacyOnPublicSubmit = (string) get_option(ACGL_FMS_NOTIFY_ON_PUBLIC_SUBMIT_OPTION, '1');
        $legacySubject = (string) get_option(ACGL_FMS_NOTIFY_SUBJECT_OPTION, '');
        $legacyBody = (string) get_option(ACGL_FMS_NOTIFY_BODY_OPTION, '');

        $typesConfigRaw = acgl_fms_admin_notification_type_defaults();
        $legacyType = isset($typesConfigRaw['new_payment_order']) && is_array($typesConfigRaw['new_payment_order'])
            ? $typesConfigRaw['new_payment_order']
            : [ 'enabled' => '1', 'subject' => '', 'body' => '' ];

        $legacyType['enabled'] = ($legacyEnabled === '1' && $legacyOnPublicSubmit === '1') ? '1' : '0';
        if (trim($legacySubject) !== '') $legacyType['subject'] = $legacySubject;
        if (trim($legacyBody) !== '') $legacyType['body'] = $legacyBody;
        $typesConfigRaw['new_payment_order'] = $legacyType;
    }

    $activeTypeIdsRaw = null;
    if (is_array($activeTypesRawStored)) {
        $activeTypeIdsRaw = $activeTypesRawStored;
    } elseif (is_string($activeTypesRawStored) && trim($activeTypesRawStored) !== '') {
        $decoded = json_decode($activeTypesRawStored, true);
        if (is_array($decoded)) {
            $activeTypeIdsRaw = $decoded;
        }
    }
    $instances = acgl_fms_admin_normalize_notification_instances($instancesRaw, [
        'types_config' => $typesConfigRaw,
        'active_type_ids' => $activeTypeIdsRaw,
    ]);

    return [
        'recipients_mode' => $recipientsMode,
        'manual_to' => trim($manualTo),
        'reply_to' => trim($replyTo),
        'reply_to_is_default' => $replyToIsDefault,
        'reply_to_cleared' => (!$replyToIsDefault && get_option(ACGL_FMS_NOTIFY_REPLY_TO_CLEARED_OPTION, '0') === '1'),
        'signature' => trim($signature) !== '' ? $signature : $defaults['signature'],
        'instances' => $instances,
    ];
}

function acgl_fms_admin_save_notification_settings($input) {
    $defaults = acgl_fms_admin_notification_defaults();
    $data = is_array($input) ? $input : [];

    $modeRaw = isset($data['recipients_mode']) ? (string) $data['recipients_mode'] : $defaults['recipients_mode'];
    $mode = acgl_fms_admin_normalize_notification_recipients_mode($modeRaw);

    $manualToRaw = isset($data['manual_to']) ? (string) $data['manual_to'] : '';
    $manualEmails = acgl_fms_admin_parse_notification_emails($manualToRaw);
    $manualTo = implode(', ', $manualEmails);

    $replyTo = isset($data['reply_to']) ? trim((string) $data['reply_to']) : '';
    if ($replyTo !== '') {
        if (function_exists('sanitize_email')) {
            $replyTo = (string) sanitize_email($replyTo);
        }
        if ($replyTo === '' || (function_exists('is_email') && !is_email($replyTo))) {
            return [ 'ok' => false, 'error' => 'Reply-To must be a valid email address.' ];
        }
    }

    $instancesInput = isset($data['instances']) && is_array($data['instances']) ? $data['instances'] : [];
    $instances = acgl_fms_admin_normalize_notification_instances($instancesInput, null);
    $anyEnabled = false;
    $usesGlobalManualList = false;
    foreach ($instances as $idx => $instanceCfg) {
        if (!is_array($instanceCfg)) continue;
        $instanceModeRaw = isset($instanceCfg['recipients_mode']) ? trim((string) $instanceCfg['recipients_mode']) : '';
        $instanceMode = $instanceModeRaw !== '' ? acgl_fms_admin_normalize_notification_recipients_mode($instanceModeRaw) : '';
        $instanceManualEmails = acgl_fms_admin_parse_notification_emails(isset($instanceCfg['manual_to']) ? (string) $instanceCfg['manual_to'] : '');
        $instances[$idx]['recipients_mode'] = $instanceMode;
        $instances[$idx]['manual_to'] = implode(', ', $instanceManualEmails);

        if ((string) ($instanceCfg['enabled'] ?? '0') === '1') {
            $anyEnabled = true;
            if ($instanceMode === 'manual_list' && count($instanceManualEmails) === 0) {
                return [ 'ok' => false, 'error' => 'Each enabled notification using Manual list mode must include at least one valid recipient email.' ];
            }
            if ($instanceMode === '' && $mode === 'manual_list') {
                $usesGlobalManualList = true;
            }
        }
    }

    $signature = isset($data['signature']) ? trim((string) $data['signature']) : '';
    if ($signature === '') $signature = $defaults['signature'];

    if ($mode === 'manual_list' && count($manualEmails) === 0 && $anyEnabled && $usesGlobalManualList) {
        return [ 'ok' => false, 'error' => 'Add at least one valid recipient email for Manual list mode.' ];
    }

    acgl_fms_admin_set_option_no_autoload(ACGL_FMS_NOTIFY_RECIPIENTS_MODE_OPTION, $mode);
    acgl_fms_admin_set_option_no_autoload(ACGL_FMS_NOTIFY_MANUAL_TO_OPTION, $manualTo);
    acgl_fms_admin_set_option_no_autoload(ACGL_FMS_NOTIFY_REPLY_TO_OPTION, $replyTo);
    acgl_fms_admin_set_option_no_autoload(ACGL_FMS_NOTIFY_REPLY_TO_CLEARED_OPTION, $replyTo === '' ? '1' : '0');
    acgl_fms_admin_set_option_no_autoload(ACGL_FMS_NOTIFY_SIGNATURE_OPTION, $signature);
    if (function_exists('wp_json_encode')) {
        acgl_fms_admin_set_option_no_autoload(ACGL_FMS_NOTIFY_INSTANCES_OPTION, (string) wp_json_encode($instances));
    } else {
        acgl_fms_admin_set_option_no_autoload(ACGL_FMS_NOTIFY_INSTANCES_OPTION, (string) json_encode($instances));
    }

    return [
        'ok' => true,
        'mode' => $mode,
        'manualCount' => count($manualEmails),
        'instanceCount' => count($instances),
    ];
}

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
        } elseif ($action === 'save_notifications') {
            $payload = [
                'enabled' => isset($_POST['acgl_fms_notify_enabled']) ? '1' : '0',
                'on_public_submit' => isset($_POST['acgl_fms_notify_on_public_submit']) ? '1' : '0',
                'recipients_mode' => isset($_POST['acgl_fms_notify_recipients_mode']) ? (string) $_POST['acgl_fms_notify_recipients_mode'] : '',
                'manual_to' => isset($_POST['acgl_fms_notify_manual_to']) ? (string) $_POST['acgl_fms_notify_manual_to'] : '',
                'reply_to' => isset($_POST['acgl_fms_notify_reply_to']) ? (string) $_POST['acgl_fms_notify_reply_to'] : '',
                'subject' => isset($_POST['acgl_fms_notify_subject']) ? (string) $_POST['acgl_fms_notify_subject'] : '',
                'body' => isset($_POST['acgl_fms_notify_body']) ? (string) $_POST['acgl_fms_notify_body'] : '',
                'signature' => isset($_POST['acgl_fms_notify_signature']) ? (string) $_POST['acgl_fms_notify_signature'] : '',
            ];

            if (function_exists('wp_unslash')) {
                foreach ($payload as $k => $v) {
                    $payload[$k] = is_string($v) ? wp_unslash($v) : $v;
                }
            } else {
                foreach ($payload as $k => $v) {
                    $payload[$k] = is_string($v) ? stripslashes($v) : $v;
                }
            }

            $res = acgl_fms_admin_save_notification_settings($payload);
            if (!empty($res['ok'])) {
                $messages[] = 'Saved email notification settings.';
            } else {
                $errors[] = isset($res['error']) ? (string) $res['error'] : 'Failed to save notification settings.';
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
    $notify = acgl_fms_admin_get_notification_settings();
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

    echo '<hr style="margin:24px 0;">';
    echo '<h2>Email Notifications</h2>';
    echo '<p>Configure email templates and recipients for FMS notification events. Delivery is handled by your active WordPress mailer (for example WP Mail SMTP).</p>';
    echo '<p class="description">Supported placeholders: <code>{{paymentOrderNo}}</code>, <code>{{year}}</code>, <code>{{createdAt}}</code>, <code>{{id}}</code>, <code>{{paymentOrderLink}}</code>, <code>{{user}}</code>, <code>{{date}}</code>, <code>{{description}}</code>, <code>{{amount}}</code>, <code>{{party}}</code>, <code>{{moneyTransferNo}}</code>, <code>{{comments}}</code>, <code>{{directLink}}</code>, <code>{{refNo}}</code>, <code>{{subject}}</code>, <code>{{priority}}</code>, <code>{{createdBy}}</code>.</p>';

    echo '<form method="post" action="">';
    wp_nonce_field('acgl_fms_admin_settings');
    echo '<input type="hidden" name="acgl_fms_action" value="save_notifications">';

    echo '<table class="form-table" role="presentation">';
    echo '<tr>';
    echo '<th scope="row">Enable notifications</th>';
    echo '<td>';
    echo '<label><input type="checkbox" name="acgl_fms_notify_enabled" value="1" ' . checked($notify['enabled'], '1', false) . '> Send FMS email notifications</label>';
    echo '</td>';
    echo '</tr>';

    echo '<tr>';
    echo '<th scope="row">Trigger events</th>';
    echo '<td>';
    echo '<label><input type="checkbox" name="acgl_fms_notify_on_public_submit" value="1" ' . checked($notify['on_public_submit'], '1', false) . '> New public payment order submission</label>';
    echo '</td>';
    echo '</tr>';

    echo '<tr>';
    echo '<th scope="row"><label for="acgl_fms_notify_recipients_mode">Recipients</label></th>';
    echo '<td>';
    echo '<select name="acgl_fms_notify_recipients_mode" id="acgl_fms_notify_recipients_mode">';
    echo '<option value="all_users_with_email" ' . selected($notify['recipients_mode'], 'all_users_with_email', false) . '>All FMS users with an email address</option>';
    echo '<option value="manual_list" ' . selected($notify['recipients_mode'], 'manual_list', false) . '>Manual recipient list</option>';
    if (strpos((string) $notify['recipients_mode'], 'user:') === 0) {
        $userKey = strtolower(trim((string) substr((string) $notify['recipients_mode'], strlen('user:'))));
        if ($userKey !== '') {
            echo '<option value="' . esc_attr('user:' . $userKey) . '" ' . selected($notify['recipients_mode'], 'user:' . $userKey, false) . '>Specific account (' . esc_html($userKey) . ')</option>';
        }
    }
    echo '</select>';
    echo '<p class="description">Manual list accepts comma-separated or line-separated email addresses.</p>';
    echo '</td>';
    echo '</tr>';

    echo '<tr>';
    echo '<th scope="row"><label for="acgl_fms_notify_manual_to">Manual recipients</label></th>';
    echo '<td>';
    echo '<textarea name="acgl_fms_notify_manual_to" id="acgl_fms_notify_manual_to" class="large-text" rows="4" placeholder="alerts@example.org, finance@example.org">' . esc_textarea($notify['manual_to']) . '</textarea>';
    echo '</td>';
    echo '</tr>';

    echo '<tr>';
    echo '<th scope="row"><label for="acgl_fms_notify_reply_to">Reply-To (optional)</label></th>';
    echo '<td><input name="acgl_fms_notify_reply_to" id="acgl_fms_notify_reply_to" type="email" class="regular-text" value="' . esc_attr($notify['reply_to']) . '" placeholder="finance@acgl.eu"></td>';
    echo '</tr>';

    echo '<tr>';
    echo '<th scope="row"><label for="acgl_fms_notify_subject">Subject template</label></th>';
    echo '<td><input name="acgl_fms_notify_subject" id="acgl_fms_notify_subject" type="text" class="large-text" value="' . esc_attr($notify['subject']) . '"></td>';
    echo '</tr>';

    echo '<tr>';
    echo '<th scope="row"><label for="acgl_fms_notify_body">Body template</label></th>';
    echo '<td>';
    echo '<textarea name="acgl_fms_notify_body" id="acgl_fms_notify_body" class="large-text" rows="8">' . esc_textarea($notify['body']) . '</textarea>';
    echo '</td>';
    echo '</tr>';

    echo '<tr>';
    echo '<th scope="row"><label for="acgl_fms_notify_signature">Signature</label></th>';
    echo '<td>';
    echo '<textarea name="acgl_fms_notify_signature" id="acgl_fms_notify_signature" class="large-text" rows="3">' . esc_textarea($notify['signature']) . '</textarea>';
    echo '</td>';
    echo '</tr>';

    echo '</table>';

    submit_button('Save Notification Settings');
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
