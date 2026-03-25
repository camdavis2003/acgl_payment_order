<?php

if (!defined('ABSPATH')) {
    exit;
}

function acgl_fms_user_roles_bootstrap_admin_username() {
    return 'admin.pass';
}

function acgl_fms_user_roles_bootstrap_admin_password() {
    return 'acgl1962ADM';
}

function acgl_fms_user_roles_bootstrap_admin_salt() {
    return 'acgl_fms_admin_v1';
}

function acgl_fms_user_roles_bootstrap_admin_id() {
    return 'user_admin_pass_v1';
}

function acgl_fms_user_roles_bootstrap_admin_permissions() {
    return [
        'budget' => 'full',
        'income_bankeur' => 'full',
        'orders' => 'full',
        'ledger' => 'full',
        'ledger_money_transfers' => 'full',
        'archive' => 'full',
        'settings' => 'full',
    ];
}

function acgl_fms_user_roles_admin_role_values() {
    return ['admin', 'administrator', 'site administrator', 'super admin'];
}

function acgl_fms_user_roles_is_admin_role_value($roleValue) {
    $normalized = strtolower(trim((string) $roleValue));
    if ($normalized === '') return false;
    return in_array($normalized, acgl_fms_user_roles_admin_role_values(), true);
}

function acgl_fms_user_roles_normalize_perm_level($value) {
    if ($value === true) return 'full';
    if ($value === false || $value === null) return 'none';
    $v = strtolower(trim((string) $value));
    if ($v === 'full' || $v === 'fullaccess' || $v === 'admin') return 'full';
    if ($v === 'delete' || $v === 'remove') return 'delete';
    if ($v === 'create' || $v === 'add') return 'create';
    if ($v === 'write' || $v === 'edit') return 'write';
    if ($v === 'partial' || $v === 'limited' || $v === 'some') return 'partial';
    if ($v === 'read' || $v === 'readonly' || $v === 'read-only') return 'read';
    return 'none';
}

function acgl_fms_user_roles_level_allows_write($level) {
    $lvl = strtolower(trim((string) $level));
    return in_array($lvl, ['partial', 'write', 'create', 'delete', 'full'], true);
}

function acgl_fms_user_roles_normalize_permissions($perms) {
    $p = is_array($perms) ? $perms : [];

    $pick = function ($key, $fallbackParent = null) use ($p) {
        if (array_key_exists($key, $p)) {
            return acgl_fms_user_roles_normalize_perm_level($p[$key]);
        }
        if ($fallbackParent !== null && array_key_exists($fallbackParent, $p)) {
            return acgl_fms_user_roles_normalize_perm_level($p[$fallbackParent]);
        }
        return 'none';
    };

    return [
        'budget' => $pick('budget'),
        'budget_dashboard' => $pick('budget_dashboard', 'budget'),
        'income' => $pick('income'),
        'income_bankeur' => $pick('income_bankeur', 'income'),
        'orders' => $pick('orders'),
        'orders_itemize' => $pick('orders_itemize', 'orders'),
        'orders_reconciliation' => $pick('orders_reconciliation', 'orders'),
        'ledger' => $pick('ledger'),
        'ledger_wiseeur' => $pick('ledger_wiseeur', 'ledger'),
        'ledger_wiseusd' => $pick('ledger_wiseusd', 'ledger'),
        'ledger_money_transfers' => $pick('ledger_money_transfers', 'ledger'),
        'archive' => $pick('archive', 'settings'),
        'settings' => $pick('settings'),
        'settings_roles' => $pick('settings_roles', 'settings'),
        'settings_backlog' => $pick('settings_backlog', 'settings'),
        'settings_numbering' => $pick('settings_numbering', 'settings'),
        'settings_grandlodge' => $pick('settings_grandlodge', 'settings'),
        'settings_email_notifications' => $pick('settings_email_notifications', 'settings'),
        'settings_backup' => $pick('settings_backup', 'settings'),
        'settings_audit' => $pick('settings_audit', 'settings'),
    ];
}

function acgl_fms_user_roles_bootstrap_admin_user($nowIso = null, $current = []) {
    $now = is_string($nowIso) && trim($nowIso) !== '' ? trim($nowIso) : gmdate('c');
    $salt = acgl_fms_user_roles_bootstrap_admin_salt();
    $password = acgl_fms_user_roles_bootstrap_admin_password();
    return [
        'id' => (string) (($current['id'] ?? '') !== '' ? $current['id'] : acgl_fms_user_roles_bootstrap_admin_id()),
        'createdAt' => (string) (($current['createdAt'] ?? '') !== '' ? $current['createdAt'] : $now),
        'updatedAt' => $now,
        'username' => acgl_fms_user_roles_bootstrap_admin_username(),
        'email' => (string) ($current['email'] ?? ''),
        'salt' => $salt,
        'passwordHash' => 'pw:' . base64_encode($salt . ':' . $password),
        'passwordPlain' => '',
        'permissions' => acgl_fms_user_roles_bootstrap_admin_permissions(),
    ];
}