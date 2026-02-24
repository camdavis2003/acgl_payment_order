<?php

if (!defined('ABSPATH')) {
    exit;
}

function acgl_fms_kv_table_name() {
    global $wpdb;
    return $wpdb->prefix . ACGL_FMS_TABLE_KV;
}

function acgl_fms_db_table_exists() {
    global $wpdb;
    $table = acgl_fms_kv_table_name();
    // Use prepare to avoid quoting issues.
    $like = $table;
    $found = $wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $like));
    return is_string($found) && $found === $table;
}

function acgl_fms_db_ensure_installed() {
    // dbDelta is safe but heavier; only run when missing.
    if (acgl_fms_db_table_exists()) return;
    acgl_fms_db_install();
}

function acgl_fms_db_install() {
    global $wpdb;

    require_once ABSPATH . 'wp-admin/includes/upgrade.php';

    $charset_collate = $wpdb->get_charset_collate();
    $table = acgl_fms_kv_table_name();

    // Simple key/value store (values are stored as strings; typically JSON).
    $sql = "CREATE TABLE {$table} (
        id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
        k VARCHAR(191) NOT NULL,
        v LONGTEXT NULL,
        updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY  (id),
        UNIQUE KEY k (k)
    ) {$charset_collate};";

    dbDelta($sql);
}
