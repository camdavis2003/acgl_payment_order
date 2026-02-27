# ACGL FMS WordPress Plugin

This plugin embeds the ACGL Financial Management System (FMS) app and provides **shared storage** via WordPress using:
- a custom DB table (`wp_acgl_fms_kv`) and
- REST API endpoints under `/wp-json/acgl-fms/v1/...`

## Install
1. Copy `wp-plugin/acgl-fms` into your WordPress site at:
   - `wp-content/plugins/acgl-fms`
2. Build/copy the static app files into the plugin `app/` folder (see below).
3. Activate the plugin in WP Admin.

Activation will:
- create the KV table
- grant `acgl_fms_access` and `acgl_fms_write` to the **Administrator** role

## Embed on a page
Create a WordPress page and add this shortcode:

`[acgl_fms]`

Optional height:

`[acgl_fms height="1100"]`

## Full-page (no theme chrome)
After activating the plugin, you can also open the app as a standalone full-page view:

`https://your-site/acgl-fms-wp/`

If you get a 404, go to **Settings → Permalinks** and click **Save Changes** once (this refreshes rewrite rules).

## Build the plugin app assets
The plugin serves the app from `wp-content/plugins/acgl-fms/app/`.

Recommended (from the repo root):

`node build-wp-plugin.js`

That script copies the current static app files into `wp-plugin/acgl-fms/app/`.

Copy these files from the repo root into `wp-plugin/acgl-fms/app/`:
- `index.html`, `menu.html`, `budget.html`, `budget_dashboard.html`, `income.html`, `reconciliation.html`, `grand_secretary_ledger.html`, `settings.html`, `itemize.html`, `loading.html`
- `app.js`
- `styles.css`

## REST API (KV store)
- `GET /wp-json/acgl-fms/v1/kv` → returns `{ items: [{k,v}, ...] }`
- `GET /wp-json/acgl-fms/v1/kv/{key}` → returns `{ k, v }` where `v` is a string or null
- `POST /wp-json/acgl-fms/v1/kv/{key}` with body `value=<string>`
- `DELETE /wp-json/acgl-fms/v1/kv/{key}`

Access control:
- read requires capability `acgl_fms_access`
- write requires capability `acgl_fms_write`

## Database
The KV table name is `{wp_prefix}acgl_fms_kv` (the prefix depends on your WordPress install).

## Automated Google Drive backups (WordPress server)
The plugin can upload **year backups** (same schema as the app's backup download) to Google Drive on a daily WordPress cron schedule.

### 1) Create a Google Service Account
- In Google Cloud Console, create a project (or use an existing one).
- Enable the **Google Drive API**.
- Create a **Service Account** and generate a **JSON key**.

### 2) Create a Drive folder and share it
- Create a folder in Google Drive for backups.
- Share that folder with the service account email (the `client_email` field in the JSON key) as **Editor**.
- Copy the folder ID from the Drive URL.

### 3) Add secrets in `wp-config.php`
Add these constants (recommended so the private key is not stored in the database):

```php
define('ACGL_FMS_GDRIVE_FOLDER_ID', 'YOUR_DRIVE_FOLDER_ID');
define('ACGL_FMS_GDRIVE_SERVICE_ACCOUNT_JSON', 'PASTE_THE_SERVICE_ACCOUNT_JSON_HERE');
```

Notes:
- `ACGL_FMS_GDRIVE_SERVICE_ACCOUNT_JSON` must be the full JSON string. If you paste it as a single-quoted string, you must keep the `\n` escapes inside the `private_key`.

#### No `wp-config.php` / file access?
If you cannot edit `wp-config.php` or upload files to the server, you can configure Drive backups in **WordPress Admin**:

- Go to **Settings → ACGL FMS → Google Drive Backups**
- Paste the Drive folder ID
- Paste the full service account JSON

The JSON is stored in `wp_options` (encrypted when OpenSSL is available). The Drive backup code will use these settings automatically if the `wp-config.php` constants are not set.

### 4) Trigger an immediate test upload (optional)
As an admin, you can run:

`POST /wp-json/acgl-fms/v1/admin/gdrive-backup/run`

This endpoint requires the `acgl_fms_write` capability.

### Schedule
- The plugin schedules a daily WordPress cron event (`acgl_fms_gdrive_backup_daily`).
- It uploads backups for all years listed in `payment_order_budget_years_v1` (and includes the active year if missing).
