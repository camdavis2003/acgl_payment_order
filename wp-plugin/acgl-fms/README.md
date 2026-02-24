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
