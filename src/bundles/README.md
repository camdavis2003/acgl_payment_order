Module-first page bundle sources

These files are now the source-of-truth for page bundles.

Build flow:
- `node generate-page-bundles.js` copies each source bundle from `src/bundles/` to the project root `app-*.js` outputs.
- `node build-wp-plugin.js` syncs those outputs into `wp-plugin/acgl-fms/app/` and cache-busts HTML asset URLs.

Notes:
- `app.js` monolith has been retired.
- Edit files in `src/bundles/` when changing page logic.
