/* Generated from app.js by generate-page-bundles.js: settings. Do not edit manually. */
/*
  Payment Order Request app (no backend)
  - Validates required fields
  - Persists payment orders in shared storage when embedded in WordPress
    (and in browser storage when run standalone)
  - Renders newest-first table with View/Delete actions
*/

(async () => {
  'use strict';

  const __acglIsLocalDevOrigin = (() => {
    try {
      const h = String(window.location.hostname || '').toLowerCase();
      return h === 'localhost' || h === '127.0.0.1' || h === '0.0.0.0';
    } catch {
      return false;
    }
  })();

  // Dev-only: prove the script is running + the button click is reaching JS.
  // This runs early so it still works even if later initialization crashes.
  if (__acglIsLocalDevOrigin) {
    try {
      const btn = document.getElementById('downloadPdfBtn');
      const requestForm = document.getElementById('paymentOrderForm');
      // Only apply the probe on the request-form page.
      if (btn && requestForm && requestForm.contains(btn) && !btn.dataset.devProbe) {
        btn.dataset.devProbe = '1';
        btn.addEventListener(
          'click',
          () => {
            const prev = String(btn.textContent || 'Download PDF');
            try { btn.textContent = 'Click OK (dev probe)'; } catch { /* ignore */ }
            window.setTimeout(() => {
              try { btn.textContent = prev; } catch { /* ignore */ }
            }, 600);
          },
          true
        );
      }
    } catch {
      // ignore
    }
  }

  const APP_TAB_TITLE = 'ACGL - FMS';
  const APP_VERSION = '1.0.0';
  const TABLE_ENHANCER_FILE = 'table-enhancements.js';
  const VIEW_EYE_ICON_SVG = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="16" height="16" aria-hidden="true" focusable="false"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>';
  const ITEMS_LIST_ICON_SVG = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" width="16" height="16" aria-hidden="true" focusable="false"><circle cx="4.5" cy="6" r="1.3"/><line x1="8" y1="6" x2="21" y2="6"/><circle cx="4.5" cy="12" r="1.3"/><line x1="8" y1="12" x2="21" y2="12"/><circle cx="4.5" cy="18" r="1.3"/><line x1="8" y1="18" x2="21" y2="18"/></svg>';
  const DOWNLOAD_ICON_SVG = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="16" height="16" aria-hidden="true" focusable="false"><path d="M12 3v11"/><polyline points="8 10 12 14 16 10"/><rect x="4" y="17" width="16" height="4" rx="1.5"/></svg>';
  const RESTORE_ICON_SVG = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" width="16" height="16" aria-hidden="true" focusable="false"><path d="M17 10a7 7 0 1 0-2.05 4.95"/><polyline points="17 5 17 10 12 10"/><rect x="4" y="13" width="16" height="4" rx="1.5"/><circle cx="7" cy="15" r="0.9"/><line x1="10" y1="15" x2="17" y2="15"/><rect x="4" y="18" width="16" height="4" rx="1.5"/><circle cx="7" cy="20" r="0.9"/><line x1="10" y1="20" x2="17" y2="20"/></svg>';
  const RECONCILE_PUZZLE_ICON_SVG = '<svg class="reconcileActionIconSvg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M3 10.5l3.1-3.1a2.8 2.8 0 0 1 3.9 0l.7.7-2 2a2.2 2.2 0 0 0 3.1 3.1l2.8-2.8 2.5 2.5"/><path d="M21 10.5l-3.1-3.1a2.8 2.8 0 0 0-3.9 0l-.7.7"/><path d="M9.5 14.8 11 16.3a1.4 1.4 0 1 0 2-2l-1.7-1.7"/><path d="M11.9 16.7 13 17.8a1.3 1.3 0 1 0 1.8-1.8l-1.1-1.1"/><path d="M14.1 17.7 15 18.6a1.1 1.1 0 1 0 1.6-1.6l-.9-.9"/><path d="M2 12.6l2.3 2.3a1.2 1.2 0 1 0 1.7-1.7l-.9-.9"/></svg>';

  function applyAppTabTitle() {
    setBrowserTabTitle(APP_TAB_TITLE);
  }

  function applyAppVersion() {
    try {
      const els = document.querySelectorAll('[data-app-version]');
      for (const el of els) {
        el.textContent = APP_VERSION;
      }
    } catch {
      // ignore
    }
  }

  function setBrowserTabTitle(title) {
    const next = String(title || '').trim();
    if (!next) return;

    try {
      document.title = next;
    } catch {
      // ignore
    }

    // When embedded in a same-origin iframe (e.g., WP portal), also try to
    // set the top-level tab title.
    try {
      if (window.top && window.top !== window) window.top.document.title = next;
    } catch {
      // ignore (likely cross-origin)
    }

    try {
      if (window.parent && window.parent !== window) window.parent.document.title = next;
    } catch {
      // ignore (likely cross-origin)
    }
  }

  applyAppTabTitle();
  applyAppVersion();

  function readAssetVersionFromScript(fileName) {
    const target = String(fileName || '').trim();
    if (!target) return '';
    try {
      const scripts = Array.from(document.querySelectorAll('script[src]'));
      for (let i = scripts.length - 1; i >= 0; i -= 1) {
        const src = String(scripts[i].getAttribute('src') || '').trim();
        if (!src) continue;
        const parsed = new URL(src, window.location.href);
        const path = String(parsed.pathname || '');
        if (!path.endsWith(`/${target}`) && path !== `/${target}` && path !== target) continue;
        const v = String(parsed.searchParams.get('v') || '').trim();
        if (v) return v;
      }
    } catch {
      // ignore
    }
    return '';
  }

  function loadSharedTableEnhancer() {
    if (window.ACGLTableEnhancer && typeof window.ACGLTableEnhancer.initAllTables === 'function') {
      return Promise.resolve(window.ACGLTableEnhancer);
    }

    if (window.__acglTableEnhancerLoaderPromise) {
      return window.__acglTableEnhancerLoaderPromise;
    }

    window.__acglTableEnhancerLoaderPromise = new Promise((resolve) => {
      try {
        const existing = Array.from(document.querySelectorAll('script[src]')).find((el) => {
          const src = String(el.getAttribute('src') || '').trim();
          return src.includes(TABLE_ENHANCER_FILE);
        });
        if (existing) {
          existing.addEventListener('load', () => resolve(window.ACGLTableEnhancer || null), { once: true });
          existing.addEventListener('error', () => resolve(null), { once: true });
          return;
        }

        const script = document.createElement('script');
        script.defer = true;
        const version = readAssetVersionFromScript('app.js');
        script.src = version
          ? `${TABLE_ENHANCER_FILE}?v=${encodeURIComponent(version)}`
          : TABLE_ENHANCER_FILE;
        script.addEventListener('load', () => resolve(window.ACGLTableEnhancer || null), { once: true });
        script.addEventListener('error', () => resolve(null), { once: true });
        document.head.appendChild(script);
      } catch {
        resolve(null);
      }
    });

    return window.__acglTableEnhancerLoaderPromise;
  }

  async function initSharedTableEnhancements() {
    if (window.__acglSharedTableEnhancementsBound) return;

    // Itemize tables must not show Columns/drag-reorder controls.
    if (getBasename(window.location.pathname) === 'itemize.html') {
      window.__acglSharedTableEnhancementsBound = true;
      return;
    }

    const enhancer = await loadSharedTableEnhancer();
    if (!enhancer || typeof enhancer.initAllTables !== 'function') return;

    enhancer.initAllTables({
      selector: 'table.table:not([data-table-enhance="off"]), table[data-table-enhance="on"]',
    });

    const refresh = () => {
      if (enhancer && typeof enhancer.refreshAll === 'function') enhancer.refreshAll();
    };

    window.addEventListener('resize', refresh);

    const navToggleBtn = document.getElementById('navToggle');
    if (navToggleBtn) {
      navToggleBtn.addEventListener('click', () => {
        window.setTimeout(refresh, 220);
      });
    }

    window.__acglSharedTableEnhancementsBound = true;
  }

  function repairJsonEscapes(textRaw) {
    const text = String(textRaw ?? '');
    // Fix common invalid JSON escapes like "C:\Users\..." (\U) by doubling
    // backslashes that are not part of a valid JSON escape sequence.
    return text
      .replace(/\\u(?![0-9a-fA-F]{4})/g, '\\\\u')
      .replace(/\\(?!["\\/bfnrtu])/g, '\\\\');
  }

  function safeJsonParse(raw, fallback) {
    const text = String(raw ?? '').trim();
    if (!text) return fallback;
    try {
      return JSON.parse(text);
    } catch (err) {
      const msg = err && typeof err.message === 'string' ? err.message : '';
      if (msg.includes('Bad Unicode escape') || msg.includes('Bad escaped character')) {
        try {
          const repaired = repairJsonEscapes(text);
          if (repaired !== text) return JSON.parse(repaired);
        } catch {
          // ignore
        }
      }
      return fallback;
    }
  }

  async function readJsonResponse(res) {
    const text = await res.text();
    if (!text) return null;
    return safeJsonParse(text, null);
  }

  const WP_CTX_KEY = 'acgl_fms_wp_ctx_v1';
  const FULLPAGE_LAST_SRC_KEY = 'acgl_fms_fullpage_last_src_v1';

  function saveWpCtxToSession(url, restNonce) {
    try {
      sessionStorage.setItem(WP_CTX_KEY, JSON.stringify({ restUrl: url, restNonce: String(restNonce || '').trim() }));
    } catch {
      // ignore
    }
  }

  function loadWpCtxFromSession() {
    try {
      const raw = String(sessionStorage.getItem(WP_CTX_KEY) || '').trim();
      if (!raw) return null;
      const parsed = JSON.parse(raw);
      return parsed && typeof parsed === 'object' ? parsed : null;
    } catch {
      return null;
    }
  }

  const wpParams = (() => {
    try {
      return new URLSearchParams(window.location.search);
    } catch {
      return new URLSearchParams();
    }
  })();

  const urlRestUrl = String(wpParams.get('restUrl') || '').trim();
  const urlRestNonce = String(wpParams.get('restNonce') || '').trim();
  if (urlRestUrl) saveWpCtxToSession(urlRestUrl, urlRestNonce);

  const IS_LOCAL_DEV_ORIGIN = __acglIsLocalDevOrigin;

  const urlWpFlag = String(wpParams.get('wp') || '').trim();
  // In dev, avoid accidentally enabling WP shared mode from a remembered restUrl.
  // Only honor remembered WP ctx when explicitly requested via query params.
  const ALLOW_REMEMBERED_WP_CTX = Boolean(urlRestUrl) || urlWpFlag === '1' || !IS_LOCAL_DEV_ORIGIN;

  const remembered = ALLOW_REMEMBERED_WP_CTX ? loadWpCtxFromSession() : null;
  const WP_REST_URL = urlRestUrl || (remembered ? remembered.restUrl : '');
  const WP_REST_NONCE = urlRestNonce || (remembered ? remembered.restNonce : '');
  // Shared storage is enabled when a REST base is provided.
  // WP nonce may be present when the viewer is logged into WordPress, but it is not required.
  const IS_WP_SHARED_MODE = Boolean(WP_REST_URL);

  function ensureWpParamsOnThisUrl() {
    if (!IS_WP_SHARED_MODE) return;
    try {
      const url = new URL(window.location.href);
      if (!String(url.searchParams.get('restUrl') || '').trim()) {
        url.searchParams.set('restUrl', WP_REST_URL);
      }
      if (WP_REST_NONCE && !String(url.searchParams.get('restNonce') || '').trim()) {
        url.searchParams.set('restNonce', WP_REST_NONCE);
      }
      if (!String(url.searchParams.get('wp') || '').trim()) {
        url.searchParams.set('wp', '1');
      }
      window.history.replaceState(null, '', url.toString());
    } catch {
      // ignore
    }
  }

  function withWpEmbedParams(href) {
    if (!IS_WP_SHARED_MODE) return href;
    const raw = String(href || '').trim();
    if (!raw) return href;
    try {
      const u = new URL(raw, window.location.href);
      if (u.origin !== window.location.origin) return href;
      if (!u.pathname.endsWith('.html')) return href;

      if (!String(u.searchParams.get('restUrl') || '').trim()) u.searchParams.set('restUrl', WP_REST_URL);
      if (WP_REST_NONCE && !String(u.searchParams.get('restNonce') || '').trim()) u.searchParams.set('restNonce', WP_REST_NONCE);
      if (!String(u.searchParams.get('wp') || '').trim()) u.searchParams.set('wp', '1');

      const base = getBasename(u.pathname);
      const qs = u.searchParams.toString();
      const hash = u.hash || '';
      return qs ? `${base}?${qs}${hash}` : `${base}${hash}`;
    } catch {
      return href;
    }
  }

  function patchInternalAnchorsForWp() {
    if (!IS_WP_SHARED_MODE) return;
    try {
      const anchors = document.querySelectorAll('a[href]');
      for (const a of anchors) {
        const href = String(a.getAttribute('href') || '').trim();
        if (!href) continue;
        if (href.startsWith('#')) continue;
        if (href.startsWith('//')) continue;
        if (/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(href)) continue; // has scheme
        if (!/\.html([?#]|$)/i.test(href)) continue;

        const wrapped = withWpEmbedParams(href);
        if (wrapped && wrapped !== href) a.setAttribute('href', wrapped);
      }
    } catch {
      // ignore
    }
  }

  function rememberFullpageLastSrcNow() {
    // In WP full-page mode, the top-level page recreates the iframe on refresh.
    // Store the current in-app URL in the *top window* sessionStorage so the wrapper
    // can restore the last visited page.
    try {
      const href = String(window.location.href || '').trim();
      if (!href) return;
      if (!window.top || !window.top.sessionStorage) return;
      window.top.sessionStorage.setItem(FULLPAGE_LAST_SRC_KEY, href);
    } catch {
      // ignore (cross-origin or storage blocked)
    }
  }

  const WP_TOKEN_KEY = 'acgl_fms_wp_token_v1';
  const WP_PERMS_KEY = 'acgl_fms_wp_perms_v1';

  function getWpToken() {
    try {
      const raw = String(sessionStorage.getItem(WP_TOKEN_KEY) || '').trim();
      return raw || '';
    } catch {
      return '';
    }
  }

  function setWpToken(token) {
    try {
      sessionStorage.setItem(WP_TOKEN_KEY, String(token || '').trim());
    } catch {
      // ignore
    }
  }

  function clearWpToken() {
    try {
      sessionStorage.removeItem(WP_TOKEN_KEY);
      sessionStorage.removeItem(WP_PERMS_KEY);
    } catch {
      // ignore
    }
  }

  function getWpPerms() {
    try {
      const raw = String(sessionStorage.getItem(WP_PERMS_KEY) || '').trim();
      if (!raw) return null;
      const parsed = JSON.parse(raw);
      return parsed && typeof parsed === 'object' ? parsed : null;
    } catch {
      return null;
    }
  }

  function decodeBase64UrlUtf8(input) {
    const raw = String(input || '').trim();
    if (!raw) return '';
    try {
      const b64 = raw.replace(/-/g, '+').replace(/_/g, '/');
      const padded = b64 + '='.repeat((4 - (b64.length % 4)) % 4);
      return decodeURIComponent(escape(atob(padded)));
    } catch {
      return '';
    }
  }

  function getWpPermsFromToken() {
    const token = getWpToken();
    if (!token) return null;
    const parts = token.split('.');
    if (parts.length < 2) return null;

    try {
      const payloadJson = decodeBase64UrlUtf8(parts[0]);
      if (!payloadJson) return null;
      const payload = JSON.parse(payloadJson);
      const perms = payload && typeof payload === 'object' ? payload.p : null;
      return perms && typeof perms === 'object' ? perms : null;
    } catch {
      return null;
    }
  }

  function getEffectiveWpPerms() {
    const fromSession = getWpPerms();
    if (fromSession && Object.keys(fromSession).length > 0) return fromSession;

    const fromToken = getWpPermsFromToken();
    if (fromToken) {
      setWpPerms(fromToken);
      return fromToken;
    }

    return fromSession;
  }

  function setWpPerms(perms) {
    try {
      sessionStorage.setItem(WP_PERMS_KEY, JSON.stringify(perms && typeof perms === 'object' ? perms : {}));
    } catch {
      // ignore
    }
  }

  function wpJoin(path) {
    const base = String(WP_REST_URL || '').trim();
    if (!base) return path;
    const withSlash = base.endsWith('/') ? base : `${base}/`;
    const p = String(path || '').replace(/^\//, '');
    return `${withSlash}${p}`;
  }

  function getWpAdminSettingsUrl() {
    const restBase = String(WP_REST_URL || '').trim();
    if (!restBase) return '';

    try {
      const u = new URL(restBase, window.location.href);
      const marker = '/wp-json/';
      const idx = u.pathname.indexOf(marker);
      u.pathname = idx >= 0
        ? `${u.pathname.slice(0, idx)}${u.pathname.slice(0, idx).endsWith('/') ? '' : '/'}wp-admin/options-general.php`
        : '/wp-admin/options-general.php';
      u.search = 'page=acgl-fms';
      u.hash = '';
      return u.toString();
    } catch {
      return '';
    }
  }

  async function wpFetchJson(url, options) {
    const token = getWpToken();
    const mergedHeaders = {
      ...(options && options.headers ? options.headers : {}),
    };
    if (token) mergedHeaders.Authorization = `Bearer ${token}`;

    // This app uses bearer tokens for authorization. Sending WordPress cookies can
    // trigger REST cookie/nonce enforcement (403) even though our routes are public.
    // Default to omitting cookies unless an individual call explicitly opts in.
    const credentials = options && typeof options.credentials === 'string'
      ? options.credentials
      : 'omit';

    // Important: When logged out, a nonce header can still trigger REST cookie checks
    // and return 403, even for public routes. Only send the nonce when we are
    // intentionally using cookie credentials.
    if (WP_REST_NONCE && credentials !== 'omit') mergedHeaders['X-WP-Nonce'] = WP_REST_NONCE;

    const res = await fetch(url, {
      credentials,
      ...options,
      headers: {
        ...mergedHeaders,
      },
    });
    return res;
  }

  function isWpSharedKey(keyRaw) {
    const key = String(keyRaw || '').trim();
    if (!key) return false;

    // Shared business data
    if (key === 'payment_order_users_v1') return true;
    if (key === 'payment_order_backlog_v1') return true;
    if (key === 'payment_order_auth_audit_v1') return true;
    if (key === 'payment_order_numbering') return true;
    if (key === 'payment_order_grand_lodge_info_v1') return true;
    if (key === 'payment_order_budget_years_v1') return true;
    if (key === 'payment_order_active_budget_year_v1') return true;
    if (key === 'payment_order_notifications_settings_v1') return true;

    // Per-year datasets
    if (key.startsWith('payment_orders_')) return true;
    if (key.startsWith('money_transfers_')) return true;
    if (key.startsWith('payment_order_income_')) return true;
    if (key.startsWith('payment_order_wise_eur_')) return true;
    if (key.startsWith('payment_order_wise_usd_')) return true;
    if (key.startsWith('payment_order_budget_table_html_')) return true;
    if (key.startsWith('payment_order_gs_ledger_verified_')) return true;

    // Backups (year-scoped snapshots)
    if (key.startsWith('payment_order_backup_')) return true;

    // Legacy/migrations (safe to share)
    if (key === 'payment_orders_legacy_migrated_v1') return true;
    if (key === 'payment_order_budget_table_html_v1') return true;

    return false;
  }

  function showWpLoginRequiredOverlay() {
    const existing = document.querySelector('.authGate[data-wp-login-required="1"]');
    if (existing) return;

    const redirectTo = (() => {
      try {
        return window.location.href;
      } catch {
        return '';
      }
    })();
    const loginUrl = `${window.location.origin}/wp-login.php?redirect_to=${encodeURIComponent(redirectTo)}`;

    const overlay = document.createElement('div');
    overlay.className = 'authGate';
    overlay.setAttribute('data-wp-login-required', '1');
    overlay.innerHTML = `
      <div class="authGate__card card">
        <h2 class="authGate__title">Sign in required</h2>
        <p class="muted">This page is embedded in WordPress. Please sign in to WordPress to access shared data.</p>
        <div class="actions">
          <a class="btn btn--primary" href="${loginUrl}">Go to WordPress sign in</a>
        </div>
      </div>
    `.trim();
    document.body.appendChild(overlay);
  }

  async function initWpSharedStorageBridge() {
    if (!IS_WP_SHARED_MODE) return;
    const dataStore = window.ACGLDataStore;
    if (!dataStore || typeof dataStore.initWpSharedStorageBridge !== 'function') return;

    const bridge = await dataStore.initWpSharedStorageBridge({
      isWpSharedMode: IS_WP_SHARED_MODE,
      wpFetchJson,
      wpJoin,
      isWpSharedKey,
      getWpToken,
      readJsonResponse,
      getBasename,
    });
    if (!bridge) return;

    // Expose a safe way to force persistence before navigation.
    // Used when the UI redirects immediately after writing shared keys.
    window.acglFmsWpFlushNow = bridge.flushNow;
    // Expose shared-store preload helpers used by auth + heavy page bootstraps.
    window.acglFmsWpHydrateSharedNow = bridge.hydrateSharedFromWp;
    window.acglFmsDataStore = {
      preloadBootstrapEssentials: bridge.preloadBootstrapEssentials,
      preloadCurrentPageDatasets: bridge.preloadCurrentPageDatasets,
      preloadKeys: bridge.preloadKeys,
      fetchSharedKeyFromWp: bridge.fetchSharedKeyFromWp,
      initWpSharedStorageBridge: dataStore.initWpSharedStorageBridge,
    };
  }

  try {
    // Never block app startup indefinitely on a network call.
    await Promise.race([
      initWpSharedStorageBridge(),
      new Promise((_, reject) => window.setTimeout(() => reject(new Error('wp_bridge_timeout')), 2500)),
    ]);
  } catch {
    // If the WP bridge fails or times out, continue in standalone mode so
    // the UI still works (sign-in, itemize, Download PDF, etc.).
  }

  // If we arrived on a page without WP params (e.g., user clicked a bare "settings.html" link),
  // restore the remembered embed params so shared mode stays consistent across pages.
  ensureWpParamsOnThisUrl();
  patchInternalAnchorsForWp();
  rememberFullpageLastSrcNow();
  try {
    window.addEventListener('beforeunload', rememberFullpageLastSrcNow);
  } catch {
    // ignore
  }

  const STORAGE_KEY = 'payment_orders';
  const PAYMENT_ORDERS_LEGACY_MIGRATED_KEY = 'payment_orders_legacy_migrated_v1';
  const THEME_KEY = 'payment_order_theme';
  const DRAFT_KEY = 'payment_order_draft';
  const DRAFT_ITEMS_KEY = 'payment_order_draft_items';
  const EDIT_ORDER_ID_KEY = 'payment_order_edit_order_id';
  const EDIT_ORDER_YEAR_KEY = 'payment_order_edit_order_year_v1';
  const NUMBERING_KEY = 'payment_order_numbering';
  const GRAND_LODGE_INFO_KEY = 'payment_order_grand_lodge_info_v1';
  const FLASH_TOKEN_KEY = 'payment_order_flash_token';
  const BUDGET_TABLE_HTML_KEY = 'payment_order_budget_table_html_v1';
  const BUDGET_YEARS_KEY = 'payment_order_budget_years_v1';
  const ACTIVE_BUDGET_YEAR_KEY = 'payment_order_active_budget_year_v1';
  const ACTIVE_BUDGET_YEAR_FALLBACK_KEY = 'payment_order_active_budget_year_local_v1';
  const BUDGET_TEMPLATE_ROWS_KEY = 'payment_order_budget_template_rows_v1';
  const USERS_KEY = 'payment_order_users_v1';
  const BACKLOG_KEY = 'payment_order_backlog_v1';
  const CURRENT_USER_KEY = 'payment_order_current_user_v1';
  const LOGIN_AT_KEY = 'payment_order_login_at_v1';
  const LAST_ACTIVITY_AT_KEY = 'payment_order_last_activity_at_v1';
  const AUTH_AUDIT_KEY = 'payment_order_auth_audit_v1';
  const APP_AUDIT_KEY = 'payment_order_app_audit_v1';
  const LAST_PAGE_KEY = 'acgl_fms_last_page_v1';
  const NOTIFICATIONS_SETTINGS_KEY = 'payment_order_notifications_settings_v1';

  const NOTIFICATION_TYPES = [
    {
      id: 'new_payment_order',
      label: 'New Payment Order',
      defaultSubject: '[ACGL FMS] New Payment Order {{paymentOrderNo}}',
      defaultBody: 'A new payment order has been submitted.\n\nPayment Order: {{paymentOrderNo}}\nYear: {{year}}\nCreated: {{createdAt}}\nID: {{id}}\nLink: {{paymentOrderLink}}',
    },
    {
      id: 'gs_review',
      label: 'Grand Secretary Review',
      defaultSubject: '[ACGL FMS] Payment Order Awaiting Grand Secretary Review',
      defaultBody: 'Payment Order {{paymentOrderNo}} is awaiting Grand Secretary review.\n\nPayment Order: {{paymentOrderNo}}\nYear: {{year}}\nLink: {{paymentOrderLink}}\nDirect link: {{directLink}}',
    },
    {
      id: 'gm_review',
      label: 'Grand Master Review',
      defaultSubject: '[ACGL FMS] Payment Order Awaiting Grand Master Review',
      defaultBody: 'Payment Order {{paymentOrderNo}} is awaiting Grand Master review.\n\nPayment Order: {{paymentOrderNo}}\nYear: {{year}}\nLink: {{paymentOrderLink}}\nDirect link: {{directLink}}',
    },
    {
      id: 'gt_processing',
      label: 'Grand Treasurer Processing',
      defaultSubject: '[ACGL FMS] Payment Order Approved for Grand Treasurer Processing',
      defaultBody: 'Payment Order {{paymentOrderNo}} has been approved and is ready for Grand Treasurer processing.\n\nPayment Order: {{paymentOrderNo}}\nYear: {{year}}\nLink: {{paymentOrderLink}}\nDirect link: {{directLink}}',
    },
    {
      id: 'budget_update',
      label: 'Budget Update',
      defaultSubject: '[ACGL FMS] Budget Updated',
      defaultBody: 'The budget for {{year}} has been updated by {{user}}.\nDirect link: {{directLink}}',
    },
    {
      id: 'new_bank_eur',
      label: 'New BankEUR',
      defaultSubject: '[ACGL FMS] New BankEUR Entry',
      defaultBody: 'A new BankEUR entry has been added.\n\nDate: {{date}}\nDescription: {{description}}\nAmount: {{amount}} EUR\nYear: {{year}}\nDirect link: {{directLink}}',
    },
    {
      id: 'new_wise_eur',
      label: 'New wiseEUR',
      defaultSubject: '[ACGL FMS] New wiseEUR Entry',
      defaultBody: 'A new wiseEUR entry has been added.\n\nDate: {{date}}\nParty: {{party}}\nYear: {{year}}\nDirect link: {{directLink}}',
    },
    {
      id: 'new_wise_usd',
      label: 'New wiseUSD',
      defaultSubject: '[ACGL FMS] New wiseUSD Entry',
      defaultBody: 'A new wiseUSD entry has been added.\n\nDate: {{date}}\nParty: {{party}}\nYear: {{year}}\nDirect link: {{directLink}}',
    },
    {
      id: 'mt_gs_verification',
      label: 'Money Transfer GS Verification',
      defaultSubject: '[ACGL FMS] New Money Transfer Created',
      defaultBody: 'A new Money Transfer has been created and is awaiting GS verification.\n\nMoney Transfer No: {{moneyTransferNo}}\nDate: {{date}}\nComments: {{comments}}\nYear: {{year}}\nDirect link: {{directLink}}',
    },
    {
      id: 'mt_gt_verification',
      label: 'Money Transfer GT Verification',
      defaultSubject: '[ACGL FMS] Money Transfer GS Verified',
      defaultBody: 'A Money Transfer has been marked as GS Verified.\n\nDate: {{date}}\nDescription: {{description}}\nYear: {{year}}\nDirect link: {{directLink}}',
    },
    {
      id: 'new_backlog',
      label: 'New Backlog',
      defaultSubject: '[ACGL FMS] New Backlog Item',
      defaultBody: 'A new backlog item has been created.\n\nRef: {{refNo}}\nSubject: {{subject}}\nPriority: {{priority}}\nCreated by: {{createdBy}}\nDirect link: {{directLink}}',
    },
  ];

  const fireNotificationEvent = async (type, vars) => {
    if (!IS_WP_SHARED_MODE || !getWpToken()) return;
    try {
      const url = wpJoin('acgl-fms/v1/admin/notifications-send-event');
      await wpFetchJson(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type: String(type), vars: vars || {} }),
      });
    } catch {
      // fire and forget — notification failures should not surface to user
    }
  };

  const USER_ROLE_CONFIG = window.ACGL_USER_ROLES;
  if (!USER_ROLE_CONFIG) {
    throw new Error('ACGL_USER_ROLES must be loaded before app.js');
  }

  const {
    ACCESS_LEVELS,
    ACCESS_LEVEL_RANK,
    ACCESS_LEVEL_CAPABILITIES,
    BOOTSTRAP_ADMIN,
    PAGE_PERMISSION_MAP,
    PERMISSION_DEFS,
    PERMISSION_FORM_ROWS,
    ROLE_ACCESS_PRESETS,
    ROLE_OPTIONS,
    STRICT_EXPLICIT_PERMISSION_KEYS,
    canRoleManageWorkflowField,
    getRoleAccessPreset,
    isAdminRoleValue,
    normalizeAccessLevel,
    normalizeRoleLabel,
  } = USER_ROLE_CONFIG;

  const HARD_CODED_ADMIN_USERNAME = BOOTSTRAP_ADMIN.username;
  const HARD_CODED_ADMIN_PASSWORD = BOOTSTRAP_ADMIN.password;
  const HARD_CODED_ADMIN_SALT = BOOTSTRAP_ADMIN.salt;

  let hardcodedAdminSeedAttempted = false;

  function isHardcodedAdminUsername(username) {
    return normalizeUsername(username) === normalizeUsername(HARD_CODED_ADMIN_USERNAME);
  }

  function buildLegacyPwHash(password, salt) {
    const pw = String(password ?? '');
    const s = String(salt ?? '');
    return `pw:${btoa(unescape(encodeURIComponent(`${s}:${pw}`)))}`;
  }

  function extractLegacyPasswordPlain(storedHash, salt) {
    const h = String(storedHash ?? '');
    const s = String(salt ?? '');
    if (!h.startsWith('pw:')) return '';
    try {
      const decoded = decodeURIComponent(escape(atob(h.slice(3))));
      const prefix = `${s}:`;
      if (!decoded.startsWith(prefix)) return '';
      return decoded.slice(prefix.length);
    } catch {
      return '';
    }
  }

  function ensureHardcodedAdminUserExists() {
    if (IS_WP_SHARED_MODE) return;
    if (hardcodedAdminSeedAttempted) return;
    hardcodedAdminSeedAttempted = true;

    try {
      const nowIso = new Date().toISOString();
      const desired = {
        id: BOOTSTRAP_ADMIN.id,
        createdAt: nowIso,
        updatedAt: nowIso,
        username: normalizeUsername(HARD_CODED_ADMIN_USERNAME),
        email: '',
        salt: HARD_CODED_ADMIN_SALT,
        passwordHash: buildLegacyPwHash(HARD_CODED_ADMIN_PASSWORD, HARD_CODED_ADMIN_SALT),
        passwordPlain: HARD_CODED_ADMIN_PASSWORD,
        permissions: { ...BOOTSTRAP_ADMIN.defaultPermissions },
      };

      const raw = localStorage.getItem(USERS_KEY);
      const parsed = raw ? JSON.parse(raw) : [];
      const users = Array.isArray(parsed) ? parsed : [];

      const idx = users.findIndex((u) => normalizeUsername(u && u.username) === desired.username);
      if (idx === -1) {
        users.push(desired);
      } else {
        const current = users[idx] && typeof users[idx] === 'object' ? users[idx] : {};
        users[idx] = {
          ...current,
          id: current.id || desired.id,
          createdAt: current.createdAt || desired.createdAt,
          updatedAt: nowIso,
          username: desired.username,
          salt: desired.salt,
          passwordHash: desired.passwordHash,
          passwordPlain: desired.passwordPlain,
          permissions: desired.permissions,
        };
      }

      localStorage.setItem(USERS_KEY, JSON.stringify(users));
    } catch {
      // ignore (e.g., storage disabled)
    }
  }

  function normalizeUsername(value) {
    return String(value ?? '').trim().toLowerCase();
  }

  function normalizeEmail(value) {
    return String(value ?? '').trim().toLowerCase();
  }

  function isValidEmail(value) {
    const v = String(value ?? '').trim();
    if (!v) return false;
    // Simple client-side check (no backend): allow common emails.
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
  }

  function loadUsers() {
    ensureHardcodedAdminUserExists();
    try {
      const raw = localStorage.getItem(USERS_KEY);
      if (!raw) return [];
      const parsed = JSON.parse(raw);
      return Array.isArray(parsed) ? parsed : [];
    } catch {
      return [];
    }
  }

  function saveUsers(users) {
    const before = loadUsers();
    const safe = Array.isArray(users) ? users : [];
    localStorage.setItem(USERS_KEY, JSON.stringify(safe));
    appendCollectionAuditEvents({
      module: 'Users',
      beforeList: before,
      afterList: safe,
      idKeys: ['id', 'username'],
      recordLabelFn: (u) => normalizeUsername(u && u.username),
    });
  }

  async function persistUsersToWpNow() {
    if (!IS_WP_SHARED_MODE) return { ok: true, skipped: true };
    try {
      const raw = String(localStorage.getItem(USERS_KEY) || '').trim();
      const value = raw ? raw : '[]';
      const url = wpJoin(`acgl-fms/v1/kv/${encodeURIComponent(String(USERS_KEY))}`);
      const res = await wpFetchJson(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ value }),
      });
      if (!res || !res.ok) return { ok: false };
      return { ok: true };
    } catch {
      return { ok: false };
    }
  }

  function ensureCurrentLoginAtIso() {
    // Older sessions may not have a stored timestamp; set it once.
    const currentUser = getCurrentUser();
    if (!currentUser) return '';

    const existing = getCurrentLoginAtIso();
    if (existing) return existing;

    const nowIso = new Date().toISOString();
    try {
      sessionStorage.setItem(LOGIN_AT_KEY, nowIso);
    } catch {
      // ignore
    }
    return nowIso;
  }

  function getCurrentUsername() {
    try {
      const raw = String(sessionStorage.getItem(CURRENT_USER_KEY) || '').trim();
      return raw;
    } catch {
      return '';
    }
  }

  function getCurrentLoginAtIso() {
    try {
      const raw = String(sessionStorage.getItem(LOGIN_AT_KEY) || '').trim();
      return raw;
    } catch {
      return '';
    }
  }

  function setCurrentUsername(username) {
    const u = String(username || '').trim();
    try {
      if (!u) {
        sessionStorage.removeItem(CURRENT_USER_KEY);
        sessionStorage.removeItem(LOGIN_AT_KEY);
        sessionStorage.removeItem(LAST_ACTIVITY_AT_KEY);
      } else {
        sessionStorage.setItem(CURRENT_USER_KEY, u);
        // Capture the time of successful sign-in for this session.
        const nowIso = new Date().toISOString();
        sessionStorage.setItem(LOGIN_AT_KEY, nowIso);
        sessionStorage.setItem(LAST_ACTIVITY_AT_KEY, nowIso);
      }
    } catch {
      // ignore
    }

  }

  function formatLoginAtForDisplay(isoString) {
    const raw = String(isoString || '').trim();
    if (!raw) return '';
    try {
      const d = new Date(raw);
      if (Number.isNaN(d.getTime())) return '';
      return new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short', hour12: false }).format(d);
    } catch {
      return '';
    }
  }

  function formatDurationMs(msRaw) {
    const ms = Number(msRaw);
    if (!Number.isFinite(ms) || ms < 0) return '';

    const totalMinutes = Math.floor(ms / 60000);
    const days = Math.floor(totalMinutes / (60 * 24));
    const hours = Math.floor((totalMinutes % (60 * 24)) / 60);
    const minutes = totalMinutes % 60;

    const parts = [];
    if (days) parts.push(`${days}d`);
    if (hours || days) parts.push(`${hours}h`);
    parts.push(`${minutes}m`);
    return parts.join(' ');
  }

  function getLastActivityMs() {
    try {
      const raw = String(sessionStorage.getItem(LAST_ACTIVITY_AT_KEY) || '').trim();
      const ms = raw ? Date.parse(raw) : NaN;
      return Number.isFinite(ms) ? ms : null;
    } catch {
      return null;
    }
  }

  function markUserActivityNow() {
    const current = getCurrentUser();
    if (!current) return;
    try {
      sessionStorage.setItem(LAST_ACTIVITY_AT_KEY, new Date().toISOString());
    } catch {
      // ignore
    }
  }

  async function performAutoLogout() {
    const prev = normalizeUsername(getCurrentUsername());
    if (!prev) return;

    // Record as an auth audit note, excluding hard-coded admin.
    await appendAuthAuditEvent('Auto log out', prev);

    // Clear session (do not also write a normal Logout record).
    setCurrentUsername('');
    if (IS_WP_SHARED_MODE) clearWpToken();

    // Bring the user back to the public request page.
    window.location.href = withWpEmbedParams('index.html?new=1');
  }

  let idleLogoutInstalled = false;
  function installIdleAutoLogout() {
    if (idleLogoutInstalled) return;
    idleLogoutInstalled = true;

    const IDLE_LIMIT_MS = 10 * 60 * 1000;

    const onActivity = () => {
      markUserActivityNow();
    };

    // Capture common user interactions.
    ['pointerdown', 'mousemove', 'keydown', 'scroll', 'touchstart', 'click', 'focus']
      .forEach((type) => {
        window.addEventListener(type, onActivity, { passive: true });
      });

    // Periodic idle check.
    window.setInterval(() => {
      const currentUser = getCurrentUser();
      if (!currentUser) return;

      // If timestamp is missing (older sessions), initialize it.
      if (!getLastActivityMs()) markUserActivityNow();

      const lastMs = getLastActivityMs();
      if (lastMs === null) return;

      const idleMs = Date.now() - lastMs;
      if (idleMs >= IDLE_LIMIT_MS) {
        void performAutoLogout();
      }
    }, 15 * 1000);
  }

  async function performLogout() {
    const prev = normalizeUsername(getCurrentUsername());
    if (prev) await appendAuthAuditEvent('Logout', prev);
    setCurrentUsername('');
    if (IS_WP_SHARED_MODE) clearWpToken();
  }

  async function persistAuthAuditToWpNow(keepalive = false, tokenOverride = '') {
    if (!IS_WP_SHARED_MODE) return { ok: true, skipped: true };
    try {
      const raw = String(localStorage.getItem(AUTH_AUDIT_KEY) || '').trim();
      const localEvents = safeJsonParse(raw, []);
      const localList = Array.isArray(localEvents) ? localEvents : [];
      const url = wpJoin(`acgl-fms/v1/kv/${encodeURIComponent(String(AUTH_AUDIT_KEY))}`);
      const headers = { 'Content-Type': 'application/json' };
      const auth = String(tokenOverride || '').trim();
      if (auth) headers.Authorization = `Bearer ${auth}`;

      // Merge server + local lists before save so concurrent clients do not
      // overwrite each other's login/logout events.
      let merged = localList;
      try {
        const getRes = await wpFetchJson(url, { method: 'GET', headers });
        if (getRes && getRes.ok) {
          const payload = await readJsonResponse(getRes);
          const remoteRaw = payload && typeof payload.v === 'string' ? payload.v : '';
          const remoteEvents = safeJsonParse(remoteRaw, []);
          const remoteList = Array.isArray(remoteEvents) ? remoteEvents : [];

          const keyOf = (e) => {
            if (!e || typeof e !== 'object') return '';
            const at = String(e.at || '').trim();
            const user = String(e.user || '').trim().toLowerCase();
            const action = String(e.action || '').trim().toLowerCase();
            const module = String(e.module || '').trim().toLowerCase();
            const record = String(e.record || '').trim().toLowerCase();
            return `${at}|${user}|${action}|${module}|${record}`;
          };

          const map = new Map();
          for (const e of remoteList) {
            const k = keyOf(e);
            if (!k) continue;
            map.set(k, e);
          }
          for (const e of localList) {
            const k = keyOf(e);
            if (!k) continue;
            map.set(k, e);
          }

          merged = Array.from(map.values());
          merged.sort((a, b) => {
            const ams = toTimeMs(a && a.at ? a.at : '') ?? 0;
            const bms = toTimeMs(b && b.at ? b.at : '') ?? 0;
            return ams - bms;
          });
          const MAX = 200;
          if (merged.length > MAX) merged = merged.slice(merged.length - MAX);

          // Keep local copy aligned with what we write to the server.
          try {
            saveAuthAuditEvents(merged);
          } catch {
            // ignore
          }
        }
      } catch {
        // If merge-read fails, still try to persist local events.
      }

      const value = JSON.stringify(Array.isArray(merged) ? merged : []);
      const res = await wpFetchJson(url, {
        method: 'POST',
        headers,
        body: JSON.stringify({ value }),
        keepalive: Boolean(keepalive),
      });
      if (!res.ok) {
        console.error('[ACGL FMS] Auth audit persist failed', res.status, url);
        return { ok: false, status: res.status };
      }
      return { ok: true };
    } catch (err) {
      console.error('[ACGL FMS] Auth audit persist error', err);
      return { ok: false, status: 0 };
    }
  }

  function loadAuthAuditEvents() {
    try {
      const raw = localStorage.getItem(AUTH_AUDIT_KEY);
      const parsed = raw ? JSON.parse(raw) : [];
      return Array.isArray(parsed) ? parsed : [];
    } catch {
      return [];
    }
  }

  function saveAuthAuditEvents(events) {
    try {
      const safe = Array.isArray(events) ? events : [];
      localStorage.setItem(AUTH_AUDIT_KEY, JSON.stringify(safe));
    } catch {
      // ignore
    }
  }

  async function appendAuthAuditEvent(actionRaw, usernameRaw) {
    const action = String(actionRaw || '').trim() || 'Event';
    const user = normalizeUsername(usernameRaw) || '—';
    const at = new Date().toISOString();

    const existing = loadAuthAuditEvents();
    const next = [...existing, { at, module: 'Auth', record: 'Session', user, action, changes: [] }];

    // Keep storage bounded.
    const MAX = 200;
    const trimmed = next.length > MAX ? next.slice(next.length - MAX) : next;
    saveAuthAuditEvents(trimmed);

    // In WP mode, localStorage writes are debounced for performance; ensure auth events
    // are persisted immediately so logout/navigation doesn't drop them.
    if (IS_WP_SHARED_MODE) {
      const tokenAtWrite = getWpToken();
      const actionLower = action.toLowerCase();
      const shouldKeepalive = actionLower === 'logout' || actionLower === 'auto log out' || actionLower === 'auto logout';
      try {
        await persistAuthAuditToWpNow(shouldKeepalive, tokenAtWrite);
      } catch {
        // ignore
      }
    }
  }

  function loadAppAuditEvents() {
    try {
      const raw = localStorage.getItem(APP_AUDIT_KEY);
      const parsed = raw ? JSON.parse(raw) : [];
      return Array.isArray(parsed) ? parsed : [];
    } catch {
      return [];
    }
  }

  function saveAppAuditEvents(events) {
    try {
      const safe = Array.isArray(events) ? events : [];
      localStorage.setItem(APP_AUDIT_KEY, JSON.stringify(safe));
    } catch {
      // ignore
    }
  }

  function getAuditActorUsername() {
    const u = getCurrentUser && getCurrentUser();
    const name = u && u.username ? String(u.username).trim() : '';
    return name;
  }

  function auditStableStringify(value) {
    const seen = new WeakSet();
    const normalize = (v) => {
      if (v === null || v === undefined) return v;
      if (typeof v === 'number') return Number.isFinite(v) ? v : null;
      if (typeof v === 'string' || typeof v === 'boolean') return v;
      if (Array.isArray(v)) return v.map((x) => normalize(x));
      if (typeof v === 'object') {
        if (seen.has(v)) return null;
        seen.add(v);
        const out = {};
        const keys = Object.keys(v).sort();
        for (const k of keys) {
          out[k] = normalize(v[k]);
        }
        return out;
      }
      return String(v);
    };
    try {
      return JSON.stringify(normalize(value));
    } catch {
      return '';
    }
  }

  function getAuditCollectionItemId(item, idKeys) {
    if (!item || typeof item !== 'object') return '';
    const keys = Array.isArray(idKeys) ? idKeys : ['id'];
    for (const key of keys) {
      const v = String((item && item[key]) || '').trim();
      if (v) return `${key}:${v}`;
    }
    return '';
  }

  function formatAuditChangeValue(value, field) {
    const key = String(field || '').trim().toLowerCase();
    if (key === 'passwordhash' || key === 'passwordplain' || key === 'salt') return '[redacted]';
    if (key === 'grandlodgesealdataurl' || key === 'grandsecretarysignaturedataurl') return '[updated]';
    if (value === null || value === undefined) return '—';
    if (typeof value === 'boolean') return value ? 'Yes' : 'No';
    if (typeof value === 'number') return Number.isFinite(value) ? String(value) : '—';
    if (Array.isArray(value)) return `${value.length} item(s)`;
    if (typeof value === 'object') return '[updated]';
    const s = String(value).trim();
    if (!s) return '—';
    return s.length > 120 ? `${s.slice(0, 117)}...` : s;
  }

  function buildAuditChangesSummary(prev, next) {
    const p = prev && typeof prev === 'object' ? prev : {};
    const n = next && typeof next === 'object' ? next : {};
    const ignore = new Set(['createdAt', 'updatedAt', 'timeline']);
    const keys = Array.from(new Set([...Object.keys(p), ...Object.keys(n)]));

    const rows = [];
    for (const key of keys) {
      if (ignore.has(key)) continue;
      const fromRaw = Object.prototype.hasOwnProperty.call(p, key) ? p[key] : null;
      const toRaw = Object.prototype.hasOwnProperty.call(n, key) ? n[key] : null;
      if (auditStableStringify(fromRaw) === auditStableStringify(toRaw)) continue;
      rows.push({
        field: key,
        from: formatAuditChangeValue(fromRaw, key),
        to: formatAuditChangeValue(toRaw, key),
      });
      if (rows.length >= 8) break;
    }

    if (rows.length === 0) {
      return [{ field: 'Record', from: '', to: 'Modified' }];
    }
    return rows;
  }

  function appendAppAuditEvent(moduleRaw, recordRaw, actionRaw, changesRaw) {
    const actor = getAuditActorUsername();
    if (!actor) return;

    const module = String(moduleRaw || '').trim() || 'App';
    const record = String(recordRaw || '').trim() || 'Record';
    const action = String(actionRaw || '').trim() || 'Modified';
    const changes = Array.isArray(changesRaw) ? changesRaw : [];
    const at = new Date().toISOString();

    const existing = loadAppAuditEvents();
    const next = [...existing, { at, module, record, user: actor, action, changes }];

    const MAX = 2000;
    const trimmed = next.length > MAX ? next.slice(next.length - MAX) : next;
    saveAppAuditEvents(trimmed);
  }

  function appendCollectionAuditEvents({ module, year, beforeList, afterList, idKeys, recordLabelFn }) {
    const actor = getAuditActorUsername();
    if (!actor) return;

    const beforeArr = Array.isArray(beforeList) ? beforeList : [];
    const afterArr = Array.isArray(afterList) ? afterList : [];
    const beforeMap = new Map();
    const afterMap = new Map();

    for (const item of beforeArr) {
      const id = getAuditCollectionItemId(item, idKeys);
      if (!id) continue;
      beforeMap.set(id, item);
    }
    for (const item of afterArr) {
      const id = getAuditCollectionItemId(item, idKeys);
      if (!id) continue;
      afterMap.set(id, item);
    }

    const moduleLabel = year !== undefined && year !== null && String(year).trim()
      ? `${String(module || 'App')} (${String(year)})`
      : String(module || 'App');

    const labelOf = (item, id) => {
      if (recordLabelFn && typeof recordLabelFn === 'function') {
        const v = String(recordLabelFn(item) || '').trim();
        if (v) return v;
      }
      const fallback = String(id || '').trim();
      return fallback || 'Record';
    };

    for (const [id, afterItem] of afterMap.entries()) {
      const beforeItem = beforeMap.get(id);
      if (!beforeItem) {
        appendAppAuditEvent(moduleLabel, labelOf(afterItem, id), 'Created', []);
        continue;
      }

      if (auditStableStringify(beforeItem) !== auditStableStringify(afterItem)) {
        appendAppAuditEvent(
          moduleLabel,
          labelOf(afterItem, id),
          'Modified',
          buildAuditChangesSummary(beforeItem, afterItem)
        );
      }
    }

    for (const [id, beforeItem] of beforeMap.entries()) {
      if (!afterMap.has(id)) {
        appendAppAuditEvent(moduleLabel, labelOf(beforeItem, id), 'Deleted', []);
      }
    }
  }

  async function hashPassword(password, salt) {
    const pw = String(password ?? '');
    const s = String(salt ?? '');
    const input = `${s}:${pw}`;

    // Prefer a real hash in secure contexts.
    try {
      if (crypto?.subtle?.digest) {
        const bytes = new TextEncoder().encode(input);
        const digest = await crypto.subtle.digest('SHA-256', bytes);
        const arr = Array.from(new Uint8Array(digest));
        const b64 = btoa(String.fromCharCode(...arr));
        return `sha256:${b64}`;
      }
    } catch {
      // fall back
    }

    // Fallback: store an obfuscated but reversible marker (not secure).
    return `pw:${btoa(unescape(encodeURIComponent(input)))}`;
  }

  function verifyPasswordSync(password, salt, storedHash) {
    const pw = String(password ?? '');
    const s = String(salt ?? '');
    const h = String(storedHash ?? '');
    if (h.startsWith('pw:')) {
      try {
        const decoded = decodeURIComponent(escape(atob(h.slice(3))));
        return decoded === `${s}:${pw}`;
      } catch {
        return false;
      }
    }
    return null;
  }

  async function verifyPassword(password, salt, storedHash) {
    const fast = verifyPasswordSync(password, salt, storedHash);
    if (fast !== null) return fast;
    const computed = await hashPassword(password, salt);
    return computed === String(storedHash || '');
  }

  function getUserByUsername(username) {
    const u = normalizeUsername(username);
    if (!u) return null;
    const users = loadUsers();
    return users.find((x) => normalizeUsername(x && x.username) === u) || null;
  }

  function getCurrentUser() {
    const u = getCurrentUsername();
    if (!u) return null;
    const normalizedUsername = normalizeUsername(u);
    const storedUser = getUserByUsername(normalizedUsername);

    if (IS_WP_SHARED_MODE) {
      const perms = getEffectiveWpPerms();
      if (perms) {
        return {
          ...(storedUser && typeof storedUser === 'object' ? storedUser : {}),
          username: normalizedUsername,
          permissions: perms,
        };
      }

      if (storedUser) {
        return {
          ...storedUser,
          username: normalizedUsername,
        };
      }
    }
    return storedUser;
  }

  function normalizePermissions(perms) {
    const p = perms && typeof perms === 'object' ? perms : {};

    const next = {};
    for (const def of PERMISSION_DEFS) {
      const own = Object.prototype.hasOwnProperty.call(p, def.key);
      let raw = own
        ? p[def.key]
        : (def.parent ? p[def.parent] : null);
      // Backward compatibility with old permission keys/structure.
      if (!own && def.key === 'income_bankeur' && Object.prototype.hasOwnProperty.call(p, 'income')) {
        raw = p.income;
      }
      if (!own && def.key === 'ledger_money_transfers' && Object.prototype.hasOwnProperty.call(p, 'ledger')) {
        raw = p.ledger;
      }
      if (!own && def.key === 'archive' && Object.prototype.hasOwnProperty.call(p, 'settings')) {
        raw = p.settings;
      }
      next[def.key] = normalizeAccessLevel(raw);
    }

    // Keep parent modules at least as permissive as any configured sub-category.
    for (const def of PERMISSION_DEFS) {
      if (!def.parent) continue;
      const childRank = ACCESS_LEVEL_RANK[next[def.key]] || 0;
      const parentRank = ACCESS_LEVEL_RANK[next[def.parent]] || 0;
      if (childRank > parentRank) next[def.parent] = next[def.key];
    }

    return next;
  }

  function isValidAccessLevel(level) {
    return ACCESS_LEVELS.includes(String(level || '').toLowerCase());
  }

  function hasOwnPermissionKey(perms, key) {
    if (!perms || typeof perms !== 'object') return false;
    if (!key) return false;
    return Object.prototype.hasOwnProperty.call(perms, key);
  }

  function hasAnyGranularChildPermissions(perms) {
    if (!perms || typeof perms !== 'object') return false;
    return PERMISSION_DEFS.some((def) => def && def.parent && hasOwnPermissionKey(perms, def.key));
  }

  function isChildPermissionKey(permKey) {
    if (!permKey) return false;
    return PERMISSION_DEFS.some((def) => def && def.key === permKey && def.parent);
  }

  function hasFullAdminPermissionSet(perms) {
    const p = normalizePermissions(perms);
    return p.budget === 'full'
      && p.income_bankeur === 'full'
      && p.orders === 'full'
      && p.ledger === 'full'
      && p.ledger_money_transfers === 'full'
      && p.archive === 'full'
      && p.settings === 'full';
  }

  function isAdminLikeUser(user) {
    if (!user) return false;
    if (isHardcodedAdminUsername(user.username)) return true;
    if (isAdminRoleValue(user.position) || isAdminRoleValue(user.role)) return true;
    if (hasFullAdminPermissionSet(user.permissions)) return true;
    const directPerms = normalizePermissions(user.permissions);
    if (directPerms.settings === 'full') return true;
    const full = getUserByUsername(user.username);
    if (full) {
      if (hasFullAdminPermissionSet(full.permissions)) return true;
      const fullPerms = normalizePermissions(full.permissions);
      if (fullPerms.settings === 'full') return true;
    }
    if (full && (isAdminRoleValue(full.position) || isAdminRoleValue(full.role))) return true;
    return false;
  }

  function hasModuleAccessLevel(user, permKey, minLevel) {
    if (!permKey) return true;
    if (isAdminLikeUser(user)) return true;
    if (STRICT_EXPLICIT_PERMISSION_KEYS.has(permKey)) {
      const rawPerms = user && user.permissions && typeof user.permissions === 'object'
        ? user.permissions
        : {};
      const hasGranularChildren = hasAnyGranularChildPermissions(rawPerms);
      if (hasGranularChildren && !hasOwnPermissionKey(rawPerms, permKey)) return false;
    }
    const p = getEffectivePermissions(user);
    const current = String((p && p[permKey]) || 'none').toLowerCase();
    const needed = isValidAccessLevel(minLevel) ? String(minLevel).toLowerCase() : 'read';
    const capabilities = ACCESS_LEVEL_CAPABILITIES[current] || ACCESS_LEVEL_CAPABILITIES.none;
    return Boolean(capabilities[needed]);
  }

  function getEffectivePermissions(user) {
    return normalizePermissions(user && user.permissions);
  }

  function isPublicItemizeDraft() {
    const base = getBasename(window.location.pathname);
    if (base !== 'itemize.html') return false;
    try {
      const params = new URLSearchParams(window.location.search || '');
      const isDraft = params.get('draft') === '1';
      const orderId = String(params.get('orderId') || '').trim();
      // Treat Itemize as public only for draft mode (new request flow).
      return isDraft && !orderId;
    } catch {
      return false;
    }
  }

  function requiredPermissionForPage(pathname) {
    const base = getBasename(pathname);

    // Public pages: always accessible without login.
    if (base === 'index.html') return null;
    if (base === 'itemize.html' && isPublicItemizeDraft()) return null;

    // Itemize for an existing order requires Itemize permission.
    if (base === 'itemize.html') return 'orders_itemize';

    return PAGE_PERMISSION_MAP[base] || null;
  }

  function isPublicRequestPage(pathname) {
    const base = getBasename(pathname);
    if (base === 'index.html') return true;
    if (base === 'about.html') return true;
    if (base === 'itemize.html') return isPublicItemizeDraft();
    return false;
  }

  function isRememberableAppPage(href) {
    const base = getBasename(href);
    if (!base || !base.endsWith('.html')) return false;
    if (base === 'loading.html') return false;
    try {
      const params = new URLSearchParams(String(href || '').split('?')[1] || '');
      if (params.get('logout') === '1') return false;
    } catch {
      // ignore
    }
    return true;
  }

  function rememberLastPageNow() {
    const base = getBasename(window.location.pathname);
    const href = `${base}${window.location.search || ''}`;
    if (!isRememberableAppPage(href)) return;
    try {
      sessionStorage.setItem(LAST_PAGE_KEY, href);
    } catch {
      // ignore
    }
  }

  function getRememberedLastPage() {
    try {
      return String(sessionStorage.getItem(LAST_PAGE_KEY) || '').trim();
    } catch {
      return '';
    }
  }

  function tryRedirectToRememberedPage(user) {
    const target = getRememberedLastPage();
    if (!target) return false;
    if (!isRememberableAppPage(target)) return false;

    const currentBase = getBasename(window.location.pathname);
    const currentHref = `${currentBase}${window.location.search || ''}`;
    if (target === currentHref) return false;

    const required = requiredPermissionForPage(target);
    if (required && user && !hasPermission(user, required)) return false;

    window.location.href = target;
    return true;
  }

  function hasPermission(user, permKey) {
    if (!permKey) return true;
    // Existing order itemization is reachable from Payment Orders.
    // Accept either explicit itemize permission or general orders access.
    if (permKey === 'orders_itemize') {
      return hasModuleAccessLevel(user, 'orders_itemize', 'read')
        || hasModuleAccessLevel(user, 'orders', 'read');
    }
    return hasModuleAccessLevel(user, permKey, 'read');
  }

  function hasExplicitPermission(user, permKey, minLevel = 'read') {
    if (!permKey) return true;
    if (!user || !user.permissions || typeof user.permissions !== 'object') return false;
    if (Object.prototype.hasOwnProperty.call(user.permissions, permKey)) {
      // Explicit key wins (including explicit "none").
      return hasModuleAccessLevel({ permissions: { [permKey]: user.permissions[permKey] } }, permKey, minLevel);
    }
    // Legacy fallback: if a child key is missing, defer to normalized/inherited permission.
    return hasModuleAccessLevel(user, permKey, minLevel);
  }

  function canWrite(user, permKey) {
    if (!permKey) return true;
    return hasModuleAccessLevel(user, permKey, 'write');
  }

  function canCreate(user, permKey) {
    if (!permKey) return true;
    return hasModuleAccessLevel(user, permKey, 'create');
  }

  function canDelete(user, permKey) {
    if (!permKey) return true;
    return hasModuleAccessLevel(user, permKey, 'delete');
  }

  function canBudgetEdit(user) {
    return canWrite(user, 'budget');
  }

  function canIncomeEdit(user) {
    return canWriteOrCreate(user, 'income_bankeur');
  }

  function canOrdersViewEdit(user) {
    return canWrite(user, 'orders');
  }

  function canOrdersItemizeRead(user) {
    return hasModuleAccessLevel(user, 'orders_itemize', 'read') || hasModuleAccessLevel(user, 'orders', 'read');
  }

  function canOrdersItemizeWrite(user) {
    return hasModuleAccessLevel(user, 'orders_itemize', 'write') || hasModuleAccessLevel(user, 'orders', 'write');
  }

  // Returns the role/position of a user, looking up from the stored users list when needed
  // (e.g. in WP shared mode the user object may only carry username + permissions).
  function getUserRole(user) {
    if (!user) return '';
    if (typeof user.position === 'string' && user.position.trim()) return normalizeRoleLabel(user.position);
    if (typeof user.role === 'string' && user.role.trim()) return normalizeRoleLabel(user.role);
    const full = getUserByUsername(user.username);
    if (full && typeof full.position === 'string' && full.position.trim()) return normalizeRoleLabel(full.position);
    return normalizeRoleLabel(String(full && full.role ? full.role : '').trim());
  }

  // Returns true if the given user is allowed to change the "With" field for the
  // specified current 'With' stage of the payment order approval workflow.
  function canChangeWithField(currentUser, currentWith) {
    if (!currentUser) return false;
    if (isHardcodedAdminUsername(currentUser.username)) return true;
    return canRoleManageWorkflowField('withField', getUserRole(currentUser), normalizeWith(currentWith));
  }

  // Returns true if the given user is allowed to change the "Status" field for the
  // specified current 'With' stage of the payment order approval workflow.
  function canChangeStatusField(currentUser, currentWith) {
    if (!currentUser) return false;
    if (isHardcodedAdminUsername(currentUser.username)) return true;
    return canRoleManageWorkflowField('statusField', getUserRole(currentUser), normalizeWith(currentWith));
  }

  function canSettingsEdit(user) {
    return canWrite(user, 'settings');
  }

  function requireBudgetEditAccess(message) {
    const user = getCurrentUser();
    if (!user) {
      window.alert('Please sign in.');
      return false;
    }
    if (!canBudgetEdit(user)) {
      window.alert(message || 'Read only access.');
      return false;
    }
    return true;
  }

  function requireIncomeEditAccess(message) {
    const user = getCurrentUser();
    if (!user) {
      window.alert('Please sign in.');
      return false;
    }
    if (!canIncomeEdit(user)) {
      window.alert(message || 'Read only access.');
      return false;
    }
    return true;
  }

  function requireWriteAccess(permKey, message, minLevel = 'write') {
    // Public New Request Form flow: allow creating a new request without login.
    // If editing an existing order, keep normal permission checks.
    if (permKey === 'orders' && isPublicRequestPage(window.location.pathname) && !getEditOrderId()) {
      // Anonymous users can submit new requests.
      // Signed-in users must have required access for Payment Orders to create.
      const maybeUser = getCurrentUser();
      if (!maybeUser) return true;
      if (!hasModuleAccessLevel(maybeUser, 'orders', minLevel)) {
        window.alert(message || 'Read only access.');
        return false;
      }
      return true;
    }

    if (IS_WP_SHARED_MODE) {
      const u = getCurrentUser();
      if (!u) {
        window.alert('Please sign in.');
        return false;
      }
    }

    const user = getCurrentUser();
    if (!user) {
      window.alert('Please sign in.');
      return false;
    }
    if (!hasModuleAccessLevel(user, permKey, minLevel)) {
      window.alert(message || 'Read only access.');
      return false;
    }
    return true;
  }

  function requireCreateAccess(permKey, message) {
    return requireWriteAccess(permKey, message, 'create');
  }

  function requireDeleteAccess(permKey, message) {
    return requireWriteAccess(permKey, message, 'delete');
  }

  function canWriteOrCreate(user, permKey) {
    if (!permKey) return true;
    return canWrite(user, permKey) || canCreate(user, permKey);
  }

  function requireWriteOrCreateAccess(permKey, message) {
    const user = getCurrentUser();
    if (!user) {
      window.alert('Please sign in.');
      return false;
    }
    if (!canWriteOrCreate(user, permKey)) {
      window.alert(message || 'Read only access.');
      return false;
    }
    return true;
  }

  function alertDisabledAction(el, fallback = 'Read only access.') {
    const msg = String(
      (el && (el.getAttribute('data-tooltip') || el.getAttribute('title'))) || fallback
    ).trim();
    window.alert(msg || fallback);
  }

  function requireOrdersViewEditAccess(message) {
    const user = getCurrentUser();
    if (!user) {
      window.alert('Please sign in.');
      return false;
    }
    if (!canOrdersViewEdit(user)) {
      window.alert(message || 'Read only access.');
      return false;
    }
    return true;
  }

  function requireSettingsEditAccess(message, permKey = 'settings') {
    // Bootstrap: allow initial setup before any users exist.
    const hasAnyUsers = loadUsers().length > 0;
    if (!hasAnyUsers) return true;

    const user = getCurrentUser();
    if (!user) {
      window.alert('Please sign in.');
      return false;
    }
    if (!canWrite(user, permKey)) {
      window.alert(message || 'Read only access.');
      return false;
    }
    return true;
  }

  function firstAllowedHrefForUser(user, resolvedYear) {
    const year = Number.isInteger(Number(resolvedYear)) ? Number(resolvedYear) : getActiveBudgetYear();
    const order = [
      { key: 'orders', href: `menu.html?year=${encodeURIComponent(String(year))}` },
      { key: 'income_bankeur', href: `income.html?year=${encodeURIComponent(String(year))}` },
      { key: 'budget', href: `budget_dashboard.html?year=${encodeURIComponent(String(year))}` },
      { key: 'ledger', href: `grand_secretary_ledger.html?year=${encodeURIComponent(String(year))}` },
      { key: 'settings', href: 'settings.html' },
    ];
    for (const it of order) {
      if (hasPermission(user, it.key)) return withWpEmbedParams(it.href);
    }
    return withWpEmbedParams('settings.html');
  }

  function getPaymentOrdersKeyForYear(year) {
    const y = Number(year);
    if (!Number.isInteger(y)) return null;
    if (y < 1900 || y > 3000) return null;
    return `payment_orders_${y}_v1`;
  }

  function getPaymentOrdersReconciliationKeyForYear(year) {
    const y = Number(year);
    if (!Number.isInteger(y)) return null;
    if (y < 1900 || y > 3000) return null;
    return `payment_orders_reconciliation_${y}_v1`;
  }

  function getMoneyTransfersKeyForYear(year) {
    const y = Number(year);
    if (!Number.isInteger(y)) return null;
    if (y < 1900 || y > 3000) return null;
    return `money_transfers_${y}_v1`;
  }

  function migrateLegacyOrdersIfNeeded(targetYear) {
    try {
      if (localStorage.getItem(PAYMENT_ORDERS_LEGACY_MIGRATED_KEY)) return;

      const legacyRaw = localStorage.getItem(STORAGE_KEY);
      if (!legacyRaw) {
        localStorage.setItem(
          PAYMENT_ORDERS_LEGACY_MIGRATED_KEY,
          JSON.stringify({ at: new Date().toISOString(), year: Number(targetYear) || null, count: 0 })
        );
        return;
      }

      let legacyParsed = [];
      try {
        const parsed = JSON.parse(legacyRaw);
        legacyParsed = Array.isArray(parsed) ? parsed : [];
      } catch {
        legacyParsed = [];
      }

      if (legacyParsed.length === 0) {
        localStorage.setItem(
          PAYMENT_ORDERS_LEGACY_MIGRATED_KEY,
          JSON.stringify({ at: new Date().toISOString(), year: Number(targetYear) || null, count: 0 })
        );
        return;
      }

      const key = getPaymentOrdersKeyForYear(targetYear);
      if (!key) return;

      // If the target year already has orders, do not merge automatically.
      if (!localStorage.getItem(key)) {
        localStorage.setItem(key, JSON.stringify(legacyParsed));
      }

      // Keep the legacy key as a backup; mark migration as done.
      localStorage.setItem(
        PAYMENT_ORDERS_LEGACY_MIGRATED_KEY,
        JSON.stringify({ at: new Date().toISOString(), year: Number(targetYear) || null, count: legacyParsed.length })
      );
    } catch {
      // ignore
    }
  }

  function getCurrentBudgetYearFromDate(d) {
    const date = d instanceof Date ? d : new Date();
    const physicalYear = date.getFullYear();
    const month = date.getMonth(); // 0=Jan ... 3=Apr
    // Budget runs roughly Apr→Apr. Apr–Dec belongs to next budget year.
    return month >= 3 ? physicalYear + 1 : physicalYear;
  }

  function loadActiveBudgetYear() {
    const parseYear = (raw) => {
      const y = Number(raw);
      if (!Number.isInteger(y)) return null;
      if (y < 1900 || y > 3000) return null;
      return y;
    };

    try {
      const primary = parseYear(localStorage.getItem(ACTIVE_BUDGET_YEAR_KEY));
      if (primary) return primary;
      return parseYear(localStorage.getItem(ACTIVE_BUDGET_YEAR_FALLBACK_KEY));
    } catch {
      return null;
    }
  }

  function saveActiveBudgetYear(year) {
    const y = Number(year);
    if (!Number.isInteger(y) || y < 1900 || y > 3000) return;
    localStorage.setItem(ACTIVE_BUDGET_YEAR_KEY, String(y));
    // Local-only fallback: protects user selection if shared hydration temporarily
    // serves stale/missing active-year data during updates or reloads.
    localStorage.setItem(ACTIVE_BUDGET_YEAR_FALLBACK_KEY, String(y));
  }

  function clearActiveBudgetYear() {
    try {
      localStorage.removeItem(ACTIVE_BUDGET_YEAR_KEY);
      localStorage.removeItem(ACTIVE_BUDGET_YEAR_FALLBACK_KEY);
    } catch {
      // ignore
    }
  }

  function getBudgetTableKeyForYear(year) {
    const y = Number(year);
    if (!Number.isInteger(y)) return null;
    return `payment_order_budget_table_html_${y}_v1`;
  }

  function getBudgetMetaKeyForYear(year) {
    const y = Number(year);
    if (!Number.isInteger(y)) return null;
    return `payment_order_budget_meta_${y}_v1`;
  }

  function loadBudgetMeta(year) {
    const y = Number.isInteger(Number(year)) ? Number(year) : getActiveBudgetYear();
    const key = getBudgetMetaKeyForYear(y);
    if (!key) return { createdAt: '', createdDate: '' };
    try {
      const raw = localStorage.getItem(key);
      if (!raw) return { createdAt: '', createdDate: '' };
      const parsed = JSON.parse(raw);
      return {
        createdAt: String((parsed && parsed.createdAt) || ''),
        createdDate: String((parsed && parsed.createdDate) || ''),
      };
    } catch {
      return { createdAt: '', createdDate: '' };
    }
  }

  function saveBudgetMeta(meta, year) {
    const y = Number.isInteger(Number(year)) ? Number(year) : getActiveBudgetYear();
    const key = getBudgetMetaKeyForYear(y);
    if (!key) return;
    const prev = loadBudgetMeta(y);
    const createdAt = String((meta && meta.createdAt) || '').trim();
    const createdDate = String((meta && meta.createdDate) || '').trim();
    const payload = { createdAt, createdDate };
    localStorage.setItem(key, JSON.stringify(payload));
    if (auditStableStringify(prev) !== auditStableStringify(payload)) {
      const action = (prev && (prev.createdAt || prev.createdDate)) ? 'Modified' : 'Created';
      appendAppAuditEvent(`Budget (${y})`, `Budget ${y}`, action, buildAuditChangesSummary(prev, payload));
    }
  }

  function ensureBudgetMetaExistsForYear(year, { createdAt } = {}) {
    const y = Number(year);
    if (!Number.isInteger(y)) return { ok: false, created: false };
    const key = getBudgetMetaKeyForYear(y);
    if (!key) return { ok: false, created: false };
    try {
      const existing = localStorage.getItem(key);
      if (existing !== null) return { ok: true, created: false };
      const iso = String(createdAt || new Date().toISOString());
      saveBudgetMeta({ createdAt: iso, createdDate: formatIsoDateOnly(iso) }, y);
      return { ok: true, created: true };
    } catch {
      return { ok: false, created: false };
    }
  }

  function loadBudgetYears() {
    try {
      const raw = localStorage.getItem(BUDGET_YEARS_KEY);
      if (!raw) return [];
      const parsed = JSON.parse(raw);
      if (!Array.isArray(parsed)) return [];
      const years = parsed
        .map((v) => Number(v))
        .filter((v) => Number.isInteger(v));
      return Array.from(new Set(years)).sort((a, b) => b - a);
    } catch {
      return [];
    }
  }

  function saveBudgetYears(years) {
    const prev = loadBudgetYears();
    const normalized = Array.from(new Set((years || []).map((v) => Number(v)).filter((v) => Number.isInteger(v))))
      .sort((a, b) => b - a);
    localStorage.setItem(BUDGET_YEARS_KEY, JSON.stringify(normalized));
    if (auditStableStringify(prev) !== auditStableStringify(normalized)) {
      appendAppAuditEvent('Budget Years', 'Budget year list', 'Modified', [
        { field: 'Years', from: prev.join(', ') || '—', to: normalized.join(', ') || '—' },
      ]);
    }
    return normalized;
  }

  function ensureBudgetYearExists(year, initialHtml) {
    const y = Number(year);
    if (!Number.isInteger(y)) return;
    const key = getBudgetTableKeyForYear(y);
    if (!key) return;

    const years = loadBudgetYears();
    if (!years.includes(y)) saveBudgetYears([y, ...years]);

    if (typeof initialHtml === 'string' && !localStorage.getItem(key)) {
      localStorage.setItem(key, initialHtml);
      // Record the budget's creation date the first time this year is created.
      ensureBudgetMetaExistsForYear(y);
    }
  }

  function isBudgetTemplateSectionValue(v) {
    return v === 1 || v === 2;
  }

  function isValidBudgetCalcOp(v) {
    return v === 'add' || v === 'subtract';
  }

  function normalizeBudgetTemplateText(v) {
    return String(v ?? '').replace(/\u00A0/g, ' ').trim();
  }

  function normalizeBudgetTemplateRow(row) {
    if (!row || typeof row !== 'object') return null;
    const section = Number(row.section);
    if (!isBudgetTemplateSectionValue(section)) return null;
    const inVal = normalizeBudgetTemplateText(row.in);
    const outVal = normalizeBudgetTemplateText(row.out);
    const description = normalizeBudgetTemplateText(row.description);

    // Skip completely empty rows.
    if (!inVal && !outVal && !description) return null;

    const calcReceiptsOp = isValidBudgetCalcOp(row.calcReceiptsOp) ? row.calcReceiptsOp : '';
    const calcExpendituresOp = isValidBudgetCalcOp(row.calcExpendituresOp) ? row.calcExpendituresOp : '';

    return {
      section,
      in: inVal,
      out: outVal,
      description,
      calcReceiptsOp,
      calcExpendituresOp,
    };
  }

  function loadBudgetTemplateRows() {
    try {
      const raw = localStorage.getItem(BUDGET_TEMPLATE_ROWS_KEY);
      if (!raw) return [];
      const parsed = JSON.parse(raw);
      if (!Array.isArray(parsed)) return [];
      const normalized = parsed.map(normalizeBudgetTemplateRow).filter(Boolean);
      return normalized;
    } catch {
      return [];
    }
  }

  function saveBudgetTemplateRows(rows) {
    const prev = loadBudgetTemplateRows();
    const normalized = Array.isArray(rows) ? rows.map(normalizeBudgetTemplateRow).filter(Boolean) : [];
    try {
      localStorage.setItem(BUDGET_TEMPLATE_ROWS_KEY, JSON.stringify(normalized));
    } catch {
      // ignore
    }
    if (auditStableStringify(prev) !== auditStableStringify(normalized)) {
      const action = prev.length === 0 && normalized.length > 0 ? 'Created' : 'Modified';
      appendAppAuditEvent('Budget Template', 'Template rows', action, [
        { field: 'Rows', from: `${prev.length} item(s)`, to: `${normalized.length} item(s)` },
      ]);
    }
    return normalized;
  }

  function readBudgetTemplateRowsFromTbodyEl(tbodyEl) {
    const tbody = tbodyEl;
    if (!tbody) return [];

    const allRows = Array.from(tbody.querySelectorAll('tr'));
    const totals = allRows.filter((r) => r.classList.contains('budgetTable__total'));
    const firstTotalIndex = totals.length >= 1 ? allRows.indexOf(totals[0]) : -1;
    const secondTotalIndex = totals.length >= 2 ? allRows.indexOf(totals[1]) : -1;

    const rows = [];
    for (const tr of allRows) {
      if (tr.classList.contains('budgetTable__spacer')) continue;
      if (tr.classList.contains('budgetTable__total')) continue;
      if (tr.classList.contains('budgetTable__remaining')) continue;
      if (tr.classList.contains('budgetTable__checksum')) continue;

      const tds = Array.from(tr.querySelectorAll('td'));
      if (tds.length < 7) continue;

      const rowIndex = allRows.indexOf(tr);
      const section = firstTotalIndex >= 0 && rowIndex >= 0 && rowIndex < firstTotalIndex ? 1 : 2;

      const inVal = normalizeBudgetTemplateText(tds[0]?.textContent);
      const outVal = normalizeBudgetTemplateText(tds[1]?.textContent);
      const desc = normalizeBudgetTemplateText(tds[2]?.textContent);
      if (!inVal && !outVal && !desc) continue;

      const kind = section === 2 ? 'budget' : 'anticipated';
      const ops = getBudgetCalcOpsForRow(kind, tr, desc);
      const receiptsOp = isValidBudgetCalcOp(tr.dataset && tr.dataset.calcReceipts) ? tr.dataset.calcReceipts : ops.receiptsOp;
      const expendituresOp = isValidBudgetCalcOp(tr.dataset && tr.dataset.calcExpenditures) ? tr.dataset.calcExpenditures : ops.expendituresOp;

      rows.push({
        section,
        in: inVal,
        out: outVal,
        description: desc,
        calcReceiptsOp: receiptsOp,
        calcExpendituresOp: expendituresOp,
      });
    }
    return saveBudgetTemplateRows(rows);
  }

  function readBudgetTemplateRowsFromTbodyHtml(tbodyHtml) {
    const html = String(tbodyHtml ?? '');
    if (!html.trim()) return [];
    try {
      const parser = new DOMParser();
      const doc = parser.parseFromString(`<table><tbody>${html}</tbody></table>`, 'text/html');
      const tbody = doc.querySelector('tbody');
      if (!tbody) return [];
      return readBudgetTemplateRowsFromTbodyEl(tbody);
    } catch {
      return [];
    }
  }

  function updateBudgetTemplateRowsFromBudgetYear(year) {
    const y = Number(year);
    if (!Number.isInteger(y)) return [];
    const key = getBudgetTableKeyForYear(y);
    if (!key) return [];
    const html = localStorage.getItem(key);
    if (!html) return [];
    return readBudgetTemplateRowsFromTbodyHtml(html);
  }

  function migrateLegacyBudgetIfNeeded() {
    const years = loadBudgetYears();
    if (years.length > 0) return years;

    const legacyHtml = localStorage.getItem(BUDGET_TABLE_HTML_KEY);
    if (!legacyHtml) return [];

    const currentYear = getCurrentBudgetYearFromDate(new Date());
    const key = getBudgetTableKeyForYear(currentYear);
    if (key && !localStorage.getItem(key)) {
      localStorage.setItem(key, legacyHtml);
    }

    return saveBudgetYears([currentYear]);
  }

  function getBudgetYearFromUrl() {
    try {
      const params = new URLSearchParams(window.location.search);
      const y = Number(params.get('year'));
      if (!Number.isInteger(y)) return null;
      if (y < 1900 || y > 3000) return null;
      return y;
    } catch {
      return null;
    }
  }

  function getActiveBudgetYear() {
    const fromUrl = getBudgetYearFromUrl();
    if (fromUrl) return fromUrl;
    const years = migrateLegacyBudgetIfNeeded();

    const active = loadActiveBudgetYear();
    if (active && (years.length === 0 || years.includes(active))) return active;

    if (years.length > 0) return years[0];
    return getCurrentBudgetYearFromDate(new Date());
  }

  function getLoginLandingBudgetYear() {
    const years = migrateLegacyBudgetIfNeeded();
    const active = loadActiveBudgetYear();
    if (active && (years.length === 0 || years.includes(active))) return active;
    if (years.length > 0) return years[0];
    return getCurrentBudgetYearFromDate(new Date());
  }

  function getNavConfig() {
    const years = migrateLegacyBudgetIfNeeded();
    const navYears = years.length > 0 ? years : [getCurrentBudgetYearFromDate(new Date())];
    const currentUser = getCurrentUser();
    const currentPageYear = getBudgetYearFromUrl();
    const activeYear = (() => {
      const stored = loadActiveBudgetYear();
      if (stored && navYears.includes(stored)) return stored;
      return null;
    })();
    const resolvedYear = (() => {
      if (currentPageYear && (years.length === 0 || navYears.includes(currentPageYear))) return currentPageYear;
      const storedActive = loadActiveBudgetYear();
      if (storedActive && navYears.includes(storedActive)) return storedActive;
      const candidate = getCurrentBudgetYearFromDate(new Date());
      if (navYears.includes(candidate)) return candidate;
      return navYears.length ? navYears[0] : candidate;
    })();
    const maybeWrapNavForWp = (items) => {
      if (!IS_WP_SHARED_MODE) return items;
      return items.map((it) => {
        const out = { ...it };
        if (out.href) out.href = withWpEmbedParams(out.href);
        if (Array.isArray(out.children)) {
          out.children = out.children.map((child) => {
            const childOut = { ...child };
            if (childOut.href) childOut.href = withWpEmbedParams(childOut.href);
            return childOut;
          });
        }
        return out;
      });
    };

    const config = maybeWrapNavForWp([
      { key: null, label: 'New Request Form', href: 'index.html?new=1' },
      {
        key: 'budget',
        label: 'Budget',
        // Parent should open the current budget year.
        href: `budget.html?year=${encodeURIComponent(String(resolvedYear))}`,
        children: [
          // Child #1: Dashboard for the current year.
          { key: 'budget_dashboard', label: 'Dashboard', href: `budget_dashboard.html?year=${encodeURIComponent(String(resolvedYear))}` },
          // Child #2+: Current year link first, then remaining budget years.
          ...[resolvedYear, ...navYears.filter((y) => y !== resolvedYear)].map((year) => ({
            label: String(year),
            href: `budget.html?year=${encodeURIComponent(String(year))}`,
            isActiveBudgetYear: resolvedYear === year || activeYear === year,
          })),
        ],
      },
      {
        key: 'ledger',
        label: 'Ledger',
        href: `grand_secretary_ledger.html?year=${encodeURIComponent(String(resolvedYear))}`,
        children: [
          ...(hasExplicitPermission(currentUser, 'income_bankeur')
            ? [
              {
                key: 'income_bankeur',
                label: 'BankEUR',
                href: `income.html?year=${encodeURIComponent(String(resolvedYear))}`,
              },
            ]
            : []),
          {
            key: 'ledger_wiseeur',
            label: 'wiseEUR',
            href: `wise_eur.html?year=${encodeURIComponent(String(resolvedYear))}`,
          },
          {
            key: 'ledger_wiseusd',
            label: 'wiseUSD',
            href: `wise_usd.html?year=${encodeURIComponent(String(resolvedYear))}`,
          },
          ...navYears.map((year) => ({
            label: String(year),
            href: `grand_secretary_ledger.html?year=${encodeURIComponent(String(year))}`,
          })),
        ],
      },
      {
        key: 'orders',
        label: 'Payment Orders',
        href: `menu.html?year=${encodeURIComponent(String(resolvedYear))}`,
        children: [
          {
            key: 'orders_reconciliation',
            label: 'Reconciliations',
            href: `reconciliation.html?year=${encodeURIComponent(String(resolvedYear))}`,
          },
          ...navYears.map((year) => ({
            label: String(year),
            href: `menu.html?year=${encodeURIComponent(String(year))}`,
          })),
        ],
      },
      {
        key: 'ledger_money_transfers',
        label: 'Money Transfers',
        href: `money_transfers.html?year=${encodeURIComponent(String(resolvedYear))}`,
        children: navYears.map((year) => ({
          label: String(year),
          href: `money_transfers.html?year=${encodeURIComponent(String(year))}`,
        })),
      },
      { key: 'archive', label: 'Archive', href: 'archive.html' },
      { key: 'settings', label: 'Admin Settings', href: 'settings.html' },
      { key: null, label: 'User Guide', href: 'user_guide.html' },
      { key: null, label: 'Help Center', href: 'help.html' },
      { key: null, label: 'About', href: 'about.html' },
      { key: null, label: 'Log out', href: 'index.html?logout=1' },
    ]);

    // If no user is logged in, keep nav minimal.
    if (!currentUser) {
      return maybeWrapNavForWp([
        { key: null, label: 'New Request Form', href: 'index.html?new=1' },
      ]);
    }

    // Filter nav by role permissions.
    return config
      .filter((it) => hasExplicitPermission(currentUser, it.key))
      .map((it) => ({
        ...it,
        children: Array.isArray(it.children)
          ? it.children.filter((child) => {
            const childKey = child && child.key ? child.key : null;
            if (childKey === 'orders_reconciliation') return true;
            return hasExplicitPermission(currentUser, childKey);
          })
          : it.children,
      }));
  }

  async function wpAuthLogin(usernameRaw, passwordRaw) {
    if (!IS_WP_SHARED_MODE) return { ok: false, error: 'not_wp_mode' };
    const username = normalizeUsername(usernameRaw);
    const password = String(passwordRaw || '').trim();
    if (!username || !password) return { ok: false, error: 'missing' };

    const url = wpJoin('acgl-fms/v1/auth/login');
    try {
      const headers = { 'Content-Type': 'application/json' };
      if (WP_REST_NONCE) headers['X-WP-Nonce'] = WP_REST_NONCE;

      const res = await fetch(url, {
        method: 'POST',
        // Do not send WordPress cookies; cookie auth can require a REST nonce and
        // cause 403 before our plugin handler runs.
        credentials: 'omit',
        headers,
        body: JSON.stringify({ username, password }),
      });

      if (!res.ok) {
        let serverError = '';
        let wpCode = '';
        try {
          const text = await res.text();
          if (text) {
            const parsed = safeJsonParse(text, null);
            if (parsed && typeof parsed.error === 'string') serverError = parsed.error;
            if (parsed && typeof parsed.code === 'string') wpCode = parsed.code;
            if (!serverError && parsed && typeof parsed.message === 'string') serverError = parsed.message;
          }
        } catch {
          // ignore
        }

        if (res.status === 429) return { ok: false, error: 'rate_limited', status: 429 };
        // Common WordPress REST failure modes should not be shown as "invalid password".
        if (res.status === 404 || wpCode === 'rest_no_route') return { ok: false, error: 'service_unavailable', status: res.status };
        if (res.status === 403) return { ok: false, error: 'forbidden', status: res.status };
        if (serverError) return { ok: false, error: serverError, status: res.status };
        return { ok: false, error: res.status >= 500 ? 'server_error' : 'invalid', status: res.status };
      }

      const data = await readJsonResponse(res);
      const token = String((data && data.token) || '').trim();
      if (!token) return { ok: false, error: 'invalid' };

      setWpToken(token);
      if (data && data.user && data.user.permissions) setWpPerms(data.user.permissions);
      if (typeof window.acglFmsWpHydrateSharedNow === 'function') {
        try {
          await window.acglFmsWpHydrateSharedNow();
        } catch {
          // ignore hydrate failures and continue login
        }
      }
      return { ok: true };
    } catch {
      return { ok: false, error: 'network' };
    }
  }
  const ACGL_LOGO_URL = 'https://acgl.online/wp-content/uploads/logos_grand_lodge/ACGL-Logo-Main.png';
  function authBrandHtml() {
    return `
      <div class="authGate__brand">
        <div class="acglLoader" aria-label="Loading">
          <img class="acglLoader__ring" src="${ACGL_LOGO_URL}" alt="" />
          <div class="acglLoader__stage" aria-hidden="true">
            <div class="acglLoader__coin">
              <img class="acglLoader__face acglLoader__front" src="${ACGL_LOGO_URL}" alt="" />
              <img class="acglLoader__face acglLoader__back" src="${ACGL_LOGO_URL}" alt="" />
            </div>
          </div>
        </div>
        <h1 class="authGate__brandTitle">Financial Management System (FMS)</h1>
      </div>
    `.trim();
  }

  function renderAuthGate() {
    const users = loadUsers();
    const hasAnyUsers = users.length > 0;
    const currentUser = getCurrentUser();

    const base = getBasename(window.location.pathname);

    // Public pages are always accessible without login.
    if (isPublicRequestPage(window.location.pathname)) {
      return { blocked: false };
    }

    // WordPress public mode: require in-app login token (not a WP login).
    if (IS_WP_SHARED_MODE) {
      const token = getWpToken();
      const currentUsername = getCurrentUsername();
      if (!token || !currentUsername || !currentUser) {
        const overlay = document.createElement('div');
        overlay.className = 'authGate';
        overlay.innerHTML = `
          <div class="authGate__card card">
            ${authBrandHtml()}
            <form id="authLoginForm" class="authGate__form" novalidate>
              <div class="field">
                <label for="authUsername">Username</label>
                <input id="authUsername" name="authUsername" type="text" autocomplete="username" required />
              </div>
              <div class="field">
                <label for="authPassword">Password</label>
                <input id="authPassword" name="authPassword" type="password" autocomplete="current-password" required />
              </div>
              <div id="authError" class="error" role="alert" aria-live="polite"></div>
              <div class="actions">
                <button type="submit" class="btn btn--primary">Sign in</button>
              </div>
            </form>
          </div>
        `.trim();
        document.body.appendChild(overlay);

        const form = overlay.querySelector('#authLoginForm');
        const userEl = overlay.querySelector('#authUsername');
        const passEl = overlay.querySelector('#authPassword');
        const errEl = overlay.querySelector('#authError');
        if (userEl && userEl.focus) userEl.focus();

        if (form) {
          form.addEventListener('submit', async (e) => {
            e.preventDefault();
            if (!userEl || !passEl) return;
            const u = normalizeUsername(userEl.value);
            const p = String(passEl.value || '').trim();

            const result = await wpAuthLogin(u, p);
            if (!result.ok) {
              if (errEl) {
                errEl.textContent = result.error === 'rate_limited'
                  ? 'Too many attempts. Please wait and try again.'
                  : result.error === 'missing' || result.error === 'missing_credentials'
                    ? 'Enter a username and password.'
                    : result.error === 'service_unavailable'
                      ? 'Sign-in service is unavailable. Please reload from the WordPress page or contact the site administrator.'
                      : result.error === 'forbidden'
                        ? 'Sign-in is blocked by the site. Please contact the site administrator.'
                    : result.error === 'server_error'
                      ? 'Sign-in service error. Please try again.'
                      : result.error === 'network'
                        ? 'Network error. Please check your connection and try again.'
                        : result.error === 'not_wp_mode'
                          ? 'WordPress connection info is missing. Please reload from the WordPress page.'
                          : 'Invalid username or password.';
              }
              return;
            }

            setCurrentUsername(u);
            await appendAuthAuditEvent('Login', u);
            const user = getCurrentUser();
            const currentRequired = requiredPermissionForPage(window.location.pathname);
            if (!currentRequired || hasPermission(user, currentRequired)) {
              window.location.reload();
              return;
            }
            const _year = getLoginLandingBudgetYear();
            window.location.href = hasPermission(user, 'budget')
              ? withWpEmbedParams(`budget_dashboard.html?year=${encodeURIComponent(String(_year))}`)
              : firstAllowedHrefForUser(user, _year);
          });
        }
        return { blocked: true };
      }

      // If logged in but lacks permission for this page, redirect.
      if (currentUser) {
        const required = requiredPermissionForPage(window.location.pathname);
        if (required && !hasPermission(currentUser, required)) {
          window.location.href = firstAllowedHrefForUser(currentUser, getActiveBudgetYear());
          return { blocked: true };
        }
      }

      return { blocked: false };
    }

    // If no users exist yet, force Settings so the first user can be created.
    // (Normally, a hard-coded admin is seeded into localStorage.)
    if (!hasAnyUsers && base !== 'settings.html') {
      const year = getActiveBudgetYear();
      window.location.href = `settings.html?year=${encodeURIComponent(String(year))}`;
      return { blocked: true };
    }

    // If users exist but none logged in, show login gate.
    if (hasAnyUsers && !currentUser) {
      const overlay = document.createElement('div');
      overlay.className = 'authGate';
      overlay.innerHTML = `
        <div class="authGate__card card">
          ${authBrandHtml()}
          <form id="authLoginForm" class="authGate__form" novalidate>
            <div class="field">
              <label for="authUsername">Username</label>
              <input id="authUsername" name="authUsername" type="text" autocomplete="username" required />
            </div>
            <div class="field">
              <label for="authPassword">Password</label>
              <input id="authPassword" name="authPassword" type="password" autocomplete="current-password" required />
            </div>
            <div id="authError" class="error" role="alert" aria-live="polite"></div>
            <div class="actions">
              <button type="submit" class="btn btn--primary">Sign in</button>
            </div>
          </form>
        </div>
      `.trim();
      document.body.appendChild(overlay);

      const form = overlay.querySelector('#authLoginForm');
      const userEl = overlay.querySelector('#authUsername');
      const passEl = overlay.querySelector('#authPassword');
      const errEl = overlay.querySelector('#authError');
      if (userEl && userEl.focus) userEl.focus();

      if (form) {
        form.addEventListener('submit', async (e) => {
          e.preventDefault();
          if (!userEl || !passEl) return;
          const u = normalizeUsername(userEl.value);
          const p = String(passEl.value || '');

          const user = getUserByUsername(u);
          if (!user) {
            if (errEl) errEl.textContent = 'Invalid username or password.';
            return;
          }
          const ok = await verifyPassword(p, user.salt, user.passwordHash);
          if (!ok) {
            if (errEl) errEl.textContent = 'Invalid username or password.';
            return;
          }

          // Persist the entered password for display in Settings.
          try {
            const users = loadUsers();
            const idx = users.findIndex((x) => normalizeUsername(x && x.username) === normalizeUsername(u));
            if (idx !== -1) {
              const nowIso = new Date().toISOString();
              users[idx] = { ...users[idx], passwordPlain: p, updatedAt: nowIso };
              saveUsers(users);
            }
          } catch {
            // ignore
          }

          setCurrentUsername(u);
          await appendAuthAuditEvent('Login', u);

          const required = requiredPermissionForPage(window.location.pathname);
          if (!hasPermission(user, required)) {
            window.location.href = firstAllowedHrefForUser(user, getActiveBudgetYear());
            return;
          }

          window.location.reload();
        });
      }
      return { blocked: true };
    }

    // If logged in but lacks permission for this page, redirect.
    if (currentUser) {
      const required = requiredPermissionForPage(window.location.pathname);
      if (required && !hasPermission(currentUser, required)) {
        window.location.href = firstAllowedHrefForUser(currentUser, getActiveBudgetYear());
        return { blocked: true };
      }
    }

    return { blocked: false };
  }

  function openAuthLoginOverlay() {
    if (!IS_WP_SHARED_MODE) {
      const users = loadUsers();
      const hasAnyUsers = users.length > 0;
      if (!hasAnyUsers) {
        // If no users exist yet, there is nothing to verify against.
        window.location.href = 'settings.html';
        return;
      }
    }

    const alreadyOpen = document.querySelector('.authGate[data-manual-auth-gate="1"]');
    if (alreadyOpen) {
      // If a previous manual gate is still in the DOM, bring it back/focus it
      // instead of no-op so Sign in never appears broken.
      alreadyOpen.hidden = false;
      try {
        alreadyOpen.removeAttribute('aria-hidden');
      } catch {
        // ignore
      }
      const existingUser = alreadyOpen.querySelector('#authUsername');
      if (existingUser && typeof existingUser.focus === 'function') existingUser.focus();
      return;
    }

    const overlay = document.createElement('div');
    overlay.className = 'authGate';
    overlay.setAttribute('data-manual-auth-gate', '1');
    overlay.innerHTML = `
      <div class="authGate__card card">
        ${authBrandHtml()}
        <form id="authLoginForm" class="authGate__form" novalidate>
          <div class="field">
            <label for="authUsername">Username</label>
            <input id="authUsername" name="authUsername" type="text" autocomplete="username" required />
          </div>
          <div class="field">
            <label for="authPassword">Password</label>
            <input id="authPassword" name="authPassword" type="password" autocomplete="current-password" required />
          </div>
          <div id="authError" class="error" role="alert" aria-live="polite"></div>
          <div class="actions">
            <button type="submit" class="btn btn--primary">Sign in</button>
          </div>
        </form>
      </div>
    `.trim();
    document.body.appendChild(overlay);

    const form = overlay.querySelector('#authLoginForm');
    const userEl = overlay.querySelector('#authUsername');
    const passEl = overlay.querySelector('#authPassword');
    const errEl = overlay.querySelector('#authError');
    if (userEl && userEl.focus) userEl.focus();

    if (form) {
      form.addEventListener('submit', async (e) => {
        e.preventDefault();
        if (!userEl || !passEl) return;
        const u = normalizeUsername(userEl.value);
        const p = String(passEl.value || '').trim();

        if (IS_WP_SHARED_MODE) {
          const result = await wpAuthLogin(u, p);
          if (!result.ok) {
            if (errEl) {
              errEl.textContent = result.error === 'rate_limited'
                ? 'Too many attempts. Please wait and try again.'
                : result.error === 'missing' || result.error === 'missing_credentials'
                  ? 'Enter a username and password.'
                  : result.error === 'service_unavailable'
                    ? 'Sign-in service is unavailable. Please reload from the WordPress page or contact the site administrator.'
                    : result.error === 'forbidden'
                      ? 'Sign-in is blocked by the site. Please contact the site administrator.'
                  : result.error === 'server_error'
                    ? 'Sign-in service error. Please try again.'
                    : result.error === 'network'
                      ? 'Network error. Please check your connection and try again.'
                      : result.error === 'not_wp_mode'
                        ? 'WordPress connection info is missing. Please reload from the WordPress page.'
                        : 'Invalid username or password.';
            }
            return;
          }

          setCurrentUsername(u);
          await appendAuthAuditEvent('Login', u);
          const user = getCurrentUser();
          const currentRequired = requiredPermissionForPage(window.location.pathname);
          if (!currentRequired || hasPermission(user, currentRequired)) {
            window.location.reload();
            return;
          }
          const _year = getLoginLandingBudgetYear();
          window.location.href = hasPermission(user, 'budget')
            ? withWpEmbedParams(`budget_dashboard.html?year=${encodeURIComponent(String(_year))}`)
            : firstAllowedHrefForUser(user, _year);
          return;
        }

        const user = getUserByUsername(u);
        if (!user) {
          if (errEl) errEl.textContent = 'Invalid username or password.';
          return;
        }
        const ok = await verifyPassword(p, user.salt, user.passwordHash);
        if (!ok) {
          if (errEl) errEl.textContent = 'Invalid username or password.';
          return;
        }

        // Persist the entered password for display in Settings.
        try {
          const users = loadUsers();
          const idx = users.findIndex((x) => normalizeUsername(x && x.username) === normalizeUsername(u));
          if (idx !== -1) {
            const nowIso = new Date().toISOString();
            users[idx] = { ...users[idx], passwordPlain: p, updatedAt: nowIso };
            saveUsers(users);
          }
        } catch {
          // ignore
        }

        setCurrentUsername(u);
        await appendAuthAuditEvent('Login', u);
        const currentRequired = requiredPermissionForPage(window.location.pathname);
        if (!currentRequired || hasPermission(user, currentRequired)) {
          window.location.reload();
          return;
        }
        const _year = getLoginLandingBudgetYear();
        window.location.href = hasPermission(user, 'budget')
          ? withWpEmbedParams(`budget_dashboard.html?year=${encodeURIComponent(String(_year))}`)
          : firstAllowedHrefForUser(user, _year);
      });
    }
  }

  function syncAuthHeaderBtn() {
    if (!authHeaderBtn) return;
    const user = getCurrentUser();
    if (user) {
      // When signed in, hide the header Sign in button.
      authHeaderBtn.hidden = true;
      authHeaderBtn.setAttribute('aria-hidden', 'true');
    } else {
      authHeaderBtn.hidden = false;
      authHeaderBtn.setAttribute('aria-hidden', 'false');
      authHeaderBtn.textContent = 'Sign in';
      authHeaderBtn.title = 'Sign in';
      authHeaderBtn.setAttribute('aria-label', 'Sign in');
    }
  }

  function syncRequestFormHamburgerVisibility() {
    if (!navToggleBtn) return;
    const base = getBasename(window.location.pathname);
    if (base !== 'index.html') return;

    const user = getCurrentUser();
    const show = Boolean(user);

    const navAside = document.getElementById('appNav');
    if (navAside) navAside.hidden = !show;

    navToggleBtn.hidden = !show;
    navToggleBtn.setAttribute('aria-hidden', String(!show));
    navToggleBtn.tabIndex = show ? 0 : -1;

    // Ensure nav is closed when anonymous (button is hidden so it can't be reopened).
    if (!show && appShell) {
      appShell.classList.add('appShell--navClosed');
    }

    // Keep aria state consistent when toggling visibility.
    updateNavToggleUi();
  }

  function getBasename(pathname) {
    const raw = String(pathname || '').replace(/\\/g, '/');
    const parts = raw.split('/').filter(Boolean);
    // When a static server serves / as index.html, the browser pathname is just "/".
    // Treat that as index.html so public-page logic behaves correctly.
    return parts.length ? parts[parts.length - 1].toLowerCase() : 'index.html';
  }

  function isActiveHref(href) {
    try {
      const current = new URL(window.location.href);
      const target = new URL(String(href || ''), current);

      if (getBasename(current.pathname) !== getBasename(target.pathname)) return false;

      for (const [k, v] of target.searchParams.entries()) {
        if (current.searchParams.get(k) !== v) return false;
      }
      return true;
    } catch {
      return false;
    }
  }

  function initNavTree() {
    const mounts = document.querySelectorAll('[data-nav-tree]');
    if (!mounts.length) return;

    const config = getNavConfig();
    let idSeq = 0;
    const isYearLabel = (label) => /^\d{4}$/.test(String(label || '').trim());

    for (const mount of mounts) {
      mount.innerHTML = '';

      const list = document.createElement('ul');
      list.className = 'appNavTree__list';

      for (const item of config) {
        const li = document.createElement('li');
        li.className = 'appNavTree__item';

        const children = Array.isArray(item.children) ? item.children : [];
        const visibleChildren = children.filter((c) => !isYearLabel(c && c.label));
        const isParent = visibleChildren.length > 0;

        if (!isParent) {
          const a = document.createElement('a');
          a.className = 'appNav__link';
          a.href = item.href;
          a.textContent = item.label;

          if (isActiveHref(item.href)) {
            a.classList.add('is-active');
            a.setAttribute('aria-current', 'page');
          }

          li.appendChild(a);
          list.appendChild(li);
          continue;
        }

        // Parent row: link + independent expand/collapse toggle.
        const row = document.createElement('div');
        row.className = 'appNavTree__row';

        const parentLink = document.createElement('a');
        parentLink.className = 'appNav__link';
        parentLink.href = item.href;
        parentLink.textContent = item.label;

        const childList = document.createElement('ul');
        childList.className = 'appNavTree__children';
        idSeq += 1;
        childList.id = `navChildren_${idSeq}`;

        let anyChildActive = false;
        for (const child of visibleChildren) {
          const childLi = document.createElement('li');
          childLi.className = 'appNavTree__childItem';

          const childA = document.createElement('a');
          childA.className = 'appNav__sublink';
          childA.href = child.href;
          childA.textContent = '';
          childA.appendChild(document.createTextNode(child.label));
          if (child.isActiveBudgetYear) {
            const badge = document.createElement('span');
            badge.className = 'appNavTree__badge';
            badge.textContent = ' (active)';
            childA.appendChild(badge);
          }

          if (isActiveHref(child.href)) {
            anyChildActive = true;
            childA.classList.add('is-active');
            childA.setAttribute('aria-current', 'page');
          }

          childLi.appendChild(childA);
          childList.appendChild(childLi);
        }

        const currentBase = getBasename(window.location.pathname);
        const parentIsActive =
          currentBase === getBasename(item.href) ||
          (item.key === 'budget' && (currentBase === 'budget.html' || currentBase === 'budget_dashboard.html'));
        if (parentIsActive || anyChildActive) {
          parentLink.classList.add('is-active');
        }

        // Default collapsed: the arrow controls open/close.
        const shouldBeOpen = false;
        li.classList.toggle('is-open', shouldBeOpen);
        childList.hidden = true;

        const toggleBtn = document.createElement('button');
        toggleBtn.type = 'button';
        toggleBtn.className = 'appNavTree__toggle';
        toggleBtn.setAttribute('aria-label', `Toggle ${item.label}`);
        toggleBtn.setAttribute('aria-controls', childList.id);
        toggleBtn.setAttribute('aria-expanded', 'false');
        toggleBtn.textContent = '▸';
        toggleBtn.addEventListener('click', (e) => {
          e.preventDefault();
          const nextOpen = !li.classList.contains('is-open');
          li.classList.toggle('is-open', nextOpen);
          childList.hidden = !nextOpen;
          toggleBtn.setAttribute('aria-expanded', nextOpen ? 'true' : 'false');
        });

        row.appendChild(parentLink);
        row.appendChild(toggleBtn);
        li.appendChild(row);
        li.appendChild(childList);
        list.appendChild(li);
      }

      mount.appendChild(list);

      // Footer row (very bottom): show who is signed in + when.
      const currentUser = getCurrentUser();
      if (currentUser) {
        const loginAtIso = ensureCurrentLoginAtIso();
        const loginAtText = formatLoginAtForDisplay(loginAtIso) || '—';
        const username = String(currentUser && currentUser.username ? currentUser.username : '').trim() || '—';

        const footer = document.createElement('div');
        footer.className = 'appNavSession';
        footer.setAttribute('data-nav-session-footer', '1');

        const seal = document.createElement('img');
        seal.className = 'appNavSession__seal';
        seal.src = ACGL_LOGO_URL;
        seal.alt = 'ACGL';
        seal.loading = 'lazy';

        const row1 = document.createElement('div');
        row1.className = 'appNavSession__row';
        row1.appendChild(document.createTextNode(`User: ${username}`));

        const row2 = document.createElement('div');
        row2.className = 'appNavSession__row';
        row2.appendChild(document.createTextNode(`Last: ${loginAtText}`));

        const meta = document.createElement('div');
        meta.className = 'appNavSession__meta';
        meta.appendChild(row1);
        meta.appendChild(row2);

        footer.appendChild(seal);
        footer.appendChild(meta);
        mount.appendChild(footer);
      }
    }
  }

  let navAutoSyncInstalled = false;
  function installNavAutoSync() {
    if (navAutoSyncInstalled) return;
    navAutoSyncInstalled = true;

    // Keep nav consistent across tabs/windows.
    // Note: the 'storage' event fires in OTHER documents, not the one doing the write.
    window.addEventListener('storage', (e) => {
      const key = e && typeof e.key === 'string' ? e.key : '';
      if (key === ACTIVE_BUDGET_YEAR_KEY || key === BUDGET_YEARS_KEY) {
        initNavTree();
      }
    });
  }

  // Backward compatibility for older pages that still call this.
  function initBudgetYearNav() {
    initNavTree();
  }

  const ORDER_STATUSES = ['Submitted', 'Review', 'Returned', 'Rejected', 'Approved', 'Paid'];
  const WITH_OPTIONS = ['Requestor', 'Grand Secretary', 'Grand Master', 'Grand Treasurer', 'Archives'];
  const SOURCE_OPTIONS = ['Commerzbank', 'wiseEUR', 'wiseUSD', 'Form Submission'];

  const BUDGET_ITEMS = [
    ['2020', 'New Lodge Petitions & Charter fees'],
    ['2030', 'Lodge Per Capita Dues'],
    ['2032', 'Lodge Dues Receipts'],
    ['2060', 'Grand Lodge - Charity - Specified'],
    ['2065', "Grand Master's Charity"],
    ['2061', 'Grand Lodge - Benevolent - Specified'],
    ['2070', 'Interest Income'],
    ['2071', 'Annual Registration Receipts'],
    ['2100', 'Expendable Supplies'],
    ['2110', 'Postage Account'],
    ['2120', 'IT & Digitization'],
    ['2140', 'Publications & Printing Account (certificates)'],
    ['2145', 'Publications & Printing of Rituals/Codes'],
    ['2150', 'Equipment Purchases - Repair & Maintenance'],
    ['2170', 'Audit and Legal Fees'],
    ['2180', 'Taxes/Insurances/Bonding Fees, etc.:'],
    ['2190', 'Annual & Semi Annual Expenses'],
    ['2200', 'Per Diem and Travel Expenses'],
    ['2201', 'Travel Expenses to VGLvD Senate Meetings'],
    ['2204', "Grand Master's Conference"],
    ['2211', 'Grand Secretaries salaries/liabilities'],
    ['2230', 'VGLvD Per Capita Dues'],
    ['2242', 'Flowers, Wreaths, Memorials:'],
    ['2243', 'Bank Charges & Fees'],
    ['2246', 'Bank Transfers - $ or EURO'],
    ['2249', 'Dues and Fees Other Than VGLvD'],
    ['2250', 'Grand Master Expense Account'],
    ['2280', 'Miscellaneous Reimbursable Items'],
    ['2998', 'Charity'],
  ];

  const BUDGET_DESC_BY_CODE = new Map(BUDGET_ITEMS.map(([code, desc]) => [code, desc]));

  const budgetDescCache = {
    outYear: null,
    outMap: null,
    inYear: null,
    inMap: null,
  };

  function getOutDescMapForYear(year) {
    const y = Number.isInteger(Number(year)) ? Number(year) : getActiveBudgetYear();
    if (budgetDescCache.outYear === y && budgetDescCache.outMap) return budgetDescCache.outMap;
    const map = new Map();
    for (const row of readOutAccountsFromBudgetYear(y)) {
      const code = String(row && row.outCode ? row.outCode : '').trim();
      const desc = String(row && row.desc ? row.desc : '').trim();
      if (/^\d{4}$/.test(code) && desc) map.set(code, desc);
    }
    budgetDescCache.outYear = y;
    budgetDescCache.outMap = map;
    return map;
  }

  function getInDescMapForYear(year) {
    const y = Number.isInteger(Number(year)) ? Number(year) : getActiveBudgetYear();
    if (budgetDescCache.inYear === y && budgetDescCache.inMap) return budgetDescCache.inMap;
    const map = new Map();
    for (const row of readInAccountsFromBudgetYear(y)) {
      const code = String(row && row.inCode ? row.inCode : '').trim();
      const desc = String(row && row.desc ? row.desc : '').trim();
      if (/^\d{4}$/.test(code) && desc) map.set(code, desc);
    }
    budgetDescCache.inYear = y;
    budgetDescCache.inMap = map;
    return map;
  }

  function inferDescFromBudgetNumberText(text) {
    const raw = String(text ?? '').trim();
    const m = raw.match(/^\d{4}\s*-\s*(.+)$/);
    return m ? String(m[1]).trim() : '';
  }

  function renderBudgetNumberSpanHtml(displayText, desc) {
    const display = String(displayText ?? '').trim();
    if (!display) return '';
    const tooltip = String(desc ?? '').trim();
    if (!tooltip) return escapeHtml(display);
    return `<span class="budgetCode" tabindex="0" data-tooltip="${escapeHtml(tooltip)}">${escapeHtml(display)}</span>`;
  }

  function renderOutBudgetNumberHtml(value, year, displayOverride) {
    const raw = String(value ?? '').trim();
    if (!raw) return '';
    const code = extractOutCodeFromBudgetNumberText(raw);
    const y = Number.isInteger(Number(year)) ? Number(year) : getActiveBudgetYear();

    const outMap = getOutDescMapForYear(y);
    const tableDesc = code && outMap ? outMap.get(code) : '';
    const lookupDesc = tableDesc || (code ? BUDGET_DESC_BY_CODE.get(code) : '') || '';
    const inferredDesc = lookupDesc || inferDescFromBudgetNumberText(raw);

    const display = displayOverride !== undefined ? String(displayOverride ?? '').trim() : raw;
    return renderBudgetNumberSpanHtml(display, inferredDesc);
  }

  function renderInBudgetNumberHtml(value, year, displayOverride) {
    const raw = String(value ?? '').trim();
    if (!raw) return '';
    const code = extractInCodeFromBudgetNumberText(raw);
    const y = Number.isInteger(Number(year)) ? Number(year) : getActiveBudgetYear();

    const inMap = getInDescMapForYear(y);
    const lookupDesc = code && inMap ? inMap.get(code) : '';
    const inferredDesc = lookupDesc || inferDescFromBudgetNumberText(raw);

    const display = displayOverride !== undefined ? String(displayOverride ?? '').trim() : code || raw;
    return renderBudgetNumberSpanHtml(display, inferredDesc);
  }

  function formatBudgetNumberForDisplay(value) {
    const raw = String(value ?? '').trim();
    if (!raw) return '';
    const m = raw.match(/^(\d{4})(?:\s*-\s*(.*))?$/);
    if (!m) return raw;
    const code = m[1];
    const desc = BUDGET_DESC_BY_CODE.get(code);
    if (desc) return `${code} - ${desc}`;
    if (m[2]) return `${code} - ${m[2]}`;
    return code;
  }

  function readOutAccountsFromBudgetYear(year) {
    const key = getBudgetTableKeyForYear(year);
    const html = key ? localStorage.getItem(key) : null;
    if (!html) return [];

    const tbody = document.createElement('tbody');
    tbody.innerHTML = String(html || '');

    const rows = Array.from(tbody.querySelectorAll('tr'));
    const seen = new Set();
    const outAccounts = [];

    for (const tr of rows) {
      if (tr.classList.contains('budgetTable__spacer')) continue;
      if (tr.classList.contains('budgetTable__total')) continue;
      if (tr.classList.contains('budgetTable__remaining')) continue;
      if (tr.classList.contains('budgetTable__checksum')) continue;

      const tds = tr.querySelectorAll('td');
      if (tds.length < 3) continue;

      const outCode = String(tds[1].textContent || '').trim();
      if (!/^\d{4}$/.test(outCode)) continue;

      if (seen.has(outCode)) continue;
      seen.add(outCode);

      const desc = String(tds[2].textContent || '').trim();
      outAccounts.push({ outCode, desc });
    }

    return outAccounts;
  }

  function readInAccountsFromBudgetYear(year) {
    const key = getBudgetTableKeyForYear(year);
    const html = key ? localStorage.getItem(key) : null;
    if (!html) return [];

    const tbody = document.createElement('tbody');
    tbody.innerHTML = String(html || '');

    const rows = Array.from(tbody.querySelectorAll('tr'));
    const seen = new Set();
    const inAccounts = [];

    for (const tr of rows) {
      if (tr.classList.contains('budgetTable__spacer')) continue;
      if (tr.classList.contains('budgetTable__total')) continue;
      if (tr.classList.contains('budgetTable__remaining')) continue;
      if (tr.classList.contains('budgetTable__checksum')) continue;

      const tds = tr.querySelectorAll('td');
      if (tds.length < 3) continue;

      const inCode = String(tds[0].textContent || '').trim();
      if (!/^\d{4}$/.test(inCode)) continue;

      if (seen.has(inCode)) continue;
      seen.add(inCode);

      const desc = String(tds[2].textContent || '').trim();
      inAccounts.push({ inCode, desc });
    }

    return inAccounts;
  }

  function formatInBudgetNumberForDisplay(value, year) {
    const raw = String(value ?? '').trim();
    if (!raw) return '';
    const y = Number.isInteger(Number(year)) ? Number(year) : getActiveBudgetYear();
    const items = readInAccountsFromBudgetYear(y);
    const match = items.find((x) => x && x.inCode === raw);
    if (match && match.desc) return `${raw} - ${match.desc}`;
    return raw;
  }

  function initBudgetNumberSelect() {
    const select = document.getElementById('budgetNumber');
    if (!select) return;

    // Preserve current selection when possible.
    const prevValue = String(select.value || '').trim();

    // Keep the placeholder (value="") option, remove the rest.
    const options = Array.from(select.querySelectorAll('option'));
    for (const opt of options) {
      if (String(opt.value) !== '') opt.remove();
    }

    const year = getActiveBudgetYear();
    const outAccounts = readOutAccountsFromBudgetYear(year);

    if (outAccounts.length === 0) {
      const none = document.createElement('option');
      none.value = '__none__';
      none.disabled = true;
      none.textContent = 'No OUT accounts found in the active budget';
      select.appendChild(none);
      return;
    }

    for (const item of outAccounts) {
      const opt = document.createElement('option');
      opt.value = item.outCode;
      opt.textContent = item.desc ? `${item.outCode} - ${item.desc}` : item.outCode;
      select.appendChild(opt);
    }

    if (prevValue && outAccounts.some((i) => i.outCode === prevValue)) {
      select.value = prevValue;
    }

    // Cross-tab sync: update the dropdown if the active budget/table changes elsewhere.
    if (!select.dataset.budgetNumbersBound) {
      select.dataset.budgetNumbersBound = 'true';
      window.addEventListener('storage', (e) => {
        const key = e && typeof e.key === 'string' ? e.key : '';
        if (
          key === ACTIVE_BUDGET_YEAR_KEY ||
          key === BUDGET_YEARS_KEY ||
          key.startsWith('payment_order_budget_table_html_')
        ) {
          initBudgetNumberSelect();
        }
      });
    }
  }

  function buildBudgetNumberOptionsHtml(selectedValue, year) {
    const y = Number.isInteger(Number(year)) ? Number(year) : getActiveBudgetYear();
    const selectedCode = extractOutCodeFromBudgetNumberText(selectedValue);
    const outAccounts = readOutAccountsFromBudgetYear(y);
    const options = ['<option value="">— Select —</option>'];
    for (const item of outAccounts) {
      if (!item || !item.outCode) continue;
      const selected = item.outCode === selectedCode ? ' selected' : '';
      const label = item.desc ? `${item.outCode} - ${item.desc}` : item.outCode;
      options.push(`<option value="${escapeHtml(item.outCode)}"${selected}>${escapeHtml(label)}</option>`);
    }
    return options.join('');
  }

  // ---- Budget impact from Approved payment orders ----

  function anticipatedReceiptsAreAddedByDescription(desc) {
    const d = String(desc ?? '').trim().toLowerCase();
    if (!d) return false;
    // Based on provided calculation sheet (Anticipated Values only):
    // - New Lodge Petitions & Charter fees -> Approved + Receipts - Expenditures
    // - Grand Lodge - Charity - Specified   -> Approved + Receipts - Expenditures
    // - Grand Master's Charity              -> Approved + Receipts - Expenditures
    // All other Anticipated lines use: Approved - Receipts - Expenditures
    const plusMatchers = [
      /new\s+lodge\s+petitions/, 
      /charter\s+fees?/, 
      /grand\s+lodge\s*-\s*charity\s*-\s*specified/, 
      /grand\s+master'?s\s+charity/, 
    ];
    return plusMatchers.some((re) => re.test(d));
  }

  function normalizeBudgetCalcToken(raw) {
    const s = String(raw ?? '').replace(/\u00A0/g, ' ').trim().toLowerCase();
    if (!s) return '';

    // Accept common variants from CSV templates
    if (s === '+' || s.includes('add') || s.includes('(+')) return 'add';
    if (s === '-' || s.includes('subtract') || s.includes('(-')) return 'subtract';
    if (s === '=' || s.includes('equals') || s.includes('(=') || s.includes(' = ')) return 'equals';

    // Fallback: operator anywhere in the token
    if (s.includes('+')) return 'add';
    if (s.includes('-')) return 'subtract';
    if (s.includes('=')) return 'equals';

    return '';
  }

  function getBudgetCalcOpsForRow(kind, rowEl, descText) {
    const receiptsOpFromRow = normalizeBudgetCalcToken(rowEl && rowEl.dataset ? rowEl.dataset.calcReceipts : '');
    const expendituresOpFromRow = normalizeBudgetCalcToken(rowEl && rowEl.dataset ? rowEl.dataset.calcExpenditures : '');

    const receiptsOp = receiptsOpFromRow === 'add' || receiptsOpFromRow === 'subtract'
      ? receiptsOpFromRow
      : (kind === 'budget' ? 'add' : (anticipatedReceiptsAreAddedByDescription(descText) ? 'add' : 'subtract'));

    const expendituresOp = expendituresOpFromRow === 'add' || expendituresOpFromRow === 'subtract'
      ? expendituresOpFromRow
      : 'subtract';

    return { receiptsOp, expendituresOp };
  }

  function computeBudgetBalance(approved, receipts, expenditures, ops) {
    const r = ops && ops.receiptsOp === 'add' ? receipts : -receipts;
    const e = ops && ops.expendituresOp === 'add' ? expenditures : -expenditures;
    return approved + r + e;
  }

  function parseBudgetMoney(text) {
    const raw = String(text ?? '').replace(/\u00A0/g, ' ').trim();
    if (!raw || raw === '-' || raw === '—') return 0;
    const isParenNeg = raw.includes('(') && raw.includes(')');
    const cleaned = raw.replace(/[^0-9.,\-]/g, '').replace(/,/g, '');
    const n = Number(cleaned);
    if (!Number.isFinite(n)) return 0;
    return isParenNeg ? -Math.abs(n) : n;
  }

  function formatBudgetEuro(amount) {
    const n = Number(amount);
    const safe = Number.isFinite(n) ? n : 0;
    return `${safe.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 })} €`;
  }

  function formatBudgetUsd(amount) {
    const n = Number(amount);
    const safe = Number.isFinite(n) ? n : 0;
    return `$ ${safe.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
  }

  function isBudgetEditableDataRow(row) {
    if (!row) return false;
    if (row.classList.contains('budgetTable__spacer')) return false;
    if (row.classList.contains('budgetTable__total')) return false;
    if (row.classList.contains('budgetTable__remaining')) return false;
    if (row.classList.contains('budgetTable__checksum')) return false;
    const tds = row.querySelectorAll('td');
    return tds.length >= 7;
  }

  function findBudgetRowForOutCode(rows, outCode, preferBudgetSection) {
    const code = String(outCode ?? '').trim();
    if (!/^\d{4}$/.test(code)) return null;

    const editableRows = rows.filter((r) => isBudgetEditableDataRow(r));
    if (editableRows.length === 0) return null;

    const totalRows = rows.filter((r) => r.classList.contains('budgetTable__total'));
    if (preferBudgetSection && totalRows.length >= 2) {
      const firstTotalIndex = rows.indexOf(totalRows[0]);
      const secondTotalIndex = rows.indexOf(totalRows[1]);
      if (firstTotalIndex >= 0 && secondTotalIndex > firstTotalIndex) {
        const section2 = rows.slice(firstTotalIndex + 1, secondTotalIndex).filter((r) => isBudgetEditableDataRow(r));
        const match = section2.find((r) => String(r.querySelectorAll('td')[1]?.textContent || '').trim() === code);
        if (match) return match;
      }
    }

    return editableRows.find((r) => String(r.querySelectorAll('td')[1]?.textContent || '').trim() === code) || null;
  }

  function findBudgetRowForInCode(rows, inCode, preferBudgetSection) {
    const code = String(inCode ?? '').trim();
    if (!/^[0-9]{4}$/.test(code)) return null;

    const editableRows = rows.filter((r) => isBudgetEditableDataRow(r));
    if (editableRows.length === 0) return null;

    const totalRows = rows.filter((r) => r.classList.contains('budgetTable__total'));
    if (preferBudgetSection && totalRows.length >= 2) {
      const firstTotalIndex = rows.indexOf(totalRows[0]);
      const secondTotalIndex = rows.indexOf(totalRows[1]);
      if (firstTotalIndex >= 0 && secondTotalIndex > firstTotalIndex) {
        const section2 = rows.slice(firstTotalIndex + 1, secondTotalIndex).filter((r) => isBudgetEditableDataRow(r));
        const match = section2.find((r) => String(r.querySelectorAll('td')[0]?.textContent || '').trim() === code);
        if (match) return match;
      }
    }

    return editableRows.find((r) => String(r.querySelectorAll('td')[0]?.textContent || '').trim() === code) || null;
  }

  /**
   * Apply one or more deltas to Budget "Receipts Euro" cells based on IN code.
   * This is used by Income entries to roll receipts into the matching budget year.
   */
  function applyIncomeBudgetReceiptsDeltas(year, deltas) {
    const y = Number(year);
    const key = getBudgetTableKeyForYear(y);
    if (!key) return { ok: false, reason: 'noBudgetKey' };

    const html = localStorage.getItem(key);
    if (!html) return { ok: false, reason: 'noBudgetHtml' };

    const list = Array.isArray(deltas) ? deltas : [];
    const normalized = list
      .map((d) => ({
        inCode: String(d && d.inCode ? d.inCode : '').trim(),
        deltaEuro: Number(d && d.deltaEuro),
      }))
      .filter((d) => /^[0-9]{4}$/.test(d.inCode) && Number.isFinite(d.deltaEuro) && d.deltaEuro !== 0);

    if (normalized.length === 0) return { ok: true, changed: false };

    const tbody = document.createElement('tbody');
    tbody.innerHTML = String(html || '');
    const rows = Array.from(tbody.querySelectorAll('tr'));

    // Validate all targets exist first (avoid partial updates).
    for (const d of normalized) {
      const target = findBudgetRowForInCode(rows, d.inCode, true);
      if (!target) return { ok: false, reason: 'rowNotFound', inCode: d.inCode };
    }

    // Apply deltas to Receipts Euro (td index 4) then recalc totals/balances.
    for (const d of normalized) {
      const targetRow = findBudgetRowForInCode(rows, d.inCode, true);
      if (!targetRow) return { ok: false, reason: 'rowNotFound', inCode: d.inCode };

      const tds = targetRow.querySelectorAll('td');
      if (tds.length < 7) return { ok: false, reason: 'invalidRow', inCode: d.inCode };

      const prev = parseBudgetMoney(tds[4]?.textContent);
      const next = prev + d.deltaEuro;
      if (tds[4]) tds[4].textContent = formatBudgetEuro(next);
    }

    recalculateBudgetTotalsInTbody(tbody);
    localStorage.setItem(key, tbody.innerHTML);
    return { ok: true, changed: true };
  }

  function extractInCodeFromBudgetNumberText(text) {
    const raw = String(text ?? '').trim();
    if (!raw) return '';
    const m = raw.match(/\b(\d{4})\b/);
    return m ? String(m[1]) : '';
  }

  function extractOutCodeFromBudgetNumberText(text) {
    const raw = String(text ?? '').trim();
    if (!raw) return '';
    const m = raw.match(/\b(\d{4})\b/);
    return m ? String(m[1]) : '';
  }

  // One-time/idempotent: for Income entries created before Budget linkage existed
  // (or imported), apply missing receipts impacts and mark them to prevent re-apply.
  function backfillIncomeBudgetReceiptImpactsIfNeeded(year) {
    const y = Number(year);
    const entries = loadIncome(y);
    if (!Array.isArray(entries) || entries.length === 0) return;

    const allowed = new Set(readInAccountsFromBudgetYear(y).map((x) => (x && x.inCode ? String(x.inCode).trim() : '')).filter(Boolean));
    if (allowed.size === 0) return;

    const toApply = [];
    for (const e of entries) {
      if (!e) continue;
      if (e.budgetReceiptImpact && typeof e.budgetReceiptImpact === 'object') continue;
      const code = extractInCodeFromBudgetNumberText(e.budgetNumber);
      const euro = Number(e.euro);
      if (!/^[0-9]{4}$/.test(code)) continue;
      if (!allowed.has(code)) continue;
      if (!Number.isFinite(euro) || euro <= 0) continue;
      toApply.push({ id: e.id, inCode: code, euro });
    }

    if (toApply.length === 0) return;

    const sums = new Map();
    for (const x of toApply) {
      sums.set(x.inCode, (sums.get(x.inCode) || 0) + x.euro);
    }
    const deltas = Array.from(sums.entries()).map(([inCode, sumEuro]) => ({ inCode, deltaEuro: sumEuro }));
    const budgetRes = applyIncomeBudgetReceiptsDeltas(y, deltas);
    if (!budgetRes || !budgetRes.ok) return;

    const nowIso = new Date().toISOString();
    const toApplyMap = new Map(toApply.map((x) => [x.id, x]));
    const next = entries.map((e) => {
      const x = e && e.id ? toApplyMap.get(e.id) : null;
      if (!e || !x) return e;
      return {
        ...e,
        budgetReceiptImpact: {
          at: nowIso,
          year: y,
          inCode: x.inCode,
          euro: x.euro,
        },
      };
    });
    saveIncome(next, y);
  }

  function recalculateBudgetTotalsInTbody(tbodyEl) {
    if (!tbodyEl) return;
    const rows = Array.from(tbodyEl.querySelectorAll('tr'));
    const totalRows = rows.filter((r) => r.classList.contains('budgetTable__total'));
    if (totalRows.length < 2) return;

    const firstTotalIndex = rows.indexOf(totalRows[0]);
    const secondTotalIndex = rows.indexOf(totalRows[1]);
    if (firstTotalIndex < 0 || secondTotalIndex < 0 || secondTotalIndex <= firstTotalIndex) return;

    const section1Rows = rows.slice(0, firstTotalIndex);
    const section2Rows = rows.slice(firstTotalIndex + 1, secondTotalIndex);

    function sumSectionAndUpdateBalances(sectionRows, kind) {
      const totals = {
        approved: 0,
        receipts: 0,
        expenditures: 0,
        balance: 0,
        receiptsUsd: 0,
        expendituresUsd: 0,
      };

      for (const row of sectionRows) {
        if (!isBudgetEditableDataRow(row)) continue;
        const tds = row.querySelectorAll('td');
        const approved = parseBudgetMoney(tds[3]?.textContent);
        const receipts = parseBudgetMoney(tds[4]?.textContent);
        const expenditures = parseBudgetMoney(tds[5]?.textContent);
        const desc = tds[2]?.textContent ?? '';
        const ops = getBudgetCalcOpsForRow(kind, row, desc);
        const balance = computeBudgetBalance(approved, receipts, expenditures, ops);

        totals.approved += approved;
        totals.receipts += receipts;
        totals.expenditures += expenditures;
        totals.balance += balance;

        // USD value columns (sign columns may be blank; value cells carry the number)
        totals.receiptsUsd += parseBudgetMoney(tds[8]?.textContent);
        totals.expendituresUsd += parseBudgetMoney(tds[10]?.textContent);

        // Keep Balance Euro consistent
        if (tds[6]) tds[6].textContent = formatBudgetEuro(balance);
      }

      return totals;
    }

    const s1 = sumSectionAndUpdateBalances(section1Rows, 'anticipated');
    const s2 = sumSectionAndUpdateBalances(section2Rows, 'budget');

    function updateTotalRow(totalRow, totals) {
      const tds = totalRow.querySelectorAll('td');
      if (tds.length < 11) return;
      tds[3].innerHTML = `<strong>${formatBudgetEuro(totals.approved)}</strong>`;
      tds[4].innerHTML = `<strong>${formatBudgetEuro(totals.receipts)}</strong>`;
      tds[5].innerHTML = `<strong>${formatBudgetEuro(totals.expenditures)}</strong>`;
      tds[6].innerHTML = `<strong>${formatBudgetEuro(totals.balance)}</strong>`;

      if (tds[7]) tds[7].textContent = '';
      if (tds[9]) tds[9].textContent = '';
      if (tds[8]) tds[8].innerHTML = `<strong>${formatBudgetUsd(totals.receiptsUsd)}</strong>`;
      if (tds[10]) tds[10].innerHTML = `<strong>${formatBudgetUsd(totals.expendituresUsd)}</strong>`;
    }

    updateTotalRow(totalRows[0], s1);
    updateTotalRow(totalRows[1], s2);

    const remainingRow = rows.find((r) => r.classList.contains('budgetTable__remaining'));
    if (remainingRow) {
      const cells = remainingRow.querySelectorAll('td');
      if (cells.length >= 7) {
        const remaining = s2.receipts + s1.balance - s2.expenditures;
        const valueCell = cells[6];
        if (valueCell) {
          valueCell.innerHTML = `<strong>${formatBudgetEuro(remaining)}</strong>`;
          if (remaining < 0) valueCell.classList.add('is-negative');
          else valueCell.classList.remove('is-negative');
        }
      }
    }

    // Checksum rows (if present)
    const receiptsChecksum = s1.receipts - s2.receipts;
    const expendituresChecksum = s1.expenditures - s2.expenditures;
    const checksumRows = Array.from(tbodyEl.querySelectorAll('tr.budgetTable__checksum'));
    for (const row of checksumRows) {
      const kind = row.getAttribute('data-checksum-kind');
      const tds = row.querySelectorAll('td');
      if (tds.length < 11) continue;

      if (kind === 'receipts') {
        tds[4].innerHTML = `<strong>${formatBudgetEuro(receiptsChecksum)}</strong>`;
        if (receiptsChecksum < 0) tds[4].classList.add('is-negative');
        else tds[4].classList.remove('is-negative');
      }

      if (kind === 'expenditures') {
        tds[5].innerHTML = `<strong>${formatBudgetEuro(expendituresChecksum)}</strong>`;
        if (expendituresChecksum < 0) tds[5].classList.add('is-negative');
        else tds[5].classList.remove('is-negative');
      }
    }
  }

  function applyApprovedOrderBudgetDeduction(order, year, appliedAtIso) {
    const y = Number(year);
    const key = getBudgetTableKeyForYear(y);
    if (!key) return { ok: false, reason: 'noBudgetKey' };

    const html = localStorage.getItem(key);
    if (!html) return { ok: false, reason: 'noBudgetHtml' };

    const outCode = String(order && order.budgetNumber ? order.budgetNumber : '').trim();
    if (!/^\d{4}$/.test(outCode)) return { ok: false, reason: 'invalidOutCode' };

    const euro = Number(order && order.euro);
    const usd = Number(order && order.usd);
    const euroAmount = Number.isFinite(euro) ? euro : 0;
    const usdAmount = Number.isFinite(usd) ? usd : 0;
    if (euroAmount === 0 && usdAmount === 0) return { ok: false, reason: 'zeroAmount' };

    const tbody = document.createElement('tbody');
    tbody.innerHTML = String(html || '');

    const rows = Array.from(tbody.querySelectorAll('tr'));
    const targetRow = findBudgetRowForOutCode(rows, outCode, true);
    if (!targetRow) return { ok: false, reason: 'rowNotFound' };

    // Detect which section the row belongs to so Balance Euro uses the right formula.
    // Balance Euro for budget section is: approved + receipts - expenditures
    // Balance Euro for anticipated section is: approved - receipts - expenditures
    let sectionKind = 'budget';
    const totalRows = rows.filter((r) => r.classList.contains('budgetTable__total'));
    if (totalRows.length >= 2) {
      const firstTotalIndex = rows.indexOf(totalRows[0]);
      const secondTotalIndex = rows.indexOf(totalRows[1]);
      const rowIndex = rows.indexOf(targetRow);
      if (rowIndex >= 0 && firstTotalIndex >= 0 && secondTotalIndex > firstTotalIndex) {
        if (rowIndex < firstTotalIndex) sectionKind = 'anticipated';
        else if (rowIndex > firstTotalIndex && rowIndex < secondTotalIndex) sectionKind = 'budget';
      }
    }

    const tds = targetRow.querySelectorAll('td');

    if (euroAmount !== 0) {
      const prevExp = parseBudgetMoney(tds[5]?.textContent);
      const nextExp = prevExp + euroAmount;
      if (tds[5]) tds[5].textContent = formatBudgetEuro(nextExp);

      const approved = parseBudgetMoney(tds[3]?.textContent);
      const receipts = parseBudgetMoney(tds[4]?.textContent);
      const desc = tds[2]?.textContent ?? '';
      const ops = getBudgetCalcOpsForRow(sectionKind, targetRow, desc);
      const balance = computeBudgetBalance(approved, receipts, nextExp, ops);
      if (tds[6]) tds[6].textContent = formatBudgetEuro(balance);
    }

    if (usdAmount !== 0) {
      const prevUsdExp = parseBudgetMoney(tds[10]?.textContent);
      const nextUsdExp = prevUsdExp + usdAmount;
      if (tds[10]) tds[10].textContent = formatBudgetUsd(nextUsdExp);
    }

    // Recalculate totals/remaining/checksums so dashboard stays consistent.
    recalculateBudgetTotalsInTbody(tbody);

    localStorage.setItem(key, tbody.innerHTML);

    return {
      ok: true,
      outCode,
      euroApplied: euroAmount,
      usdApplied: usdAmount,
      at: String(appliedAtIso || new Date().toISOString()),
    };
  }

  function applyOrderBudgetExpendituresDelta(outCode, year, euroDelta, usdDelta, appliedAtIso) {
    const y = Number(year);
    const key = getBudgetTableKeyForYear(y);
    if (!key) return { ok: false, reason: 'noBudgetKey' };

    const out = String(outCode ?? '').trim();
    if (!/^\d{4}$/.test(out)) return { ok: false, reason: 'invalidOutCode' };

    const euro = Number(euroDelta);
    const usd = Number(usdDelta);
    const euroAmount = Number.isFinite(euro) ? euro : 0;
    const usdAmount = Number.isFinite(usd) ? usd : 0;
    if (euroAmount === 0 && usdAmount === 0) {
      return { ok: true, changed: false, outCode: out, euroDelta: 0, usdDelta: 0, at: String(appliedAtIso || new Date().toISOString()) };
    }

    const html = localStorage.getItem(key);
    if (!html) return { ok: false, reason: 'noBudgetHtml' };

    const tbody = document.createElement('tbody');
    tbody.innerHTML = String(html || '');

    const rows = Array.from(tbody.querySelectorAll('tr'));
    const targetRow = findBudgetRowForOutCode(rows, out, true);
    if (!targetRow) return { ok: false, reason: 'rowNotFound', outCode: out };

    // Detect which section the row belongs to so Balance Euro uses the right formula.
    let sectionKind = 'budget';
    const totalRows = rows.filter((r) => r.classList.contains('budgetTable__total'));
    if (totalRows.length >= 2) {
      const firstTotalIndex = rows.indexOf(totalRows[0]);
      const secondTotalIndex = rows.indexOf(totalRows[1]);
      const rowIndex = rows.indexOf(targetRow);
      if (rowIndex >= 0 && firstTotalIndex >= 0 && secondTotalIndex > firstTotalIndex) {
        if (rowIndex < firstTotalIndex) sectionKind = 'anticipated';
        else if (rowIndex > firstTotalIndex && rowIndex < secondTotalIndex) sectionKind = 'budget';
      }
    }

    const tds = targetRow.querySelectorAll('td');
    if (tds.length < 11) return { ok: false, reason: 'invalidRow', outCode: out };

    if (euroAmount !== 0) {
      const prevExp = parseBudgetMoney(tds[5]?.textContent);
      const nextExp = prevExp + euroAmount;
      if (tds[5]) tds[5].textContent = formatBudgetEuro(nextExp);

      const approved = parseBudgetMoney(tds[3]?.textContent);
      const receipts = parseBudgetMoney(tds[4]?.textContent);
      const desc = tds[2]?.textContent ?? '';
      const ops = getBudgetCalcOpsForRow(sectionKind, targetRow, desc);
      const balance = computeBudgetBalance(approved, receipts, nextExp, ops);
      if (tds[6]) tds[6].textContent = formatBudgetEuro(balance);
    }

    if (usdAmount !== 0) {
      const prevUsdExp = parseBudgetMoney(tds[10]?.textContent);
      const nextUsdExp = prevUsdExp + usdAmount;
      if (tds[10]) tds[10].textContent = formatBudgetUsd(nextUsdExp);
    }

    recalculateBudgetTotalsInTbody(tbody);
    localStorage.setItem(key, tbody.innerHTML);

    return {
      ok: true,
      changed: true,
      outCode: out,
      euroDelta: euroAmount,
      usdDelta: usdAmount,
      at: String(appliedAtIso || new Date().toISOString()),
    };
  }

  function formatBudgetUsdOrDash(amount) {
    const n = Number(amount);
    const safe = Number.isFinite(n) ? n : 0;
    if (safe === 0) return '-';
    return formatBudgetUsd(safe);
  }

  function normalizeBudgetTemplateKeyText(v) {
    return String(v ?? '').replace(/\u00A0/g, ' ').trim();
  }

  function makeBudgetTemplateLineKey(inVal, outVal, desc) {
    const a = normalizeBudgetTemplateKeyText(inVal);
    const b = normalizeBudgetTemplateKeyText(outVal);
    if (a || b) return `${a}::${b}`;
    return `desc::${normalizeBudgetTemplateKeyText(desc).toLowerCase()}`;
  }

  function mockApprovedEuroForBudgetCode(code, section) {
    const raw = String(code ?? '').trim();
    if (!/^\d{4}$/.test(raw)) return 0;
    const n = Number(raw);
    if (!Number.isFinite(n)) return 0;

    const mod = n % 100;
    const isAnticipated = Number(section) === 1;
    const bump = isAnticipated ? 10 : 5;
    const scale = isAnticipated ? 100 : 200;
    return Math.max(0, (mod + bump) * scale);
  }

  function getMockApprovedEuroForTemplateRow(templateRow) {
    const r = templateRow || {};
    const section = Number(r.section) === 1 ? 1 : 2;
    const outCode = normalizeBudgetTemplateKeyText(r.out);
    const inCode = normalizeBudgetTemplateKeyText(r.in);
    const code = /^\d{4}$/.test(outCode) ? outCode : inCode;
    return mockApprovedEuroForBudgetCode(code, section);
  }

  function buildBudgetDataRowForTemplateRow(templateRow) {
    const r = templateRow || {};
    const inVal = normalizeBudgetTemplateKeyText(r.in);
    const outVal = normalizeBudgetTemplateKeyText(r.out);
    const desc = normalizeBudgetTemplateKeyText(r.description);

    const tr = document.createElement('tr');
    const receiptsOp = normalizeBudgetCalcToken(r.calcReceiptsOp);
    const expendituresOp = normalizeBudgetCalcToken(r.calcExpendituresOp);
    if (receiptsOp === 'add' || receiptsOp === 'subtract') tr.dataset.calcReceipts = receiptsOp;
    if (expendituresOp === 'add' || expendituresOp === 'subtract') tr.dataset.calcExpenditures = expendituresOp;

    tr.innerHTML = `
      <td class="num">${escapeHtml(inVal)}</td>
      <td class="num">${escapeHtml(outVal)}</td>
      <td>${escapeHtml(desc)}</td>
      <td class="num budgetTable__euro">0.00 €</td>
      <td class="num budgetTable__euro">0.00 €</td>
      <td class="num budgetTable__euro">0.00 €</td>
      <td class="num budgetTable__bal">0.00 €</td>
      <td class="budgetTable__usdSign">$</td>
      <td class="num budgetTable__usd">-</td>
      <td class="budgetTable__usdSign">$</td>
      <td class="num budgetTable__usd">-</td>
    `.trim();
    return tr;
  }

  function insertBudgetTemplateDataRowIntoSection(tbody, section, newRow) {
    const totals = tbody.querySelectorAll('tr.budgetTable__total');
    const firstTotal = totals.length >= 1 ? totals[0] : null;
    const secondTotal = totals.length >= 2 ? totals[1] : null;

    if (Number(section) === 1 && firstTotal) {
      const prev = firstTotal.previousElementSibling;
      const anchor = prev && prev.classList && prev.classList.contains('budgetTable__spacer') ? prev : firstTotal;
      anchor.insertAdjacentElement('beforebegin', newRow);
      return;
    }

    if (Number(section) === 2 && secondTotal) {
      secondTotal.insertAdjacentElement('beforebegin', newRow);
      return;
    }

    tbody.appendChild(newRow);
  }

  function ensureBudgetTemplateRowsExistInTbody(tbody, templateRows) {
    const normalized = Array.isArray(templateRows) ? templateRows.map(normalizeBudgetTemplateRow).filter(Boolean) : [];
    if (!normalized.length) return { added: 0 };

    const existingKeys = new Set();
    const allRows = Array.from(tbody.querySelectorAll('tr'));
    for (const tr of allRows) {
      if (!isBudgetEditableDataRow(tr)) continue;
      const tds = tr.querySelectorAll('td');
      const key = makeBudgetTemplateLineKey(tds[0]?.textContent, tds[1]?.textContent, tds[2]?.textContent);
      if (key) existingKeys.add(key);
    }

    let added = 0;
    for (const r of normalized) {
      const key = makeBudgetTemplateLineKey(r.in, r.out, r.description);
      if (!key || existingKeys.has(key)) continue;
      const rowEl = buildBudgetDataRowForTemplateRow(r);
      insertBudgetTemplateDataRowIntoSection(tbody, r.section, rowEl);
      existingKeys.add(key);
      added += 1;
    }

    return { added };
  }

  function applyMockApprovedEuroToBudgetTbody(tbody, year, { force = false } = {}) {
    const y = Number(year);
    if (!Number.isInteger(y)) return { ok: false, changed: false, reason: 'invalidYear' };
    if (!tbody) return { ok: false, changed: false, reason: 'noTbody' };

    const allRows = Array.from(tbody.querySelectorAll('tr'));
    const totals = allRows.filter((r) => r.classList.contains('budgetTable__total'));
    const firstTotalIndex = totals.length >= 1 ? allRows.indexOf(totals[0]) : -1;

    let changed = false;
    for (const tr of allRows) {
      if (!isBudgetEditableDataRow(tr)) continue;
      const tds = tr.querySelectorAll('td');
      if (tds.length < 7) continue;

      const rowIndex = allRows.indexOf(tr);
      const section = firstTotalIndex >= 0 && rowIndex >= 0 && rowIndex < firstTotalIndex ? 1 : 2;

      const inCode = String(tds[0]?.textContent || '').trim();
      const outCode = String(tds[1]?.textContent || '').trim();
      const code = /^\d{4}$/.test(outCode) ? outCode : inCode;

      const desired = formatBudgetEuro(mockApprovedEuroForBudgetCode(code, section));
      const prevText = String(tds[3]?.textContent ?? '').trim();

      if (!force) {
        const prev = parseBudgetMoney(prevText);
        if (Math.abs(prev) > 0.0001) continue;
      }

      if (tds[3] && prevText !== desired) {
        tds[3].textContent = desired;
        changed = true;
      }
    }

    return { ok: true, changed };
  }

  /**
   * Ledger-driven budget sync.
   *
   * Policy: Outside of Manual Budget edits and Budget CSV import,
   * the Budget table's Receipts/Expenditures columns are derived from the Ledger only.
   *
   * This recomputes Receipts/Expenditures (EUR + USD) from derived
   * Grand Secretary Ledger rows and writes them into the Budget table.
   */
  function syncBudgetFromLedger(year) {
    const y = Number(year);
    if (!Number.isInteger(y)) return { ok: false, reason: 'invalidYear' };

    const budgetKey = getBudgetTableKeyForYear(y);
    if (!budgetKey) return { ok: false, reason: 'noBudgetKey' };

    const html = localStorage.getItem(budgetKey);
    if (!html) return { ok: false, reason: 'noBudgetHtml' };

    // Safety: never risk pruning user rows due to HTML parsing/serialization quirks.
    // If parsing would drop any <tr> elements, abort without writing.
    const expectedTrCount = (String(html).match(/<tr\b/gi) || []).length;

    const ledgerRows = buildGsLedgerRowsForYear(y);
    const receiptsEuroByCode = new Map();
    const receiptsUsdByCode = new Map();
    const expendituresEuroByCode = new Map();
    const expendituresUsdByCode = new Map();

    for (const r of Array.isArray(ledgerRows) ? ledgerRows : []) {
      if (!r) continue;
      const code = String(r.budgetNumber || '').trim();
      if (!/^\d{4}$/.test(code)) continue;

      const euro = r.euro === null || r.euro === undefined || r.euro === '' ? Number.NaN : Number(r.euro);
      const usd = r.usd === null || r.usd === undefined || r.usd === '' ? Number.NaN : Number(r.usd);

      const hasEuro = Number.isFinite(euro) && euro !== 0;
      const hasUsd = Number.isFinite(usd) && usd !== 0;
      if (!hasEuro && !hasUsd) continue;

      // Apply rule per-currency:
      //  - Positive -> Receipts (IN column)
      //  - Negative -> Expenditures (OUT column) (store as positive in Budget)
      if (hasEuro) {
        const amt = Math.abs(euro);
        if (euro < 0) expendituresEuroByCode.set(code, (expendituresEuroByCode.get(code) || 0) + amt);
        else receiptsEuroByCode.set(code, (receiptsEuroByCode.get(code) || 0) + amt);
      }

      if (hasUsd) {
        const amt = Math.abs(usd);
        if (usd < 0) expendituresUsdByCode.set(code, (expendituresUsdByCode.get(code) || 0) + amt);
        else receiptsUsdByCode.set(code, (receiptsUsdByCode.get(code) || 0) + amt);
      }
    }

    const tbody = document.createElement('tbody');
    tbody.innerHTML = String(html || '');
    let rows = Array.from(tbody.querySelectorAll('tr'));

    if (expectedTrCount > 0 && rows.length < expectedTrCount) {
      return { ok: false, reason: 'parseDroppedRows', expectedTrCount, parsedTrCount: rows.length };
    }

    // Restore any missing Budget item rows based on the persisted template.
    // This is non-destructive: it only adds missing rows, never removes or edits existing rows.
    let changed = false;
    const templateRows = loadBudgetTemplateRows();
    const restore = ensureBudgetTemplateRowsExistInTbody(tbody, templateRows);
    if (restore && restore.added > 0) {
      changed = true;
      rows = Array.from(tbody.querySelectorAll('tr'));
    }

    // Enforce policy: clear any non-ledger values from receipts/expenditures columns.
    // Ledger values will be applied immediately after.
    for (const row of rows) {
      if (!isBudgetEditableDataRow(row)) continue;
      const tds = row.querySelectorAll('td');
      if (tds.length < 11) continue;

      const prevReceiptsEuro = parseBudgetMoney(tds[4]?.textContent);
      if (Math.abs(prevReceiptsEuro) > 0.0001) {
        if (tds[4]) tds[4].textContent = formatBudgetEuro(0);
        changed = true;
      }

      const prevExpendituresEuro = parseBudgetMoney(tds[5]?.textContent);
      if (Math.abs(prevExpendituresEuro) > 0.0001) {
        if (tds[5]) tds[5].textContent = formatBudgetEuro(0);
        changed = true;
      }

      const receiptsUsdText = String(tds[8]?.textContent || '').trim();
      if (receiptsUsdText && receiptsUsdText !== '-' && Math.abs(parseBudgetMoney(receiptsUsdText)) > 0.0001) {
        if (tds[8]) tds[8].textContent = '-';
        changed = true;
      } else if (receiptsUsdText !== '-') {
        if (tds[8]) tds[8].textContent = '-';
        changed = true;
      }

      const expendituresUsdText = String(tds[10]?.textContent || '').trim();
      if (expendituresUsdText && expendituresUsdText !== '-' && Math.abs(parseBudgetMoney(expendituresUsdText)) > 0.0001) {
        if (tds[10]) tds[10].textContent = '-';
        changed = true;
      } else if (expendituresUsdText !== '-') {
        if (tds[10]) tds[10].textContent = '-';
        changed = true;
      }
    }

    const inCodes = new Set();
    const outCodes = new Set();
    for (const row of rows) {
      if (!isBudgetEditableDataRow(row)) continue;
      const tds = row.querySelectorAll('td');
      const inCode = String(tds[0]?.textContent || '').trim();
      const outCode = String(tds[1]?.textContent || '').trim();
      if (/^\d{4}$/.test(inCode)) inCodes.add(inCode);
      if (/^\d{4}$/.test(outCode)) outCodes.add(outCode);
    }

    const approxEqual = (a, b) => Math.abs(Number(a) - Number(b)) < 0.0001;

    // Receipts (IN code): set Receipts EUR (td[4]) and Receipts USD (td[8])
    for (const code of inCodes) {
      const targetRow = findBudgetRowForInCode(rows, code, true);
      if (!targetRow) continue;
      const tds = targetRow.querySelectorAll('td');
      if (tds.length < 11) continue;

      const desiredEuro = receiptsEuroByCode.get(code) || 0;
      const desiredUsd = receiptsUsdByCode.get(code) || 0;

      const prevEuro = parseBudgetMoney(tds[4]?.textContent);
      if (!approxEqual(prevEuro, desiredEuro)) {
        if (tds[4]) tds[4].textContent = formatBudgetEuro(desiredEuro);
        changed = true;
      }

      const prevUsd = parseBudgetMoney(tds[8]?.textContent);
      if (!approxEqual(prevUsd, desiredUsd) || (desiredUsd === 0 && String(tds[8]?.textContent || '').trim() !== '-')) {
        if (tds[8]) tds[8].textContent = formatBudgetUsdOrDash(desiredUsd);
        changed = true;
      }
    }

    // Expenditures (OUT code): set Expenditures EUR (td[5]) and Expenditures USD (td[10])
    for (const code of outCodes) {
      const targetRow = findBudgetRowForOutCode(rows, code, true);
      if (!targetRow) continue;
      const tds = targetRow.querySelectorAll('td');
      if (tds.length < 11) continue;

      const desiredEuro = expendituresEuroByCode.get(code) || 0;
      const desiredUsd = expendituresUsdByCode.get(code) || 0;

      const prevEuro = parseBudgetMoney(tds[5]?.textContent);
      if (!approxEqual(prevEuro, desiredEuro)) {
        if (tds[5]) tds[5].textContent = formatBudgetEuro(desiredEuro);
        changed = true;
      }

      const prevUsd = parseBudgetMoney(tds[10]?.textContent);
      if (!approxEqual(prevUsd, desiredUsd) || (desiredUsd === 0 && String(tds[10]?.textContent || '').trim() !== '-')) {
        if (tds[10]) tds[10].textContent = formatBudgetUsdOrDash(desiredUsd);
        changed = true;
      }
    }

    if (!changed) return { ok: true, changed: false };

    // Backup the prior table HTML before writing ledger-derived values.
    // This is a safety net in case a browser HTML parser/serializer ever behaves unexpectedly.
    try {
      localStorage.setItem(`${budgetKey}_backup_before_ledger_sync_v1`, String(html));
    } catch {
      // ignore
    }

    recalculateBudgetTotalsInTbody(tbody);
    localStorage.setItem(budgetKey, tbody.innerHTML);
    return { ok: true, changed: true };
  }

  function initMasonicYearSelectFromBudgets(preferredYear2) {
    if (!masonicYearInput) return;
    if (String(masonicYearInput.tagName || '').toUpperCase() !== 'SELECT') return;

    const preferred = String(Number(preferredYear2 ?? '')).trim();
    const years = migrateLegacyBudgetIfNeeded();

    // Clear all options.
    masonicYearInput.innerHTML = '';

    const placeholder = document.createElement('option');
    placeholder.value = '';
    placeholder.disabled = true;
    placeholder.selected = true;
    placeholder.textContent = 'Select a budget…';
    masonicYearInput.appendChild(placeholder);

    const seenValues = new Set();
    for (const year of years) {
      const yy = Number(year) % 100;
      const value = String(yy);
      if (seenValues.has(value)) continue;
      seenValues.add(value);

      const opt = document.createElement('option');
      opt.value = value;
      opt.textContent = `${year} Budget (${String(yy).padStart(2, '0')})`;
      masonicYearInput.appendChild(opt);
    }

    // Ensure the current saved setting is always selectable.
    if (preferred && !seenValues.has(preferred)) {
      const custom = document.createElement('option');
      custom.value = preferred;
      custom.textContent = `${String(Number(preferred)).padStart(2, '0')} (not in budgets)`;
      masonicYearInput.appendChild(custom);
    }

    // Select preferred if possible, otherwise fall back to the first real option.
    if (preferred) {
      masonicYearInput.value = preferred;
    }
    if (!masonicYearInput.value) {
      const firstReal = masonicYearInput.querySelector('option:not([value=""])');
      if (firstReal) masonicYearInput.value = firstReal.value;
    }

    // Keep options up-to-date if budgets change.
    if (!masonicYearInput.dataset.budgetYearsBound) {
      masonicYearInput.dataset.budgetYearsBound = 'true';
      window.addEventListener('storage', (e) => {
        const key = e && typeof e.key === 'string' ? e.key : '';
        if (key === BUDGET_YEARS_KEY) {
          initMasonicYearSelectFromBudgets(masonicYearInput.value);
        }
      });
    }
  }

  // Elements are page-dependent (form page vs menu/list page)
  const form = document.getElementById('paymentOrderForm');
  const resetBtn = document.getElementById('resetBtn');

  const tbody = document.getElementById('ordersTbody');
  const emptyState = document.getElementById('emptyState');
  const clearAllBtn = document.getElementById('clearAllBtn');
  const ordersClearSearchBtn = document.getElementById('ordersClearSearchBtn');
  const reconciliationBtn = document.getElementById('reconciliationBtn');
  const newPoBtn = document.getElementById('newPoBtn');

  // Hide protected UI immediately; page init will unhide only when authorized.
  const rolesCardBoot = document.querySelector('section.card[data-settings-card="roles"]');
  if (rolesCardBoot) rolesCardBoot.hidden = true;
  if (reconciliationBtn) reconciliationBtn.hidden = true;
  const gsLedgerBankEurBtnBoot = document.getElementById('gsLedgerBankEurBtn');
  const gsLedgerWiseEurBtnBoot = document.getElementById('gsLedgerWiseEurBtn');
  const gsLedgerWiseUsdBtnBoot = document.getElementById('gsLedgerWiseUsdBtn');
  if (gsLedgerBankEurBtnBoot) gsLedgerBankEurBtnBoot.hidden = true;
  if (gsLedgerWiseEurBtnBoot) gsLedgerWiseEurBtnBoot.hidden = true;
  if (gsLedgerWiseUsdBtnBoot) gsLedgerWiseUsdBtnBoot.hidden = true;

  // Payment Orders Reconciliation list page
  const reconcileTbody = document.getElementById('reconcileOrdersTbody');
  const reconcileEmptyState = document.getElementById('reconcileEmptyState');
  const reconcileClearSearchBtn = document.getElementById('reconcileClearSearchBtn');
  const reconcileToPaymentOrdersBtn = document.getElementById('reconcileToPaymentOrdersBtn');

  const modal = document.getElementById('detailsModal');
  const modalBody = document.getElementById('modalBody');
  const editOrderBtn = document.getElementById('editOrderBtn');
  const saveOrderBtn = document.getElementById('saveOrderBtn');

  // Income list page
  const incomeTbody = document.getElementById('incomeTbody');
  const incomeEmptyState = document.getElementById('incomeEmptyState');
  const incomeClearAllBtn = document.getElementById('incomeClearAllBtn');
  const incomeClearSearchBtn = document.getElementById('incomeClearSearchBtn');
  const incomeModal = document.getElementById('incomeModal');
  const incomeModalBody = document.getElementById('incomeModalBody');
  const incomeSaveBtn = document.getElementById('incomeSaveBtn');

  // wiseEUR list page
  const wiseEurTbody = document.getElementById('wiseEurTbody');
  const wiseEurEmptyState = document.getElementById('wiseEurEmptyState');
  const wiseEurClearSearchBtn = document.getElementById('wiseEurClearSearchBtn');
  const wiseEurModal = document.getElementById('wiseEurModal');
  const wiseEurModalBody = document.getElementById('wiseEurModalBody');
  const wiseEurSaveBtn = document.getElementById('wiseEurSaveBtn');

  // wiseUSD list page
  const wiseUsdTbody = document.getElementById('wiseUsdTbody');
  const wiseUsdEmptyState = document.getElementById('wiseUsdEmptyState');
  const wiseUsdClearSearchBtn = document.getElementById('wiseUsdClearSearchBtn');
  const wiseUsdModal = document.getElementById('wiseUsdModal');
  const wiseUsdModalBody = document.getElementById('wiseUsdModalBody');
  const wiseUsdSaveBtn = document.getElementById('wiseUsdSaveBtn');

  // Grand Secretary Ledger page
  const gsLedgerTbody = document.getElementById('gsLedgerTbody');
  const gsLedgerEmptyState = document.getElementById('gsLedgerEmptyState');
  const gsLedgerClearSearchBtn = document.getElementById('gsLedgerClearSearchBtn');

  const themeToggle = document.getElementById('themeToggle');

  // Request form (index.html) header auth button
  const authHeaderBtn = document.getElementById('authHeaderBtn');
  const requestHeaderPopoutLinks = Array.from(document.querySelectorAll('[data-popout-link="1"]'));

  // Request form submission token
  const submitToken = document.getElementById('submitToken');
  const cancelEditBtn = document.getElementById('cancelEditBtn');

  // Menu page flash token (one-time message after redirects)
  const flashToken = document.getElementById('flashToken');

  let submitTokenHideTimer = null;
  let flashTokenHideTimer = null;

  async function preloadBootstrapSharedData() {
    if (!IS_WP_SHARED_MODE) return;
    const store = window.acglFmsDataStore;
    if (!store || typeof store.preloadBootstrapEssentials !== 'function') return;
    try {
      await Promise.race([
        store.preloadBootstrapEssentials(),
        new Promise((resolve) => window.setTimeout(resolve, 8000)),
      ]);
    } catch {
      // ignore
    }
  }

  async function preloadCurrentPageSharedData() {
    if (!IS_WP_SHARED_MODE) return;
    const store = window.acglFmsDataStore;
    if (!store || typeof store.preloadCurrentPageDatasets !== 'function') return;
    try {
      await Promise.race([
        store.preloadCurrentPageDatasets(),
        new Promise((resolve) => window.setTimeout(resolve, 8000)),
      ]);
    } catch {
      // ignore
    }
  }

  // Remember where the user is in this session so a refresh/login can return here.
  await preloadBootstrapSharedData();
  rememberLastPageNow();

  const authGateResult = renderAuthGate();
  if (authGateResult && authGateResult.blocked) return;

  await preloadCurrentPageSharedData();

  function positionToast(el) {
    if (!el) return;
    // Bottom-right fixed toast
    el.style.top = 'auto';
    el.style.left = 'auto';
    el.style.bottom = '16px';
    el.style.right = '16px';
  }

  function hideToast(el, timerKey) {
    if (!el) return;
    if (timerKey === 'submit' && submitTokenHideTimer) {
      window.clearTimeout(submitTokenHideTimer);
      submitTokenHideTimer = null;
    }
    if (timerKey === 'flash' && flashTokenHideTimer) {
      window.clearTimeout(flashTokenHideTimer);
      flashTokenHideTimer = null;
    }
    el.hidden = true;
    el.innerHTML = '';
  }

  function showToast(el, message, timerKey) {
    if (!el) return;
    const msg = String(message || '').trim();
    if (!msg) {
      hideToast(el, timerKey);
      return;
    }

    el.innerHTML = `
      <span class="token__msg"></span>
      <button type="button" class="token__close" aria-label="Close">X</button>
    `.trim();

    const msgEl = el.querySelector('.token__msg');
    if (msgEl) msgEl.textContent = msg;

    const closeEl = el.querySelector('.token__close');
    if (closeEl) {
      closeEl.addEventListener('click', (e) => {
        e.preventDefault();
        e.stopPropagation();
        hideToast(el, timerKey);
      });
    }

    el.hidden = false;
    positionToast(el);

    if (timerKey === 'submit') {
      if (submitTokenHideTimer) window.clearTimeout(submitTokenHideTimer);
      submitTokenHideTimer = window.setTimeout(() => hideToast(el, 'submit'), 4500);
    } else if (timerKey === 'flash') {
      if (flashTokenHideTimer) window.clearTimeout(flashTokenHideTimer);
      flashTokenHideTimer = window.setTimeout(() => hideToast(el, 'flash'), 4500);
    }
  }

  // App shell left navigation (optional per page)
  const appShell = document.querySelector('[data-app-shell]');
  const navToggleBtn = document.getElementById('navToggle');
  const appMain = document.querySelector('.appMain');
  const siteHeader = document.querySelector('.site-header');

  // Lock the page header so it doesn't scroll away.
  // We set a fixed position and dynamically match the appMain column width/left
  // so it aligns properly when the left navigation is shown/hidden.
  function lockSiteHeaderToViewport() {
    if (!appMain || !siteHeader) return;
    if (siteHeader.dataset.locked === '1') return;
    siteHeader.dataset.locked = '1';

    const spacerAttr = 'data-site-header-spacer';
    let spacer = appMain.querySelector(`[${spacerAttr}]`);

    if (!spacer) {
      spacer = document.createElement('div');
      spacer.setAttribute(spacerAttr, '');
      spacer.style.height = '0px';
      spacer.style.flex = '0 0 auto';
      appMain.insertBefore(spacer, appMain.firstChild);
    }

    if (siteHeader.dataset.movedToBody !== '1') {
      siteHeader.dataset.movedToBody = '1';
      document.body.insertBefore(siteHeader, document.body.firstChild);
    }

    const apply = () => {
      try {
        const rect = appMain.getBoundingClientRect();
        if (!rect || !Number.isFinite(rect.width) || rect.width <= 0) return;

        siteHeader.style.position = 'fixed';
        siteHeader.style.top = '0';
        siteHeader.style.left = `${Math.round(rect.left)}px`;
        siteHeader.style.width = `${Math.round(rect.width)}px`;
        siteHeader.style.zIndex = '1500';

        const h = Math.ceil(siteHeader.getBoundingClientRect().height);
        if (Number.isFinite(h) && h > 0) {
          spacer.style.height = `${h}px`;
          appMain.style.paddingTop = '';
        }
      } catch {
        // ignore
      }
    };

    apply();
    window.addEventListener('resize', apply);
    window.addEventListener('load', apply);
    window.addEventListener('scroll', apply, { passive: true });

    if (navToggleBtn && appShell) {
      const schedule = () => window.requestAnimationFrame(apply);
      navToggleBtn.addEventListener('click', schedule);
      appShell.addEventListener('transitionend', schedule);
    }
  }

  lockSiteHeaderToViewport();

  // Tables with sticky headers/footers: size the scroll wrapper to the viewport.
  // This avoids "too tall" tables on pages with larger headers (e.g., Income).
  function fitFixedFooterTableWrapsToViewport() {
    const baseBottomPadding = 8;

    const getViewportHeight = () => {
      if (window.visualViewport && Number.isFinite(window.visualViewport.height)) {
        return window.visualViewport.height;
      }
      return window.innerHeight;
    };

    const apply = () => {
      try {
        const viewportH = getViewportHeight();
        const wraps = document.querySelectorAll('.table-wrap.fixedFooterTableWrap');
        if (!wraps || wraps.length === 0) return;

        wraps.forEach((wrap) => {
          const rect = wrap.getBoundingClientRect();
          if (!rect || !Number.isFinite(rect.top)) return;

          const main = wrap.closest('main');
          const card = wrap.closest('.card');
          const mainStyles = main ? window.getComputedStyle(main) : null;
          const cardStyles = card ? window.getComputedStyle(card) : null;

          const mainPaddingBottom = mainStyles ? parseFloat(mainStyles.paddingBottom) || 0 : 0;
          const cardPaddingBottom = cardStyles ? parseFloat(cardStyles.paddingBottom) || 0 : 0;
          const cardMarginBottom = cardStyles ? parseFloat(cardStyles.marginBottom) || 0 : 0;

          const bottomPadding = baseBottomPadding + mainPaddingBottom + cardPaddingBottom + cardMarginBottom;
          const available = Math.floor(viewportH - rect.top - bottomPadding);
          const maxH = Math.max(260, available);
          wrap.style.maxHeight = `${maxH}px`;
        });
      } catch {
        // ignore
      }
    };

    apply();
    window.addEventListener('resize', apply);
    window.addEventListener('load', apply);

    if (window.visualViewport) {
      window.visualViewport.addEventListener('resize', apply);
    }

    if (navToggleBtn && appShell) {
      const schedule = () => window.requestAnimationFrame(apply);
      navToggleBtn.addEventListener('click', schedule);
      appShell.addEventListener('transitionend', schedule);
    }
  }

  fitFixedFooterTableWrapsToViewport();

  // Settings page (numbering)
  const numberingForm = document.getElementById('numberingForm');
  const masonicYearInput = document.getElementById('masonicYear');
  const firstNumberInput = document.getElementById('firstNumber');
  const firstMoneyTransferNumberInput = document.getElementById('firstMoneyTransferNumber');
  const savePoNumberingBtn = document.getElementById('savePoNumberingBtn');
  const saveMtNumberingBtn = document.getElementById('saveMtNumberingBtn');

  // Settings page (Grand Lodge Information)
  const grandLodgeInfoForm = document.getElementById('grandLodgeInfoForm');
  const grandMasterInput = document.getElementById('grandMaster');
  const grandSecretaryInput = document.getElementById('grandSecretary');
  const grandTreasurerInput = document.getElementById('grandTreasurer');
  const officialAddressInput = document.getElementById('officialAddress');
  const operationAddressInput = document.getElementById('operationAddress');
  const grandLodgeSealFileInput = document.getElementById('grandLodgeSealFile');
  const grandSecretarySignatureFileInput = document.getElementById('grandSecretarySignatureFile');
  const grandLodgeSealSavedMeta = document.getElementById('grandLodgeSealSavedMeta');
  const grandSecretarySignatureSavedMeta = document.getElementById('grandSecretarySignatureSavedMeta');
  const backupOpenWpAdminLink = document.getElementById('backupOpenWpAdminLink');
  const backupWpAdminUnavailable = document.getElementById('backupWpAdminUnavailable');
  const notificationsSearchInput = document.getElementById('notificationsSearchInput');
  const notificationsClearSearchBtn = document.getElementById('notificationsClearSearchBtn');
  const notificationsNewBtn = document.getElementById('notificationsNewBtn');
  const notificationsListTbody = document.getElementById('notificationsListTbody');
  const notificationsEmptyState = document.getElementById('notificationsEmptyState');
  const notificationsModal = document.getElementById('notificationsModal');
  const notificationsModalTitle = document.getElementById('notificationsModalTitle');
  const notificationsForm = document.getElementById('notificationsForm');
  const notificationsTypeSelectEl = document.getElementById('notificationsTypeSelect');
  const notificationsTypeEnabledInput = document.getElementById('notificationsTypeEnabled');
  const notificationsRecipientsModeInput = document.getElementById('notificationsRecipientsMode');
  const notificationsManualToWrap = document.getElementById('notificationsManualToWrap');
  const notificationsManualToInput = document.getElementById('notificationsManualTo');
  const notificationsReplyToInput = document.getElementById('notificationsReplyTo');
  const notificationsTestToInput = document.getElementById('notificationsTestTo');
  const notificationsSubjectInput = document.getElementById('notificationsSubject');
  const notificationsBodyInput = document.getElementById('notificationsBody');
  const notificationsSignatureInput = document.getElementById('notificationsSignature');
  const notificationsStatusEl = document.getElementById('notificationsStatus');
  const notificationsLastTestEl = document.getElementById('notificationsLastTest');
  const notificationsTestBtn = document.getElementById('notificationsTestBtn');
  const notificationsSaveBtn = document.getElementById('notificationsSaveBtn');

  // Settings page (roles)
  const createUserForm = document.getElementById('createUserForm');
  const usersTbody = document.getElementById('usersTbody');
  const usersEmptyState = document.getElementById('usersEmptyState');
  const logoutBtn = document.getElementById('logoutBtn');

  // Form page helpers
  const itemsStatus = document.getElementById('itemsStatus');
  const itemsErrorEl = document.getElementById('error-items');

  const euroField = document.getElementById('euro');
  const usdField = document.getElementById('usd');
  const downloadPdfBtn = document.getElementById('downloadPdfBtn');

  let currentViewedOrderId = null;
  let hidePoProgressTooltip = () => {};

  // Money Transfers page
  const moneyTransfersTbody = document.getElementById('moneyTransfersTbody');
  const moneyTransfersEmptyState = document.getElementById('moneyTransfersEmptyState');
  const moneyTransfersClearSearchBtn = document.getElementById('moneyTransfersClearSearchBtn');

  const mtRangeModal = document.getElementById('mtRangeModal');
  const mtDateInput = document.getElementById('mtDate');
  const mtRangeErrorEl = document.getElementById('mtRangeError');
  const mtRangeSubmitBtn = document.getElementById('mtRangeSubmitBtn');

  // Money Transfer builder page
  const mtBuilderTbody = document.getElementById('mtBuilderTbody');
  const mtBuilderEmptyState = document.getElementById('mtBuilderEmptyState');
  const mtBuilderClearSearchBtn = document.getElementById('mtBuilderClearSearchBtn');
  const mtBuilderSelectItemsBtn = document.getElementById('mtBuilderSelectItemsBtn');
  const mtBuilderDateInput = document.getElementById('mtBuilderDate');
  const mtBuilderDateInlineError = document.getElementById('mtBuilderDateInlineError');
  const mtEntrySelectModal = document.getElementById('mtEntrySelectModal');
  const mtEntrySelectTbody = document.getElementById('mtEntrySelectTbody');
  const mtEntrySelectEmptyState = document.getElementById('mtEntrySelectEmptyState');
  const mtEntrySelectAddBtn = document.getElementById('mtEntrySelectAddBtn');

  // Request form CAPTCHA (client-side human check)
  let requestCaptchaExpected = null;

  function generateRequestCaptcha() {
    if (!form) return;
    const promptEl = document.getElementById('captchaPrompt');
    const inputEl = form.elements.namedItem('captchaAnswer');
    if (!promptEl || !inputEl) return;

    const a = 2 + Math.floor(Math.random() * 8); // 2..9
    const b = 2 + Math.floor(Math.random() * 8); // 2..9
    requestCaptchaExpected = String(a + b);
    promptEl.textContent = `What is ${a} + ${b}?`;
    if (typeof inputEl.value === 'string') inputEl.value = '';
  }

  function getEditOrderId() {
    const id = localStorage.getItem(EDIT_ORDER_ID_KEY);
    if (!id || typeof id !== 'string') return null;

    const currentYear = getActiveBudgetYear();
    const storedYear = Number(localStorage.getItem(EDIT_ORDER_YEAR_KEY));
    if (Number.isInteger(storedYear) && storedYear !== currentYear) {
      localStorage.removeItem(EDIT_ORDER_ID_KEY);
      localStorage.removeItem(EDIT_ORDER_YEAR_KEY);
      return null;
    }

    return id;
  }

  function setEditOrderId(id) {
    if (!id) {
      localStorage.removeItem(EDIT_ORDER_ID_KEY);
      localStorage.removeItem(EDIT_ORDER_YEAR_KEY);
      return;
    }
    localStorage.setItem(EDIT_ORDER_ID_KEY, id);
    localStorage.setItem(EDIT_ORDER_YEAR_KEY, String(getActiveBudgetYear()));
  }

  // Itemize page elements
  const itemModal = document.getElementById('itemModal');
  const itemForm = document.getElementById('itemForm');
  const itemsTbody = document.getElementById('itemsTbody');
  const itemsEmptyState = document.getElementById('itemsEmptyState');
  const totalEuroEl = document.getElementById('totalEuro');
  const totalUsdEl = document.getElementById('totalUsd');
  const saveItemsBtn = document.getElementById('saveItemsBtn');
  const editingItemIdEl = document.getElementById('editingItemId');
  const addOrUpdateItemBtn = document.getElementById('addOrUpdateItemBtn');
  const openItemModalBtn = document.getElementById('openItemModalBtn');
  const addMilageBtn = document.getElementById('addMilageBtn');
  const itemizeContext = document.getElementById('itemizeContext');

  // Attachments (itemize page)
  const attachmentsDropzone = document.getElementById('attachmentsDropzone');
  const attachmentsInput = document.getElementById('attachmentsInput');
  const attachmentsTbody = document.getElementById('attachmentsTbody');
  const attachmentsEmptyState = document.getElementById('attachmentsEmptyState');
  const attachmentsError = document.getElementById('attachmentsError');

  const ATTACHMENTS_DB = 'payment_order_attachments_db';
  const ATTACHMENTS_STORE = 'attachments';
  const ATTACHMENTS_DB_VERSION = 1;

  function getPreferredTheme() {
    const saved = localStorage.getItem(THEME_KEY);
    if (saved === 'light' || saved === 'dark') return saved;
    return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  }

  /** @param {'light'|'dark'} theme */
  function applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    const isDark = theme === 'dark';

    if (themeToggle) {
      if (typeof themeToggle.checked === 'boolean') {
        themeToggle.checked = isDark;
        themeToggle.setAttribute('aria-checked', String(isDark));
      }

      // Show what the user can switch to.
      const switchToText = isDark ? 'Light mode' : 'Dark mode';
      const labelEl = typeof themeToggle.closest === 'function' ? themeToggle.closest('label') : null;
      const textEl = labelEl ? labelEl.querySelector('.switch__text') : null;
      if (textEl) textEl.textContent = switchToText;
      themeToggle.setAttribute('aria-label', switchToText);
    }
  }

  function updateNavToggleUi() {
    if (!appShell || !navToggleBtn) return;
    const isClosed = appShell.classList.contains('appShell--navClosed');
    navToggleBtn.setAttribute('aria-expanded', String(!isClosed));
    navToggleBtn.setAttribute('aria-label', isClosed ? 'Open navigation' : 'Close navigation');
    navToggleBtn.title = isClosed ? 'Open navigation' : 'Close navigation';
  }

  function setTheme(theme) {
    localStorage.setItem(THEME_KEY, theme);
    applyTheme(theme);
  }

  function showSubmitToken(message) {
    if (!submitToken) return;
    showToast(submitToken, message, 'submit');
  }

  function setFlashToken(message) {
    const msg = String(message || '').trim();
    if (!msg) {
      localStorage.removeItem(FLASH_TOKEN_KEY);
      return;
    }
    localStorage.setItem(FLASH_TOKEN_KEY, msg);
  }

  function consumeFlashToken() {
    const msg = String(localStorage.getItem(FLASH_TOKEN_KEY) || '').trim();
    if (msg) localStorage.removeItem(FLASH_TOKEN_KEY);
    return msg;
  }

  function showFlashToken(message) {
    if (!flashToken) return;
    showToast(flashToken, message, 'flash');
  }

  function ensurePaymentOrdersListExistsForYear(year) {
    const y = Number(year);
    if (!Number.isInteger(y)) return { ok: false, created: false };
    const storageKey = getPaymentOrdersKeyForYear(y);
    if (!storageKey) return { ok: false, created: false };

    try {
      const existing = localStorage.getItem(storageKey);
      if (existing !== null) return { ok: true, created: false };
      localStorage.setItem(storageKey, JSON.stringify([]));
      return { ok: true, created: true };
    } catch {
      return { ok: false, created: false };
    }
  }

  function ensurePaymentOrdersReconciliationListExistsForYear(year) {
    const y = Number(year);
    if (!Number.isInteger(y)) return { ok: false, created: false };
    const storageKey = getPaymentOrdersReconciliationKeyForYear(y);
    if (!storageKey) return { ok: false, created: false };

    try {
      const existing = localStorage.getItem(storageKey);
      if (existing !== null) return { ok: true, created: false };
      localStorage.setItem(storageKey, JSON.stringify([]));
      return { ok: true, created: true };
    } catch {
      return { ok: false, created: false };
    }
  }

  function ensureMoneyTransfersListExistsForYear(year) {
    const y = Number(year);
    if (!Number.isInteger(y)) return { ok: false, created: false };
    const storageKey = getMoneyTransfersKeyForYear(y);
    if (!storageKey) return { ok: false, created: false };

    try {
      const existing = localStorage.getItem(storageKey);
      if (existing !== null) return { ok: true, created: false };
      localStorage.setItem(storageKey, JSON.stringify([]));
      return { ok: true, created: true };
    } catch {
      return { ok: false, created: false };
    }
  }

  /** @returns {Array<Object>} */
  function loadMoneyTransfers(year) {
    const resolvedYear = Number.isInteger(Number(year)) ? Number(year) : getActiveBudgetYear();
    const storageKey = getMoneyTransfersKeyForYear(resolvedYear);
    if (!storageKey) return [];
    try {
      const raw = localStorage.getItem(storageKey);
      if (!raw) return [];
      const parsed = JSON.parse(raw);
      return Array.isArray(parsed) ? parsed : [];
    } catch {
      return [];
    }
  }

  /** @param {Array<Object>} transfers */
  function saveMoneyTransfers(transfers, year) {
    const resolvedYear = Number.isInteger(Number(year)) ? Number(year) : getActiveBudgetYear();
    const storageKey = getMoneyTransfersKeyForYear(resolvedYear);
    if (!storageKey) return;
    const before = loadMoneyTransfers(resolvedYear);
    const safe = Array.isArray(transfers) ? transfers : [];
    localStorage.setItem(storageKey, JSON.stringify(safe));
    appendCollectionAuditEvents({
      module: 'Money Transfers',
      year: resolvedYear,
      beforeList: before,
      afterList: safe,
      idKeys: ['id', 'moneyTransferNo', 'mtNo', 'no'],
      recordLabelFn: (t) => String((t && (t.moneyTransferNo || t.mtNo || t.no || t.id)) || '').trim(),
    });
  }

  /** @returns {Array<Object>} */
  function loadReconciliationOrders(year) {
    const resolvedYear = Number.isInteger(Number(year)) ? Number(year) : getActiveBudgetYear();
    const storageKey = getPaymentOrdersReconciliationKeyForYear(resolvedYear);
    if (!storageKey) return [];
    try {
      const raw = localStorage.getItem(storageKey);
      if (!raw) return [];
      const parsed = JSON.parse(raw);
      const orders = Array.isArray(parsed) ? parsed : [];
      return migrateKnownUsdOrderSourcesIfNeeded(resolvedYear, orders, { kind: 'reconciliation', storageKey });
    } catch {
      return [];
    }
  }

  function migrateKnownUsdOrderSourcesIfNeeded(year, orders, opts) {
    const y = Number(year);
    if (!Number.isInteger(y)) return Array.isArray(orders) ? orders : [];
    const kind = opts && opts.kind ? String(opts.kind) : 'orders';
    const storageKey = opts && opts.storageKey ? String(opts.storageKey) : '';
    if (!storageKey) return Array.isArray(orders) ? orders : [];

    const migrationKey = `payment_orders_known_usd_source_fix_${kind}_${y}_v1`;
    try {
      if (localStorage.getItem(migrationKey) === '1') return Array.isArray(orders) ? orders : [];
    } catch {
      return Array.isArray(orders) ? orders : [];
    }

    const list = Array.isArray(orders) ? orders : [];

    function hasUsdValue(o) {
      const usdNum = Number(o && o.usd);
      if (Number.isFinite(usdNum) && usdNum > 0) return true;
      const items = Array.isArray(o && o.items) ? o.items : [];
      return items.some((it) => {
        const n = Number(it && it.usd);
        return Number.isFinite(n) && n > 0;
      });
    }

    const fixCanons = new Set(['PO25-04']);

    let changed = false;
    const patched = list.map((o) => {
      if (!o || typeof o !== 'object') return o;
      const canon = canonicalizePaymentOrderNo(o.paymentOrderNo);
      if (!fixCanons.has(canon)) return o;
      if (!hasUsdValue(o)) return o;
      const src = String(o.source || '').trim();
      if (src === 'wiseUSD') return o;
      if (src && src !== 'Commerzbank') return o;
      changed = true;
      return { ...o, source: 'wiseUSD' };
    });

    try {
      if (changed) localStorage.setItem(storageKey, JSON.stringify(patched));
      localStorage.setItem(migrationKey, '1');
    } catch {
      // ignore
    }

    return changed ? patched : list;
  }

  /** @param {Array<Object>} orders */
  function saveReconciliationOrders(orders, year) {
    const resolvedYear = Number.isInteger(Number(year)) ? Number(year) : getActiveBudgetYear();
    const storageKey = getPaymentOrdersReconciliationKeyForYear(resolvedYear);
    if (!storageKey) return;
    const before = loadReconciliationOrders(resolvedYear);
    const safe = Array.isArray(orders) ? orders : [];
    localStorage.setItem(storageKey, JSON.stringify(safe));
    appendCollectionAuditEvents({
      module: 'Reconciliation',
      year: resolvedYear,
      beforeList: before,
      afterList: safe,
      idKeys: ['id', 'sourceEntryId', 'paymentOrderNo'],
      recordLabelFn: (o) => formatPaymentOrderNoForDisplay(o && o.paymentOrderNo) || String((o && o.id) || '').trim(),
    });
  }

  function upsertReconciliationOrderBySource(order, year) {
    if (!order) return;
    const source = String(order.source || '').trim();
    const sourceEntryId = String(order.sourceEntryId || '').trim();
    if (!source || !sourceEntryId) return;

    // Reconciliation intake entries must never carry an auto-generated PO number.
    const sanitizedOrder = {
      ...order,
      paymentOrderNo: '',
    };

    const y = Number.isInteger(Number(year)) ? Number(year) : getActiveBudgetYear();
    const existing = loadReconciliationOrders(y);
    const idx = existing.findIndex((o) => (
      o
      && String(o.source || '').trim() === source
      && String(o.sourceEntryId || '').trim() === sourceEntryId
    ));

    const next = idx >= 0
      ? existing.map((o, i) => (i === idx ? sanitizedOrder : o))
      : [sanitizedOrder, ...existing];
    saveReconciliationOrders(next, y);
  }

  function removeReconciliationOrderBySource(sourceRaw, sourceEntryIdRaw, year) {
    const source = String(sourceRaw || '').trim();
    const sourceEntryId = String(sourceEntryIdRaw || '').trim();
    if (!source || !sourceEntryId) return;

    const y = Number.isInteger(Number(year)) ? Number(year) : getActiveBudgetYear();
    const existing = loadReconciliationOrders(y);
    const next = existing.filter((o) => !(
      o
      && String(o.source || '').trim() === source
      && String(o.sourceEntryId || '').trim() === sourceEntryId
    ));
    if (next.length !== existing.length) saveReconciliationOrders(next, y);
  }

  /** @returns {Array<Object>} */
  function loadOrders(year) {
    const resolvedYear = Number.isInteger(Number(year)) ? Number(year) : getActiveBudgetYear();
    migrateLegacyOrdersIfNeeded(resolvedYear);
    const storageKey = getPaymentOrdersKeyForYear(resolvedYear);
    if (!storageKey) return [];
    try {
      const raw = localStorage.getItem(storageKey);
      if (!raw) return [];
      const parsed = JSON.parse(raw);
      const orders = Array.isArray(parsed) ? parsed : [];
      return migrateKnownUsdOrderSourcesIfNeeded(resolvedYear, orders, { kind: 'orders', storageKey });
    } catch {
      return [];
    }
  }

  /** @param {Array<Object>} orders */
  function saveOrders(orders, year) {
    const resolvedYear = Number.isInteger(Number(year)) ? Number(year) : getActiveBudgetYear();
    const storageKey = getPaymentOrdersKeyForYear(resolvedYear);
    if (!storageKey) return;
    localStorage.setItem(storageKey, JSON.stringify(orders));

    // Budget updates are ledger-driven only.
    syncBudgetFromLedger(resolvedYear);
  }

  function loadDraft() {
    try {
      const raw = localStorage.getItem(DRAFT_KEY);
      if (!raw) return null;
      const parsed = JSON.parse(raw);
      return parsed && typeof parsed === 'object' ? parsed : null;
    } catch {
      return null;
    }
  }

  function saveDraft(draft) {
    localStorage.setItem(DRAFT_KEY, JSON.stringify(draft));
  }

  function clearDraft() {
    localStorage.removeItem(DRAFT_KEY);
    localStorage.removeItem(DRAFT_ITEMS_KEY);
  }

  /** @returns {Array<Object>} */
  function loadDraftItems() {
    try {
      const raw = localStorage.getItem(DRAFT_ITEMS_KEY);
      if (!raw) return [];
      const parsed = JSON.parse(raw);
      return Array.isArray(parsed) ? parsed : [];
    } catch {
      return [];
    }
  }

  /** @param {Array<Object>} items */
  function saveDraftItems(items) {
    localStorage.setItem(DRAFT_ITEMS_KEY, JSON.stringify(items));
  }

  function escapeHtml(value) {
    return String(value)
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;')
      .replaceAll("'", '&#39;');
  }

  function formatMoney(n) {
    if (n === null || n === undefined || n === '') return '';
    const num = Number(n);
    if (!Number.isFinite(num)) return '';
    return num.toLocaleString('en-US', {
      minimumFractionDigits: 2,
      maximumFractionDigits: 2,
    });
  }

  /**
   * @param {number|null|undefined|string} amount
   * @param {'EUR'|'USD'} currency
   */
  function formatCurrency(amount, currency) {
    const formatted = formatMoney(amount);
    if (!formatted) return '';
    const symbol = currency === 'EUR' ? '€' : '$';
    return `${symbol} ${formatted}`;
  }

  function sumItems(items) {
    const totals = { euro: 0, usd: 0 };
    for (const it of items || []) {
      const e = Number(it.euro);
      const u = Number(it.usd);
      if (Number.isFinite(e)) totals.euro += e;
      if (Number.isFinite(u)) totals.usd += u;
    }
    return totals;
  }

  function updateItemsStatus() {
    if (!itemsStatus) return;
    const count = loadDraftItems().length;
    itemsStatus.textContent = `Items: ${count}`;
  }

  function inferCurrencyModeFromItems(items) {
    const hasEuro = (items || []).some((it) => it && it.euro !== null && it.euro !== undefined);
    const hasUsd = (items || []).some((it) => it && it.usd !== null && it.usd !== undefined);
    if (hasEuro && hasUsd) return 'MIXED';
    if (hasEuro) return 'EUR';
    if (hasUsd) return 'USD';
    return null;
  }

  function syncCurrencyFieldsFromItems() {
    if (!form) return;
    if (!euroField || !usdField) return;

    const items = loadDraftItems();
    const totals = sumItems(items);
    const mode = inferCurrencyModeFromItems(items);

    if (!mode) {
      euroField.value = '';
      usdField.value = '';
      return;
    }

    if (mode === 'MIXED') {
      // Should be prevented in itemize page, but keep display consistent.
      euroField.value = totals.euro.toFixed(2);
      usdField.value = totals.usd.toFixed(2);
      return;
    }

    if (mode === 'EUR') {
      euroField.value = totals.euro.toFixed(2);
      usdField.value = '';
    } else {
      usdField.value = totals.usd.toFixed(2);
      euroField.value = '';
    }
  }

  function normalizeOrderStatus(status) {
    const s = String(status || '').trim();
    if (!s) return 'Submitted';
    const match = ORDER_STATUSES.find((opt) => opt.toLowerCase() === s.toLowerCase());
    return match || 'Submitted';
  }

  function normalizeWith(withValue) {
    const s = String(withValue || '').trim();
    if (!s) return 'Grand Secretary';
    const match = WITH_OPTIONS.find((opt) => opt.toLowerCase() === s.toLowerCase());
    return match || 'Grand Secretary';
  }

  function getAllowedOrderStatusesForWith(withValue) {
    const withLabel = normalizeWith(withValue);
    if (withLabel === 'Grand Treasurer') {
      return ORDER_STATUSES.filter((s) => s !== 'Approved');
    }
    return [...ORDER_STATUSES];
  }

  function normalizeOrderSource(sourceValue) {
    const s = String(sourceValue || '').trim();
    if (!s) return '';
    const match = SOURCE_OPTIONS.find((opt) => opt.toLowerCase() === s.toLowerCase());
    return match || s;
  }

  // ---- Payment Order No. numbering ----

  function getDefaultMasonicYear2() {
    const yy = new Date().getFullYear() % 100;
    return String(yy).padStart(2, '0');
  }

  function normalizeMasonicYear2(value) {
    const raw = String(value ?? '').trim();
    if (!raw) return getDefaultMasonicYear2();
    const n = Number(raw);
    if (!Number.isFinite(n)) return getDefaultMasonicYear2();
    const clamped = Math.max(0, Math.min(99, Math.trunc(n)));
    return String(clamped).padStart(2, '0');
  }

  function normalizeSequence(value) {
    const raw = String(value ?? '').trim();
    const n = Number(raw);
    if (!Number.isFinite(n)) return 1;
    return Math.max(1, Math.trunc(n));
  }

  // ---- Grand Lodge Information ----

  function normalizePersonName(value) {
    const s = String(value ?? '');
    return s.replace(/\s+/g, ' ').trim();
  }

  function normalizeGermanAddressMultiline(value) {
    const raw = String(value ?? '').replace(/\r\n/g, '\n');
    const lines = raw
      .split('\n')
      .map((l) => String(l).replace(/\s+$/g, ''));

    // Trim leading/trailing blank lines
    while (lines.length && !lines[0].trim()) lines.shift();
    while (lines.length && !lines[lines.length - 1].trim()) lines.pop();

    // Collapse multiple blank lines
    const out = [];
    for (const line of lines) {
      const isBlank = !String(line).trim();
      const prevBlank = out.length ? !String(out[out.length - 1]).trim() : false;
      if (isBlank && prevBlank) continue;
      out.push(line.trimEnd());
    }
    return out.join('\n').trim();
  }

  function loadGrandLodgeInfo() {
    try {
      const raw = localStorage.getItem(GRAND_LODGE_INFO_KEY);
      if (!raw) {
        return {
          grandMaster: '',
          grandSecretary: '',
          grandTreasurer: '',
          officialAddress: '',
          operationAddress: '',
          grandLodgeSealDataUrl: '',
          grandLodgeSealFileName: '',
          grandSecretarySignatureDataUrl: '',
          grandSecretarySignatureFileName: '',
        };
      }
      const parsed = JSON.parse(raw);
      return {
        grandMaster: normalizePersonName(parsed && parsed.grandMaster),
        grandSecretary: normalizePersonName(parsed && parsed.grandSecretary),
        grandTreasurer: normalizePersonName(parsed && parsed.grandTreasurer),
        officialAddress: normalizeGermanAddressMultiline(parsed && parsed.officialAddress),
        operationAddress: normalizeGermanAddressMultiline(parsed && parsed.operationAddress),
        grandLodgeSealDataUrl: String((parsed && parsed.grandLodgeSealDataUrl) || ''),
        grandLodgeSealFileName: String((parsed && parsed.grandLodgeSealFileName) || ''),
        grandSecretarySignatureDataUrl: String((parsed && parsed.grandSecretarySignatureDataUrl) || ''),
        grandSecretarySignatureFileName: String((parsed && parsed.grandSecretarySignatureFileName) || ''),
      };
    } catch {
      return {
        grandMaster: '',
        grandSecretary: '',
        grandTreasurer: '',
        officialAddress: '',
        operationAddress: '',
        grandLodgeSealDataUrl: '',
        grandLodgeSealFileName: '',
        grandSecretarySignatureDataUrl: '',
        grandSecretarySignatureFileName: '',
      };
    }
  }

  function saveGrandLodgeInfo(info) {
    const prev = loadGrandLodgeInfo();
    const payload = {
      grandMaster: normalizePersonName(info && info.grandMaster),
      grandSecretary: normalizePersonName(info && info.grandSecretary),
      grandTreasurer: normalizePersonName(info && info.grandTreasurer),
      officialAddress: normalizeGermanAddressMultiline(info && info.officialAddress),
      operationAddress: normalizeGermanAddressMultiline(info && info.operationAddress),
      grandLodgeSealDataUrl: String((info && info.grandLodgeSealDataUrl) || ''),
      grandLodgeSealFileName: String((info && info.grandLodgeSealFileName) || ''),
      grandSecretarySignatureDataUrl: String((info && info.grandSecretarySignatureDataUrl) || ''),
      grandSecretarySignatureFileName: String((info && info.grandSecretarySignatureFileName) || ''),
    };
    localStorage.setItem(GRAND_LODGE_INFO_KEY, JSON.stringify(payload));
    if (auditStableStringify(prev) !== auditStableStringify(payload)) {
      const action = (prev && (prev.grandMaster || prev.grandSecretary || prev.grandTreasurer || prev.officialAddress || prev.operationAddress))
        ? 'Modified'
        : 'Created';
      appendAppAuditEvent('Grand Lodge Settings', 'Grand Lodge info', action, buildAuditChangesSummary(prev, payload));
    }
  }

  function readFileAsDataUrl(file) {
    return new Promise((resolve, reject) => {
      try {
        if (!file) {
          resolve('');
          return;
        }
        const reader = new FileReader();
        reader.onerror = () => reject(new Error('read_failed'));
        reader.onload = () => resolve(String(reader.result || ''));
        reader.readAsDataURL(file);
      } catch (e) {
        reject(e);
      }
    });
  }

  function loadNumberingSettings() {
    try {
      const raw = localStorage.getItem(NUMBERING_KEY);
      if (!raw) return { year2: getDefaultMasonicYear2(), nextSeq: 1, mtNextSeq: 1 };
      const parsed = JSON.parse(raw);
      return {
        year2: normalizeMasonicYear2(parsed && parsed.year2),
        nextSeq: normalizeSequence(parsed && parsed.nextSeq),
        mtNextSeq: normalizeSequence(parsed && parsed.mtNextSeq),
      };
    } catch {
      return { year2: getDefaultMasonicYear2(), nextSeq: 1, mtNextSeq: 1 };
    }
  }

  function saveNumberingSettings(settings) {
    const prev = loadNumberingSettings();
    const year2 = normalizeMasonicYear2((settings && settings.year2) ?? prev.year2);
    const yearChanged = normalizeMasonicYear2(prev.year2) !== year2;
    const hasNextSeq = Boolean(settings && Object.prototype.hasOwnProperty.call(settings, 'nextSeq'));
    const hasMtNextSeq = Boolean(settings && Object.prototype.hasOwnProperty.call(settings, 'mtNextSeq'));
    const nextSeq = normalizeSequence(hasNextSeq ? settings.nextSeq : (yearChanged ? 1 : prev.nextSeq));
    const mtNextSeq = normalizeSequence(hasMtNextSeq ? settings.mtNextSeq : (yearChanged ? 1 : prev.mtNextSeq));
    const payload = { year2, nextSeq, mtNextSeq };
    localStorage.setItem(NUMBERING_KEY, JSON.stringify(payload));
    if (auditStableStringify(prev) !== auditStableStringify(payload)) {
      appendAppAuditEvent('Numbering', 'Payment Order / Money Transfer numbering', 'Modified', buildAuditChangesSummary(prev, payload));
    }
  }

  function canonicalizePaymentOrderNo(value) {
    const s = String(value ?? '').trim().toUpperCase();
    if (!s) return '';
    // Treat older formats as equivalent:
    // - "POYY-##" (no separator)
    // - "PO-YY-##" (dash)
    // - "PO YY-##" (space)
    const noSpaces = s.replace(/\s+/g, '');
    return noSpaces.replace(/^PO-/, 'PO');
  }

  function getPaymentOrderNoSortParts(value) {
    const canon = canonicalizePaymentOrderNo(value);
    const m = canon.match(/^PO(\d{2})-(\d+)$/i);
    if (!m) return null;
    const year2 = Number(m[1]);
    const seq = Number(m[2]);
    if (!Number.isFinite(year2) || !Number.isFinite(seq)) return null;
    return { year2, seq };
  }

  function formatPaymentOrderNoForDisplay(value) {
    const raw = String(value ?? '').trim();
    if (!raw) return '';
    const mYear = raw.match(/^PO(?:\s+|-)?(\d{2})-(\d+)$/i);
    if (mYear) {
      const n = Number(mYear[2]);
      const seqText = Number.isFinite(n) ? (n < 100 ? String(n).padStart(2, '0') : String(n)) : mYear[2];
      return `PO ${mYear[1]}-${seqText}`;
    }

    // Normalize "PO-..." to "PO ..." for display.
    const normalized = raw.replace(/^PO-\s*/i, 'PO ').replace(/^PO\s+/i, 'PO ');

    // For non-year formats like "PO DEV-001", keep the prefix and ensure the numeric sequence
    // uses 2 digits unless it reaches 100.
    const mGeneric = normalized.match(/^PO\s+(.+)-(\d+)$/i);
    if (mGeneric) {
      const n = Number(mGeneric[2]);
      const seqText = Number.isFinite(n) ? (n < 100 ? String(n).padStart(2, '0') : String(n)) : mGeneric[2];
      return `PO ${mGeneric[1]}-${seqText}`;
    }

    return normalized;
  }

  function formatPaymentOrderNo(year2, seq) {
    const y = normalizeMasonicYear2(year2);
    const n = normalizeSequence(seq);
    const seqText = n < 100 ? String(n).padStart(2, '0') : String(n);
    return `PO ${y}-${seqText}`;
  }

  function formatMoneyTransferNo(year2, seq) {
    const y = normalizeMasonicYear2(year2);
    const n = normalizeSequence(seq);
    const seqText = n < 100 ? String(n).padStart(2, '0') : String(n);
    return `MT ${y}-${seqText}`;
  }

  function getYear2ForBudgetYear(year) {
    const y = Number(year);
    if (!Number.isInteger(y)) return null;
    const yy = ((y % 100) + 100) % 100;
    return String(yy).padStart(2, '0');
  }

  function inferNextSequenceFromOrdersForYear2(orders, year2) {
    const y2 = normalizeMasonicYear2(year2);
    let maxSeq = 0;
    for (const o of orders || []) {
      const canon = canonicalizePaymentOrderNo(o && o.paymentOrderNo);
      const m = canon.match(/^PO(\d{2})-(\d+)$/i);
      if (!m) continue;
      if (m[1] !== y2) continue;
      const n = Number(m[2]);
      if (!Number.isFinite(n)) continue;
      const seq = Math.trunc(n);
      if (seq > maxSeq) maxSeq = seq;
    }
    return Math.max(1, maxSeq + 1);
  }

  function syncNumberingSettingsToBudgetYear(year) {
    const year2 = getYear2ForBudgetYear(year);
    if (!year2) return false;

    const orders = loadOrders(year);
    const nextFromOrders = inferNextSequenceFromOrdersForYear2(orders, year2);

    const current = loadNumberingSettings();
    const isSameYear2 = normalizeMasonicYear2(current.year2) === year2;
    const nextSeq = isSameYear2 ? Math.max(normalizeSequence(current.nextSeq), nextFromOrders) : nextFromOrders;

    // Money Transfer numbering defaults to restarting at 1 each year.
    const mtNextSeq = isSameYear2 ? normalizeSequence(current.mtNextSeq) : 1;

    if (isSameYear2 && normalizeSequence(current.nextSeq) === nextSeq && normalizeSequence(current.mtNextSeq) === mtNextSeq) return false;
    saveNumberingSettings({ year2, nextSeq, mtNextSeq });
    return true;
  }

  function getNextPaymentOrderNo() {
    const s = loadNumberingSettings();
    return formatPaymentOrderNo(s.year2, s.nextSeq);
  }

  function getNextMoneyTransferNo() {
    const s = loadNumberingSettings();
    return formatMoneyTransferNo(s.year2, s.mtNextSeq);
  }

  function advancePaymentOrderSequence() {
    const s = loadNumberingSettings();
    const current = normalizeSequence(s.nextSeq);
    const next = current + 1;
    saveNumberingSettings({ year2: s.year2, nextSeq: next });
    return true;
  }

  function advanceMoneyTransferSequence() {
    const s = loadNumberingSettings();
    const current = normalizeSequence(s.mtNextSeq);
    const next = current + 1;
    saveNumberingSettings({ year2: s.year2, mtNextSeq: next });
    return true;
  }

  function setPaymentOrderNoField(value) {
    if (!form) return;
    const el = form.elements.namedItem('paymentOrderNo');
    if (!el) return;
    const raw = String(value ?? '').trim();
    el.value = formatPaymentOrderNoForDisplay(raw) || raw;
    el.readOnly = true;
    el.setAttribute('aria-readonly', 'true');
  }

  const PUBLIC_PAYMENT_ORDER_NO_PLACEHOLDER = 'auto-applied';

  function setPaymentOrderNoPlaceholder() {
    if (!form) return;
    const el = form.elements.namedItem('paymentOrderNo');
    if (!el) return;
    el.value = PUBLIC_PAYMENT_ORDER_NO_PLACEHOLDER;
    el.readOnly = true;
    el.setAttribute('aria-readonly', 'true');
    el.title = 'Payment Order No. is auto-applied when saving.';
  }

  function replacePaymentOrderNoWithSelect(selectedValue, year) {
    if (!form) return;
    const input = form.elements.namedItem('paymentOrderNo');
    if (!input) return;

    const field = input.closest ? input.closest('.field') : null;
    const labelReq = field ? field.querySelector('.req') : null;
    if (labelReq) labelReq.remove();

    const select = document.createElement('select');
    select.id = 'paymentOrderNo';
    select.name = 'paymentOrderNo';
    select.autocomplete = 'off';

    const emptyOpt = document.createElement('option');
    emptyOpt.value = '';
    emptyOpt.textContent = '';
    select.appendChild(emptyOpt);

    ensurePaymentOrdersListExistsForYear(year);
    const byCanonical = new Map();
    for (const order of loadOrders(year) || []) {
      const raw = String(order && order.paymentOrderNo ? order.paymentOrderNo : '').trim();
      if (!raw) continue;
      const display = formatPaymentOrderNoForDisplay(raw) || raw;
      const canonical = canonicalizePaymentOrderNo(display);
      if (canonical && !byCanonical.has(canonical)) byCanonical.set(canonical, { raw, display });
    }

    if (selectedValue) {
      const display = formatPaymentOrderNoForDisplay(selectedValue) || selectedValue;
      const canonical = canonicalizePaymentOrderNo(display);
      if (canonical && !byCanonical.has(canonical)) byCanonical.set(canonical, { raw: selectedValue, display });
    }

    const sorted = Array.from(byCanonical.values()).sort((a, b) =>
      String(a.display).localeCompare(String(b.display), undefined, { numeric: true, sensitivity: 'base' })
    );

    for (const entry of sorted) {
      const opt = document.createElement('option');
      opt.value = entry.raw;
      opt.textContent = entry.display;
      select.appendChild(opt);
    }

    select.value = selectedValue || '';
    if (input.parentNode) input.parentNode.replaceChild(select, input);
  }

  function maybeAutofillPaymentOrderNo() {
    if (!form) return;
    if (form.dataset.reconciliationEdit === '1') return;

    // Keep numbering aligned to the active budget year so the next PO No.
    // displayed on the form matches what will be generated on submit.
    // Avoid syncing/writing shared numbering in unauthenticated WP mode.
    if (!IS_WP_SHARED_MODE || getWpToken()) {
      syncNumberingSettingsToBudgetYear(getActiveBudgetYear());
    }

    const editId = getEditOrderId();
    if (editId) {
      const year = getActiveBudgetYear();
      const existing = getOrderById(editId, year);
      if (existing && existing.paymentOrderNo) setPaymentOrderNoField(existing.paymentOrderNo);
      return;
    }

    // In WP shared mode, unauthenticated viewers should not see the next number.
    // It will be generated and applied at save-time once the user is logged in.
    if (IS_WP_SHARED_MODE && !getWpToken()) {
      setPaymentOrderNoPlaceholder();
      return;
    }

    // Only restore a draft Payment Order No when explicitly resuming a draft.
    // Otherwise stale drafts can cause the field to show a previously-used number.
    try {
      const params = new URLSearchParams(window.location.search);
      const resumeDraft = params.get('resumeDraft') === '1';
      if (resumeDraft) {
        const draft = loadDraft();
        if (draft && String(draft.paymentOrderNo || '').trim()) {
          setPaymentOrderNoField(draft.paymentOrderNo);
          return;
        }
      }
    } catch {
      // ignore
    }

    setPaymentOrderNoField(getNextPaymentOrderNo());
  }

  async function maybeAutofillPaymentOrderNoFromWpPublicEndpoint() {
    if (!form) return;
    if (!IS_WP_SHARED_MODE) return;
    if (getWpToken()) return;

    const editId = getEditOrderId();
    if (editId) return;

    try {
      const params = new URLSearchParams(window.location.search);
      const resumeDraft = params.get('resumeDraft') === '1';
      if (resumeDraft) return;
    } catch {
      // ignore
    }

    try {
      const year = getActiveBudgetYear();
      const url = `${wpJoin('acgl-fms/v1/public/next-po')}?year=${encodeURIComponent(String(year))}`;
      const res = await wpFetchJson(url, { method: 'GET' });
      if (!res.ok) return;
      const payload = await readJsonResponse(res);
      if (!payload || payload.ok !== true) return;
      const po = String(payload.paymentOrderNo || '').trim();
      if (!po) return;
      setPaymentOrderNoField(po);
    } catch {
      // ignore
    }
  }

  function getIbanUtils() {
    const u = window.IbanUtils;
    if (!u || typeof u !== 'object') return null;
    if (typeof u.validateIban !== 'function') return null;
    if (typeof u.formatIban !== 'function') return null;
    return u;
  }

  function getBicUtils() {
    const u = window.BicUtils;
    if (!u || typeof u !== 'object') return null;
    if (typeof u.validateBic !== 'function') return null;
    if (typeof u.formatBic !== 'function') return null;
    return u;
  }

  function normalizeUsBankText(raw) {
    const trimmed = String(raw ?? '').trim();
    if (!trimmed) return '';
    return trimmed.replace(/[\s-]+/g, '');
  }

  function getUsAccountTypeFromForm() {
    if (!form) return '';
    const checkingEl = form.elements.namedItem('usAccountTypeChecking');
    const savingsEl = form.elements.namedItem('usAccountTypeSavings');
    const checking = Boolean(checkingEl && typeof checkingEl.checked === 'boolean' && checkingEl.checked);
    const savings = Boolean(savingsEl && typeof savingsEl.checked === 'boolean' && savingsEl.checked);
    if (checking && !savings) return 'Checking';
    if (savings && !checking) return 'Savings';
    return '';
  }

  function setUsAccountTypeOnForm(value) {
    if (!form) return;
    const checkingEl = form.elements.namedItem('usAccountTypeChecking');
    const savingsEl = form.elements.namedItem('usAccountTypeSavings');
    const v = String(value || '').trim();
    if (checkingEl && typeof checkingEl.checked === 'boolean') checkingEl.checked = v === 'Checking';
    if (savingsEl && typeof savingsEl.checked === 'boolean') savingsEl.checked = v === 'Savings';
  }

  function getBankDetailsModeFromForm() {
    if (!form) return 'INTL';
    const toggle = form.elements.namedItem('bankDetailsToggle');
    const checked = toggle && typeof toggle.checked === 'boolean' ? toggle.checked : false;
    return checked ? 'US' : 'INTL';
  }

  function setBankDetailsModeOnForm(mode) {
    if (!form) return;
    const m = mode === 'US' ? 'US' : 'INTL';
    const toggle = form.elements.namedItem('bankDetailsToggle');
    if (toggle && typeof toggle.checked === 'boolean') toggle.checked = m === 'US';
  }

  function applyBankDetailsModeToUi(mode) {
    const m = mode === 'US' ? 'US' : 'INTL';
    const labelA = document.getElementById('bankFieldLabelA');
    const labelB = document.getElementById('bankFieldLabelB');
    const ibanEl = form ? form.elements.namedItem('iban') : null;
    const bicEl = form ? form.elements.namedItem('bic') : null;
    const bankDetailsToggleField = document.getElementById('bankDetailsToggleField');
    const usAccountTypeField = document.getElementById('usAccountTypeField');
    const usAccountTypeStar = document.getElementById('usAccountTypeReqStar');
    const specialEl = form ? form.elements.namedItem('specialInstructions') : null;
    const usToken = document.getElementById('usBankRequirementsToken');
    const specialStar = document.getElementById('specialInstructionsReqStar');
    const modeText = document.getElementById('bankDetailsModeText');
    const toggle = form ? form.elements.namedItem('bankDetailsToggle') : null;

    // Keep the switch UI in sync with the active mode.
    if (toggle && typeof toggle.checked === 'boolean') toggle.checked = m === 'US';
    // Show what the user can switch to (not the currently-active mode).
    const switchToText = m === 'US' ? 'International (IBAN)' : 'US Bank Details';
    if (modeText) modeText.textContent = switchToText;
    if (toggle) toggle.setAttribute('aria-label', switchToText);

    if (labelA) labelA.textContent = m === 'US' ? 'Account' : 'IBAN';
    if (labelB) labelB.textContent = m === 'US' ? 'Routing' : 'BIC';

    if (ibanEl) {
      ibanEl.placeholder = m === 'US' ? 'Account number' : 'DE00 0000 0000 0000 00';
      ibanEl.autocomplete = 'off';
      ibanEl.type = 'text';
      if (m === 'US') ibanEl.setAttribute('inputmode', 'numeric');
      else ibanEl.removeAttribute('inputmode');
    }

    if (bicEl) {
      bicEl.placeholder = m === 'US' ? 'Routing number' : 'DEUTDEFF';
      bicEl.autocomplete = 'off';
      bicEl.type = 'text';
      if (m === 'US') bicEl.setAttribute('inputmode', 'numeric');
      else bicEl.removeAttribute('inputmode');
    }

    if (specialEl) {
      if (m === 'US') {
        specialEl.required = true;
        specialEl.setAttribute('aria-required', 'true');
      } else {
        specialEl.required = false;
        specialEl.removeAttribute('aria-required');
      }
    }

    if (specialStar) specialStar.hidden = m !== 'US';

    if (usAccountTypeField) usAccountTypeField.hidden = m !== 'US';
    if (usAccountTypeStar) usAccountTypeStar.hidden = m !== 'US';

    // Layout: in US mode, show Account Type to the right of Bank Details.
    if (bankDetailsToggleField && bankDetailsToggleField.classList) {
      if (m === 'US') bankDetailsToggleField.classList.remove('field--span2');
      else bankDetailsToggleField.classList.add('field--span2');
    }

    if (usToken) usToken.hidden = m !== 'US';
  }

  function saveFormToDraft() {
    if (!form) return;
    const budgetEl = form.elements.namedItem('budgetNumber');

    const bankDetailsMode = getBankDetailsModeFromForm();

    const ibanUtils = getIbanUtils();
    const ibanRaw = form.iban?.value?.trim?.() || '';
    const ibanNormalized = bankDetailsMode === 'US'
      ? normalizeUsBankText(ibanRaw)
      : (ibanUtils ? ibanUtils.validateIban(ibanRaw).normalized : String(ibanRaw).trim());

    const bicUtils = getBicUtils();
    const bicRaw = form.bic?.value?.trim?.() || '';
    const bicNormalized = bankDetailsMode === 'US'
      ? normalizeUsBankText(bicRaw)
      : (bicUtils ? bicUtils.validateBic(bicRaw).normalized : String(bicRaw).trim());

    const draft = {
      paymentOrderNo: form.paymentOrderNo?.value?.trim?.() || '',
      date: form.date?.value?.trim?.() || '',
      name: form.name?.value?.trim?.() || '',
      euro: form.euro?.value?.trim?.() || '',
      usd: form.usd?.value?.trim?.() || '',
      address: form.address?.value?.trim?.() || '',
      iban: ibanNormalized,
      bic: bicNormalized,
      usAccountType: getUsAccountTypeFromForm(),
      specialInstructions: form.specialInstructions?.value?.trim?.() || '',
      bankDetailsMode,
      budgetNumber: extractOutCodeFromBudgetNumberText(budgetEl ? String(budgetEl.value || '').trim() : ''),
      purpose: form.purpose?.value?.trim?.() || '',
    };
    saveDraft(draft);
  }

  function openItemizeDraft() {
    clearItemsError();
    saveFormToDraft();
    const year = getActiveBudgetYear();
    window.location.href = `itemize.html?draft=1&year=${encodeURIComponent(String(year))}`;
  }

  function showItemsError(message) {
    if (!itemsErrorEl) return;
    itemsErrorEl.textContent = message;
  }

  function clearItemsError() {
    if (!itemsErrorEl) return;
    itemsErrorEl.textContent = '';
  }

  function formatDate(isoDate) {
    // Keep it stable in all browsers/WP embeds: show as YYYY-MM-DD if present.
    return String(isoDate || '').trim();
  }

  function clearFieldErrors() {
    if (!form) return;
    const errorEls = document.querySelectorAll('.error');
    errorEls.forEach((el) => (el.textContent = ''));

    const inputs = form.querySelectorAll('input, textarea, select');
    inputs.forEach((el) => el.classList.remove('input-error'));
  }

  /**
   * @returns {{ ok: boolean, values?: Object, errors?: Record<string,string> }}
   */
  function validateForm() {
    if (!form) {
      return { ok: false, errors: { _form: 'Form not found on this page.' } };
    }

    const budgetEl = form.elements.namedItem('budgetNumber');
    const budgetNumberRaw = budgetEl ? String(budgetEl.value || '').trim() : '';

    const values = {
      paymentOrderNo: form.paymentOrderNo.value.trim(),
      date: form.date.value.trim(),
      name: form.name.value.trim(),
      address: form.address.value.trim(),
      iban: form.iban.value.trim(),
      bic: form.bic.value.trim(),
      usAccountType: getUsAccountTypeFromForm(),
      specialInstructions: form.specialInstructions.value.trim(),
      bankDetailsMode: getBankDetailsModeFromForm(),
      budgetNumber: extractOutCodeFromBudgetNumberText(budgetNumberRaw),
      purpose: form.purpose.value.trim(),
      captchaAnswer: form.captchaAnswer ? String(form.captchaAnswer.value || '').trim() : '',
    };

    const errors = {};

    if (values.bankDetailsMode === 'US') {
      values.iban = normalizeUsBankText(values.iban);
      values.bic = normalizeUsBankText(values.bic);
      if (!values.iban) errors.iban = 'This field is required.';
      if (!values.bic) errors.bic = 'This field is required.';
      if (!values.usAccountType) errors.usAccountType = 'Select Checking or Savings.';
      if (!values.specialInstructions) errors.specialInstructions = 'This field is required.';
    } else {
      // Normalize + validate IBAN independently so we can return the specific messages.
      {
        const ibanUtils = getIbanUtils();
        if (ibanUtils) {
          const res = ibanUtils.validateIban(values.iban);
          values.iban = res.normalized;
          if (!res.isValid) errors.iban = res.error || 'IBAN is required';
        } else {
          // Should not happen (iban.js is expected), but keep a safe fallback.
          const trimmed = String(values.iban || '').trim();
          values.iban = trimmed;
          if (!trimmed) errors.iban = 'IBAN is required';
        }
      }

      // Normalize + validate BIC independently so we can return the specific messages.
      {
        const bicUtils = getBicUtils();
        if (bicUtils) {
          const res = bicUtils.validateBic(values.bic);
          values.bic = res.normalized;
          if (!res.isValid) errors.bic = res.error || 'BIC is required';
        } else {
          const trimmed = String(values.bic || '').trim();
          values.bic = trimmed;
          if (!trimmed) errors.bic = 'BIC is required';
        }
      }
    }

    // Required checks (all fields except currency; currency is validated as an either/or pair)
    const requiredKeys = [
      ...(form.dataset.reconciliationEdit === '1' ? [] : ['paymentOrderNo']),
      'date',
      'name',
      'address',
      'purpose',
      'captchaAnswer',
    ];
    for (const key of requiredKeys) {
      if (!values[key]) errors[key] = 'This field is required.';
    }

    if (!errors.captchaAnswer) {
      if (requestCaptchaExpected === null) {
        errors.captchaAnswer = 'Captcha is not ready. Please reload the page.';
      } else if (values.captchaAnswer !== requestCaptchaExpected) {
        errors.captchaAnswer = 'Incorrect captcha answer.';
      }
    }

    if (Object.keys(errors).length > 0) {
      return { ok: false, errors };
    }

    return {
      ok: true,
      values: {
        ...values,
      },
    };
  }

  // ---- Attachments (WP Media in shared mode; IndexedDB standalone) ----

  function getWpAttachmentsUrl(pathWithNoLeadingSlash) {
    const base = wpJoin('acgl-fms/v1');
    const p = String(pathWithNoLeadingSlash || '').replace(/^\//, '');
    return `${base}/${p}`;
  }

  async function wpListAttachments(targetKey) {
    const url = `${getWpAttachmentsUrl('attachments')}?targetKey=${encodeURIComponent(String(targetKey || ''))}`;
    const res = await wpFetchJson(url, { method: 'GET' });
    if (res.status === 401 || res.status === 403) throw new Error('not_authorized');
    if (!res.ok) throw new Error(`list_failed_${res.status}`);
    const payload = await readJsonResponse(res);
    if (!payload || typeof payload !== 'object') throw new Error('invalid_json');
    const items = payload && Array.isArray(payload.items) ? payload.items : [];
    return items;
  }

  async function wpGetAttachmentById(id) {
    const numericId = Number.parseInt(String(id || ''), 10);
    if (!Number.isFinite(numericId) || numericId <= 0) return null;
    const url = getWpAttachmentsUrl(`attachments/${numericId}`);
    const res = await wpFetchJson(url, { method: 'GET' });
    if (res.status === 401 || res.status === 403) throw new Error('not_authorized');
    if (!res.ok) return null;
    const payload = await readJsonResponse(res);
    return payload && typeof payload === 'object' ? payload : null;
  }

  async function wpUploadAttachment(targetKey, file, context) {
    const url = getWpAttachmentsUrl('attachments/upload');
    const fd = new FormData();
    fd.append('targetKey', String(targetKey || ''));
    if (context && context.year) fd.append('year', String(context.year));
    if (context && context.paymentOrderNo) fd.append('paymentOrderNo', String(context.paymentOrderNo));
    if (context && context.orderId) fd.append('orderId', String(context.orderId));
    fd.append('file', file, file && file.name ? file.name : 'attachment');

    const res = await wpFetchJson(url, { method: 'POST', body: fd });
    if (res.status === 401 || res.status === 403) throw new Error('not_authorized');
    if (!res.ok) throw new Error(`upload_failed_${res.status}`);
    const payload = await readJsonResponse(res);
    if (!payload || payload.ok !== true) throw new Error('upload_failed');
    return payload.item && typeof payload.item === 'object' ? payload.item : null;
  }

  async function wpUploadBacklogAttachment(itemId, file) {
    const id = String(itemId || '').trim();
    if (!id) throw new Error('missing_item_id');
    const url = getWpAttachmentsUrl('backlog-attachments/upload');
    const fd = new FormData();
    fd.append('itemId', id);
    fd.append('file', file, file && file.name ? file.name : 'attachment');

    const res = await wpFetchJson(url, { method: 'POST', body: fd });
    if (res.status === 401 || res.status === 403) throw new Error('not_authorized');
    if (!res.ok) throw new Error(`upload_failed_${res.status}`);
    const payload = await readJsonResponse(res);
    if (!payload || payload.ok !== true) throw new Error('upload_failed');
    const item = payload.item && typeof payload.item === 'object' ? payload.item : null;
    appendAppAuditEvent('Backlog Attachments', `Item ${id}`, 'Created', [
      { field: 'Attachment', from: '', to: String((item && item.name) || (file && file.name) || 'attachment') },
    ]);
    return item;
  }

  async function wpDeleteAttachmentById(id) {
    const numericId = Number.parseInt(String(id || ''), 10);
    if (!Number.isFinite(numericId) || numericId <= 0) return;
    const url = getWpAttachmentsUrl(`attachments/${numericId}`);
    const res = await wpFetchJson(url, { method: 'DELETE' });
    if (res.status === 401 || res.status === 403) throw new Error('not_authorized');
    if (!res.ok) throw new Error(`delete_failed_${res.status}`);
  }

  async function wpDeleteAttachmentsByTargetKey(targetKey) {
    const url = `${getWpAttachmentsUrl('attachments')}?targetKey=${encodeURIComponent(String(targetKey || ''))}`;
    const res = await wpFetchJson(url, { method: 'DELETE' });
    if (res.status === 401 || res.status === 403) throw new Error('not_authorized');
    if (!res.ok) throw new Error(`delete_failed_${res.status}`);
  }

  let attachmentsDbPromise = null;

  function showAttachmentsError(message) {
    if (!attachmentsError) return;
    attachmentsError.textContent = message || '';
  }

  function openAttachmentsDb() {
    if (attachmentsDbPromise) return attachmentsDbPromise;
    attachmentsDbPromise = new Promise((resolve, reject) => {
      if (!window.indexedDB) {
        reject(new Error('IndexedDB not available in this browser.'));
        return;
      }

      const req = window.indexedDB.open(ATTACHMENTS_DB, ATTACHMENTS_DB_VERSION);
      req.onupgradeneeded = () => {
        const db = req.result;
        if (!db.objectStoreNames.contains(ATTACHMENTS_STORE)) {
          const store = db.createObjectStore(ATTACHMENTS_STORE, { keyPath: 'id' });
          store.createIndex('by_targetKey', 'targetKey', { unique: false });
          store.createIndex('by_createdAt', 'createdAt', { unique: false });
        }
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error || new Error('Failed to open attachments database.'));
    });
    return attachmentsDbPromise;
  }

  function idbRequestToPromise(req) {
    return new Promise((resolve, reject) => {
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }

  async function listAttachments(targetKey) {
    if (IS_WP_SHARED_MODE) {
      return wpListAttachments(targetKey);
    }

    const db = await openAttachmentsDb();
    const tx = db.transaction(ATTACHMENTS_STORE, 'readonly');
    const store = tx.objectStore(ATTACHMENTS_STORE);
    const index = store.index('by_targetKey');
    const attachments = await idbRequestToPromise(index.getAll(targetKey));

    // Sort newest-first
    return (attachments || []).sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)));
  }

  async function addAttachment(targetKey, file, context) {
    if (IS_WP_SHARED_MODE) {
      const uploaded = await wpUploadAttachment(targetKey, file, context);
      appendAppAuditEvent('Attachments', String(targetKey || 'Attachment'), 'Created', [
        { field: 'Attachment', from: '', to: String((uploaded && uploaded.name) || (file && file.name) || 'attachment') },
      ]);
      return uploaded;
    }

    const db = await openAttachmentsDb();
    const tx = db.transaction(ATTACHMENTS_STORE, 'readwrite');
    const store = tx.objectStore(ATTACHMENTS_STORE);
    const record = {
      id: (crypto?.randomUUID ? crypto.randomUUID() : `att_${Date.now()}_${Math.random().toString(16).slice(2)}`),
      targetKey,
      name: file.name,
      type: file.type || 'application/octet-stream',
      size: file.size,
      lastModified: file.lastModified || null,
      createdAt: new Date().toISOString(),
      blob: file, // File is a Blob; IndexedDB can store Blobs.
    };
    await idbRequestToPromise(store.put(record));
    appendAppAuditEvent('Attachments', String(targetKey || 'Attachment'), 'Created', [
      { field: 'Attachment', from: '', to: String(record.name || 'attachment') },
    ]);
    return record;
  }

  async function deleteAttachmentById(id) {
    let existing = null;
    try {
      existing = await getAttachmentById(id);
    } catch {
      existing = null;
    }

    if (IS_WP_SHARED_MODE) {
      await wpDeleteAttachmentById(id);
      const target = existing && existing.targetKey ? String(existing.targetKey) : 'Attachment';
      const name = existing && existing.name ? String(existing.name) : String(id || 'attachment');
      appendAppAuditEvent('Attachments', target, 'Deleted', [
        { field: 'Attachment', from: name, to: '' },
      ]);
      return;
    }
    const db = await openAttachmentsDb();
    const tx = db.transaction(ATTACHMENTS_STORE, 'readwrite');
    const store = tx.objectStore(ATTACHMENTS_STORE);
    await idbRequestToPromise(store.delete(id));
    const target = existing && existing.targetKey ? String(existing.targetKey) : 'Attachment';
    const name = existing && existing.name ? String(existing.name) : String(id || 'attachment');
    appendAppAuditEvent('Attachments', target, 'Deleted', [
      { field: 'Attachment', from: name, to: '' },
    ]);
  }

  async function deleteAttachmentsByTargetKey(targetKey) {
    if (!targetKey) return;
    if (IS_WP_SHARED_MODE) {
      await wpDeleteAttachmentsByTargetKey(targetKey);
      return;
    }

    const db = await openAttachmentsDb();
    const tx = db.transaction(ATTACHMENTS_STORE, 'readwrite');
    const store = tx.objectStore(ATTACHMENTS_STORE);
    const index = store.index('by_targetKey');

    // Prefer keys-only API when available.
    let keys;
    if (typeof index.getAllKeys === 'function') {
      keys = await idbRequestToPromise(index.getAllKeys(targetKey));
    } else {
      const records = await idbRequestToPromise(index.getAll(targetKey));
      keys = (records || []).map((r) => r && r.id).filter(Boolean);
    }

    for (const id of keys || []) {
      // eslint-disable-next-line no-await-in-loop
      await idbRequestToPromise(store.delete(id));
    }
  }

  async function clearDraftAttachments() {
    try {
      await deleteAttachmentsByTargetKey('draft');
    } catch {
      // Ignore; draft reset should not fail the UI.
    }
  }

  function formatBytes(bytes) {
    const n = Number(bytes);
    if (!Number.isFinite(n) || n < 0) return '';
    if (n < 1024) return `${n} B`;
    const kb = n / 1024;
    if (kb < 1024) return `${kb.toFixed(1)} KB`;
    const mb = kb / 1024;
    if (mb < 1024) return `${mb.toFixed(1)} MB`;
    const gb = mb / 1024;
    return `${gb.toFixed(1)} GB`;
  }

  function getAttachmentTargetKey(itemizeTarget) {
    if (itemizeTarget?.isDraft) return 'draft';
    if (itemizeTarget?.orderId) return `order:${itemizeTarget.orderId}`;
    return null;
  }

  async function getAttachmentById(id) {
    if (!id) return null;
    if (IS_WP_SHARED_MODE) {
      return wpGetAttachmentById(id);
    }
    const db = await openAttachmentsDb();
    const tx = db.transaction(ATTACHMENTS_STORE, 'readonly');
    const store = tx.objectStore(ATTACHMENTS_STORE);
    const record = await idbRequestToPromise(store.get(id));
    return record || null;
  }

  function openUrlInNewTab(url) {
    const href = String(url || '').trim();
    if (!href) return;
    const a = document.createElement('a');
    a.href = href;
    a.target = '_blank';
    a.rel = 'noopener noreferrer';
    document.body.appendChild(a);
    a.click();
    a.remove();
  }

  function openBlobInNewTab(blob) {
    if (!blob) return;
    const url = URL.createObjectURL(blob);

    // Use a synthetic anchor so we can enforce noopener/noreferrer.
    const a = document.createElement('a');
    a.href = url;
    a.target = '_blank';
    a.rel = 'noopener noreferrer';
    document.body.appendChild(a);
    a.click();
    a.remove();

    // Keep the object URL alive briefly so the new tab can load it.
    setTimeout(() => URL.revokeObjectURL(url), 2 * 60 * 1000);
  }

  function downloadBlob(blob, fileName) {
    if (!blob) return;
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = fileName || 'attachment';
    document.body.appendChild(a);
    a.click();
    a.remove();
    // Keep the object URL alive long enough for large files to start downloading.
    setTimeout(() => URL.revokeObjectURL(url), 2 * 60 * 1000);
  }

  function downloadUrl(url, fileName) {
    const href = String(url || '').trim();
    if (!href) return;
    const a = document.createElement('a');
    a.href = href;
    if (fileName) a.download = fileName;
    a.rel = 'noopener noreferrer';
    document.body.appendChild(a);
    a.click();
    a.remove();
  }

  function dataUrlToUint8Array(dataUrl) {
    const s = String(dataUrl || '');
    const m = s.match(/^data:([^;]+);base64,(.*)$/);
    if (!m) return null;
    const b64 = m[2] || '';
    try {
      const bin = atob(b64);
      const out = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
      return out;
    } catch {
      return null;
    }
  }

  function getDataUrlMime(dataUrl) {
    const s = String(dataUrl || '');
    const m = s.match(/^data:([^;]+);base64,/);
    return m ? String(m[1] || '') : '';
  }

  async function fetchBinary(url) {
    const res = await fetch(url, { cache: 'no-store' });
    if (!res.ok) throw new Error('fetch_failed');
    const buf = await res.arrayBuffer();
    return new Uint8Array(buf);
  }

  function getTodayStamp() {
    const d = new Date();
    const yyyy = d.getFullYear();
    const mm = String(d.getMonth() + 1).padStart(2, '0');
    const dd = String(d.getDate()).padStart(2, '0');
    return `${yyyy}-${mm}-${dd}`;
  }

  async function generatePaymentOrderPdfFromTemplate(options = {}) {
    let stage = 'init';
    const describeErr = (err) => {
      try {
        if (!err) return '';
        const name = typeof err.name === 'string' ? err.name : '';
        const msg = typeof err.message === 'string' ? err.message : String(err);
        const head = [name, msg].filter(Boolean).join(': ');
        return head || String(err);
      } catch {
        return '';
      }
    };

    try {
      const PDFLib = window.PDFLib;
      if (!PDFLib || !PDFLib.PDFDocument) {
        window.alert('PDF library not loaded.');
        return;
      }

      const debug = Boolean(options && options.debug);
      // Download-only behavior (no preview / new-tab navigation).

      const order = options && options.order && typeof options.order === 'object' ? options.order : null;
      if (!form && !order) {
        window.alert('Payment Order data not found. Open an order (View) or use the request form.');
        return;
      }

      let templateBytes;
      try {
        stage = 'fetch_template';
        templateBytes = await fetchBinary('payment_order_template.pdf');
      } catch {
        window.alert('Missing PDF template file: payment_order_template.pdf');
        return;
      }

      let pdfDoc;
      try {
        stage = 'load_template';
        pdfDoc = await PDFLib.PDFDocument.load(templateBytes);
      } catch (err) {
        // If the template is encrypted/corrupt, pdf-lib throws; previously this
        // became an unhandled rejection and the button looked like a no-op.
        console.error('Failed to load PDF template', err);
        window.alert('Could not load the PDF template. Ensure payment_order_template.pdf is a valid, unencrypted PDF.');
        return;
      }

      stage = 'get_page';
      const pages = pdfDoc.getPages();
      const page = pages && pages.length ? pages[0] : null;
      if (!page) {
        window.alert('Invalid PDF template.');
        return;
      }

      stage = 'embed_font';
      const font = await pdfDoc.embedFont(PDFLib.StandardFonts.Helvetica);
      const fontBold = await pdfDoc.embedFont(PDFLib.StandardFonts.HelveticaBold);

      const drawTextWrapped = (textRaw, opts) => {
        const HALF_LINE_MARKER = '__HALF_LINE__';
        const text = String(textRaw ?? '').replace(/\r\n/g, '\n');
        const x = Number(opts && opts.x);
        const startY = Number(opts && opts.y);
        const size = Number(opts && opts.size) || 10;
        const firstLineOffset = Number(opts && opts.firstLineOffset) || 0;
        const alignRaw = String((opts && opts.align) || 'left').toLowerCase();
        const align = (alignRaw === 'center' || alignRaw === 'right') ? alignRaw : 'left';
        const maxWidth = Number(opts && opts.maxWidth) || 0;
        const maxHeight = Number(opts && opts.maxHeight) || 0;
        const lineHeight = Number(opts && opts.lineHeight) || Math.max(10, size + 2);
        if (!Number.isFinite(x) || !Number.isFinite(startY)) return;
        if (!text.trim()) return;

        const pageSize = page.getSize();
        const effectiveMaxWidth = maxWidth > 0 ? maxWidth : Math.max(40, pageSize.width - x - 24);
        const effectiveMaxHeight = maxHeight > 0 ? maxHeight : 0;

        const pushWrappedLine = (out, rawLine) => {
          const line = String(rawLine ?? '');
          if (!line) {
            out.push('');
            return;
          }
          const words = line.split(/\s+/g);
          let cur = '';
          for (const w of words) {
            const next = cur ? `${cur} ${w}` : w;
            const wNext = font.widthOfTextAtSize(next, size);
            if (wNext <= effectiveMaxWidth || !cur) {
              cur = next;
              continue;
            }
            out.push(cur);
            cur = w;
          }
          if (cur) out.push(cur);
        };

        const lines = [];
        for (const rawLine of text.split('\n')) pushWrappedLine(lines, rawLine);

        let y = startY;
        let didDrawFirstTextLine = false;
        const minY = effectiveMaxHeight > 0 ? startY - effectiveMaxHeight : -Infinity;
        for (const line of lines) {
          if (y < minY) break;
          const lineText = String(line);
          if (lineText === HALF_LINE_MARKER) {
            y -= (lineHeight * 0.35);
            continue;
          }
          if (!lineText) {
            y -= lineHeight;
            continue;
          }
          const lineWidth = font.widthOfTextAtSize(lineText, size);
          const offset = Math.max(0, effectiveMaxWidth - lineWidth);
          const drawX = align === 'center'
            ? x + (offset / 2)
            : align === 'right'
              ? x + offset
              : x;
          const drawY = y + (!didDrawFirstTextLine ? firstLineOffset : 0);
          page.drawText(lineText, { x: drawX, y: drawY, size, font });
          didDrawFirstTextLine = true;
          y -= lineHeight;
        }
      };

      const drawFittedCenteredText = (textRaw, opts) => {
        const text = String(textRaw ?? '').replace(/\s+/g, ' ').trim();
        const x = Number(opts && opts.x);
        const y = Number(opts && opts.y);
        const maxWidth = Number(opts && opts.maxWidth) || 0;
        const size0 = Number(opts && opts.size) || 10;
        const minSize = Number(opts && opts.minSize) || Math.max(7, size0 - 3);
        const useFont = (opts && opts.font) || font;
        if (!text || !Number.isFinite(x) || !Number.isFinite(y) || !(maxWidth > 0)) return;

        let size = size0;
        while (size > minSize && useFont.widthOfTextAtSize(text, size) > maxWidth) size -= 0.25;

        const w = useFont.widthOfTextAtSize(text, size);
        const drawX = x + Math.max(0, (maxWidth - w) / 2);
        page.drawText(text, { x: drawX, y, size, font: useFont });
      };

    const drawMarker = (x, y, label) => {
      if (!debug) return;
      const c = PDFLib.rgb(1, 0, 0);
      page.drawLine({ start: { x: x - 6, y }, end: { x: x + 6, y }, thickness: 0.7, color: c });
      page.drawLine({ start: { x, y: y - 6 }, end: { x, y: y + 6 }, thickness: 0.7, color: c });
      page.drawText(String(label || ''), { x: x + 8, y: y + 2, size: 6, font, color: c });
    };

    if (debug) {
      const { width, height } = page.getSize();

      // Calibration grid (more detailed + more readable labels)
      const step = 10;
      const majorEvery = 50;
      const minorEvery = 25;

      const microColor = PDFLib.rgb(0.94, 0.94, 0.94);
      const minorColor = PDFLib.rgb(0.86, 0.86, 0.86);
      const majorColor = PDFLib.rgb(0.72, 0.72, 0.72);
      const labelColor = PDFLib.rgb(0.35, 0.35, 0.35);

      for (let x = 0; x <= width; x += step) {
        const isMajor = x % majorEvery === 0;
        const isMinor = !isMajor && x % minorEvery === 0;
        const color = isMajor ? majorColor : isMinor ? minorColor : microColor;
        const thickness = isMajor ? 0.6 : isMinor ? 0.45 : 0.25;
        page.drawLine({ start: { x, y: 0 }, end: { x, y: height }, thickness, color });
        if (isMajor) {
          page.drawText(String(x), { x: x + 2, y: height - 12, size: 6, font, color: labelColor });
        }
      }

      for (let y = 0; y <= height; y += step) {
        const isMajor = y % majorEvery === 0;
        const isMinor = !isMajor && y % minorEvery === 0;
        const color = isMajor ? majorColor : isMinor ? minorColor : microColor;
        const thickness = isMajor ? 0.6 : isMinor ? 0.45 : 0.25;
        page.drawLine({ start: { x: 0, y }, end: { x: width, y }, thickness, color });
        if (isMajor) {
          page.drawText(String(y), { x: 2, y: y + 2, size: 6, font, color: labelColor });
        }
      }

      page.drawText(`CALIBRATION MODE — page ${Math.round(width)}x${Math.round(height)}`,
        {
          x: 40,
          y: height - 22,
          size: 9,
          font,
          color: PDFLib.rgb(1, 0, 0),
        });
    }

    const value = (name) => {
      const key = String(name || '').trim();
      if (!key) return '';

      // If an order is provided (e.g., from the View modal), use it.
      if (order) {
        try {
          if (key === 'euro' || key === 'usd') {
            const n = order[key];
            return n === null || n === undefined ? '' : String(n).trim();
          }
          return String(order[key] ?? '').trim();
        } catch {
          return '';
        }
      }

      // Otherwise read from the request form.
      try {
        const el = form.elements.namedItem(key);
        return el && typeof el.value === 'string' ? el.value.trim() : '';
      } catch {
        return '';
      }
    };

    const stripPaymentOrderPrefix = (raw) => {
      const s = String(raw ?? '').trim();
      if (!s) return '';
      return s.replace(/^po\s*/i, '').trim();
    };

    const formatMoneyWithSymbol = (textRaw, symbol) => {
      const rawText = String(textRaw ?? '').trim();
      if (!rawText) return '';

      const m = rawText.match(/-?\d[\d\s.,]*/);
      let s = String(m ? m[0] : rawText).replace(/\s+/g, '');

      if (s.includes(',') && s.includes('.')) s = s.replace(/,/g, '');
      else if (s.includes(',') && !s.includes('.')) s = s.replace(/,/g, '.');

      s = s.replace(/(?!^-)[^0-9.]/g, '');
      const parts = s.split('.');
      if (parts.length > 2) {
        const dec = parts.pop();
        const intPart = parts.join('');
        s = `${intPart}.${dec}`;
      }

      const n = Number.parseFloat(s);
      if (!Number.isFinite(n)) return rawText;
      const sign = n < 0 ? '-' : '';
      const abs = Math.abs(n);
      return `${sign}${symbol}${abs.toFixed(2)}`;
    };

    const lookupBudgetDescriptionForOutCode = (budgetNumberRaw) => {
      const code = String(budgetNumberRaw ?? '').trim().match(/^\d{4}/)?.[0] || '';
      if (!code) return '';
      try {
        const year = typeof getActiveBudgetYear === 'function' ? getActiveBudgetYear() : undefined;
        const outMap = typeof getOutDescMapForYear === 'function' ? getOutDescMapForYear(year) : null;
        const fromTable = outMap && typeof outMap.get === 'function' ? outMap.get(code) : '';
        const fromStatic = (typeof BUDGET_DESC_BY_CODE !== 'undefined' && BUDGET_DESC_BY_CODE && typeof BUDGET_DESC_BY_CODE.get === 'function')
          ? BUDGET_DESC_BY_CODE.get(code)
          : '';
        return String(fromTable || fromStatic || '').trim();
      } catch {
        return '';
      }
    };

    // Replace the template's top-right printed date (e.g. "31-03-2024") with
    // the current digital form version by masking the entire top-right corner
    // above the summary stamp.
    {
      const { width, height } = page.getSize();
      const versionText = 'Digital Form V1: 2026-02-28';
      const size = 7;

      // The summary stamp starts at y = (height - 32). Mask everything ABOVE it.
      const stampStartY = height - 32;
      const maskY = stampStartY - 2;

      // Mask the full top-right corner to the page edge.
      // (Wider than half-page because the template's printed date sits a bit
      // left of the right margin.)
      const maskX = Math.max(0, width - 500);
      const maskW = Math.max(0, width - maskX);
      // Extend beyond the computed page height to also cover any template
      // content that sits in a CropBox/visual margin above MediaBox.
      const maskH = Math.max(0, height - maskY + 200);

      page.drawRectangle({
        x: maskX,
        y: maskY,
        width: maskW,
        height: maskH,
        color: PDFLib.rgb(1, 1, 1),
      });

      if (debug) {
        page.drawRectangle({
          x: maskX,
          y: maskY,
          width: maskW,
          height: maskH,
          borderWidth: 0.7,
          borderColor: PDFLib.rgb(1, 0, 0),
          color: PDFLib.rgb(1, 1, 1),
          opacity: 0,
        });
        drawMarker(maskX, maskY, 'formVersion_mask');
      }

      // Place replacement text at the top-right inside the masked region.
      const textW = font.widthOfTextAtSize(versionText, size);
      const rightMargin = 32;
      const xText = Math.max(32, width - rightMargin - textW);
      // Put the label as high as possible; if the visible page extends beyond
      // `height`, this keeps it in the masked region.
      const yText = height - 8;
      page.drawText(versionText, { x: xText, y: yText, size, font });
    }

    // Mask and redraw the template header line "Ancient Free and Accepted Masons"
    // using a slightly larger size and the same font style as the main header.
    {
      const { width } = page.getSize();
      const headerText = 'Ancient Free and Accepted Masons';
      const size = 12;

      // Approximate y-position under the "American Canadian Grand Lodge" header.
      // Adjust here if the template changes.
      const y = 812;

      const textW = fontBold.widthOfTextAtSize(headerText, size);
      const x = Math.max(24, (width - textW) / 2 - 7);

      // Mask the printed line behind it.
      const padX = 18;
      const padY = 4;
      page.drawRectangle({
        x: Math.max(0, x - padX),
        y: y - padY,
        width: Math.min(width, textW + (padX * 2)),
        height: size + (padY * 2),
        color: PDFLib.rgb(1, 1, 1),
      });

      page.drawText(headerText, { x, y, size, font: fontBold });

      if (debug) {
        drawMarker(x, y, 'afam_header');
      }
    }

    // Mask the template's divider line above the BUDGET section and redraw as
    // a bold dotted line.
    {
      const { width } = page.getSize();

      // Approximate y-position for the divider just above the "BUDGET, FILING..." heading.
      // Adjust here if the template changes.
      const yLine = 268;
      const leftX = 40;
      const rightX = width - 40;

      // Mask the original printed line.
      page.drawRectangle({
        x: leftX - 6,
        y: yLine - 4,
        width: (rightX - leftX) + 12,
        height: 10,
        color: PDFLib.rgb(1, 1, 1),
      });

      // Draw dotted line as circles.
      const dotColor = PDFLib.rgb(0, 0, 0);
      const dotRadius = 1.2;
      const dotStep = 7;
      const maxX = rightX - (dotStep * 7);
      for (let x = leftX; x <= maxX; x += dotStep) {
        page.drawCircle({ x, y: yLine, size: dotRadius, color: dotColor });
      }

      if (debug) {
        drawMarker(leftX, yLine, 'budget_divider');
      }
    }

    // Always write a small summary block at the top-right so the output is
    // visibly different from the template even if field coordinates are not
    // tuned yet.
    {
      const { width, height } = page.getSize();
      const poNoRaw = value('paymentOrderNo') || 'DRAFT';
      const poNoDisplay = poNoRaw === 'DRAFT' ? 'DRAFT' : stripPaymentOrderPrefix(poNoRaw);
      const dateDisplay = value('date') || getTodayStamp();
      const nameDisplay = value('name');
      const euroDisplay = formatMoneyWithSymbol(value('euro'), '€');
      const usdDisplay = formatMoneyWithSymbol(value('usd'), '$');

      const lines = [
        `Payment Order No: ${poNoDisplay}`,
        `Date: ${dateDisplay}`,
        nameDisplay ? `Name: ${nameDisplay}` : '',
        euroDisplay ? `Euro: ${euroDisplay}` : '',
        usdDisplay ? `USD: ${usdDisplay}` : '',
      ].filter(Boolean);

      let y = height - 32;
      const size = 9;
      const rightMargin = 32;
      const rightX = width - rightMargin;
      for (const line of lines) {
        const s = String(line);
        const w = font.widthOfTextAtSize(s, size);
        const x = Math.max(32, rightX - w);
        page.drawText(s, { x, y, size, font });
        y -= 12;
      }
    }

    const gl = loadGrandLodgeInfo();

    // Field coordinates from calibration sheet (pdf-lib coords: x→right, y→up).
    const textFields = [
      { key: 'paymentOrderNo', source: 'form', x: 350, y: 721, size: 13 },
      { key: 'date', source: 'form', x: 420, y: 687, size: 10 },
      { key: 'grandTreasurer', source: 'gl', x: 167, y: 687, size: 10 },
      { key: 'name', source: 'form', x: 130, y: 585, size: 10 },

      { key: 'address', source: 'form', x: 130, y: 570, size: 9, wrap: true, lineHeight: 11, maxWidth: 470, maxHeight: 70, firstLineOffset: 1 },
      { key: 'iban', source: 'form', x: 130, y: 540, size: 10 },
      { key: 'bic', source: 'form', x: 130, y: 525, size: 10 },

      { key: 'euro', source: 'form', x: 180, y: 615, size: 10 },
      { key: 'usd', source: 'form', x: 280, y: 615, size: 10 },

      { key: 'budgetNumber', source: 'form', x: 200, y: 226, size: 10 },
      { key: 'specialInstructions', source: 'form', x: 60, y: 435, size: 9, wrap: true, lineHeight: 11, maxWidth: 540, maxHeight: 180 },
      { key: 'purpose', source: 'form', x: 50, y: 210, size: 9, wrap: true, lineHeight: 11, maxWidth: 540, maxHeight: 180 },

      { key: 'grandMaster', source: 'gl', x: -47, y: 765, size: 10, maxWidth: 270, fitCenter: true },
      { key: 'grandSecretary', source: 'gl', x: 370, y: 765, size: 10, maxWidth: 270, fitCenter: true, marker: 'grandSecretary_top' },
      { key: 'grandSecretary', source: 'gl', x: 406, y: 290, size: 10, marker: 'grandSecretary_sig' },

      // Operation Address box: bottom ~280, top ~810. Start from the top and wrap downward.
      { key: 'operationAddress', source: 'gl', x: 182, y: 795, yBottom: 280, size: 9, wrap: true, align: 'center', lineHeight: 11, maxWidth: 240, marker: 'operationAddress' },
    ];

    const readFieldValue = (f) => {
      if (!f || typeof f !== 'object') return '';
      const addBlankLineAfterFirstLine = (textRaw) => {
        const HALF_LINE_MARKER = '__HALF_LINE__';
        const text = String(textRaw ?? '');
        const lines = text.replace(/\r\n/g, '\n').split('\n');
        if (lines.length < 2) return text;
        if (lines[1] === '' || lines[1] === HALF_LINE_MARKER) return text;
        lines.splice(1, 0, HALF_LINE_MARKER);
        return lines.join('\n');
      };

      if (f.source === 'gl') {
        try {
          const rawGl = String((gl && gl[f.key]) || '').trim();
          return rawGl;
        } catch {
          return '';
        }
      }

      const raw = String(value(f.key) || '');
      if (f.key === 'paymentOrderNo') return stripPaymentOrderPrefix(raw);
      if (f.key === 'address') return addBlankLineAfterFirstLine(raw);
      if (f.key === 'euro') return formatMoneyWithSymbol(raw, '€');
      if (f.key === 'usd') return formatMoneyWithSymbol(raw, '$');
      return raw;
    };

    for (const f of textFields) {
      const v = readFieldValue(f);
      if (f.fitCenter) {
        drawFittedCenteredText(v, {
          x: f.x,
          y: f.y,
          size: f.size,
          minSize: 8,
          maxWidth: f.maxWidth,
          font,
        });
      } else if (f.wrap) {
        const maxHeight = Number.isFinite(f.maxHeight) && f.maxHeight > 0
          ? f.maxHeight
          : (Number.isFinite(f.yBottom) ? Math.max(0, Number(f.y) - Number(f.yBottom)) : 0);
        drawTextWrapped(v, {
          x: f.x,
          y: f.y,
          size: f.size,
          align: f.align,
          maxWidth: f.maxWidth,
          maxHeight,
          lineHeight: f.lineHeight,
          firstLineOffset: f.firstLineOffset,
        });
      } else {
        const useFont = f.key === 'paymentOrderNo' ? fontBold : font;
        page.drawText(String(v), { x: f.x, y: f.y, size: f.size, font: useFont });
      }

      if (f.key === 'budgetNumber') {
        const desc = lookupBudgetDescriptionForOutCode(v);
        if (desc) {
          const codeW = font.widthOfTextAtSize(String(v || ''), Number(f.size) || 10);
          const descX = Number(f.x) + Math.max(10, codeW + 4);
          const { width } = page.getSize();
          const maxWidth = Math.max(120, (width - 40) - descX);
          drawTextWrapped(` - ${desc}`, {
            x: descX,
            y: f.y,
            size: f.size,
            maxWidth,
            maxHeight: 24,
            lineHeight: 11,
          });
          drawMarker(descX, f.y, 'budget_desc');
        }
      }
      drawMarker(f.x, f.y, String(f.marker || f.key));
    }

    const gsCredsAllowed = order ? shouldApplyGsCredentials(order) : false;
    const sealBytes = gsCredsAllowed && gl && gl.grandLodgeSealDataUrl ? dataUrlToUint8Array(gl.grandLodgeSealDataUrl) : null;
    const sigBytes = gsCredsAllowed && gl && gl.grandSecretarySignatureDataUrl ? dataUrlToUint8Array(gl.grandSecretarySignatureDataUrl) : null;

    if (sealBytes) {
      stage = 'embed_seal';
      const mime = getDataUrlMime(gl.grandLodgeSealDataUrl);
      const img = mime === 'image/jpeg' ? await pdfDoc.embedJpg(sealBytes) : await pdfDoc.embedPng(sealBytes);
      const pageSize = page.getSize();
      const leftX = 355;
      const bottomY = 280;
      const topY = 330;
      const targetH = Math.max(12, topY - bottomY);
      const aspect = img.height ? (img.width / img.height) : 1;
      const targetW = Math.min(pageSize.width - 8 - leftX, Math.max(12, targetH * aspect));
      const rect = { x: leftX, y: bottomY, width: targetW, height: targetH };
      page.drawImage(img, rect);
      drawMarker(rect.x, rect.y, 'seal');
      if (debug) {
        page.drawRectangle({
          x: rect.x,
          y: rect.y,
          width: rect.width,
          height: rect.height,
          borderWidth: 0.7,
          borderColor: PDFLib.rgb(1, 0, 0),
          color: PDFLib.rgb(1, 1, 1),
          opacity: 0,
        });
      }
    }

    if (sigBytes) {
      stage = 'embed_signature';
      const mime = getDataUrlMime(gl.grandSecretarySignatureDataUrl);
      const img = mime === 'image/jpeg' ? await pdfDoc.embedJpg(sigBytes) : await pdfDoc.embedPng(sigBytes);
      const pageSize = page.getSize();
      const leftX = 405;
      const bottomY = 295;
      const topY = 315;
      const targetH = Math.max(10, topY - bottomY);
      const aspect = img.height ? (img.width / img.height) : 3;
      const targetW = Math.min(pageSize.width - 8 - leftX, Math.max(40, targetH * aspect));
      const rect = { x: leftX, y: bottomY, width: targetW, height: targetH };
      page.drawImage(img, rect);
      drawMarker(rect.x, rect.y, 'signature');
      if (debug) {
        page.drawRectangle({
          x: rect.x,
          y: rect.y,
          width: rect.width,
          height: rect.height,
          borderWidth: 0.7,
          borderColor: PDFLib.rgb(1, 0, 0),
          color: PDFLib.rgb(1, 1, 1),
          opacity: 0,
        });
      }
    }

      // Set the initial view zoom to 125%.
      // Note: not all PDF viewers honor OpenAction zoom.
      try {
        const zoom = 1.25;
        const PDFName = PDFLib && PDFLib.PDFName;
        if (PDFName && pdfDoc && pdfDoc.context && pdfDoc.catalog && page && page.ref) {
          const openAction = pdfDoc.context.obj([page.ref, PDFName.of('XYZ'), null, null, zoom]);
          pdfDoc.catalog.set(PDFName.of('OpenAction'), openAction);
        }
      } catch {
        // ignore
      }

      stage = 'save_pdf';
      const outBytes = await pdfDoc.save();
      const blob = new Blob([outBytes], { type: 'application/pdf' });
      const poNo = String(value('paymentOrderNo') || '').trim().replace(/[^a-z0-9_-]+/gi, '_');
      const stamp = getTodayStamp();

      stage = 'download';
      const filename = debug
        ? `payment_order_${poNo || 'draft'}_${stamp}_calibration.pdf`
        : `payment_order_${poNo || 'draft'}_${stamp}.pdf`;
      downloadBlob(blob, filename);
    } catch (err) {
      console.error('PDF generation failed', err);
      // Provide a useful hint without requiring the console.
      try {
        window.alert(`Could not generate the PDF (stage: ${stage || 'unknown'}). ${describeErr(err)}`.trim());
      } catch {
        window.alert('Could not generate the PDF. Check the browser console for details.');
      }
    }
  }

  function openAttachmentInNewTab(att) {
    if (!att || typeof att !== 'object') return;
    if (att.url) {
      openUrlInNewTab(att.url);
      return;
    }
    if (att.blob) {
      openBlobInNewTab(att.blob);
    }
  }

  function downloadAttachment(att) {
    if (!att || typeof att !== 'object') return;
    if (att.url) {
      downloadUrl(att.url, att.name);
      return;
    }
    if (att.blob) {
      downloadBlob(att.blob, att.name);
    }
  }

  function renderAttachmentsTable(attachments) {
    if (!attachmentsTbody || !attachmentsEmptyState) return;
    attachmentsTbody.innerHTML = '';

    if (!attachments || attachments.length === 0) {
      attachmentsEmptyState.hidden = false;
      return;
    }

    attachmentsEmptyState.hidden = true;
    attachmentsTbody.innerHTML = attachments
      .map((a, idx) => {
        const safeName = escapeHtml(a.name);
        const safeId = escapeHtml(a.id);
        return `
          <tr data-attachment-id="${safeId}">
            <td class="num">${idx + 1}</td>
            <td>${safeName}</td>
            <td class="num">${escapeHtml(formatBytes(a.size))}</td>
            <td class="actions">
              <button type="button" class="btn btn--viewGrey btn--viewIcon" data-attachment-action="view" title="View" aria-label="View">${VIEW_EYE_ICON_SVG}</button>
              <button type="button" class="btn btn--ghost" data-attachment-action="download">Download</button>
              <button type="button" class="btn btn--danger" data-attachment-action="delete">Remove</button>
            </td>
              <button type="button" class="btn btn--editIcon" data-notifications-open-edit="${escapeHtml(instanceId)}" aria-label="Edit"><svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path d="M15.502 1.94a.5.5 0 0 1 0 .706L14.459 3.69l-2-2L13.502.646a.5.5 0 0 1 .707 0l1.293 1.293zm-1.75 2.456-2-2L4.939 9.21a.5.5 0 0 0-.121.196l-.805 2.414a.25.25 0 0 0 .316.316l2.414-.805a.5.5 0 0 0 .196-.12l6.813-6.814z"/><path fill-rule="evenodd" d="M1 13.5A1.5 1.5 0 0 0 2.5 15h11a1.5 1.5 0 0 0 1.5-1.5v-6a.5.5 0 0 0-1 0v6a.5.5 0 0 1-.5.5h-11a.5.5 0 0 1-.5-.5v-11a.5.5 0 0 1 .5-.5H9a.5.5 0 0 0 0-1H2.5A1.5 1.5 0 0 0 1 2.5z"/></svg></button>
        `.trim();
      })
      .join('');
  }

  function renderModalAttachments(attachments) {
    if (!attachments || attachments.length === 0) {
      return '<div class="muted">No attachments.</div>';
    }

    return attachments
      .map((a) => {
        const safeId = escapeHtml(a.id);
        const safeName = escapeHtml(a.name || 'attachment');
        const passwordPlain = String(u && typeof u.passwordPlain === 'string' ? u.passwordPlain : '')
          || extractLegacyPasswordPlain(u && u.passwordHash, u && u.salt);
        const safeSize = escapeHtml(formatBytes(a.size));
        return `
          <div class="modalAttRow" data-attachment-id="${safeId}">
            <div class="modalAttName">
              <div>${safeName}</div>
              <div class="muted">${safeSize}</div>
            </div>
            <div class="modalAttActions">
              <button type="button" class="btn btn--viewGrey btn--viewIcon" data-modal-attachment-action="view" title="View" aria-label="View">${VIEW_EYE_ICON_SVG}</button>
              <button type="button" class="btn btn--ghost" data-modal-attachment-action="download">Download</button>
            </div>
          </div>
        `.trim();
      })
      .join('');
  }

  async function refreshAttachments(targetKey) {
    if (!targetKey) return;
    try {
      const attachments = await listAttachments(targetKey);
      renderAttachmentsTable(attachments);
    } catch (err) {
      const code = String(err && err.message ? err.message : '');
      if (code === 'not_authorized') showAttachmentsError('Sign in to view attachments.');
      else showAttachmentsError('Could not load attachments.');
      // eslint-disable-next-line no-console
      console.error(err);
    }
  }

  async function handleAddedFiles(targetKey, fileList, context) {
    const files = Array.from(fileList || []);
    if (files.length === 0) return;

    if (IS_WP_SHARED_MODE) {
      // In WordPress shared mode, uploading attachments requires sign-in.
      if (!getCurrentUser()) {
        showAttachmentsError('Sign in to upload attachments.');
        return;
      }
      const requiredLevel = context && context.orderId ? 'write' : 'create';
      if (!requireWriteAccess('orders', 'Payment Orders is read only for your account.', requiredLevel)) return;

      const po = context && typeof context.paymentOrderNo === 'string' ? context.paymentOrderNo.trim() : '';
      const oid = context && typeof context.orderId === 'string' ? context.orderId.trim() : '';
      if (!po && !oid) {
        showAttachmentsError('Enter the Payment Order No. before uploading documents.');
        return;
      }
    }

    showAttachmentsError('');
    for (const file of files) {
      try {
        // eslint-disable-next-line no-await-in-loop
        await addAttachment(targetKey, file, context);
      } catch (err) {
        // Likely quota or unsupported blob storage.
        const code = String(err && err.message ? err.message : '');
        if (code === 'not_authorized') showAttachmentsError('Sign in to upload attachments.');
        else showAttachmentsError('Attachment could not be saved.');
        // eslint-disable-next-line no-console
        console.error(err);
        break;
      }
    }

    await refreshAttachments(targetKey);
  }

  function isDevEnvironment() {
    const host = String(window.location.hostname || '').toLowerCase();
    return host === 'localhost' || host === '127.0.0.1' || host === '::1';
  }

  const MOCK_VERSION_KEY = 'payment_orders_mock_version';
  const MOCK_VERSION = '3';
  const RECONCILIATION_MOCK_VERSION_KEY = 'payment_orders_reconciliation_mock_version';
  const RECONCILIATION_MOCK_VERSION = '2';

  function isMockOrder(order) {
    return !!order && typeof order === 'object' && String(order.id || '').startsWith('mock_');
  }

  function isMockReconciliationOrder(order) {
    return !!order && typeof order === 'object' && String(order.id || '').startsWith('mock_rec_');
  }

  function makeMockReconciliationOrders(year, now = Date.now()) {
    const y = Number(year);
    const year2 = String(y % 100).padStart(2, '0');
    const baseDate = `${y}-03-`;
    const makeIso = (offsetDays) => new Date(now - offsetDays * 1000 * 60 * 60 * 24).toISOString();

    const templates = [
      {
        paymentOrderNo: `PO ${year2}-90`,
        date: `${baseDate}04`,
        name: 'Riley Example',
        euro: 148.75,
        usd: null,
        source: 'Commerzbank',
        budgetNumber: '2200',
        with: 'Requestor',
        status: 'Submitted',
        purpose: 'Travel reimbursement pending reconciliation.',
      },
      {
        paymentOrderNo: `PO ${year2}-91`,
        date: `${baseDate}11`,
        name: 'Morgan Example',
        euro: 92.40,
        usd: null,
        source: 'Commerzbank',
        budgetNumber: '2100',
        with: 'Grand Secretary',
        status: 'Review',
        purpose: 'Office supplies reimbursement pending reconciliation.',
      },
      {
        paymentOrderNo: `PO ${year2}-92`,
        date: `${baseDate}18`,
        name: 'Casey Example',
        euro: null,
        usd: 64.15,
        source: 'wiseUSD',
        budgetNumber: '2246',
        with: 'Requestor',
        status: 'Submitted',
        purpose: 'USD transfer fee reimbursement pending reconciliation.',
      },
    ];

    return templates.map((t, idx) => {
      const createdAt = makeIso(12 - idx * 2);
      return {
        id: `mock_rec_${y}_${idx + 1}`,
        createdAt,
        updatedAt: createdAt,
        source: String(t.source || '').trim() || 'Commerzbank',
        paymentOrderNo: t.paymentOrderNo,
        date: t.date,
        name: t.name,
        euro: t.euro,
        usd: t.usd,
        budgetNumber: t.budgetNumber,
        purpose: t.purpose,
        with: t.with,
        status: t.status,
        address: '123 Example Street\nExample City',
        iban: 'DE00 0000 0000 0000 0000 00',
        bic: 'EXAMPLED1XXX',
        specialInstructions: '',
      };
    });
  }

  function makeMockOrders(now) {
    const mock = [
      {
        id: `mock_${now}_1`,
        createdAt: new Date(now - 1000 * 60 * 5).toISOString(),
        status: 'Review',
        paymentOrderNo: 'PO-DEV-001',
        date: '2026-02-15',
        name: 'Alex Example',
        // Totals are derived from items, but kept here for list rendering.
        euro: 0,
        usd: null,
        items: [
          { id: `mock_${now}_1_i1`, title: 'Train tickets', euro: 80.5, usd: null },
          { id: `mock_${now}_1_i2`, title: 'Hotel (1 night)', euro: 120.0, usd: null },
          { id: `mock_${now}_1_i3`, title: 'Meals', euro: 45.0, usd: null },
        ],
        address: '123 Example Street\nExample City',
        iban: 'DE89 3704 0044 0532 0130 00',
        bic: 'DEUTDEFFXXX',
        specialInstructions: 'Urgent reimbursement. Please process this week.',
        budgetNumber: '2200',
        purpose: 'Travel reimbursement.',
      },
      {
        id: `mock_${now}_2`,
        createdAt: new Date(now - 1000 * 60 * 15).toISOString(),
        status: 'Approved',
        paymentOrderNo: 'PO-DEV-002',
        date: '2026-02-10',
        name: 'Taylor Example',
        euro: null,
        usd: 0,
        items: [
          { id: `mock_${now}_2_i1`, title: 'Supplies', euro: null, usd: 60.0 },
          { id: `mock_${now}_2_i2`, title: 'Shipping', euro: null, usd: 29.99 },
          { id: `mock_${now}_2_i3`, title: 'Service fee', euro: null, usd: 12.5 },
        ],
        address: '456 Sample Ave\nSampletown',
        iban: 'GB82 WEST 1234 5698 7654 32',
        bic: 'BARCGB22',
        specialInstructions: 'Pay in USD only.',
        budgetNumber: '2100',
        purpose: 'Supplies reimbursement.',
      },
      {
        id: `mock_${now}_3`,
        createdAt: new Date(now - 1000 * 60 * 35).toISOString(),
        status: 'Paid',
        paymentOrderNo: 'PO-DEV-003',
        date: '2026-02-01',
        name: 'Jordan Example',
        euro: 0,
        usd: null,
        items: [
          { id: `mock_${now}_3_i1`, title: 'Zero-value test entry', euro: 0, usd: null },
        ],
        address: '789 Demo Road\nDemoville',
        iban: 'FR14 2004 1010 0505 0001 3M02 606',
        bic: 'BNPAFRPPXXX',
        specialInstructions: 'N/A',
        budgetNumber: '2280',
        purpose: 'Zero-value test entry.',
      },
    ];

    // Compute totals from items for each mock order
    return mock.map((o) => {
      const totals = sumItems(o.items || []);
      const hasUsd = (o.items || []).some((it) => it && it.usd !== null && it.usd !== undefined);
      const hasEuro = (o.items || []).some((it) => it && it.euro !== null && it.euro !== undefined);
      return {
        ...o,
        euro: hasEuro ? totals.euro : null,
        usd: hasUsd ? totals.usd : null,
      };
    });
  }

  function ensureMockItemsAndTotals(order) {
    const next = { ...order };

    // Keep existing status if set, but normalize it; otherwise default.
    next.status = normalizeOrderStatus(next.status);

    if (!Array.isArray(next.items) || next.items.length === 0) {
      // Backfill a single item from the stored total.
      const euro = next.euro === null || next.euro === undefined ? null : Number(next.euro);
      const usd = next.usd === null || next.usd === undefined ? null : Number(next.usd);
      next.items = [
        {
          id: (crypto?.randomUUID ? crypto.randomUUID() : `it_${Date.now()}_${Math.random().toString(16).slice(2)}`),
          title: 'Mock item',
          euro: Number.isFinite(euro) ? euro : null,
          usd: Number.isFinite(usd) ? usd : null,
        },
      ];
    }

    // Ensure every item has id/title and only one currency
    next.items = next.items.map((it, idx) => {
      const safe = it && typeof it === 'object' ? { ...it } : {};
      if (!safe.id) safe.id = (crypto?.randomUUID ? crypto.randomUUID() : `it_${Date.now()}_${idx}_${Math.random().toString(16).slice(2)}`);
      if (!safe.title) safe.title = `Mock item ${idx + 1}`;
      const hasEuro = safe.euro !== null && safe.euro !== undefined && safe.euro !== '';
      const hasUsd = safe.usd !== null && safe.usd !== undefined && safe.usd !== '';
      if (hasEuro && hasUsd) {
        // Prefer the original order's currency if known; otherwise keep euro.
        const orderPref = next.euro !== null && next.euro !== undefined ? 'EUR' : (next.usd !== null && next.usd !== undefined ? 'USD' : 'EUR');
        if (orderPref === 'EUR') safe.usd = null;
        else safe.euro = null;
      }
      return safe;
    });

    const totals = sumItems(next.items);
    const hasUsd = next.items.some((it) => it && it.usd !== null && it.usd !== undefined);
    const hasEuro = next.items.some((it) => it && it.euro !== null && it.euro !== undefined);
    next.euro = hasEuro ? totals.euro : null;
    next.usd = hasUsd ? totals.usd : null;
    return next;
  }

  function formatEuroValue(n, opts) {
    const num = Number(n);
    const isNeg = num < 0;
    const abs = Math.abs(num);
    const fmt = new Intl.NumberFormat('en-US', {
      minimumFractionDigits: 2,
      maximumFractionDigits: 2,
    }).format(abs);
    const prefix = opts && opts.prefix ? String(opts.prefix) : '';
    const suffix = opts && opts.suffix ? String(opts.suffix) : '';
    return `${isNeg ? '-' : ''}${prefix}${fmt}${suffix}`;
  }

  function buildBudgetTbodyHtmlFromLines(section1, section2) {
    const sec1Lines = Array.isArray(section1) ? section1 : [];
    const sec2Lines = Array.isArray(section2) ? section2 : [];

    function normalizeLine(line) {
      const safe = line && typeof line === 'object' ? line : {};
      const inCode = String(safe.inCode || '').trim();
      const outCode = String(safe.outCode || '').trim();
      const desc = String(safe.desc || '').trim();
      const approved = Number(safe.approved || 0);
      const receipts = Number(safe.receipts || 0);
      const expenditures = Number(safe.expenditures || 0);
      return {
        inCode: /^\d{4}$/.test(inCode) ? inCode : '',
        outCode: /^\d{4}$/.test(outCode) ? outCode : '',
        desc,
        approved: Number.isFinite(approved) ? approved : 0,
        receipts: Number.isFinite(receipts) ? receipts : 0,
        expenditures: Number.isFinite(expenditures) ? expenditures : 0,
      };
    }

    function lineRowHtml(line, kind) {
      const l = normalizeLine(line);
      const ops = getBudgetCalcOpsForRow(kind, null, l.desc);
      const balance = computeBudgetBalance(l.approved, l.receipts, l.expenditures, ops);

      const approvedText = `EUR ${formatEuroValue(l.approved)}`;
      const receiptsText = `${formatEuroValue(l.receipts)} €`;
      const expText = `${formatEuroValue(l.expenditures)} €`;
      const balText = `${formatEuroValue(balance)} €`;

      return `
        <tr data-calc-receipts="${escapeHtml(ops.receiptsOp)}" data-calc-expenditures="${escapeHtml(ops.expendituresOp)}">
          <td class="num">${escapeHtml(l.inCode)}</td>
          <td class="num">${escapeHtml(l.outCode)}</td>
          <td>${escapeHtml(l.desc)}</td>
          <td class="num budgetTable__euro">${escapeHtml(approvedText)}</td>
          <td class="num budgetTable__euro">${escapeHtml(receiptsText)}</td>
          <td class="num budgetTable__euro">${escapeHtml(expText)}</td>
          <td class="num budgetTable__bal">${escapeHtml(balText)}</td>
          <td class="budgetTable__usdSign">$</td>
          <td class="num budgetTable__usd">-</td>
          <td class="budgetTable__usdSign">$</td>
          <td class="num budgetTable__usd">-</td>
        </tr>
      `.trim();
    }

    function sumSection(lines, kind) {
      const totals = { approved: 0, receipts: 0, expenditures: 0, balance: 0 };
      for (const line of lines) {
        const l = normalizeLine(line);
        totals.approved += l.approved;
        totals.receipts += l.receipts;
        totals.expenditures += l.expenditures;
        const ops = getBudgetCalcOpsForRow(kind, null, l.desc);
        const balance = computeBudgetBalance(l.approved, l.receipts, l.expenditures, ops);
        totals.balance += balance;
      }
      return totals;
    }

    const s1 = sumSection(sec1Lines, 'anticipated');
    const s2 = sumSection(sec2Lines, 'budget');

    const remaining = s2.receipts + s1.balance - s2.expenditures;
    const receiptsChecksum = s1.receipts - s2.receipts;
    const expendituresChecksum = s1.expenditures - s2.expenditures;

    const sec1Html = sec1Lines.map((l) => lineRowHtml(l, 'anticipated')).join('\n');
    const sec2Html = sec2Lines.map((l) => lineRowHtml(l, 'budget')).join('\n');

    const sec1TotalRow = `
      <tr class="budgetTable__total">
        <td></td>
        <td></td>
        <td><strong>Total Anticipated Values</strong></td>
        <td class="num"><strong>${escapeHtml(`${formatEuroValue(s1.approved)} €`)}</strong></td>
        <td class="num"><strong>${escapeHtml(`${formatEuroValue(s1.receipts)} €`)}</strong></td>
        <td class="num"><strong>${escapeHtml(`${formatEuroValue(s1.expenditures)} €`)}</strong></td>
        <td class="num"><strong>${escapeHtml(`${formatEuroValue(s1.balance)} €`)}</strong></td>
        <td class="budgetTable__usdSign"></td>
        <td class="num budgetTable__usd"><strong>$ 0.00</strong></td>
        <td class="budgetTable__usdSign"></td>
        <td class="num budgetTable__usd"><strong>$ 0.00</strong></td>
      </tr>
    `.trim();

    const sec2TotalRow = `
      <tr class="budgetTable__total">
        <td></td>
        <td></td>
        <td><strong>Total Budget, Receipts, Expenditures</strong></td>
        <td class="num"><strong>${escapeHtml(`${formatEuroValue(s2.approved)} €`)}</strong></td>
        <td class="num"><strong>${escapeHtml(`${formatEuroValue(s2.receipts)} €`)}</strong></td>
        <td class="num"><strong>${escapeHtml(`${formatEuroValue(s2.expenditures)} €`)}</strong></td>
        <td class="num"><strong>${escapeHtml(`${formatEuroValue(s2.balance)} €`)}</strong></td>
        <td class="budgetTable__usdSign"></td>
        <td class="num budgetTable__usd"><strong>$ 0.00</strong></td>
        <td class="budgetTable__usdSign"></td>
        <td class="num budgetTable__usd"><strong>$ 0.00</strong></td>
      </tr>
    `.trim();

    const remainingRow = `
      <tr class="budgetTable__remaining">
        <td></td>
        <td></td>
        <td><strong>Remaining funds of balance</strong></td>
        <td></td>
        <td></td>
        <td></td>
        <td class="num"><strong>${escapeHtml(`${formatEuroValue(remaining)} €`)}</strong></td>
        <td></td>
        <td></td>
        <td></td>
        <td></td>
      </tr>
    `.trim();

    const checksumSpacer = `
      <tr class="budgetTable__spacer budgetTable__checksumSpacer">
        <td colspan="11"></td>
      </tr>
    `.trim();

    const receiptsChecksumRow = `
      <tr class="budgetTable__checksum" data-checksum-kind="receipts">
        <td></td>
        <td></td>
        <td><strong>Receipts Checksum</strong></td>
        <td></td>
        <td class="num"><strong>${escapeHtml(`${formatEuroValue(receiptsChecksum)} €`)}</strong></td>
        <td></td>
        <td></td>
        <td></td>
        <td></td>
        <td></td>
        <td></td>
      </tr>
    `.trim();

    const expendituresChecksumRow = `
      <tr class="budgetTable__checksum" data-checksum-kind="expenditures">
        <td></td>
        <td></td>
        <td><strong>Expenditures Checksum</strong></td>
        <td></td>
        <td></td>
        <td class="num"><strong>${escapeHtml(`${formatEuroValue(expendituresChecksum)} €`)}</strong></td>
        <td></td>
        <td></td>
        <td></td>
        <td></td>
        <td></td>
      </tr>
    `.trim();

    return [
      sec1Html,
      '<tr class="budgetTable__spacer"><td colspan="11"></td></tr>',
      sec1TotalRow,
      '<tr class="budgetTable__spacer"><td colspan="11"></td></tr>',
      sec2Html,
      sec2TotalRow,
      remainingRow,
      checksumSpacer,
      receiptsChecksumRow,
      expendituresChecksumRow,
    ]
      .filter(Boolean)
      .join('\n');
  }

  function seedMockData2025IfDev() {
    if (!isDevEnvironment()) return;

    const targetYear = 2025;

    // Seed a full budget for 2025 if missing.
    const budgetKey = getBudgetTableKeyForYear(targetYear);
    if (budgetKey && !String(localStorage.getItem(budgetKey) || '').trim()) {
      let sourceHtml = null;

      // Prefer cloning from an existing saved budget year (if any).
      const years = migrateLegacyBudgetIfNeeded();
      const candidates = [];
      const active = loadActiveBudgetYear();
      if (active && Number.isInteger(active)) candidates.push(active);
      for (const y of years) candidates.push(y);

      for (const y of Array.from(new Set(candidates))) {
        const k = getBudgetTableKeyForYear(y);
        const h = k ? localStorage.getItem(k) : null;
        if (h && String(h).trim()) {
          sourceHtml = String(h);
          break;
        }
      }

      // If we happen to be on the budget page, fall back to the current template.
      if (!sourceHtml) {
        const existingTbody = document.querySelector('table.budgetTable tbody');
        if (existingTbody && existingTbody.innerHTML) sourceHtml = existingTbody.innerHTML;
      }

      // Final fallback: generate a complete budget from a small curated set.
      if (!sourceHtml) {
        const anticipated = [
          { inCode: '1030', outCode: '2030', desc: 'Lodge Per Capita Dues', approved: 67000, receipts: 25614, expenditures: 0 },
          { inCode: '1060', outCode: '2060', desc: 'Grand Lodge - Charity - Specified', approved: 0, receipts: 500, expenditures: 0 },
          { inCode: '1065', outCode: '2065', desc: "Grand Master's Charity", approved: 0, receipts: 9791.23, expenditures: 5000 },
          { inCode: '1071', outCode: '2071', desc: 'Annual Registration Receipts', approved: 25000, receipts: 5250, expenditures: 0 },
          { inCode: '1020', outCode: '2020', desc: 'New Lodge Petitions & Charter fees', approved: 0, receipts: 0, expenditures: 0 },
        ];

        const budget = [
          { inCode: '1100', outCode: '2100', desc: 'Expendable Supplies', approved: 1500, receipts: 0, expenditures: 218 },
          { inCode: '1120', outCode: '2120', desc: 'IT & Digitization', approved: 3500, receipts: 140, expenditures: 635.08 },
          { inCode: '1200', outCode: '2200', desc: 'Per Diem and Travel Expenses', approved: 15000, receipts: 0, expenditures: 7285.75 },
          { inCode: '2243', outCode: '2243', desc: 'Bank Charges & Fees', approved: 1200, receipts: 0, expenditures: 842.15 },
          { inCode: '2280', outCode: '2280', desc: 'Miscellaneous Reimbursable Items', approved: 2500, receipts: 0, expenditures: 1200 },
          { inCode: '2170', outCode: '2170', desc: 'Audit and Legal Fees', approved: 4000, receipts: 0, expenditures: 3050 },
          { inCode: '2140', outCode: '2140', desc: 'Publications & Printing Account (certificates)', approved: 150, receipts: 971.85, expenditures: 0 },
          { inCode: '1998', outCode: '2998', desc: 'Charity', approved: 4950, receipts: 0, expenditures: 1000 },
        ];

        sourceHtml = buildBudgetTbodyHtmlFromLines(anticipated, budget);
      }

      ensureBudgetYearExists(targetYear, sourceHtml);
    }

    // Seed 2025 Payment Orders (year-scoped) if missing / too few.
    const ordersKey = getPaymentOrdersKeyForYear(targetYear);
    if (ordersKey) {
      let existing = [];
      try {
        const raw = localStorage.getItem(ordersKey);
        const parsed = raw ? JSON.parse(raw) : null;
        existing = Array.isArray(parsed) ? parsed : [];
      } catch {
        existing = [];
      }

      // Backfill missing Source for the seeded 2025 mock Payment Orders (PO 25-01..PO 25-10).
      // This keeps old dev data consistent without requiring localStorage resets.
      const targetYear2 = String(targetYear % 100).padStart(2, '0');
      const seededPoCanons = new Set(
        Array.from({ length: 10 }, (_, idx) => `PO${targetYear2}-${String(idx + 1).padStart(2, '0')}`)
      );
      let patchedExisting = false;
      existing = existing.map((o) => {
        if (!o || typeof o !== 'object') return o;
        if (!isMockOrder(o)) return o;
        const canon = canonicalizePaymentOrderNo(o.paymentOrderNo);
        if (!seededPoCanons.has(canon)) return o;
        const src = String(o.source || '').trim();
        if (src) return o;
        patchedExisting = true;
        return { ...o, source: 'Form Submission' };
      });

      // Fix specific seeded/mock payment orders that are USD but incorrectly marked as Commerzbank.
      // (Requested: PO 25-04 and PO 25-92 should be wiseUSD when they are USD.)
      const forceWiseUsdCanons = new Set([
        `PO${targetYear2}-04`,
        `PO${targetYear2}-92`,
      ]);
      existing = existing.map((o) => {
        if (!o || typeof o !== 'object') return o;
        if (!isMockOrder(o)) return o;
        const canon = canonicalizePaymentOrderNo(o.paymentOrderNo);
        if (!forceWiseUsdCanons.has(canon)) return o;
        const usdNum = Number(o.usd);
        if (!Number.isFinite(usdNum) || usdNum <= 0) return o;
        const src = String(o.source || '').trim();
        if (src === 'wiseUSD') return o;
        patchedExisting = true;
        return { ...o, source: 'wiseUSD' };
      });
      if (patchedExisting) {
        localStorage.setItem(ordersKey, JSON.stringify(existing));
      }

      const existingCanon = new Set(existing.map((o) => canonicalizePaymentOrderNo(o && o.paymentOrderNo)));

      const year2 = String(targetYear % 100).padStart(2, '0');
      const baseMs = Date.UTC(targetYear, 1, 20, 12, 0, 0); // Feb 20, YYYY

      const templates = [
        {
          status: 'Paid',
          with: 'Archives',
          date: `${targetYear}-01-08`,
          name: 'Morgan Example',
          budgetNumber: '2100',
          purpose: 'Supplies reimbursement (stationery + shipping).',
          currency: 'EUR',
          items: [
            { title: 'Office supplies', euro: 84.5 },
            { title: 'Shipping', euro: 18.25 },
          ],
        },
        {
          status: 'Approved',
          with: 'Grand Treasurer',
          date: `${targetYear}-01-22`,
          name: 'Casey Example',
          budgetNumber: '2120',
          purpose: 'Software subscription (annual renewal).',
          currency: 'EUR',
          items: [
            { title: 'Service subscription', euro: 240.0 },
          ],
        },
        {
          status: 'Review',
          with: 'Grand Secretary',
          date: `${targetYear}-02-05`,
          name: 'Riley Example',
          budgetNumber: '2243',
          purpose: 'Bank fee adjustment for prior month.',
          currency: 'EUR',
          items: [
            { title: 'Bank fees', euro: 35.0 },
          ],
        },
        {
          status: 'Paid',
          with: 'Grand Treasurer',
          date: `${targetYear}-02-18`,
          name: 'Taylor Example',
          budgetNumber: '2200',
          purpose: 'Travel reimbursement (rail + lodging).',
          currency: 'EUR',
          items: [
            { title: 'Rail tickets', euro: 156.8 },
            { title: 'Hotel (1 night)', euro: 119.0 },
          ],
        },
        {
          status: 'Submitted',
          with: 'Requestor',
          date: `${targetYear}-03-02`,
          name: 'Jordan Example',
          budgetNumber: '2280',
          purpose: 'Miscellaneous reimbursable items.',
          currency: 'EUR',
          items: [
            { title: 'Replacement adapter', euro: 22.9 },
            { title: 'Small tools', euro: 16.1 },
          ],
        },
        {
          status: 'Approved',
          with: 'Grand Master',
          date: `${targetYear}-03-15`,
          name: 'Avery Example',
          budgetNumber: '2140',
          purpose: 'Certificate printing (small batch).',
          currency: 'EUR',
          items: [
            { title: 'Printing', euro: 65.0 },
          ],
        },
        {
          status: 'Review',
          with: 'Grand Secretary',
          date: `${targetYear}-04-03`,
          name: 'Alex Example',
          budgetNumber: '2170',
          purpose: 'Legal consult (invoice #LE-2025-04).',
          currency: 'EUR',
          items: [
            { title: 'Consultation fee', euro: 180.0 },
          ],
        },
        {
          status: 'Paid',
          with: 'Grand Treasurer',
          date: `${targetYear}-05-09`,
          name: 'Sam Example',
          budgetNumber: '2246',
          purpose: 'International transfer fees (USD wire).',
          currency: 'USD',
          items: [
            { title: 'Wire transfer fee', usd: 25.0 },
            { title: 'Processing', usd: 10.0 },
          ],
        },
        {
          status: 'Approved',
          with: 'Grand Treasurer',
          date: `${targetYear}-06-12`,
          name: 'Quinn Example',
          budgetNumber: '2120',
          purpose: 'Digitization equipment purchase.',
          currency: 'USD',
          items: [
            { title: 'Scanner accessory', usd: 79.99 },
            { title: 'Cables', usd: 14.5 },
          ],
        },
        {
          status: 'Submitted',
          with: 'Requestor',
          date: `${targetYear}-07-01`,
          name: 'Jamie Example',
          budgetNumber: '2250',
          purpose: 'Grand Master expense (meal receipt).',
          currency: 'EUR',
          items: [
            { title: 'Meal', euro: 42.0 },
          ],
        },
      ];

      const generated = templates
        .map((t, idx) => {
          const createdAt = new Date(baseMs - idx * 1000 * 60 * 60 * 24 * 10).toISOString();
          const updatedAt = new Date(baseMs - idx * 1000 * 60 * 60 * 24 * 10 + 1000 * 60 * 25).toISOString();

          const items = (t.items || []).map((it, j) => ({
            id: `mock_${targetYear}_${idx + 1}_i${j + 1}`,
            title: it.title,
            euro: it.euro !== undefined ? (it.euro ?? null) : null,
            usd: it.usd !== undefined ? (it.usd ?? null) : null,
          }));

          const totals = sumItems(items);
          const mode = inferCurrencyModeFromItems(items);

          const paymentOrderNo = `PO ${year2}-${String(idx + 1).padStart(2, '0')}`;
          const timeline = [{ at: createdAt, with: t.with, status: t.status }];

          return {
            id: `mock_${targetYear}_${idx + 1}_${baseMs}`,
            createdAt,
            updatedAt,
            source: 'Form Submission',
            status: normalizeOrderStatus(t.status),
            with: normalizeWith(t.with),
            paymentOrderNo,
            date: t.date,
            name: t.name,
            euro: mode === 'EUR' ? totals.euro : null,
            usd: mode === 'USD' ? totals.usd : null,
            items,
            address: '123 Example Street\nExample City',
            iban: 'DE00 0000 0000 0000 0000 00',
            bic: 'EXAMPLED1XXX',
            specialInstructions: '',
            budgetNumber: String(t.budgetNumber || '').trim(),
            purpose: t.purpose,
            timeline,
          };
        })
        .filter((o) => {
          const canon = canonicalizePaymentOrderNo(o && o.paymentOrderNo);
          return canon && !existingCanon.has(canon);
        });

      const next = [...existing, ...generated];

      // If we still don't have enough unique orders, top up with generic entries.
      let seq = templates.length + 1;
      while (next.length < 10) {
        const paymentOrderNo = `PO ${year2}-${String(seq).padStart(2, '0')}`;
        const canon = canonicalizePaymentOrderNo(paymentOrderNo);
        if (canon && !existingCanon.has(canon)) {
          const createdAt = new Date(baseMs - next.length * 1000 * 60 * 60 * 24 * 7).toISOString();
          const item = { id: `mock_${targetYear}_topup_${seq}_i1`, title: 'Misc reimbursement', euro: 25.0, usd: null };
          next.push({
            id: `mock_${targetYear}_topup_${seq}_${baseMs}`,
            createdAt,
            updatedAt: createdAt,
            source: 'Form Submission',
            status: 'Submitted',
            with: 'Requestor',
            paymentOrderNo,
            date: `${targetYear}-08-01`,
            name: 'Pat Example',
            euro: 25.0,
            usd: null,
            items: [item],
            address: '123 Example Street\nExample City',
            iban: 'DE00 0000 0000 0000 0000 00',
            bic: 'EXAMPLED1XXX',
            specialInstructions: '',
            budgetNumber: '2280',
            purpose: 'Top-up mock payment order.',
            timeline: [{ at: createdAt, with: 'Requestor', status: 'Submitted' }],
          });
          existingCanon.add(canon);
        }
        seq += 1;
        if (seq > 99) break;
      }

      if (existing.length < 10) {
        localStorage.setItem(ordersKey, JSON.stringify(next));
      }
    }

    // Seed 2025 Income (year-scoped) if missing / too few.
    // Keep this key local so dev seeding doesn't depend on workflow helpers
    // that can be stripped from page-specific bundles.
    const incomeKey = `payment_order_income_${targetYear}_v1`;
    if (incomeKey) {
      const INCOME_MOCK_VERSION_KEY = 'payment_orders_income_mock_version';
      const INCOME_MOCK_VERSION = '3';

      let existingIncome = [];
      try {
        const raw = localStorage.getItem(incomeKey);
        const parsed = raw ? JSON.parse(raw) : null;
        existingIncome = Array.isArray(parsed) ? parsed : [];
      } catch {
        existingIncome = [];
      }

      const storedIncomeMockVersion = localStorage.getItem(INCOME_MOCK_VERSION_KEY);

      const existingIds = new Set(existingIncome.map((e) => String(e && e.id ? e.id : '')));
      const baseMs = Date.UTC(targetYear, 7, 15, 12, 0, 0); // Aug 15, YYYY

      const incomeTemplates = [
        { date: `${targetYear}-01-03`, remitter: 'Harmony Lodge No. 12', budgetNumber: '1030', euro: 25614.0, description: 'Per capita dues received (batch 1).' },
        { date: `${targetYear}-01-15`, remitter: 'Grand Lodge Registration Office', budgetNumber: '1071', euro: 5250.0, description: 'Annual registration receipts (batch 1).' },
        { date: `${targetYear}-02-01`, remitter: 'Office of the Grand Master', budgetNumber: '1065', euro: 9791.23, description: 'Charity receipts received (benefit event).' },
        { date: `${targetYear}-02-12`, remitter: 'Grand Lodge Charity Committee', budgetNumber: '1060', euro: 500.0, description: 'Specified charity donation received.' },
        { date: `${targetYear}-03-05`, remitter: 'New Horizons Lodge UD', budgetNumber: '1020', euro: 1200.0, description: 'Petition and charter fees received.' },
        { date: `${targetYear}-03-28`, remitter: 'Jordan Example', budgetNumber: '1200', euro: 180.0, description: 'Travel advance returned (unused portion).' },
        { date: `${targetYear}-04-10`, remitter: 'ACGL IT Services', budgetNumber: '1120', euro: 140.0, description: 'Digitization cost share reimbursement received.' },
        { date: `${targetYear}-05-20`, remitter: 'Example Office Supplies Ltd.', budgetNumber: '1100', euro: 250.0, description: 'Supplier rebate/credit received.' },
        { date: `${targetYear}-06-07`, remitter: 'Taylor Example', budgetNumber: '2280', euro: 75.5, description: 'Returned reimbursable items (credit).' },
        { date: `${targetYear}-07-18`, remitter: 'Charity Trust of Example City', budgetNumber: '1998', euro: 1000.0, description: 'Charity contribution received.' },
      ];

      // Upgrade existing seeded mock income entries when the template changes.
      if (storedIncomeMockVersion !== INCOME_MOCK_VERSION) {
        const nowIso = new Date().toISOString();
        const templateById = new Map(
          incomeTemplates.map((t, idx) => {
            const id = `mock_income_${targetYear}_${String(idx + 1).padStart(2, '0')}`;
            return [id, t];
          })
        );

        const hasAnyIncomeMock = existingIncome.some((e) => e && typeof e.id === 'string' && e.id.startsWith(`mock_income_${targetYear}_`));
        if (hasAnyIncomeMock) {
          const upgraded = existingIncome.map((e) => {
            if (!e || typeof e !== 'object') return e;
            const id = String(e.id || '');
            const tpl = templateById.get(id);
            if (!tpl) return e;
            return {
              ...e,
              date: tpl.date,
              remitter: tpl.remitter,
              budgetNumber: String(tpl.budgetNumber || '').trim(),
              euro: Number(tpl.euro),
              description: tpl.description,
              updatedAt: nowIso,
            };
          });
          localStorage.setItem(incomeKey, JSON.stringify(upgraded));
          existingIncome = upgraded;
        }

        // Ensure a mock negative BankEUR entry exists corresponding to the Commerzbank mock expenditure
        // that also creates PO 25-91 in Reconciliation.
        const year2 = String(targetYear % 100).padStart(2, '0');
        const po91IncomeId = `mock_income_${targetYear}_neg_po_${year2}_91`;
        const po91BudgetNumber = '2100';
        const hasPo91Income = existingIncome.some((e) => e && String(e.id || '') === po91IncomeId);
        if (!hasPo91Income) {
          const createdAt = new Date(baseMs - 11 * 1000 * 60 * 60 * 24 * 9).toISOString();
          const po91Entry = {
            id: po91IncomeId,
            createdAt,
            updatedAt: nowIso,
            date: `${targetYear}-03-11`,
            remitter: 'Morgan Example',
            budgetNumber: po91BudgetNumber,
            euro: -92.40,
            description: 'Office supplies reimbursement.',
          };
          existingIncome = [po91Entry, ...existingIncome];
          localStorage.setItem(incomeKey, JSON.stringify(existingIncome));
        } else {
          const patched = existingIncome.map((e) => {
            if (!e || typeof e !== 'object') return e;
            if (String(e.id || '') !== po91IncomeId) return e;
            const cur = String(e.budgetNumber || '').trim();
            if (cur === po91BudgetNumber) return e;
            return { ...e, budgetNumber: po91BudgetNumber, updatedAt: nowIso };
          });
          existingIncome = patched;
          localStorage.setItem(incomeKey, JSON.stringify(existingIncome));
        }

        localStorage.setItem(INCOME_MOCK_VERSION_KEY, INCOME_MOCK_VERSION);
      }

      const needed = Math.max(0, 10 - existingIncome.length);
      if (needed > 0) {
        const additions = [];

        for (let idx = 0; idx < incomeTemplates.length && additions.length < needed; idx += 1) {
          const t = incomeTemplates[idx];
          const createdAt = new Date(baseMs - idx * 1000 * 60 * 60 * 24 * 9).toISOString();
          const id = `mock_income_${targetYear}_${String(idx + 1).padStart(2, '0')}`;
          if (existingIds.has(id)) continue;
          existingIds.add(id);
          additions.push({
            id,
            createdAt,
            updatedAt: createdAt,
            date: t.date,
            remitter: t.remitter,
            budgetNumber: String(t.budgetNumber || '').trim(),
            euro: Number(t.euro),
            description: t.description,
          });
        }

        // Top up with generic entries if templates were not enough.
        const fallbackCodes = readInAccountsFromBudgetYear(targetYear).map((x) => x && x.inCode).filter(Boolean);
        const fallbackRemitters = [
          'Alex Example',
          'Pat Example',
          'Riverside Lodge No. 8',
          'Grand Lodge Secretariat',
          'Example Bank Plc',
        ];
        let seq = incomeTemplates.length + 1;
        while (existingIncome.length + additions.length < 10) {
          const id = `mock_income_${targetYear}_topup_${String(seq).padStart(2, '0')}`;
          if (!existingIds.has(id)) {
            const createdAt = new Date(baseMs - (existingIncome.length + additions.length) * 1000 * 60 * 60 * 24 * 7).toISOString();
            const budgetNumber = fallbackCodes.length > 0 ? String(fallbackCodes[(seq - 1) % fallbackCodes.length]) : '1030';
            additions.push({
              id,
              createdAt,
              updatedAt: createdAt,
              date: `${targetYear}-08-01`,
              remitter: String(fallbackRemitters[(seq - 1) % fallbackRemitters.length]),
              budgetNumber,
              euro: 25.0,
              description: 'Top-up mock income entry.',
            });
            existingIds.add(id);
          }
          seq += 1;
          if (seq > 99) break;
        }

        const nextIncome = [...existingIncome, ...additions];
        localStorage.setItem(incomeKey, JSON.stringify(nextIncome));
      }
    }
  }

  function seedMockOrdersIfDev() {
    if (!isDevEnvironment()) return;

    const year = getActiveBudgetYear();
    const existing = loadOrders(year);
    const storedVersion = localStorage.getItem(MOCK_VERSION_KEY);

    // Fresh seed
    if (existing.length === 0) {
      const now = Date.now();
      saveOrders(makeMockOrders(now), year);
      localStorage.setItem(MOCK_VERSION_KEY, MOCK_VERSION);
      return;
    }

    // Upgrade existing mock entries only
    const hasAnyMock = existing.some((o) => isMockOrder(o));
    if (!hasAnyMock) return;
    if (storedVersion === MOCK_VERSION) return;

    const now = Date.now();
    const templates = makeMockOrders(now);
    const templateByNo = new Map(templates.map((t) => [t.paymentOrderNo, t]));

    const upgraded = existing.map((o) => {
      if (!isMockOrder(o)) return o;

      const tpl = o.paymentOrderNo && templateByNo.get(o.paymentOrderNo);
      const base = tpl
        ? { ...tpl, id: o.id, createdAt: o.createdAt || tpl.createdAt }
        : { ...o };

      return ensureMockItemsAndTotals(base);
    });

    saveOrders(upgraded, year);
    localStorage.setItem(MOCK_VERSION_KEY, MOCK_VERSION);
  }

  function seedMockReconciliationIfDev(year) {
    if (!isDevEnvironment()) return;

    const y = Number(year);
    if (!Number.isInteger(y)) return;

    ensurePaymentOrdersReconciliationListExistsForYear(y);
    const existing = loadReconciliationOrders(y);
    const storedVersion = localStorage.getItem(RECONCILIATION_MOCK_VERSION_KEY);

    // Fresh seed
    if (!Array.isArray(existing) || existing.length === 0) {
      saveReconciliationOrders(makeMockReconciliationOrders(y), y);
      localStorage.setItem(RECONCILIATION_MOCK_VERSION_KEY, RECONCILIATION_MOCK_VERSION);
      return;
    }

    // Upgrade existing mock entries only
    const hasAnyMock = existing.some((o) => isMockReconciliationOrder(o));
    if (!hasAnyMock) return;
    if (storedVersion === RECONCILIATION_MOCK_VERSION) return;

    const templates = makeMockReconciliationOrders(y);
    const templateByNo = new Map(
      templates.map((t) => [canonicalizePaymentOrderNo(t && t.paymentOrderNo), t])
    );

    const upgraded = existing.map((o) => {
      if (!isMockReconciliationOrder(o)) return o;

      const canon = canonicalizePaymentOrderNo(o && o.paymentOrderNo);
      const tpl = canon ? templateByNo.get(canon) : null;
      if (!tpl) return o;

      return {
        ...tpl,
        id: o.id,
        createdAt: o.createdAt || tpl.createdAt,
      };
    });

    saveReconciliationOrders(upgraded, y);
    localStorage.setItem(RECONCILIATION_MOCK_VERSION_KEY, RECONCILIATION_MOCK_VERSION);
  }

  /** @param {Record<string,string>} errors */
  function showErrors(errors) {
    if (!form) return;
    for (const [key, message] of Object.entries(errors)) {
      if (key === 'usAccountType') {
        const checkingEl = form.elements.namedItem('usAccountTypeChecking');
        const savingsEl = form.elements.namedItem('usAccountTypeSavings');
        if (checkingEl && checkingEl.classList) checkingEl.classList.add('input-error');
        if (savingsEl && savingsEl.classList) savingsEl.classList.add('input-error');
        const errorEl = document.getElementById('error-usAccountType');
        if (errorEl) errorEl.textContent = message;
        continue;
      }

      const input = form.elements.namedItem(key);
      if (input && input.classList) input.classList.add('input-error');

      const errorEl = document.getElementById(`error-${key}`);
      if (errorEl) errorEl.textContent = message;
    }

    // Focus first invalid field
    const firstKey = Object.keys(errors)[0];
    if (firstKey === 'usAccountType') {
      const firstEl = form.elements.namedItem('usAccountTypeChecking') || form.elements.namedItem('usAccountTypeSavings');
      if (firstEl && firstEl.focus) firstEl.focus();
    } else {
      const firstEl = form.elements.namedItem(firstKey);
      if (firstEl && firstEl.focus) firstEl.focus();
    }
  }

  function buildPaymentOrder(values) {
    const createdAt = new Date().toISOString();
    const source = String(values && values.source ? values.source : '').trim() || 'Commerzbank';
    const built = {
      id: (crypto?.randomUUID ? crypto.randomUUID() : `po_${Date.now()}_${Math.random().toString(16).slice(2)}`),
      createdAt,
      ...values,
      source,
      status: 'Submitted',
      with: 'Requestor',
    };
    return {
      ...built,
      timeline: [
        {
          at: createdAt,
          with: getOrderWithLabel(built),
          status: getOrderStatusLabel(built),
          actorWith: getOrderWithLabel(built),
          actorStatus: getOrderStatusLabel(built),
          user: getTimelineUsername(),
          action: 'Created',
          changes: computeOrderAuditChanges(null, built),
        },
      ],
    };
  }

  function getOrderStatusLabel(order) {
    return normalizeOrderStatus(order && order.status);
  }

  function getOrderWithLabel(order) {
    return normalizeWith(order && order.with);
  }

  function formatIsoDateOnly(isoString) {
    const s = String(isoString || '').trim();
    if (!s) return '';
    const ms = toTimeMs(s);
    if (ms === null) return s.length >= 10 ? s.slice(0, 10) : s;
    const d = new Date(ms);
    const yyyy = d.getFullYear();
    const mm = String(d.getMonth() + 1).padStart(2, '0');
    const dd = String(d.getDate()).padStart(2, '0');
    return `${yyyy}-${mm}-${dd}`;
  }

  function formatIsoDateTimeShort(isoString) {
    const s = String(isoString || '').trim();
    if (!s) return '';
    const ms = toTimeMs(s);
    if (ms === null) {
      const base = s.replace('T', ' ');
      return base.length >= 16 ? base.slice(0, 16) : base;
    }
    const d = new Date(ms);
    const yyyy = d.getFullYear();
    const mm = String(d.getMonth() + 1).padStart(2, '0');
    const dd = String(d.getDate()).padStart(2, '0');
    const hh = String(d.getHours()).padStart(2, '0');
    const min = String(d.getMinutes()).padStart(2, '0');
    return `${yyyy}-${mm}-${dd} ${hh}:${min}`;
  }

  function toTimeMs(isoString) {
    const ms = Date.parse(String(isoString || '').trim());
    return Number.isFinite(ms) ? ms : null;
  }

  function ensureOrderTimeline(order) {
    const existing = Array.isArray(order && order.timeline) ? order.timeline : [];
    if (existing.length > 0) return existing;

    const createdAt = String((order && order.createdAt) || new Date().toISOString());
    return [
      {
        at: createdAt,
        with: getOrderWithLabel(order),
        status: getOrderStatusLabel(order),
        user: '—',
        action: 'Created',
        changes: [],
      },
    ];
  }

  function appendTimelineEvent(order, evt) {
    const timeline = ensureOrderTimeline(order);
    return [...timeline, evt];
  }

  function hasPaymentOrderGrandMasterApproval(order) {
    const timeline = ensureOrderTimeline(order);
    for (const evt of Array.isArray(timeline) ? timeline : []) {
      if (!evt || typeof evt !== 'object') continue;
      const actorWith = normalizeWith(evt.actorWith);
      const actorStatus = normalizeOrderStatus(evt.actorStatus);
      if (actorWith === 'Grand Master' && actorStatus === 'Approved') return true;

      const withLabel = normalizeWith(evt.with);
      const statusLabel = normalizeOrderStatus(evt.status);
      if (withLabel === 'Grand Master' && statusLabel === 'Approved') return true;
    }
    return false;
  }

  // Returns true if the Grand Secretary has approved this payment order at least once.
  function hasPaymentOrderGrandSecretaryApproval(order) {
    const timeline = ensureOrderTimeline(order);
    for (const evt of Array.isArray(timeline) ? timeline : []) {
      if (!evt || typeof evt !== 'object') continue;
      const actorWithRaw = String(evt.actorWith || '').trim();
      const actorStatusRaw = String(evt.actorStatus || '').trim();
      const actorWith = actorWithRaw ? normalizeWith(actorWithRaw) : '';
      const actorStatus = actorStatusRaw ? normalizeOrderStatus(actorStatusRaw) : '';
      if (actorWith === 'Grand Secretary' && actorStatus === 'Approved') return true;
      // Legacy entries (before actorWith tracking): check direct with/status fields.
      const withRaw = String(evt.with || '').trim();
      const statusRaw = String(evt.status || '').trim();
      const withLabel = withRaw ? normalizeWith(withRaw) : '';
      const statusLabel = statusRaw ? normalizeOrderStatus(statusRaw) : '';
      if (withLabel === 'Grand Secretary' && statusLabel === 'Approved') return true;
    }
    return false;
  }

  // Returns true if the Grand Lodge Seal and Grand Secretary Signature should be
  // embedded in the payment order PDF for the given order.
  // Rules:
  //   - Only applied after the GS has approved the order.
  //   - Once approved, the credentials remain even as the order moves to GM/GT.
  //   - If the order is sent back to Grand Secretary with status Review, the
  //     credentials are removed until the GS approves again.
  function shouldApplyGsCredentials(order) {
    if (!hasPaymentOrderGrandSecretaryApproval(order)) return false;
    const currentWith = normalizeWith(getOrderWithLabel(order));
    const currentStatus = normalizeOrderStatus(getOrderStatusLabel(order));
    if (currentWith === 'Grand Secretary' && currentStatus === 'Review') return false;
    return true;
  }

  async function wpPublicSubmitPaymentOrder(year, values, items) {
    const url = wpJoin('acgl-fms/v1/public/submit-po');
    const body = {
      year: String(year || ''),
      values: values && typeof values === 'object' ? values : {},
      items: Array.isArray(items) ? items : [],
    };

    const res = await wpFetchJson(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });

    // Read once so we can surface non-JSON server errors (e.g. HTML 500 pages).
    const rawText = await res.text();
    const payload = rawText ? safeJsonParse(rawText, null) : null;

    if (!res.ok) {
      const errObj = payload && typeof payload === 'object' ? payload : null;
      const errCode = errObj && errObj.error ? String(errObj.error) : '';
      const errMsg = errObj && errObj.message ? String(errObj.message) : '';
      const errField = errObj && errObj.field ? String(errObj.field) : '';
      const suffix = errMsg ? ` (${errMsg})` : (errField ? ` (${errField})` : '');
      const err = errCode
        ? `${errCode}${suffix}`
        : `submit_failed_${res.status}${rawText ? `: ${String(rawText).slice(0, 200)}` : ''}`;
      throw new Error(err);
    }

    if (!payload || payload.ok !== true) {
      throw new Error('submit_failed');
    }
    return payload;
  }

  function auditIsBlank(value) {
    if (value === null || value === undefined) return true;
    const s = String(value).trim();
    return !s || s === '—' || s === '-';
  }

  function auditMoney(value) {
    const n = Number(value);
    if (!Number.isFinite(n)) return '—';
    return n.toFixed(2);
  }

  function auditValue(value) {
    if (value === null || value === undefined) return '—';
    if (typeof value === 'number') return Number.isFinite(value) ? String(value) : '—';
    if (typeof value === 'boolean') return value ? 'Yes' : 'No';
    const s = String(value).trim();
    return s ? s : '—';
  }

  /**
   * @param {any|null} prev
   * @param {any} next
   * @returns {Array<{field:string, from:string, to:string}>}
   */
  function computeIncomeAuditChanges(prev, next) {
    const p = prev && typeof prev === 'object' ? prev : null;
    const n = next && typeof next === 'object' ? next : null;
    if (!n) return [];

    const fields = [
      { key: 'date', label: 'Date', fmt: (v) => auditValue(v) },
      { key: 'remitter', label: 'Remitter', fmt: (v) => auditValue(v) },
      { key: 'budgetNumber', label: 'Budget Nr.', fmt: (v) => auditValue(v) },
      { key: 'euro', label: 'Euro', fmt: (v) => (auditIsBlank(v) ? '—' : auditMoney(v)) },
      { key: 'description', label: 'Description', fmt: (v) => auditValue(v) },
    ];

    const changes = [];
    for (const f of fields) {
      const from = f.fmt(p ? p[f.key] : null);
      const to = f.fmt(n ? n[f.key] : null);
      if (from === to) continue;
      changes.push({ field: f.label, from, to });
    }
    return changes;
  }

  /**
   * @param {any|null} prev
   * @param {any} next
   * @returns {Array<{field:string, from:string, to:string}>}
   */
  function computeOrderAuditChanges(prev, next) {
    const p = prev && typeof prev === 'object' ? prev : null;
    const n = next && typeof next === 'object' ? next : null;
    if (!n) return [];

    const fields = [
      {
        key: 'paymentOrderNo',
        label: 'Payment Order No.',
        fmt: (v) => {
          const raw = auditValue(v);
          if (raw === '—') return '—';
          return formatPaymentOrderNoForDisplay(raw);
        },
      },
      { key: 'date', label: 'Date', fmt: (v) => auditValue(v) },
      { key: 'name', label: 'Name', fmt: (v) => auditValue(v) },
      { key: 'budgetNumber', label: 'Budget Nr.', fmt: (v) => auditValue(v) },
      { key: 'source', label: 'Source', fmt: (v) => auditValue(v) },
      { key: 'purpose', label: 'Purpose', fmt: (v) => auditValue(v) },
      { key: 'address', label: 'Address', fmt: (v) => auditValue(v) },
      { key: 'iban', label: 'IBAN', fmt: (v) => auditValue(v) },
      { key: 'bic', label: 'BIC', fmt: (v) => auditValue(v) },
      { key: 'specialInstructions', label: 'Special Instructions', fmt: (v) => auditValue(v) },
      { key: 'euro', label: 'Euro Total', fmt: (v) => (auditIsBlank(v) ? '—' : auditMoney(v)) },
      { key: 'usd', label: 'USD Total', fmt: (v) => (auditIsBlank(v) ? '—' : auditMoney(v)) },
      { key: 'with', label: 'With', fmt: (v) => (auditIsBlank(v) ? '—' : normalizeWith(v)) },
      { key: 'status', label: 'Status', fmt: (v) => (auditIsBlank(v) ? '—' : normalizeOrderStatus(v)) },
    ];

    const changes = [];
    for (const f of fields) {
      const from = f.fmt(p ? p[f.key] : null);
      const to = f.fmt(n ? n[f.key] : null);
      if (from === to) continue;
      changes.push({ field: f.label, from, to });
    }

    const prevItems = Array.isArray(p && p.items) ? p.items : [];
    const nextItems = Array.isArray(n && n.items) ? n.items : [];
    if (prevItems.length !== nextItems.length) {
      changes.push({ field: 'Items', from: `${prevItems.length} item(s)`, to: `${nextItems.length} item(s)` });
    }

    return changes;
  }

  function getTimelineUsername() {
    const u = getCurrentUser && getCurrentUser();
    const name = u && u.username ? String(u.username).trim() : '';
    if (!name) return 'Unknown';
    return name;
  }

  function ensureIncomeTimeline(entry) {
    const existing = Array.isArray(entry && entry.timeline) ? entry.timeline : [];
    if (existing.length > 0) return existing;

    const createdAt = String((entry && entry.createdAt) || new Date().toISOString());
    return [
      {
        at: createdAt,
        user: '—',
        action: 'Created',
        changes: computeIncomeAuditChanges(null, entry),
      },
    ];
  }

  function appendIncomeTimelineEvent(entry, evt) {
    const timeline = ensureIncomeTimeline(entry);
    return [...timeline, evt];
  }

  function renderIncomeTimelineGraph(entry) {
    const timeline = ensureIncomeTimeline(entry);

    const timelineSorted = [...timeline]
      .filter((e) => e && typeof e === 'object' && e.at)
      .map((e) => ({ ...e, _ms: toTimeMs(e.at) }))
      .filter((e) => e._ms !== null)
      .sort((a, b) => a._ms - b._ms);

    const createdAt = String(entry && entry.createdAt ? entry.createdAt : '').trim();
    const updatedAt = String(entry && entry.updatedAt ? entry.updatedAt : '').trim();
    const txDate = formatDate(entry && entry.date);

    const createdLabel = createdAt ? formatIsoDateOnly(createdAt) : '—';
    const updatedLabel = updatedAt ? formatIsoDateOnly(updatedAt) : '—';
    const rangeEndLabel = formatIsoDateOnly(updatedAt || createdAt);

    const timelineForDisplay = [...timelineSorted].sort((a, b) => b._ms - a._ms);
    const eventsHtml = timelineForDisplay
      .map((e) => {
        const t = formatIsoDateTimeShort(e.at);
        const user = e.user !== undefined ? String(e.user || '—') : '—';
        const action = e.action !== undefined ? String(e.action || '—') : '—';
        return `<div class="timelinegraph__event"><span class="timelinegraph__eventTime">${escapeHtml(t)}</span><span class="timelinegraph__eventSep">•</span><span>User: <strong>${escapeHtml(user)}</strong></span><span class="timelinegraph__eventSep">•</span><span>Action: <strong>${escapeHtml(action)}</strong></span></div>`;
      })
      .join('');

    return `
      <div id="incomeTimelineGraphWrap">
        <div class="timelinegraph" aria-label="Income timeline">
          <div class="timelinegraph__header">
            <div class="timelinegraph__title">Timeline</div>
            <div class="timelinegraph__range">${escapeHtml(createdLabel)} → ${escapeHtml(rangeEndLabel)}</div>
          </div>

          <div class="timelinegraph__meta">
            <span>Transaction Date: <strong>${escapeHtml(txDate)}</strong></span>
            <span class="timelinegraph__sep">|</span>
            <span>Created: <strong>${escapeHtml(createdLabel)}</strong></span>
            <span class="timelinegraph__sep">|</span>
            <span>Updated: <strong>${escapeHtml(updatedLabel)}</strong></span>
          </div>

          <div class="timelinegraph__events" aria-label="Timeline events">
            ${eventsHtml}
          </div>
        </div>
      </div>
    `.trim();
  }

  function buildTimelineSegments({ startMs, endMs, initialValue, events, field, normalizeFn }) {
    const sorted = [...(events || [])]
      .filter((e) => e && typeof e === 'object' && e.at)
      .map((e) => ({ ...e, _ms: toTimeMs(e.at) }))
      .filter((e) => e._ms !== null)
      .sort((a, b) => a._ms - b._ms);

    let cursorMs = startMs;
    let currentValue = initialValue;

    const segments = [];
    for (const e of sorted) {
      if (e[field] === undefined) continue;
      const t = Math.max(startMs, Math.min(endMs, e._ms));
      if (t > cursorMs) {
        segments.push({ from: cursorMs, to: t, value: currentValue });
      }
      currentValue = normalizeFn(e[field]);
      cursorMs = t;
    }

    if (endMs > cursorMs) segments.push({ from: cursorMs, to: endMs, value: currentValue });
    return segments;
  }

  function renderTimelineGraph(order) {
    const timeline = ensureOrderTimeline(order);

    const timelineSorted = [...timeline]
      .filter((e) => e && typeof e === 'object' && e.at)
      .map((e) => ({ ...e, _ms: toTimeMs(e.at) }))
      .filter((e) => e._ms !== null)
      .sort((a, b) => a._ms - b._ms);

    const createdAt = String(order && order.createdAt ? order.createdAt : '').trim();
    const updatedAt = String(order && order.updatedAt ? order.updatedAt : '').trim();
    const requestDate = formatDate(order && order.date);

    const startMsRaw = toTimeMs(createdAt) ?? (timelineSorted[0]?._ms ?? Date.now());
    const lastEvtMs = timelineSorted.length > 0 ? timelineSorted[timelineSorted.length - 1]._ms : null;
    const endCandidate = Math.max(
      toTimeMs(updatedAt || createdAt) ?? startMsRaw,
      lastEvtMs ?? startMsRaw
    );
    const endMsRaw = endCandidate;
    const startMs = startMsRaw;
    const endMs = endMsRaw > startMsRaw ? endMsRaw : startMsRaw + 1;

    const createdLabel = createdAt ? formatIsoDateOnly(createdAt) : '—';
    const updatedLabel = updatedAt ? formatIsoDateOnly(updatedAt) : '—';
    const rangeEndLabel = formatIsoDateOnly(updatedAt || createdAt);

    // Display newest-first in the event list.
    const timelineForDisplay = [...timelineSorted].sort((a, b) => b._ms - a._ms);

    const eventsHtml = timelineForDisplay
      .map((e) => {
        const t = formatIsoDateTimeShort(e.at);
        const user = e.user !== undefined ? String(e.user || '—') : '—';
        const w = e.with !== undefined ? normalizeWith(e.with) : '—';
        const s = e.status !== undefined ? normalizeOrderStatus(e.status) : '—';
        const actorWith = e.actorWith !== undefined ? normalizeWith(e.actorWith) : '';
        const actorStatus = e.actorStatus !== undefined ? normalizeOrderStatus(e.actorStatus) : '';
        const hasActor = (actorWith && actorWith !== w) || (actorStatus && actorStatus !== s);
        const actorHtml = hasActor
          ? `${actorWith ? `<span class="timelinegraph__eventSep">•</span><span>Actor: <strong>${escapeHtml(actorWith)}</strong></span>` : ''}${actorStatus ? `<span class="timelinegraph__eventSep">•</span><span>Actor Status: <strong>${escapeHtml(actorStatus)}</strong></span>` : ''}`
          : '';
        const commentRaw = e.comment !== undefined ? String(e.comment || '') : '';
        const comment = commentRaw.trim();
        const commentHtml = comment
          ? `<span class="timelinegraph__eventSep">•</span><span>Comment: <strong>${escapeHtml(comment).replace(/\n/g, '<br>')}</strong></span>`
          : '';
        return `<div class="timelinegraph__event"><span class="timelinegraph__eventTime">${escapeHtml(t)}</span><span class="timelinegraph__eventSep">•</span><span>Modified by: <strong>${escapeHtml(user)}</strong></span><span class="timelinegraph__eventSep">•</span><span>With: <strong>${escapeHtml(w)}</strong></span><span class="timelinegraph__eventSep">•</span><span>Status: <strong>${escapeHtml(s)}</strong></span>${actorHtml}${commentHtml}</div>`;
      })
      .join('');

    return `
      <div id="timelineGraphWrap">
        <div class="timelinegraph" aria-label="Request timeline graph">
          <div class="timelinegraph__header">
            <div class="timelinegraph__title">Timeline</div>
            <div class="timelinegraph__range">${escapeHtml(createdLabel)} → ${escapeHtml(rangeEndLabel)}</div>
          </div>

          <div class="timelinegraph__meta">
            <span>Request Date: <strong>${escapeHtml(requestDate)}</strong></span>
            <span class="timelinegraph__sep">|</span>
            <span>Created: <strong>${escapeHtml(createdLabel)}</strong></span>
            <span class="timelinegraph__sep">|</span>
            <span>Updated: <strong>${escapeHtml(updatedLabel)}</strong></span>
          </div>

          <div class="timelinegraph__events" aria-label="Timeline events">
            ${eventsHtml}
          </div>
        </div>
      </div>
    `.trim();
  }

  /** @param {Array<Object>} orders */
  function renderOrders(orders) {
    if (!tbody || !emptyState) return;
    tbody.innerHTML = '';

    const year = getActiveBudgetYear();

    const currentUser = getCurrentUser();
    const canEditOrders = currentUser ? canWriteOrCreate(currentUser, 'orders') : false;
    const canDeleteOrders = currentUser ? canDelete(currentUser, 'orders') : false;
    const canViewItems = currentUser ? canOrdersItemizeRead(currentUser) : false;
    const editDisabledAttr = '';
    const editAriaDisabled = canEditOrders ? 'false' : 'true';
    const editTooltipAttr = canEditOrders ? '' : ' data-tooltip="Edit and create access required for Payment Orders."';
    const deleteDisabledAttr = '';
    const deleteAriaDisabled = canDeleteOrders ? 'false' : 'true';
    const deleteTooltipAttr = canDeleteOrders ? '' : ' data-tooltip="Requires Delete access for Payment Orders."';

    const itemsDisabledAttr = '';
    const itemsAriaDisabled = canViewItems ? 'false' : 'true';
    const itemsTooltipAttr = canViewItems ? '' : ' data-tooltip="Requires Payment Orders access."';

    if (!orders || orders.length === 0) {
      emptyState.hidden = false;
      return;
    }

    emptyState.hidden = true;

    const rowsHtml = orders
      .map((o) => {
        const isMissingRequired = hasOrderMissingRequiredValues(o);
        const statusLabel = getOrderStatusLabel(o);
        const isApproved = String(statusLabel || '').trim().toLowerCase() === 'approved';
        const withLabel = getOrderWithLabel(o);
        const isGtReview =
          String(statusLabel || '').trim().toLowerCase() === 'review' &&
          String(withLabel || '').trim().toLowerCase() === 'grand treasurer';
        const rowClasses = [];
        if (isMissingRequired) rowClasses.push('ordersRow--missingRequired');
        if (isApproved) rowClasses.push('ordersRow--approved');
        if (isGtReview) rowClasses.push('ordersRow--gtReview');
        const rowClass = rowClasses.length ? ` class="${rowClasses.join(' ')}"` : '';
        return `
          <tr${rowClass} data-id="${escapeHtml(o.id)}">
            <td><a href="#" class="poNoDownloadLink" data-action="downloadPdf" title="Download PDF">${escapeHtml(formatPaymentOrderNoForDisplay(o.paymentOrderNo))}</a></td>
            <td>${escapeHtml(formatDate(o.date))}</td>
            <td>${escapeHtml(String(o.source || '').trim())}</td>
            <td>${escapeHtml(o.name)}</td>
            <td class="num">${escapeHtml(formatCurrency(o.euro, 'EUR'))}</td>
            <td class="num">${escapeHtml(formatCurrency(o.usd, 'USD'))}</td>
            <td>${renderOutBudgetNumberHtml(o.budgetNumber, year)}</td>
            <td>${escapeHtml(o.purpose)}</td>
            <td>${escapeHtml(getOrderWithLabel(o))}</td>
            <td>${escapeHtml(statusLabel)}</td>
            <td class="actions">
              <button type="button" class="btn btn--viewGrey btn--viewIcon" data-action="view" title="View" aria-label="View">${VIEW_EYE_ICON_SVG}</button>
              <button type="button" class="btn btn--editIcon" data-action="edit" title="${canEditOrders ? 'Edit' : 'Read-only access for Payment Orders.'}" aria-disabled="${editAriaDisabled}"${editDisabledAttr}${editTooltipAttr}><svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path d="M15.502 1.94a.5.5 0 0 1 0 .706L14.459 3.69l-2-2L13.502.646a.5.5 0 0 1 .707 0l1.293 1.293zm-1.75 2.456-2-2L4.939 9.21a.5.5 0 0 0-.121.196l-.805 2.414a.25.25 0 0 0 .316.316l2.414-.805a.5.5 0 0 0 .196-.12l6.813-6.814z"/><path fill-rule="evenodd" d="M1 13.5A1.5 1.5 0 0 0 2.5 15h11a1.5 1.5 0 0 0 1.5-1.5v-6a.5.5 0 0 0-1 0v6a.5.5 0 0 1-.5.5h-11a.5.5 0 0 1-.5-.5v-11a.5.5 0 0 1 .5-.5H9a.5.5 0 0 0 0-1H2.5A1.5 1.5 0 0 0 1 2.5z"/></svg></button>
              <button type="button" class="btn btn--itemsIcon" data-action="items" title="${canViewItems ? 'Items' : 'Requires Payment Orders access.'}" aria-label="Items" aria-disabled="${itemsAriaDisabled}"${itemsDisabledAttr}${itemsTooltipAttr}>${ITEMS_LIST_ICON_SVG}</button>
              <button type="button" class="btn btn--x" data-action="delete" aria-label="Delete request" title="${canDeleteOrders ? 'Delete' : 'Requires Delete access for Payment Orders.'}" aria-disabled="${deleteAriaDisabled}"${deleteDisabledAttr}${deleteTooltipAttr}><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path d="M5.5 5.5A.5.5 0 0 1 6 6v5a.5.5 0 0 1-1 0V6a.5.5 0 0 1 .5-.5m2.5 0A.5.5 0 0 1 8.5 6v5a.5.5 0 0 1-1 0V6a.5.5 0 0 1 .5-.5m3 .5a.5.5 0 0 0-1 0v5a.5.5 0 0 0 1 0z"/><path d="M14.5 3a1 1 0 0 1-1 1H13l-.777 9.33A2 2 0 0 1 10.23 15H5.77a2 2 0 0 1-1.993-1.67L3 4h-.5a1 1 0 1 1 0-2H5a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1h2.5a1 1 0 0 1 1 1M6 2v1h4V2zm-2 2 .774 9.287A1 1 0 0 0 5.77 14h4.46a1 1 0 0 0 .996-.713L12 4z"/></svg></button>
            </td>
          </tr>
        `.trim();
      })
      .join('');

    tbody.innerHTML = rowsHtml;
  }

  function hasOrderMissingRequiredValues(order) {
    if (!order) return true;
    const paymentOrderNo = String(order.paymentOrderNo || '').trim();
    const date = String(order.date || '').trim();
    const name = String(order.name || '').trim();
    const address = String(order.address || '').trim();
    const budgetNumberRaw = String(order.budgetNumber || '').trim();
    const purpose = String(order.purpose || '').trim();

    // Budget Nr. must be present and parse to a 4-digit OUT code.
    const outCode = extractOutCodeFromBudgetNumberText(budgetNumberRaw);
    if (!paymentOrderNo || !date || !name || !address || !purpose || !outCode) return true;

    const bankMode = String(order.bankDetailsMode || '').trim().toUpperCase();
    const iban = String(order.iban || '').trim();
    const bic = String(order.bic || '').trim();
    if (bankMode === 'US') {
      const usAccountType = String(order.usAccountType || '').trim();
      const specialInstructions = String(order.specialInstructions || '').trim();
      if (!iban || !bic || !usAccountType || !specialInstructions) return true;
    } else if (!iban || !bic) {
      return true;
    }

    return false;
  }

  
  // [bundle-strip:settings-remove-payment-orders-and-reconciliation] removed in page-specific build.
// ---- Roles / Users (settings page) ----

  function countSettingsUsers(users) {
    const list = Array.isArray(users) ? users : [];
    return list.filter((u) => u && getEffectivePermissions(u).settings !== 'none').length;
  }

  const usersTableViewState = {
    editingUsername: null,
    globalFilter: '',
    defaultEmptyText: '',
  };

  function formatAccessLabel(level) {
    const lv = String(level || 'none').toLowerCase();
    if (lv === 'full') return 'Admin';
    if (lv === 'delete') return 'Delete';
    if (lv === 'create') return 'Create';
    if (lv === 'write') return 'Write';
    if (lv === 'read') return 'View';
    return 'None';
  }

  function getUsersFilterTokens(filterText) {
    const raw = String(filterText || '').trim().toLowerCase();
    if (!raw) return [];
    return raw.split(/\s+/).map((t) => t.trim()).filter(Boolean);
  }

  function userMatchesUsersFilter(user, tokens) {
    if (!tokens || tokens.length === 0) return true;
    const u = user || {};
    const p = getEffectivePermissions(u);
    const haystack = [
      normalizeUsername(u.username),
      normalizeEmail(u.email),
      formatAccessLabel(p.budget),
      formatAccessLabel(p.income),
      formatAccessLabel(p.orders),
      formatAccessLabel(p.ledger),
      formatAccessLabel(p.settings),
    ]
      .filter(Boolean)
      .join(' ')
      .toLowerCase();
    return tokens.every((t) => haystack.includes(t));
  }

  function applyMaxVisibleUsers(maxVisibleUsers) {
    const tableEl = document.getElementById('usersTable');
    const wrapEl = tableEl && tableEl.closest ? tableEl.closest('.table-wrap') : null;
    if (!wrapEl || !usersTbody) return;

    const maxUsers = Math.max(1, Number(maxVisibleUsers) || 1);
    const maxRows = maxUsers;
    const rows = Array.from(usersTbody.querySelectorAll('tr'));

    wrapEl.style.overflowY = 'auto';
    if (!rows || rows.length <= maxRows) {
      wrapEl.style.maxHeight = '';
      return;
    }

    const prevScrollTop = wrapEl.scrollTop;
    if (prevScrollTop) wrapEl.scrollTop = 0;
    let total = 0;
    try {
      const wrapRect = wrapEl.getBoundingClientRect ? wrapEl.getBoundingClientRect() : null;
      const last = rows[Math.min(maxRows, rows.length) - 1];
      const lastRect = last && last.getBoundingClientRect ? last.getBoundingClientRect() : null;
      if (wrapRect && lastRect) {
        total = (lastRect.bottom - wrapRect.top);
      }
    } finally {
      if (prevScrollTop) wrapEl.scrollTop = prevScrollTop;
    }

    if (!Number.isFinite(total) || total <= 0) {
      total = 0;
      for (let i = 0; i < Math.min(maxRows, rows.length); i += 1) {
        total += rows[i].offsetHeight;
      }
    }

    wrapEl.style.maxHeight = `${Math.max(140, Math.ceil(total))}px`;
  }

  function renderUsersTable() {
    if (!usersTbody || !usersEmptyState) return;
    const users = loadUsers();
    const visibleUsers = (Array.isArray(users) ? users : []).filter((u) => (
      normalizeUsername(u && u.username) !== normalizeUsername(HARD_CODED_ADMIN_USERNAME)
    ));
    const filterTokens = getUsersFilterTokens(usersTableViewState.globalFilter);
    const filteredUsers = visibleUsers.filter((u) => userMatchesUsersFilter(u, filterTokens));
    const currentUser = getCurrentUser();
    const canEdit = currentUser ? canWrite(currentUser, 'settings_roles') : false;

    if (!usersTableViewState.defaultEmptyText) {
      usersTableViewState.defaultEmptyText = String(usersEmptyState.textContent || '').trim() || 'No users yet.';
    }

    usersTbody.innerHTML = '';
    if (!visibleUsers || visibleUsers.length === 0) {
      usersEmptyState.hidden = false;
      usersEmptyState.textContent = usersTableViewState.defaultEmptyText;
      return;
    }

    if (!filteredUsers || filteredUsers.length === 0) {
      usersEmptyState.hidden = false;
      usersEmptyState.textContent = 'No users match your search.';
      return;
    }
    usersEmptyState.hidden = true;

    const rows = filteredUsers
      .slice()
      .sort((a, b) => normalizeUsername(a && a.username).localeCompare(normalizeUsername(b && b.username)))
      .map((u) => {
        const username = normalizeUsername(u && u.username);
        const email = normalizeEmail(u && u.email);
        const role = String(u && typeof u.position === 'string' ? u.position : '').trim();
        const passwordPlain = String(u && typeof u.passwordPlain === 'string' ? u.passwordPlain : '')
          || extractLegacyPasswordPlain(u && u.passwordHash, u && u.salt);
        const isEditing = Boolean(usersTableViewState.editingUsername && usersTableViewState.editingUsername === username);
        const isProtected = username === normalizeUsername(HARD_CODED_ADMIN_USERNAME);
        const safeName = escapeHtml(username);
        const safeEmail = escapeHtml(email);
        const roleTooltipAttr = role ? ` data-role-tooltip="${escapeHtml(role)}"` : '';
        const disabled = canEdit && !isProtected ? '' : 'disabled';

        const safePw = escapeHtml(passwordPlain);
        const maskedPw = passwordPlain ? '********' : '—';
        const passwordControl = isEditing
          ? `<input type="text" class="usersTable__detailsInput" data-new-password autocomplete="new-password" value="${safePw}" aria-label="Password" ${disabled} />`
          : `<span class="usersTable__permLabel">${maskedPw}</span>`;

        const emailControl = isEditing
          ? `<input type="email" class="usersTable__detailsInput" data-email autocomplete="email" placeholder="(optional)" value="${safeEmail}" aria-label="Email" ${disabled} />`
          : `<span class="usersTable__permLabel">${email ? escapeHtml(email) : '—'}</span>`;

        const roleOptionsHtml = (() => {
          const r = String(role || '').trim();
          const has = r && ROLE_OPTIONS.includes(r);
          const extra = !has && r ? `<option value="${escapeHtml(r)}" selected>${escapeHtml(r)}</option>` : '';
          const placeholder = `<option value="" ${r ? '' : 'selected'}>Select a role…</option>`;
          const opts = ROLE_OPTIONS
            .map((v) => `<option value="${escapeHtml(v)}" ${v === r ? 'selected' : ''}>${escapeHtml(v)}</option>`)
            .join('');
          return `${extra}${placeholder}${opts}`;
        })();

        const roleControl = isEditing
          ? `<select class="usersTable__detailsInput" data-role aria-label="Role" ${disabled}>${roleOptionsHtml}</select>`
          : `<span class="usersTable__permLabel">${role ? escapeHtml(role) : '—'}</span>`;

        const actionsCell = (() => {
          const editDisabled = disabled ? 'disabled' : '';
          const deleteDisabled = disabled ? 'disabled' : '';
          const protectTitle = isProtected ? ' title="This user is protected."' : '';

          if (!isEditing) {
            return `
              <button type="button" class="btn btn--editIcon" data-action="edit" aria-label="Edit" ${editDisabled}${protectTitle}><svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path d="M15.502 1.94a.5.5 0 0 1 0 .706L14.459 3.69l-2-2L13.502.646a.5.5 0 0 1 .707 0l1.293 1.293zm-1.75 2.456-2-2L4.939 9.21a.5.5 0 0 0-.121.196l-.805 2.414a.25.25 0 0 0 .316.316l2.414-.805a.5.5 0 0 0 .196-.12l6.813-6.814z"/><path fill-rule="evenodd" d="M1 13.5A1.5 1.5 0 0 0 2.5 15h11a1.5 1.5 0 0 0 1.5-1.5v-6a.5.5 0 0 0-1 0v6a.5.5 0 0 1-.5.5h-11a.5.5 0 0 1-.5-.5v-11a.5.5 0 0 1 .5-.5H9a.5.5 0 0 0 0-1H2.5A1.5 1.5 0 0 0 1 2.5z"/></svg></button>
              <button type="button" class="btn btn--x" data-action="delete" aria-label="Delete user" ${deleteDisabled}${protectTitle}><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path d="M5.5 5.5A.5.5 0 0 1 6 6v5a.5.5 0 0 1-1 0V6a.5.5 0 0 1 .5-.5m2.5 0A.5.5 0 0 1 8.5 6v5a.5.5 0 0 1-1 0V6a.5.5 0 0 1 .5-.5m3 .5a.5.5 0 0 0-1 0v5a.5.5 0 0 0 1 0z"/><path d="M14.5 3a1 1 0 0 1-1 1H13l-.777 9.33A2 2 0 0 1 10.23 15H5.77a2 2 0 0 1-1.993-1.67L3 4h-.5a1 1 0 1 1 0-2H5a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1h2.5a1 1 0 0 1 1 1M6 2v1h4V2zm-2 2 .774 9.287A1 1 0 0 0 5.77 14h4.46a1 1 0 0 0 .996-.713L12 4z"/></svg></button>
            `.trim();
          }

          return `
            <button type="button" class="btn btn--primary" data-action="save" ${editDisabled}${protectTitle}>Save</button>
            <button type="button" class="btn" data-action="cancel" ${editDisabled}${protectTitle}>Cancel</button>
            <button type="button" class="btn btn--ghost" data-action="edit-roles" ${editDisabled}${protectTitle}>Edit Roles</button>
          `.trim();
        })();

        const actionsWrap = `<div class="usersTable__actions">${actionsCell}</div>`;

        return `
          <tr data-username="${safeName}">
            <td>
              <div class="usersTable__identity">
                <strong${roleTooltipAttr}>${safeName}</strong>
              </div>
            </td>
            <td>${passwordControl}</td>
            <td>${emailControl}</td>
            <td>${roleControl}</td>
            <td class="actions">${actionsWrap}</td>
          </tr>
        `.trim();
      })
      .join('');

    usersTbody.innerHTML = rows;

    // Enforce: max 3 visible users; scroll to see the rest.
    // Run twice to reduce cases where first paint hasn't finalized heights yet.
    requestAnimationFrame(() => {
      applyMaxVisibleUsers(3);
      requestAnimationFrame(() => applyMaxVisibleUsers(3));
    });
  }

  async function createUser(usernameRaw, passwordRaw, permissions, emailRaw, positionRaw) {
    const username = normalizeUsername(usernameRaw);
    const password = String(passwordRaw || '').trim();
    const email = normalizeEmail(emailRaw);
    const position = String(positionRaw || '').trim();
    if (!username) return { ok: false, reason: 'username' };
    if (!password || !password.trim()) return { ok: false, reason: 'password' };
    if (email && !isValidEmail(email)) return { ok: false, reason: 'email' };

    const existing = loadUsers();
    if (existing.some((u) => normalizeUsername(u && u.username) === username)) {
      return { ok: false, reason: 'duplicate' };
    }

    const normalizedPerms = normalizePermissions(permissions);
    // Bootstrap safety: the very first user must be able to access Settings.
    if (existing.length === 0) normalizedPerms.settings = 'write';

    const salt = (crypto?.randomUUID ? crypto.randomUUID() : `salt_${Date.now()}_${Math.random().toString(16).slice(2)}`);
    const passwordHash = await hashPassword(password, salt);
    const nowIso = new Date().toISOString();

    const user = {
      id: (crypto?.randomUUID ? crypto.randomUUID() : `user_${Date.now()}_${Math.random().toString(16).slice(2)}`),
      createdAt: nowIso,
      updatedAt: nowIso,
      username,
      email,
      position: position || '',
      salt,
      passwordHash,
      passwordPlain: password,
      permissions: normalizedPerms,
    };

    const merged = [...existing, user];
    saveUsers(merged);
    const wpRes = await persistUsersToWpNow();
    if (wpRes && wpRes.ok === false) {
      // Avoid “phantom” users that appear saved locally but never reached WordPress.
      saveUsers(existing);
      return { ok: false, reason: 'wp_save_failed' };
    }
    return { ok: true, user };
  }

  async function updateUser(usernameRaw, nextPermissions, newPasswordRaw, nextEmailRaw, nextRoleRaw) {
    const username = normalizeUsername(usernameRaw);
    const newPassword = String(newPasswordRaw || '').trim();
    const nextEmail = normalizeEmail(nextEmailRaw);
    const nextRole = String(nextRoleRaw ?? '').trim();
    if (nextEmail && !isValidEmail(nextEmail)) return { ok: false, reason: 'email' };
    const users = loadUsers();
    const idx = users.findIndex((u) => normalizeUsername(u && u.username) === username);
    if (idx === -1) return { ok: false, reason: 'notfound' };

    // Hard-coded admin: always enforce full access.
    if (username === normalizeUsername(HARD_CODED_ADMIN_USERNAME)) {
      ensureHardcodedAdminUserExists();
      return { ok: true, user: getUserByUsername(username) };
    }

    const nextPerms = normalizePermissions(nextPermissions);

    // Ensure at least one Settings-capable user remains.
    const current = users[idx];
    const wasSettings = getEffectivePermissions(current).settings;
    if (wasSettings !== 'none' && nextPerms.settings === 'none') {
      const others = users.filter((u, i) => i !== idx);
      if (countSettingsUsers(others) === 0) {
        return { ok: false, reason: 'lastSettings' };
      }
    }

    const nowIso = new Date().toISOString();
    const updated = { ...current, permissions: nextPerms, email: nextEmail, position: nextRole || '', updatedAt: nowIso };

    // Only update password when a non-whitespace value is provided.
    if (newPassword && newPassword.trim()) {
      const salt = current && current.salt ? String(current.salt) : (crypto?.randomUUID ? crypto.randomUUID() : String(Date.now()));
      updated.salt = salt;
      updated.passwordHash = await hashPassword(newPassword, salt);
      updated.passwordPlain = newPassword;
    }

    const next = users.map((u, i) => (i === idx ? updated : u));
    saveUsers(next);
    const wpRes = await persistUsersToWpNow();
    if (wpRes && wpRes.ok === false) {
      // Avoid showing edits locally that never reached WordPress.
      saveUsers(users);
      return { ok: false, reason: 'wp_save_failed' };
    }
    return { ok: true, user: updated };
  }

  function deleteUser(usernameRaw) {
    const username = normalizeUsername(usernameRaw);

    // Hard-coded admin: cannot be deleted.
    if (username === normalizeUsername(HARD_CODED_ADMIN_USERNAME)) return { ok: false, reason: 'protected' };

    const users = loadUsers();
    const idx = users.findIndex((u) => normalizeUsername(u && u.username) === username);
    if (idx === -1) return { ok: false, reason: 'notfound' };

    const target = users[idx];
    const isSettingsUser = getEffectivePermissions(target).settings !== 'none';
    if (isSettingsUser) {
      const others = users.filter((_, i) => i !== idx);
      if (countSettingsUsers(others) === 0) {
        return { ok: false, reason: 'lastSettings' };
      }
    }

    const next = users.filter((_, i) => i !== idx);
    saveUsers(next);

    const current = normalizeUsername(getCurrentUsername());
    if (current && current === username) {
      performLogout();
    }

    return { ok: true };
  }

  function loadBacklogItems() {
    try {
      const raw = localStorage.getItem(BACKLOG_KEY);
      if (!raw) return [];
      const parsed = JSON.parse(raw);
      if (!Array.isArray(parsed)) return [];
      return parsed.filter((x) => x && typeof x === 'object');
    } catch {
      return [];
    }
  }

  function saveBacklogItems(items) {
    const before = loadBacklogItems();
    const safe = Array.isArray(items) ? items : [];
    localStorage.setItem(BACKLOG_KEY, JSON.stringify(safe));
    appendCollectionAuditEvents({
      module: 'Backlog',
      beforeList: before,
      afterList: safe,
      idKeys: ['id', 'refNo'],
      recordLabelFn: (it) => String((it && (it.refNo || it.id || it.subject)) || '').trim(),
    });
  }

  function normalizeBacklogPriority(valueRaw) {
    const n = Number.parseInt(String(valueRaw ?? ''), 10);
    if (!Number.isFinite(n)) return 3;
    if (n < 1) return 1;
    if (n > 5) return 5;
    return n;
  }

  function isFiveDigitNumber(valueRaw) {
    const s = String(valueRaw || '').trim();
    return /^\d{5}$/.test(s);
  }

  function generateUniqueBacklogNumber(used) {
    const usedSet = used instanceof Set ? used : new Set();
    for (let i = 0; i < 80; i += 1) {
      const n = 10000 + Math.floor(Math.random() * 90000);
      const s = String(n);
      if (!usedSet.has(s)) return s;
    }
    // Fallback: last 5 digits of epoch seconds.
    const s = String(Math.floor(Date.now() / 1000) % 100000).padStart(5, '0');
    if (!usedSet.has(s)) return s;
    // Final fallback: brute force.
    for (let n = 10000; n <= 99999; n += 1) {
      const v = String(n);
      if (!usedSet.has(v)) return v;
    }
    return String(10000);
  }

  function getBacklogQueryTokens() {
    const searchInput = document.getElementById('backlogSearch');
    const raw = searchInput ? String(searchInput.value || '') : '';
    return raw
      .trim()
      .toLowerCase()
      .split(/\s+/)
      .filter(Boolean);
  }

  function backlogItemHaystack(it) {
    const parts = [
      it && it.refNo ? String(it.refNo) : '',
      it && it.priority !== undefined ? String(it.priority) : '',
      it && it.subject ? String(it.subject) : '',
      it && it.description ? String(it.description) : '',
      it && it.createdBy ? String(it.createdBy) : '',
      it && it.completedBy ? String(it.completedBy) : '',
      it && it.archivedBy ? String(it.archivedBy) : '',
      it && it.attachmentName ? String(it.attachmentName) : '',
    ];
    const comments = Array.isArray(it && it.comments) ? it.comments : [];
    for (const c of comments) {
      if (!c || typeof c !== 'object') continue;
      parts.push(String(c.by || ''));
      parts.push(String(c.text || ''));
    }
    return parts.join(' ').toLowerCase();
  }

  function backlogMatchesTokens(it, tokens) {
    if (!tokens || tokens.length === 0) return true;
    const hay = backlogItemHaystack(it);
    for (const t of tokens) {
      if (!hay.includes(t)) return false;
    }
    return true;
  }

  function applyMaxVisibleBacklogItems(listEl, maxVisible) {
    if (!listEl) return;
    const items = Array.from(listEl.querySelectorAll('.backlog__item'));

    listEl.style.overflowY = 'auto';
    if (items.length <= maxVisible) {
      listEl.style.maxHeight = '';
      return;
    }

    const first = items[0];
    const last = items[Math.min(maxVisible, items.length) - 1];
    const prevScrollTop = listEl.scrollTop;
    if (prevScrollTop) listEl.scrollTop = 0;
    let total = 0;
    try {
      const listRect = listEl.getBoundingClientRect ? listEl.getBoundingClientRect() : null;
      const firstRect = first && first.getBoundingClientRect ? first.getBoundingClientRect() : null;
      const lastRect = last && last.getBoundingClientRect ? last.getBoundingClientRect() : null;
      if (listRect && firstRect && lastRect) {
        total = (lastRect.bottom - listRect.top);
      }
    } finally {
      if (prevScrollTop) listEl.scrollTop = prevScrollTop;
    }

    if (!Number.isFinite(total) || total <= 0) {
      const cs = window.getComputedStyle ? window.getComputedStyle(listEl) : null;
      const gapRaw = cs ? (cs.rowGap || cs.gap || '0px') : '0px';
      const gap = Number.parseFloat(String(gapRaw)) || 0;
      total = 0;
      for (let i = 0; i < Math.min(maxVisible, items.length); i += 1) {
        total += items[i].offsetHeight;
      }
      total += gap * (maxVisible - 1);
    }

    listEl.style.maxHeight = `${Math.max(80, Math.ceil(total))}px`;
  }

  function getBacklogDisplayUser() {
    const u = normalizeUsername(getCurrentUsername());
    return u || '—';
  }

  function getBacklogAuditRecord(item) {
    if (!item || typeof item !== 'object') return 'Backlog Item';
    const ref = String(item.refNo || '').trim();
    const subject = String(item.subject || '').trim();
    if (ref && subject) return `${ref} - ${subject}`;
    if (ref) return ref;
    if (subject) return subject;
    return String(item.id || 'Backlog Item');
  }

  function syncModalPageScrollLock() {
    if (!document || !document.body || !document.documentElement) return;
    const hasOpenModal = Boolean(document.querySelector('.modal.is-open'));
    document.body.classList.toggle('is-modal-open', hasOpenModal);
    document.documentElement.classList.toggle('is-modal-open', hasOpenModal);
  }

  function openSimpleModal(modalEl, focusSelector) {
    if (!modalEl) return;
    modalEl.classList.add('is-open');
    modalEl.setAttribute('aria-hidden', 'false');
    syncModalPageScrollLock();
    const focusTarget = focusSelector ? modalEl.querySelector(focusSelector) : null;
    if (focusTarget && typeof focusTarget.focus === 'function') focusTarget.focus();
  }

  function closeSimpleModal(modalEl) {
    if (!modalEl) return;
    modalEl.classList.remove('is-open');
    modalEl.setAttribute('aria-hidden', 'true');
    syncModalPageScrollLock();
  }

  function clearBacklogFormErrors(formEl) {
    if (!formEl) return;
    const errors = Array.from(formEl.querySelectorAll('.error'));
    errors.forEach((el) => {
      el.textContent = '';
    });
  }

  function setBacklogFieldError(formEl, fieldId, message) {
    if (!formEl) return;
    const el = document.getElementById(`error-${String(fieldId || '').trim()}`);
    if (el) el.textContent = String(message || '');
  }

  function closeBacklogItemModal() {
    const modalEl = document.getElementById('backlogItemModal');
    const formEl = document.getElementById('backlogItemForm');
    if (formEl) {
      formEl.removeAttribute('data-edit-id');
      formEl.removeAttribute('data-existing-attachment-id');
      formEl.removeAttribute('data-remove-attachment');
      clearBacklogFormErrors(formEl);
      formEl.reset();
    }

    const currentEl = document.getElementById('backlogAttachmentCurrent');
    const viewBtn = document.getElementById('backlogAttachmentViewBtn');
    const removeBtn = document.getElementById('backlogAttachmentRemoveBtn');
    if (currentEl) {
      currentEl.textContent = '';
      currentEl.hidden = true;
    }
    if (viewBtn) viewBtn.hidden = true;
    if (removeBtn) removeBtn.hidden = true;

    closeSimpleModal(modalEl);
  }

  function closeBacklogCommentModal() {
    const modalEl = document.getElementById('backlogCommentModal');
    const formEl = document.getElementById('backlogCommentForm');
    if (formEl) {
      formEl.removeAttribute('data-item-id');
      formEl.removeAttribute('data-edit-comment-idx');
      clearBacklogFormErrors(formEl);
      formEl.reset();
    }
    const deleteBtn = document.getElementById('backlogCommentDeleteBtn');
    if (deleteBtn) {
      deleteBtn.hidden = true;
      deleteBtn.disabled = false;
    }
    closeSimpleModal(modalEl);
  }

  function renderBacklogList(canEdit) {
    const listEl = document.getElementById('backlogList');
    const emptyEl = document.getElementById('backlogEmptyState');
    const metaEl = document.getElementById('backlogMeta');
    const searchInput = document.getElementById('backlogSearch');
    const clearBtn = document.getElementById('backlogClearSearchBtn');
    const archiveToggleEl = document.getElementById('backlogArchiveToggle');
    const archiveWrapEl = document.getElementById('backlogArchiveWrap');
    const archiveEmptyEl = document.getElementById('backlogArchiveEmptyState');
    const archiveListEl = document.getElementById('backlogArchiveList');
    if (!listEl || !emptyEl) return;

    const hasArchiveUi = Boolean(archiveToggleEl && archiveWrapEl && archiveEmptyEl && archiveListEl);
    const showArchivedOnly = hasArchiveUi && archiveWrapEl.dataset.open === '1';

    // Bind search UI once.
    if (searchInput && !searchInput.dataset.bound) {
      searchInput.dataset.bound = 'true';
      searchInput.addEventListener('input', () => {
        renderBacklogList(canEdit);
      });
      searchInput.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
          searchInput.value = '';
          renderBacklogList(canEdit);
        }
      });
    }
    if (clearBtn && searchInput && !clearBtn.dataset.bound) {
      clearBtn.dataset.bound = 'true';
      clearBtn.addEventListener('click', () => {
        searchInput.value = '';
        renderBacklogList(canEdit);
        searchInput.focus();
      });
    }
    if (clearBtn && searchInput) {
      const has = Boolean(String(searchInput.value || '').trim());
      clearBtn.hidden = !has;
    }

    // One mode at a time: either show archived-only or active-only.
    if (hasArchiveUi) {
      archiveToggleEl.textContent = showArchivedOnly ? 'Active' : 'Archive';
      archiveToggleEl.setAttribute('aria-expanded', showArchivedOnly ? 'true' : 'false');
      archiveWrapEl.hidden = !showArchivedOnly;
    }
    listEl.hidden = Boolean(showArchivedOnly);

    const tokens = getBacklogQueryTokens();
    const items = loadBacklogItems();
    const usedRefNos = new Set(
      items
        .map((x) => (x && typeof x === 'object' ? String(x.refNo || '') : ''))
        .filter((x) => isFiveDigitNumber(x))
    );

    let needsSave = false;
    const patched = items.map((it, idx) => {
      if (!it || typeof it !== 'object') return it;
      const out = { ...it };

      const id = String(out.id || '').trim();
      if (!id) {
        out.id = (crypto?.randomUUID ? crypto.randomUUID() : `bl_${Date.now()}_${idx}_${Math.random().toString(16).slice(2)}`);
        needsSave = true;
      }

      let refNo = String(out.refNo || out.backlogNo || out.number || out.ticketNo || '').trim();
      if (!isFiveDigitNumber(refNo) || usedRefNos.has(refNo)) {
        refNo = generateUniqueBacklogNumber(usedRefNos);
        out.refNo = refNo;
        needsSave = true;
      } else {
        out.refNo = refNo;
        if (!out.refNo || String(out.refNo) !== refNo) needsSave = true;
      }
      usedRefNos.add(refNo);

      return out;
    });

    if (needsSave) saveBacklogItems(patched);

    const normalized = patched
      .map((it) => {
        if (!it || typeof it !== 'object') return null;
        const id = String(it.id || '').trim();
        const refNo = String(it.refNo || '').trim();
        const priority = normalizeBacklogPriority(it.priority);
        const subject = String(it.subject || '').trim();
        const description = String(it.description || '').trim();
        const createdAt = it.createdAt ? String(it.createdAt) : new Date().toISOString();
        const createdBy = it.createdBy !== undefined ? String(it.createdBy || '—') : '—';
        const archived = Boolean(it.archived) || Boolean(it.completed);
        const archivedAt = it.archivedAt ? String(it.archivedAt) : (it.completedAt ? String(it.completedAt) : '');
        const archivedBy = it.archivedBy !== undefined ? String(it.archivedBy || '—') : (it.completedBy !== undefined ? String(it.completedBy || '—') : '—');
        const completed = Boolean(it.completed) || archived;
        const completedAt = it.completedAt ? String(it.completedAt) : (archivedAt ? String(archivedAt) : '');
        const completedBy = it.completedBy !== undefined ? String(it.completedBy || '—') : (archivedBy ? String(archivedBy || '—') : '—');
        const comments = Array.isArray(it.comments) ? it.comments.filter((c) => c && typeof c === 'object') : [];
        const attachmentId = it.attachmentId !== undefined && it.attachmentId !== null ? String(it.attachmentId) : '';
        const attachmentName = String(it.attachmentName || '').trim();
        return {
          id,
          refNo,
          priority,
          subject,
          description,
          createdAt,
          createdBy,
          archived,
          archivedAt,
          archivedBy,
          completed,
          completedAt,
          completedBy,
          comments,
          attachmentId,
          attachmentName,
        };
      })
      .filter((it) => it && it.subject && it.description)
      .filter((it) => backlogMatchesTokens(it, tokens));

    const activeItems = normalized.filter((x) => !x.archived);
    const archivedItems = normalized.filter((x) => x.archived);

    activeItems.sort((a, b) => {
      const ap = normalizeBacklogPriority(a.priority);
      const bp = normalizeBacklogPriority(b.priority);
      if (ap !== bp) return ap - bp;
      const am = toTimeMs(a.createdAt) ?? 0;
      const bm = toTimeMs(b.createdAt) ?? 0;
      return bm - am;
    });

    archivedItems.sort((a, b) => {
      const ap = normalizeBacklogPriority(a.priority);
      const bp = normalizeBacklogPriority(b.priority);
      if (ap !== bp) return ap - bp;
      const am = toTimeMs(a.archivedAt || a.completedAt || a.createdAt) ?? 0;
      const bm = toTimeMs(b.archivedAt || b.completedAt || b.createdAt) ?? 0;
      if (bm !== am) return bm - am;
      const ac = toTimeMs(a.createdAt) ?? 0;
      const bc = toTimeMs(b.createdAt) ?? 0;
      return bc - ac;
    });

    if (metaEl) {
      const label = tokens.length > 0
        ? `${activeItems.length} open • ${archivedItems.length} archived • ${normalized.length} match`
        : `${activeItems.length} open • ${archivedItems.length} archived • ${normalized.length} total`;
      metaEl.textContent = label;
    }

    const actionsDisabled = !canEdit;

    function renderItems(itemsToRender) {
      return itemsToRender
        .map((it) => {
          const createdLabel = it.createdAt ? formatIsoDateTimeShort(it.createdAt) : '—';
          const completedLabel = it.completedAt ? formatIsoDateTimeShort(it.completedAt) : '—';

          const comments = (Array.isArray(it.comments) ? it.comments : [])
            .map((c, commentIdx) => {
              const at = c.at ? String(c.at) : '';
              const by = c.by !== undefined ? String(c.by || '—') : '—';
              const text = String(c.text || '').trim();
              if (!text) return '';
              const time = at ? formatIsoDateTimeShort(at) : '—';
              return `
              <div class="backlog__comment" data-comment-idx="${escapeHtml(commentIdx)}">
                <div class="backlog__commentHead">
                  <span><strong>${escapeHtml(by)}</strong></span>
                  <span class="timelinegraph__eventSep">•</span>
                  <span>${escapeHtml(time)}</span>
                </div>
                <div class="backlog__commentBody">${escapeHtml(text)}</div>
              </div>
            `.trim();
            })
            .filter(Boolean)
            .join('');

          const subjectClass = it.completed ? 'backlog__subject backlog__subject--completed' : 'backlog__subject';
          const itemClass = it.completed ? 'backlog__item backlog__item--completed' : 'backlog__item';
          const completeText = it.completed ? 'Reopen' : 'Complete';

          const attachmentBtn = it.attachmentId
            ? `<button type="button" class="btn btn--ghost" data-backlog-action="attachment">Attachment</button>`
            : '';

          const completedMeta = it.completed
            ? ` <span class="timelinegraph__eventSep">•</span> <span>Completed: <strong>${escapeHtml(completedLabel)}</strong></span> <span class="timelinegraph__eventSep">•</span> <span>By: <strong>${escapeHtml(it.completedBy || '—')}</strong></span>`
            : '';

          return `
          <div class="${itemClass}" data-id="${escapeHtml(it.id)}">
            <div class="backlog__header">
              <div class="${subjectClass}">#${escapeHtml(it.refNo)} • P${escapeHtml(it.priority)} • ${escapeHtml(it.subject)}</div>
              <div class="backlog__meta">
                <span>Created: <strong>${escapeHtml(createdLabel)}</strong></span>
                <span class="timelinegraph__eventSep">•</span>
                <span>By: <strong>${escapeHtml(it.createdBy || '—')}</strong></span>
                ${completedMeta}
              </div>
            </div>
            <div class="backlog__desc">${escapeHtml(it.description)}</div>
            <div class="backlog__actions">
              ${attachmentBtn}
              <button type="button" class="btn btn--viewGrey" data-backlog-action="comment" ${actionsDisabled ? 'aria-disabled="true" data-tooltip="Read only access."' : ''}>Comment</button>
              <button type="button" class="btn btn--backlogEdit" data-backlog-action="edit" ${actionsDisabled ? 'aria-disabled="true" data-tooltip="Read only access."' : ''}>Edit</button>
              <button type="button" class="btn" data-backlog-action="complete" ${actionsDisabled ? 'aria-disabled="true" data-tooltip="Read only access."' : ''}>${escapeHtml(completeText)}</button>
              <button type="button" class="btn btn--danger" data-backlog-action="delete" ${actionsDisabled ? 'aria-disabled="true" data-tooltip="Read only access."' : ''}>Delete</button>
            </div>
            ${comments ? `<div class="backlog__comments" aria-label="Comments">${comments}</div>` : ''}
          </div>
        `.trim();
        })
        .join('');
    }

    if (!showArchivedOnly) {
      emptyEl.textContent = tokens.length > 0 ? 'No matching backlog items.' : 'No active backlog items.';
      emptyEl.hidden = activeItems.length > 0;
      listEl.innerHTML = activeItems.length > 0 ? renderItems(activeItems) : '';

      if (hasArchiveUi) {
        archiveListEl.innerHTML = '';
        archiveEmptyEl.textContent = tokens.length > 0 ? 'No matching archived items.' : 'No archived items.';
        archiveEmptyEl.hidden = true;
      }
      return;
    }

    // Archived-only view.
    emptyEl.hidden = true;
    emptyEl.textContent = tokens.length > 0 ? 'No matching backlog items.' : 'No active backlog items.';
    listEl.innerHTML = '';

    if (hasArchiveUi) {
      archiveEmptyEl.textContent = tokens.length > 0 ? 'No matching archived items.' : 'No archived items.';
      archiveEmptyEl.hidden = archivedItems.length > 0;
      archiveListEl.innerHTML = archivedItems.length > 0 ? renderItems(archivedItems) : '';
    }
  }

  function initBacklogSettingsSection(canEdit) {
    const addBtn = document.getElementById('backlogAddBtn');
    const listEl = document.getElementById('backlogList');
    const archiveToggleEl = document.getElementById('backlogArchiveToggle');
    const archiveWrapEl = document.getElementById('backlogArchiveWrap');
    const archiveListEl = document.getElementById('backlogArchiveList');
    const itemModal = document.getElementById('backlogItemModal');
    const itemForm = document.getElementById('backlogItemForm');
    const commentModal = document.getElementById('backlogCommentModal');
    const commentForm = document.getElementById('backlogCommentForm');
    const commentDeleteBtn = document.getElementById('backlogCommentDeleteBtn');
    if (!addBtn || !listEl || !itemModal || !itemForm || !commentModal || !commentForm) return;

    addBtn.disabled = !canEdit;
    if (!canEdit) addBtn.setAttribute('data-tooltip', 'Read only access.');

    if (!addBtn.dataset.bound) {
      addBtn.dataset.bound = 'true';
      addBtn.addEventListener('click', () => {
        if (!canEdit) return;
        const titleEl = document.getElementById('backlogItemModalTitle');
        if (titleEl) titleEl.textContent = 'Add Backlog Item';
        itemForm.removeAttribute('data-edit-id');
        clearBacklogFormErrors(itemForm);
        itemForm.reset();
        openSimpleModal(itemModal, '#backlogSubject');
      });
    }

    if (archiveToggleEl && archiveWrapEl && !archiveToggleEl.dataset.bound) {
      archiveToggleEl.dataset.bound = 'true';
      archiveToggleEl.addEventListener('click', () => {
        const showArchivedOnly = archiveWrapEl.dataset.open === '1';
        archiveWrapEl.dataset.open = showArchivedOnly ? '0' : '1';
        renderBacklogList(canEdit);
      });
    }

    // Modal close handlers (backdrop, buttons)
    if (!itemModal.dataset.bound) {
      itemModal.dataset.bound = 'true';
      itemModal.addEventListener('click', (e) => {
        const closeTarget = e.target.closest('[data-modal-close]');
        if (closeTarget) closeBacklogItemModal();
      });
    }
    if (!commentModal.dataset.bound) {
      commentModal.dataset.bound = 'true';
      commentModal.addEventListener('click', (e) => {
        const closeTarget = e.target.closest('[data-modal-close]');
        if (closeTarget) closeBacklogCommentModal();
      });
    }

    function bindBacklogListActions(targetListEl) {
      if (!targetListEl || targetListEl.dataset.bound) return;
      targetListEl.dataset.bound = 'true';
      targetListEl.addEventListener('click', async (e) => {
        const btn = e.target.closest('button[data-backlog-action]');
        if (!btn) return;
        const row = btn.closest('.backlog__item');
        if (!row) return;
        const id = row.getAttribute('data-id');
        const action = btn.getAttribute('data-backlog-action');
        if (!id || !action) return;

        const isViewAction = action === 'attachment';
        if (!isViewAction && !canEdit) {
          window.alert('Read only access.');
          return;
        }

        const items = loadBacklogItems();
        const idx = items.findIndex((x) => x && typeof x === 'object' && String(x.id || '') === String(id));
        if (idx === -1) return;
        const current = items[idx];

        if (action === 'attachment') {
          const attId = current && current.attachmentId !== undefined && current.attachmentId !== null ? String(current.attachmentId).trim() : '';
          if (!attId) return;
          try {
            const att = await getAttachmentById(attId);
            if (att) openAttachmentInNewTab(att);
          } catch (err) {
            // eslint-disable-next-line no-console
            console.error(err);
          }
          return;
        }

        if (action === 'edit') {
          const titleEl = document.getElementById('backlogItemModalTitle');
          if (titleEl) titleEl.textContent = 'Edit Backlog Item';
          itemForm.setAttribute('data-edit-id', String(id));
          itemForm.removeAttribute('data-remove-attachment');
          clearBacklogFormErrors(itemForm);
          const subj = document.getElementById('backlogSubject');
          const pri = document.getElementById('backlogPriority');
          const desc = document.getElementById('backlogDescription');
          const fileEl = document.getElementById('backlogAttachment');
          const currentEl = document.getElementById('backlogAttachmentCurrent');
          const viewBtn = document.getElementById('backlogAttachmentViewBtn');
          const removeBtn = document.getElementById('backlogAttachmentRemoveBtn');
          if (subj) subj.value = String(current.subject || '');
          if (pri) pri.value = String(normalizeBacklogPriority(current.priority));
          if (desc) desc.value = String(current.description || '');
          if (fileEl) fileEl.value = '';

          const attId = current && current.attachmentId !== undefined && current.attachmentId !== null ? String(current.attachmentId).trim() : '';
          const attName = String(current.attachmentName || '').trim();
          if (attId) itemForm.setAttribute('data-existing-attachment-id', attId);
          else itemForm.removeAttribute('data-existing-attachment-id');

          if (currentEl) {
            currentEl.textContent = attName ? `Current: ${attName}` : 'Current attachment set.';
            currentEl.hidden = !attId;
          }
          if (viewBtn) viewBtn.hidden = !attId;
          if (removeBtn) removeBtn.hidden = !attId;

          openSimpleModal(itemModal, '#backlogSubject');
          return;
        }

        if (action === 'delete') {
          const ok = window.confirm('Delete this backlog item?');
          if (!ok) return;

          const attId = current && current.attachmentId !== undefined && current.attachmentId !== null ? String(current.attachmentId).trim() : '';
          if (attId) {
            try {
              await deleteAttachmentById(attId);
            } catch {
              // Ignore attachment deletion errors; item deletion should proceed.
            }
          }

          const next = items.filter((x) => x && typeof x === 'object' && String(x.id || '') !== String(id));
          saveBacklogItems(next);
          appendAppAuditEvent('Backlog', getBacklogAuditRecord(current), 'Deleted', []);
          renderBacklogList(canEdit);
          return;
        }

        if (action === 'complete') {
          const wasArchived = Boolean(current.archived) || Boolean(current.completed);
          const now = new Date().toISOString();
          const by = getBacklogDisplayUser();
          const nextItem = wasArchived
            ? {
              ...current,
              archived: false,
              archivedAt: '',
              archivedBy: '',
              completed: false,
              completedAt: '',
              completedBy: '',
            }
            : {
              ...current,
              archived: true,
              archivedAt: now,
              archivedBy: by,
              completed: true,
              completedAt: now,
              completedBy: by,
            };
          const next = items.slice();
          next[idx] = nextItem;
          saveBacklogItems(next);
          appendAppAuditEvent('Backlog', getBacklogAuditRecord(nextItem), 'Modified', [
            {
              field: 'Archived',
              from: wasArchived ? 'Yes' : 'No',
              to: wasArchived ? 'No' : 'Yes',
            },
          ]);
          renderBacklogList(canEdit);
          return;
        }

        if (action === 'comment') {
          const titleEl = document.getElementById('backlogCommentModalTitle');
          if (titleEl) titleEl.textContent = 'Add Comment';
          commentForm.setAttribute('data-item-id', String(id));
          commentForm.removeAttribute('data-edit-comment-idx');
          if (commentDeleteBtn) {
            commentDeleteBtn.hidden = true;
            commentDeleteBtn.disabled = !canEdit;
          }
          clearBacklogFormErrors(commentForm);
          commentForm.reset();
          openSimpleModal(commentModal, '#backlogComment');
        }
      });
    }

    function bindBacklogCommentDblClick(targetListEl) {
      if (!targetListEl || targetListEl.dataset.commentDblBound) return;
      targetListEl.dataset.commentDblBound = '1';
      targetListEl.addEventListener('dblclick', (e) => {
        if (!canEdit) return;
        const commentEl = e.target.closest('.backlog__comment');
        if (!commentEl) return;
        const row = commentEl.closest('.backlog__item');
        if (!row) return;
        const itemId = row.getAttribute('data-id');
        const idxRaw = commentEl.getAttribute('data-comment-idx');
        const commentIdx = Number.parseInt(String(idxRaw || ''), 10);
        if (!itemId || !Number.isFinite(commentIdx) || commentIdx < 0) return;

        const items = loadBacklogItems();
        const itemIndex = items.findIndex((x) => x && typeof x === 'object' && String(x.id || '') === String(itemId));
        if (itemIndex === -1) return;
        const current = items[itemIndex];
        const comments = Array.isArray(current.comments) ? current.comments : [];
        if (commentIdx >= comments.length) return;
        const existing = comments[commentIdx] && typeof comments[commentIdx] === 'object' ? comments[commentIdx] : null;
        const text = existing ? String(existing.text || '').trim() : '';

        const titleEl = document.getElementById('backlogCommentModalTitle');
        if (titleEl) titleEl.textContent = 'Edit Comment';
        commentForm.setAttribute('data-item-id', String(itemId));
        commentForm.setAttribute('data-edit-comment-idx', String(commentIdx));
        if (commentDeleteBtn) {
          commentDeleteBtn.hidden = false;
          commentDeleteBtn.disabled = !canEdit;
        }
        clearBacklogFormErrors(commentForm);
        commentForm.reset();
        const textEl = document.getElementById('backlogComment');
        if (textEl) textEl.value = text;
        openSimpleModal(commentModal, '#backlogComment');
      });
    }

    bindBacklogListActions(listEl);
    bindBacklogListActions(archiveListEl);
    bindBacklogCommentDblClick(listEl);
    bindBacklogCommentDblClick(archiveListEl);

    if (!itemForm.dataset.bound) {
      itemForm.dataset.bound = 'true';
      itemForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        if (!canEdit) return;
        clearBacklogFormErrors(itemForm);

        const subjectEl = document.getElementById('backlogSubject');
        const descEl = document.getElementById('backlogDescription');
        const priEl = document.getElementById('backlogPriority');
        const fileEl = document.getElementById('backlogAttachment');
        const subject = subjectEl ? String(subjectEl.value || '').trim() : '';
        const description = descEl ? String(descEl.value || '').trim() : '';
        const priority = normalizeBacklogPriority(priEl ? priEl.value : 3);

        let ok = true;
        if (!subject) {
          setBacklogFieldError(itemForm, 'backlogSubject', 'Subject is required.');
          ok = false;
        }
        if (!description) {
          setBacklogFieldError(itemForm, 'backlogDescription', 'Description is required.');
          ok = false;
        }
        if (!Number.isFinite(priority) || priority < 1 || priority > 5) {
          setBacklogFieldError(itemForm, 'backlogPriority', 'Priority must be 1–5.');
          ok = false;
        }
        if (!ok) return;

        const editId = itemForm.getAttribute('data-edit-id');
        const items = loadBacklogItems();

        // Attachment handling: create or update attachment if a file is chosen.
        const existingAttachmentId = String(itemForm.getAttribute('data-existing-attachment-id') || '').trim();
        const removeExisting = itemForm.getAttribute('data-remove-attachment') === '1';
        const selectedFile = fileEl && fileEl.files && fileEl.files.length > 0 ? fileEl.files[0] : null;

        async function removeExistingAttachmentIfAny() {
          if (!existingAttachmentId) return;
          try {
            await deleteAttachmentById(existingAttachmentId);
          } catch {
            // Ignore deletion errors.
          }
        }

        async function uploadNewAttachmentForItem(itemId) {
          if (!selectedFile) return null;

          if (IS_WP_SHARED_MODE) {
            if (!getCurrentUser()) throw new Error('not_authorized');
            if (!requireWriteOrCreateAccess('settings_backlog', 'Backlog is view only for your account.')) throw new Error('not_authorized');
            return wpUploadBacklogAttachment(itemId, selectedFile);
          }

          // Standalone: store in IndexedDB and reference by id.
          return addAttachment(`backlog:${itemId}`, selectedFile, null);
        }

        if (editId) {
          const idx = items.findIndex((x) => x && typeof x === 'object' && String(x.id || '') === String(editId));
          if (idx === -1) return;

          let nextAttachment = null;
          if (selectedFile) {
            await removeExistingAttachmentIfAny();
            try {
              nextAttachment = await uploadNewAttachmentForItem(editId);
            } catch (err) {
              const code = String(err && err.message ? err.message : '');
              if (code === 'not_authorized') setBacklogFieldError(itemForm, 'backlogAttachment', 'Sign in to upload attachments.');
              else setBacklogFieldError(itemForm, 'backlogAttachment', 'Attachment could not be saved.');
              return;
            }
          } else if (removeExisting) {
            await removeExistingAttachmentIfAny();
          }

          const next = items.slice();
          const base = { ...next[idx], subject, description, priority };

          if (nextAttachment) {
            base.attachmentId = nextAttachment.id;
            base.attachmentName = nextAttachment.name;
          } else if (removeExisting) {
            base.attachmentId = '';
            base.attachmentName = '';
          }

          next[idx] = base;
          saveBacklogItems(next);
        } else {
          const id = (crypto?.randomUUID ? crypto.randomUUID() : `bl_${Date.now()}_${Math.random().toString(16).slice(2)}`);
          const now = new Date().toISOString();
          const by = getBacklogDisplayUser();

          let nextAttachment = null;
          if (selectedFile) {
            try {
              nextAttachment = await uploadNewAttachmentForItem(id);
            } catch (err) {
              const code = String(err && err.message ? err.message : '');
              if (code === 'not_authorized') setBacklogFieldError(itemForm, 'backlogAttachment', 'Sign in to upload attachments.');
              else setBacklogFieldError(itemForm, 'backlogAttachment', 'Attachment could not be saved.');
              return;
            }
          }

          const nextItem = {
            id,
            refNo: generateUniqueBacklogNumber(new Set(loadBacklogItems().map((x) => (x && typeof x === 'object' ? String(x.refNo || '') : '')).filter((x) => isFiveDigitNumber(x)))),
            priority,
            subject,
            description,
            createdAt: now,
            createdBy: by,
            archived: false,
            archivedAt: '',
            archivedBy: '',
            completed: false,
            completedAt: '',
            completedBy: '',
            comments: [],
          };

          if (nextAttachment) {
            nextItem.attachmentId = nextAttachment.id;
            nextItem.attachmentName = nextAttachment.name;
          }

          saveBacklogItems([nextItem, ...items]);
          void fireNotificationEvent('new_backlog', {
            refNo: String(nextItem.refNo || ''),
            subject: String(nextItem.subject || ''),
            priority: String(nextItem.priority || ''),
            createdBy: String(nextItem.createdBy || ''),
            directLink: String(window.location.href || ''),
          });
        }

        closeBacklogItemModal();
        renderBacklogList(canEdit);
      });
    }

    // Attachment controls inside the modal.
    if (!itemForm.dataset.attachmentControlsBound) {
      itemForm.dataset.attachmentControlsBound = '1';
      const viewBtn = document.getElementById('backlogAttachmentViewBtn');
      const removeBtn = document.getElementById('backlogAttachmentRemoveBtn');
      const currentEl = document.getElementById('backlogAttachmentCurrent');
      const fileEl = document.getElementById('backlogAttachment');

      if (viewBtn && !viewBtn.dataset.bound) {
        viewBtn.dataset.bound = '1';
        viewBtn.addEventListener('click', async () => {
          const attId = String(itemForm.getAttribute('data-existing-attachment-id') || '').trim();
          if (!attId) return;
          try {
            const att = await getAttachmentById(attId);
            if (att) openAttachmentInNewTab(att);
          } catch (err) {
            // eslint-disable-next-line no-console
            console.error(err);
          }
        });
      }

      if (removeBtn && !removeBtn.dataset.bound) {
        removeBtn.dataset.bound = '1';
        removeBtn.addEventListener('click', () => {
          itemForm.setAttribute('data-remove-attachment', '1');
          itemForm.removeAttribute('data-existing-attachment-id');
          if (currentEl) {
            currentEl.textContent = 'Attachment will be removed when you Save.';
            currentEl.hidden = false;
          }
          if (viewBtn) viewBtn.hidden = true;
          if (removeBtn) removeBtn.hidden = true;
          if (fileEl) fileEl.value = '';
        });
      }
    }

    if (!commentForm.dataset.bound) {
      commentForm.dataset.bound = 'true';
      commentForm.addEventListener('submit', (e) => {
        e.preventDefault();
        if (!canEdit) return;
        clearBacklogFormErrors(commentForm);

        const itemId = commentForm.getAttribute('data-item-id');
        const editIdxRaw = commentForm.getAttribute('data-edit-comment-idx');
        const editIdx = editIdxRaw !== null ? Number.parseInt(String(editIdxRaw || ''), 10) : Number.NaN;
        const textEl = document.getElementById('backlogComment');
        const text = textEl ? String(textEl.value || '').trim() : '';
        if (!itemId) return;
        if (!text) {
          setBacklogFieldError(commentForm, 'backlogComment', 'Comment is required.');
          return;
        }

        const items = loadBacklogItems();
        const idx = items.findIndex((x) => x && typeof x === 'object' && String(x.id || '') === String(itemId));
        if (idx === -1) return;
        const current = items[idx];
        const comments = Array.isArray(current.comments) ? current.comments.slice() : [];

        const now = new Date().toISOString();
        const by = getBacklogDisplayUser();

        if (Number.isFinite(editIdx) && editIdx >= 0 && editIdx < comments.length) {
          const existing = comments[editIdx] && typeof comments[editIdx] === 'object' ? comments[editIdx] : {};
          const id = String(existing.id || '').trim() || (crypto?.randomUUID ? crypto.randomUUID() : `c_${Date.now()}_${Math.random().toString(16).slice(2)}`);
          comments[editIdx] = {
            ...existing,
            id,
            at: now,
            by,
            text,
          };
          appendAppAuditEvent('Backlog Comment', getBacklogAuditRecord(current), 'Modified', [
            { field: 'Comment', from: String(existing.text || '').trim() || '—', to: text },
          ]);
        } else {
          comments.push({
            id: (crypto?.randomUUID ? crypto.randomUUID() : `c_${Date.now()}_${Math.random().toString(16).slice(2)}`),
            at: now,
            by,
            text,
          });
          appendAppAuditEvent('Backlog Comment', getBacklogAuditRecord(current), 'Created', [
            { field: 'Comment', from: '', to: text },
          ]);
        }

        const next = items.slice();
        next[idx] = { ...current, comments };
        saveBacklogItems(next);

        closeBacklogCommentModal();
        renderBacklogList(canEdit);
      });
    }

    if (commentDeleteBtn && !commentDeleteBtn.dataset.bound) {
      commentDeleteBtn.dataset.bound = 'true';
      commentDeleteBtn.addEventListener('click', () => {
        if (!canEdit) return;
        const itemId = commentForm.getAttribute('data-item-id');
        const editIdxRaw = commentForm.getAttribute('data-edit-comment-idx');
        const editIdx = editIdxRaw !== null ? Number.parseInt(String(editIdxRaw || ''), 10) : Number.NaN;
        if (!itemId || !Number.isFinite(editIdx) || editIdx < 0) return;

        const ok = window.confirm('Delete this comment?');
        if (!ok) return;

        const items = loadBacklogItems();
        const idx = items.findIndex((x) => x && typeof x === 'object' && String(x.id || '') === String(itemId));
        if (idx === -1) return;
        const current = items[idx];
        const comments = Array.isArray(current.comments) ? current.comments.slice() : [];
        if (editIdx >= comments.length) return;
        const existing = comments[editIdx] && typeof comments[editIdx] === 'object' ? comments[editIdx] : null;
        comments.splice(editIdx, 1);

        const next = items.slice();
        next[idx] = { ...current, comments };
        saveBacklogItems(next);
        appendAppAuditEvent('Backlog Comment', getBacklogAuditRecord(current), 'Deleted', [
          { field: 'Comment', from: String(existing && existing.text ? existing.text : 'Comment'), to: '' },
        ]);

        closeBacklogCommentModal();
        renderBacklogList(canEdit);
      });
    }

    renderBacklogList(canEdit);
  }

  function getCookieValue(nameRaw) {
    const name = String(nameRaw || '').trim();
    if (!name) return '';
    const all = String(document.cookie || '');
    if (!all) return '';
    const parts = all.split(';');
    for (const p of parts) {
      const idx = p.indexOf('=');
      if (idx === -1) continue;
      const k = p.slice(0, idx).trim();
      if (k !== name) continue;
      return p.slice(idx + 1).trim();
    }
    return '';
  }

  function setCookieValue(nameRaw, valueRaw, maxAgeDays) {
    const name = String(nameRaw || '').trim();
    if (!name) return;
    const value = String(valueRaw ?? '');
    const days = Number(maxAgeDays);
    const maxAge = Number.isFinite(days) && days > 0 ? Math.floor(days * 24 * 60 * 60) : (365 * 24 * 60 * 60);
    document.cookie = `${name}=${value}; Max-Age=${maxAge}; Path=/; SameSite=Lax`;
  }

  function getSettingsCardOrderCookieName() {
    const username = normalizeUsername(getCurrentUsername());
    if (!username) return '';
    return `acgl_settings_card_order_v1_${encodeURIComponent(username)}`;
  }

  function readSettingsCardOrderFromCookie() {
    const cookieName = getSettingsCardOrderCookieName();
    if (!cookieName) return null;
    const raw = getCookieValue(cookieName);
    if (!raw) return null;
    try {
      const decoded = decodeURIComponent(raw);
      const parsed = JSON.parse(decoded);
      if (!Array.isArray(parsed)) return null;
      return parsed.map((x) => String(x || '').trim()).filter(Boolean);
    } catch {
      return null;
    }
  }

  function writeSettingsCardOrderToCookie(orderKeys) {
    const cookieName = getSettingsCardOrderCookieName();
    if (!cookieName) return;
    const arr = Array.isArray(orderKeys) ? orderKeys.map((x) => String(x || '').trim()).filter(Boolean) : [];
    setCookieValue(cookieName, encodeURIComponent(JSON.stringify(arr)), 365);
  }

  function getSettingsCardFullWidthCookieName() {
    const username = normalizeUsername(getCurrentUsername());
    if (!username) return 'acgl_settings_card_fullwidth_v1';
    return `acgl_settings_card_fullwidth_v1_${encodeURIComponent(username)}`;
  }

  function readSettingsCardFullWidthFromCookie() {
    const cookieName = getSettingsCardFullWidthCookieName();
    if (!cookieName) return null;
    const raw = getCookieValue(cookieName);
    if (!raw) return null;
    try {
      const decoded = decodeURIComponent(raw);
      const parsed = JSON.parse(decoded);
      if (!Array.isArray(parsed)) return null;
      return parsed.map((x) => String(x || '').trim()).filter(Boolean);
    } catch {
      return null;
    }
  }

  function writeSettingsCardFullWidthToCookie(fullWidthKeys) {
    const cookieName = getSettingsCardFullWidthCookieName();
    if (!cookieName) return;
    const arr = Array.isArray(fullWidthKeys) ? fullWidthKeys.map((x) => String(x || '').trim()).filter(Boolean) : [];
    setCookieValue(cookieName, encodeURIComponent(JSON.stringify(arr)), 365);
  }

  function getSettingsCardsContainer() {
    const main = document.querySelector('main.container');
    if (!main) return null;
    return main;
  }

  function getSettingsCardEls(containerEl) {
    if (!containerEl) return [];
    return Array.from(containerEl.querySelectorAll('section.card[data-settings-card][draggable="true"]'));
  }

  function applySettingsCardOrder(containerEl) {
    const order = readSettingsCardOrderFromCookie();
    if (!order || order.length === 0) return;

    const cards = getSettingsCardEls(containerEl);
    if (cards.length === 0) return;

    const byKey = new Map();
    for (const el of cards) {
      const key = String(el.getAttribute('data-settings-card') || '').trim();
      if (!key) continue;
      byKey.set(key, el);
    }

    const seen = new Set();
    for (const key of order) {
      const el = byKey.get(key);
      if (!el) continue;
      containerEl.appendChild(el);
      seen.add(key);
    }

    // Any cards not in the saved list stay after, in current DOM order.
    for (const el of cards) {
      const key = String(el.getAttribute('data-settings-card') || '').trim();
      if (!key || seen.has(key)) continue;
      containerEl.appendChild(el);
    }
  }

  function applySettingsCardFullWidth(containerEl) {
    const keys = readSettingsCardFullWidthFromCookie();
    const set = new Set(Array.isArray(keys) ? keys : []);
    for (const el of getSettingsCardEls(containerEl)) {
      const key = String(el.getAttribute('data-settings-card') || '').trim();
      if (!key) continue;
      if (set.has(key)) el.classList.add('settingsCard--full');
      else el.classList.remove('settingsCard--full');
    }
  }

  function installSettingsCardGearButtons() {
    const containerEl = getSettingsCardsContainer();
    if (!containerEl) return;

    // Ensure saved layout preferences are applied even if the dropdown UI is hidden.
    applySettingsCardFullWidth(containerEl);

    const cards = getSettingsCardEls(containerEl);

    const getTitle = (cardEl) => {
      const h2 = cardEl.querySelector('h2');
      const txt = h2 ? String(h2.textContent || '').trim() : '';
      if (txt) return txt;
      const key = String(cardEl.getAttribute('data-settings-card') || '').trim();
      return key || 'Section';
    };

    for (const card of cards) {
      const key = String(card.getAttribute('data-settings-card') || '').trim();
      if (!key) continue;
      const header = card.querySelector('.list-header');
      if (!header) continue;

      let actions = header.querySelector('.list-actions');
      if (!actions) {
        actions = document.createElement('div');
        actions.className = 'list-actions';
        header.appendChild(actions);
      }

      // Avoid duplicates.
      if (actions.querySelector(`[data-settings-layout-gear="${key}"]`)) continue;

      // Remove any legacy injected controls from older builds.
      for (const legacy of Array.from(actions.querySelectorAll('[data-settings-layout-select], [data-settings-gear]'))) {
        legacy.remove();
      }

      const title = getTitle(card);
      const details = document.createElement('details');
      details.className = 'settingsGear';
      details.setAttribute('data-settings-layout-gear', key);

      const summary = document.createElement('summary');
      summary.className = 'btn btn--ghost';
      summary.textContent = '⚙';
      summary.title = 'Layout';
      summary.setAttribute('aria-label', `Layout options for ${title}`);
      details.appendChild(summary);

      const panel = document.createElement('div');
      panel.className = 'settingsGear__panel';

      const toggleBtn = document.createElement('button');
      toggleBtn.type = 'button';
      toggleBtn.className = 'actionLink';

      const readFullWidthSet = () => {
        const keys = readSettingsCardFullWidthFromCookie();
        return new Set(Array.isArray(keys) ? keys : []);
      };

      const refreshLabel = () => {
        const isFull = card.classList.contains('settingsCard--full');
        toggleBtn.textContent = isFull ? 'Column view' : 'Full width';
      };

      toggleBtn.addEventListener('click', () => {
        const isFull = card.classList.contains('settingsCard--full');
        const set = readFullWidthSet();
        if (isFull) set.delete(key);
        else set.add(key);
        writeSettingsCardFullWidthToCookie(Array.from(set));
        applySettingsCardFullWidth(containerEl);
        refreshLabel();
        details.open = false;
      });

      details.addEventListener('toggle', () => {
        if (!details.open) return;
        // Close any other open gear menus.
        for (const other of Array.from(containerEl.querySelectorAll('details.settingsGear[open]')))
          if (other !== details) other.open = false;
        refreshLabel();
      });

      panel.appendChild(toggleBtn);
      details.appendChild(panel);
      actions.appendChild(details);
    }

    // Click outside closes any open gear dropdowns.
    if (!containerEl.dataset.settingsGearOutsideBound) {
      containerEl.dataset.settingsGearOutsideBound = '1';
      document.addEventListener('click', (e) => {
        const target = e && e.target ? e.target : null;
        if (!target) return;
        for (const d of Array.from(containerEl.querySelectorAll('details.settingsGear[open]'))) {
          if (!d.contains(target)) d.open = false;
        }
      });
    }
  }

  function saveSettingsCardOrder(containerEl) {
    const cards = getSettingsCardEls(containerEl);
    const keys = cards
      .map((el) => String(el.getAttribute('data-settings-card') || '').trim())
      .filter(Boolean);
    writeSettingsCardOrderToCookie(keys);
  }

  function initSettingsCardsDragAndDrop() {
    const cookieName = getSettingsCardOrderCookieName();
    if (!cookieName) return;

    const containerEl = getSettingsCardsContainer();
    if (!containerEl) return;
    if (containerEl.dataset.settingsCardDndBound) return;
    containerEl.dataset.settingsCardDndBound = '1';

    applySettingsCardOrder(containerEl);
    applySettingsCardFullWidth(containerEl);

    let draggedEl = null;
    let lastDragPointerDownTarget = null;

    function isInteractiveTarget(t) {
      if (!t || !t.closest) return false;
      return Boolean(t.closest('input, textarea, select, button, a, label'));
    }

    function isSettingsCardDragHandleTarget(t, cardEl) {
      if (!t || !t.closest || !cardEl) return false;
      const headerEl = t.closest('.list-header');
      return Boolean(headerEl && cardEl.contains(headerEl));
    }

    if (!containerEl.dataset.settingsCardPointerDownBound) {
      containerEl.dataset.settingsCardPointerDownBound = '1';
      containerEl.addEventListener('pointerdown', (e) => {
        lastDragPointerDownTarget = e && e.target ? e.target : null;
      }, true);
      // Fallback for environments where Pointer Events are unavailable.
      containerEl.addEventListener('mousedown', (e) => {
        lastDragPointerDownTarget = e && e.target ? e.target : null;
      }, true);
    }

    function getDragAfterElement(container, y) {
      const els = getSettingsCardEls(container).filter((el) => el !== draggedEl);
      let closest = { offset: Number.NEGATIVE_INFINITY, el: null };
      for (const el of els) {
        const box = el.getBoundingClientRect();
        const offset = y - (box.top + box.height / 2);
        if (offset < 0 && offset > closest.offset) {
          closest = { offset, el };
        }
      }
      return closest.el;
    }

    for (const card of getSettingsCardEls(containerEl)) {
      card.addEventListener('dragstart', (e) => {
        const handleTarget = (lastDragPointerDownTarget && card.contains(lastDragPointerDownTarget))
          ? lastDragPointerDownTarget
          : (e && e.target ? e.target : null);
        if (isInteractiveTarget(handleTarget) || !isSettingsCardDragHandleTarget(handleTarget, card)) {
          e.preventDefault();
          return;
        }
        draggedEl = card;
        card.classList.add('card--dragging');
        try {
          e.dataTransfer.effectAllowed = 'move';
          e.dataTransfer.setData('text/plain', String(card.getAttribute('data-settings-card') || ''));
        } catch {
          // ignore
        }
      });
      card.addEventListener('dragend', () => {
        if (draggedEl) draggedEl.classList.remove('card--dragging');
        draggedEl = null;
        lastDragPointerDownTarget = null;
        saveSettingsCardOrder(containerEl);
      });
    }

    containerEl.addEventListener('dragover', (e) => {
      if (!draggedEl) return;
      e.preventDefault();
      const afterEl = getDragAfterElement(containerEl, e.clientY);
      if (!afterEl) {
        containerEl.appendChild(draggedEl);
        return;
      }
      if (afterEl === draggedEl) return;
      containerEl.insertBefore(draggedEl, afterEl);
    });

    containerEl.addEventListener('drop', (e) => {
      if (!draggedEl) return;
      e.preventDefault();
      saveSettingsCardOrder(containerEl);
    });
  }

  function renderSettingsAuditLog() {
    const listEl = document.getElementById('auditLogList');
    const emptyEl = document.getElementById('auditLogEmptyState');
    const metaEl = document.getElementById('auditLogMeta');
    const searchInput = document.getElementById('auditLogSearch');
    const clearBtn = document.getElementById('auditLogClearSearchBtn');
    if (!listEl || !emptyEl) return;

    // Avoid nested vertical scrollbars: the Settings card body handles scrolling.
    try {
      listEl.style.maxHeight = '';
      listEl.style.overflowY = '';
    } catch {
      // ignore
    }

    function getQueryTokens() {
      const raw = searchInput ? String(searchInput.value || '') : '';
      return raw
        .trim()
        .toLowerCase()
        .split(/\s+/)
        .filter(Boolean);
    }

    function eventHaystack(ev) {
      const parts = [
        ev && ev.at ? String(ev.at) : '',
        ev && ev.module ? String(ev.module) : '',
        ev && ev.record ? String(ev.record) : '',
        ev && ev.user ? String(ev.user) : '',
        ev && ev.action ? String(ev.action) : '',
      ];

      const changes = Array.isArray(ev && ev.changes) ? ev.changes : [];
      for (const c of changes) {
        if (!c || typeof c !== 'object') continue;
        parts.push(String(c.field || ''));
        parts.push(String(c.from ?? ''));
        parts.push(String(c.to ?? ''));
      }

      return parts.join(' ').toLowerCase();
    }

    function matchesTokens(ev, tokens) {
      if (!tokens || tokens.length === 0) return true;
      const hay = eventHaystack(ev);
      for (const t of tokens) {
        if (!hay.includes(t)) return false;
      }
      return true;
    }

    // Bind search input once (re-renders Activity Log on change)
    if (searchInput && !searchInput.dataset.bound) {
      searchInput.dataset.bound = 'true';
      searchInput.addEventListener('input', () => {
        renderSettingsAuditLog();
      });
      searchInput.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
          searchInput.value = '';
          renderSettingsAuditLog();
        }
      });
    }
    if (clearBtn && searchInput && !clearBtn.dataset.bound) {
      clearBtn.dataset.bound = 'true';
      clearBtn.addEventListener('click', () => {
        searchInput.value = '';
        renderSettingsAuditLog();
      });
    }

    const activeYear = getActiveBudgetYear();
    const activeYearInt = Number.isInteger(Number(activeYear)) ? Number(activeYear) : null;
    const knownYears = typeof loadBudgetYears === 'function' ? loadBudgetYears() : [];
    const yearsToInclude = Array.from(
      new Set([
        ...(activeYearInt ? [activeYearInt] : []),
        ...(Array.isArray(knownYears) ? knownYears : []),
      ].map((v) => Number(v)).filter((v) => Number.isInteger(v)))
    ).sort((a, b) => b - a);

    if (yearsToInclude.length === 0) {
      emptyEl.hidden = false;
      listEl.innerHTML = '';
      if (metaEl) metaEl.textContent = 'No active year selected.';
      return;
    }

    /** @type {Array<{ms:number, at:string, module:string, record:string, user:string, action:string, changes:Array<{field:string,from:string,to:string}>}>} */
    const events = [];

    const loadOrdersForAudit = (year) => {
      if (typeof loadOrders === 'function') return loadOrders(year);
      try {
        const key = `payment_orders_${Number(year)}_v1`;
        const raw = localStorage.getItem(key);
        const parsed = raw ? JSON.parse(raw) : null;
        return Array.isArray(parsed) ? parsed : [];
      } catch {
        return [];
      }
    };

    const ensureOrderTimelineForAudit = (order) => {
      if (typeof ensureOrderTimeline === 'function') return ensureOrderTimeline(order);
      return [];
    };

    const persistOrderTimelineForAudit = (order, year) => {
      if (typeof upsertOrder === 'function') {
        upsertOrder(order, year);
      }
    };

    const loadIncomeForAudit = (year) => {
      if (typeof loadIncome === 'function') return loadIncome(year);
      try {
        const key = `payment_order_income_${Number(year)}_v1`;
        const raw = localStorage.getItem(key);
        const parsed = raw ? JSON.parse(raw) : null;
        return Array.isArray(parsed) ? parsed : [];
      } catch {
        return [];
      }
    };

    const ensureIncomeTimelineForAudit = (entry) => {
      if (typeof ensureIncomeTimeline === 'function') return ensureIncomeTimeline(entry);
      return [];
    };

    const persistIncomeTimelineForAudit = (entry, year) => {
      if (typeof upsertIncomeEntry === 'function') {
        upsertIncomeEntry(entry, year);
      }
    };

    for (const year of yearsToInclude) {
      const orders = loadOrdersForAudit(year);
      for (const order of orders || []) {
        if (!order || typeof order !== 'object') continue;
        let timeline = Array.isArray(order.timeline) ? order.timeline : [];
        if (timeline.length === 0) {
          timeline = ensureOrderTimelineForAudit(order);
          // Persist a seeded timeline once so the Activity Log is truly recorded.
          // (Avoid fabricating timestamps: only persist if the record already has createdAt.)
          if (order.createdAt) {
            persistOrderTimelineForAudit({ ...order, timeline }, year);
          }
        }
        const po = formatPaymentOrderNoForDisplay(order.paymentOrderNo);
        const name = String(order.name || '').trim();
        const record = `${po}${name ? ` — ${name}` : ''}`.trim() || 'Payment Order';

        for (let i = 0; i < timeline.length; i += 1) {
          const e = timeline[i];
          if (!e || typeof e !== 'object' || !e.at) continue;
          const ms = toTimeMs(e.at) ?? 0;
          const user = e.user !== undefined ? String(e.user || '—') : '—';
          const action = e.action !== undefined ? String(e.action || '—') : (i === 0 ? 'Created' : 'Edited');
          const isCreated = String(action).trim().toLowerCase() === 'created';
          let changes = Array.isArray(e.changes) ? e.changes : [];
          if (isCreated) changes = [];

          // If workflow auto-changed With/Status, preserve the actor's original action in the log.
          const withFinal = e.with !== undefined ? normalizeWith(e.with) : '—';
          const statusFinal = e.status !== undefined ? normalizeOrderStatus(e.status) : '—';
          const actorWith = e.actorWith !== undefined ? normalizeWith(e.actorWith) : '';
          const actorStatus = e.actorStatus !== undefined ? normalizeOrderStatus(e.actorStatus) : '';
          const actorDiffers = (actorWith && actorWith !== withFinal) || (actorStatus && actorStatus !== statusFinal);
          if (actorDiffers) {
            const actorRows = [];
            if (actorWith && actorWith !== withFinal) actorRows.push({ field: 'Actor With', from: '', to: actorWith });
            if (actorStatus && actorStatus !== statusFinal) actorRows.push({ field: 'Actor Status', from: '', to: actorStatus });
            changes = [...actorRows, ...changes];
          }

          events.push({ ms, at: String(e.at), module: `Payment Orders (${year})`, record, user, action, changes });
        }
      }

      const income = loadIncomeForAudit(year);
      for (const entry of income || []) {
        if (!entry || typeof entry !== 'object') continue;
        let timeline = Array.isArray(entry.timeline) ? entry.timeline : [];
        if (timeline.length === 0) {
          timeline = ensureIncomeTimelineForAudit(entry);
          // Persist a seeded timeline once so the Activity Log is truly recorded.
          // (Avoid fabricating timestamps: only persist if the record already has createdAt.)
          if (entry.createdAt) {
            persistIncomeTimelineForAudit({ ...entry, timeline }, year);
          }
        }
        const tx = formatDate(entry.date);
        const remitter = String(entry.remitter || '').trim();
        const record = `${tx}${remitter ? ` — ${remitter}` : ''}`.trim() || 'Income';

        for (let i = 0; i < timeline.length; i += 1) {
          const e = timeline[i];
          if (!e || typeof e !== 'object' || !e.at) continue;
          const ms = toTimeMs(e.at) ?? 0;
          const user = e.user !== undefined ? String(e.user || '—') : '—';
          const action = e.action !== undefined ? String(e.action || '—') : (i === 0 ? 'Created' : 'Edited');
          const isCreated = String(action).trim().toLowerCase() === 'created';
          let changes = Array.isArray(e.changes) ? e.changes : [];
          if (isCreated) changes = [];
          events.push({ ms, at: String(e.at), module: `Income (${year})`, record, user, action, changes });
        }
      }
    }

    // Auth events (Login/Logout) grouped into sessions.
    {
      const raw = loadAuthAuditEvents()
        .filter((e) => e && typeof e === 'object' && e.at)
        .map((e) => {
          const at = String(e.at);
          const ms = toTimeMs(at) ?? 0;
          const module = e.module ? String(e.module) : 'Auth';
          const record = e.record ? String(e.record) : 'Session';
          const user = e.user !== undefined ? normalizeUsername(e.user) || '—' : '—';
          const action = e.action !== undefined ? String(e.action || '—') : 'Event';
          return { ms, at, module, record, user, action };
        })
        .sort((a, b) => a.ms - b.ms);

      const openLoginByUser = new Map();

      const makeSessionEvent = (login, logout) => {
        const loginAt = login && login.at ? String(login.at) : '';
        const logoutAt = logout && logout.at ? String(logout.at) : '';
        const loginMs = login && Number.isFinite(login.ms) ? Number(login.ms) : null;
        const logoutMs = logout && Number.isFinite(logout.ms) ? Number(logout.ms) : null;

        const user = (login && login.user) ? String(login.user) : ((logout && logout.user) ? String(logout.user) : '—');

        const loginText = loginAt ? formatIsoDateTimeShort(loginAt) : '—';
        const logoutText = logoutAt ? formatIsoDateTimeShort(logoutAt) : '—';
        const durText = (loginMs != null && logoutMs != null)
          ? (formatDurationMs(Math.max(0, logoutMs - loginMs)) || '0m')
          : '—';

        const logoutActionLower = String(logout && logout.action ? logout.action : '').trim().toLowerCase();
        const isAuto = logoutActionLower === 'auto log out' || logoutActionLower === 'auto logout';

        const at = logoutAt || loginAt || new Date().toISOString();
        const ms = (logoutMs != null ? logoutMs : (loginMs != null ? loginMs : (toTimeMs(at) ?? 0)));

        const changeRows = [
          { field: 'Login', from: '', to: loginText },
          { field: 'Logout', from: '', to: logoutText },
        ];
        if (isAuto) changeRows.push({ field: 'Note', from: '', to: 'Auto log out' });
        changeRows.push({ field: 'Total time logged in', from: '', to: durText });

        return {
          ms,
          at,
          module: 'Auth',
          record: 'Session',
          user,
          action: 'Session',
          changes: changeRows,
        };
      };

      for (const e of raw) {
        const actionLower = String(e.action || '').trim().toLowerCase();
        if (actionLower === 'login') {
          openLoginByUser.set(String(e.user || '—'), e);
          continue;
        }
        if (actionLower === 'logout' || actionLower === 'auto log out' || actionLower === 'auto logout') {
          const open = openLoginByUser.get(String(e.user || '—'));
          if (open) {
            events.push(makeSessionEvent(open, e));
            openLoginByUser.delete(String(e.user || '—'));
          } else {
            // Logout without a matching login.
            events.push(makeSessionEvent(null, e));
          }
          continue;
        }

        // Any other auth event: keep as-is.
        events.push({
          ms: e.ms,
          at: e.at,
          module: String(e.module || 'Auth'),
          record: String(e.record || 'Session'),
          user: String(e.user || '—'),
          action: String(e.action || 'Event'),
          changes: [],
        });
      }

      // Unclosed sessions (login without logout).
      for (const open of openLoginByUser.values()) {
        events.push(makeSessionEvent(open, null));
      }
    }

    // Generic app audit events (Users, Backlog, Money Transfers, Wise, Budget, Settings, etc.)
    {
      const raw = loadAppAuditEvents();
      for (const e of Array.isArray(raw) ? raw : []) {
        if (!e || typeof e !== 'object' || !e.at) continue;
        const at = String(e.at);
        const ms = toTimeMs(at) ?? 0;
        const module = e.module ? String(e.module) : 'App';
        const record = e.record ? String(e.record) : 'Record';
        const user = e.user !== undefined ? String(e.user || '—') : '—';
        const action = e.action !== undefined ? String(e.action || '—') : 'Modified';
        const changes = Array.isArray(e.changes) ? e.changes : [];
        events.push({ ms, at, module, record, user, action, changes });
      }
    }

    events.sort((a, b) => b.ms - a.ms);
    const tokens = getQueryTokens();
    const filtered = tokens.length > 0 ? events.filter((ev) => matchesTokens(ev, tokens)) : events;

    if (metaEl) {
      const yearLabel = (yearsToInclude.length === 1)
        ? `Year: ${yearsToInclude[0]}`
        : `Years: ${yearsToInclude.slice(0, 3).join(', ')}${yearsToInclude.length > 3 ? ', …' : ''}`;
      metaEl.textContent = tokens.length > 0
        ? `${yearLabel} • ${filtered.length} shown of ${events.length} event(s)`
        : `${yearLabel} • ${events.length} event(s)`;
    }

    if (clearBtn) {
      const hasSearch = tokens.length > 0;
      clearBtn.hidden = !hasSearch;
      clearBtn.disabled = !hasSearch;
    }

    const hasAny = events.length > 0;
    const hasAnyFiltered = filtered.length > 0;
    emptyEl.hidden = hasAnyFiltered;
    if (!hasAny) {
      listEl.innerHTML = '';
      return;
    }

    if (!hasAnyFiltered) {
      emptyEl.textContent = tokens.length > 0
        ? 'No timeline events match your search.'
        : 'No timeline events found for the active year.';
      listEl.innerHTML = '';
      return;
    }

    // Reset empty state text in case a previous search changed it.
    emptyEl.textContent = 'No timeline events found for the active year.';

    listEl.innerHTML = filtered
      .map((e) => {
        const time = formatIsoDateTimeShort(e.at);
        const actionLower = String(e.action || '').trim().toLowerCase();
        const isCreated = actionLower === 'created';

        const changesHtml = isCreated
          ? ''
          : (e.changes && e.changes.length > 0
            ? `<div class="auditLog__changes">${e.changes
              .map((c) => {
                const field = escapeHtml(String(c.field || 'Field'));
                const from = escapeHtml(String(c.from ?? '—'));
                const to = escapeHtml(String(c.to ?? '—'));
                const showArrow = String(c.from ?? '').trim() !== '';
                return `
                  <div class="auditLog__change">
                    <div class="auditLog__field">${field}</div>
                    <div class="auditLog__values">${showArrow ? `<strong>${from}</strong> → <strong>${to}</strong>` : `<strong>${to}</strong>`}</div>
                  </div>
                `.trim();
              })
              .join('')}</div>`
            : `<div class="auditLog__changes"><div class="auditLog__noChanges">No field changes recorded.</div></div>`);

        return `
          <div class="auditLog__item">
            <div class="auditLog__header">
              <span><strong>${escapeHtml(time)}</strong></span>
              <span class="timelinegraph__eventSep">•</span>
              <span>Module: <strong>${escapeHtml(e.module)}</strong></span>
              <span class="timelinegraph__eventSep">•</span>
              <span>Record: <strong>${escapeHtml(e.record)}</strong></span>
              <span class="timelinegraph__eventSep">•</span>
              <span>User: <strong>${escapeHtml(e.user)}</strong></span>
              <span class="timelinegraph__eventSep">•</span>
              <span>Action: <strong>${escapeHtml(e.action)}</strong></span>
            </div>
            ${changesHtml}
          </div>
        `.trim();
      })
      .join('');

  }

  function initRolesSettingsPage() {
    if (!createUserForm || !usersTbody || !usersEmptyState) return;

    const currentUser = getCurrentUser();
    const hasAnyUsers = loadUsers().length > 0 || Boolean(currentUser);
    const hasExplicitSettingsAccess = (permKey, minLevel = 'read') => {
      if (!hasAnyUsers) return true;
      if (!currentUser || !permKey) return false;
      if (isAdminLikeUser(currentUser)) return true;
      const rawPerms = currentUser && currentUser.permissions && typeof currentUser.permissions === 'object'
        ? currentUser.permissions
        : {};
      if (Object.prototype.hasOwnProperty.call(rawPerms, permKey)) {
        // Explicit key wins (including explicit "none").
        return hasModuleAccessLevel({ permissions: { [permKey]: rawPerms[permKey] } }, permKey, minLevel);
      }
      // Legacy fallback: if a settings child key is missing, defer to inherited permission.
      return hasModuleAccessLevel(currentUser, permKey, minLevel);
    };

    const hasStrictExplicitSettingsAccess = (permKey, minLevel = 'read') => {
      if (!hasAnyUsers) return true;
      if (!currentUser || !permKey) return false;
      if (isAdminLikeUser(currentUser)) return true;
      const rawPerms = currentUser && currentUser.permissions && typeof currentUser.permissions === 'object'
        ? currentUser.permissions
        : {};
      const hasSettingsChildren = hasAnyGranularChildPermissions(rawPerms)
        && PERMISSION_DEFS.some((def) => def && def.parent === 'settings' && hasOwnPermissionKey(rawPerms, def.key));
      if (hasOwnPermissionKey(rawPerms, permKey)) {
        return hasModuleAccessLevel({ permissions: { [permKey]: rawPerms[permKey] } }, permKey, minLevel);
      }
      if (hasSettingsChildren && isChildPermissionKey(permKey)) {
        // Full access at Settings parent should still grant all Settings child cards.
        const settingsParentLevel = hasOwnPermissionKey(rawPerms, 'settings') ? rawPerms.settings : null;
        if (settingsParentLevel != null) {
          const settingsAllows = hasModuleAccessLevel({ permissions: { settings: settingsParentLevel } }, 'settings', minLevel);
          if (settingsAllows) return true;
        }
        return false;
      }
      return hasModuleAccessLevel(currentUser, permKey, minLevel);
    };

    const canEditRoles = hasStrictExplicitSettingsAccess('settings_roles', 'write');
    const canEditBacklog = hasExplicitSettingsAccess('settings_backlog', 'write') || hasExplicitSettingsAccess('settings_backlog', 'create');
    const canViewAudit = hasExplicitSettingsAccess('settings_audit', 'read');
    const canViewRolesCard = hasStrictExplicitSettingsAccess('settings_roles', 'read');

    const settingsCardPermMap = {
      roles: 'settings_roles',
      backlog: 'settings_backlog',
      numbering: 'settings_numbering',
      grandlodge: 'settings_grandlodge',
      notifications: 'settings_email_notifications',
      backup: 'settings_backup',
      audit: 'settings_audit',
    };

    for (const [cardKey, permKey] of Object.entries(settingsCardPermMap)) {
      const cardEl = document.querySelector(`section.card[data-settings-card="${cardKey}"]`);
      if (!cardEl) continue;
      if (!hasAnyUsers) {
        cardEl.hidden = false;
        continue;
      }
      if (cardKey === 'roles') {
        cardEl.hidden = !canViewRolesCard;
        continue;
      }
      cardEl.hidden = !hasExplicitSettingsAccess(permKey, 'read');
    }

    const createUserModal = document.getElementById('createUserModal');
    const openCreateUserBtn = document.getElementById('openCreateUserBtn');
    const usersSearchInput = document.getElementById('usersSearch');
    const usersClearSearchBtn = document.getElementById('usersClearSearchBtn');
    const createUserModalTitle = document.getElementById('createUserModalTitle');
    const createUserSubmitBtn = document.querySelector('button[type="submit"][form="createUserForm"]');

    let hideUsersRoleTooltip = () => {};
    let hideCreateUserTooltip = () => {};

    const renderUsersTableSafe = () => {
      hideUsersRoleTooltip();
      hideCreateUserTooltip();
      renderUsersTable();
    };

    // Settings page: allow each user to reorder cards (persisted via cookie).
    initSettingsCardsDragAndDrop();
    installSettingsCardGearButtons();

    // Settings page: keep card headers fixed; only body content scrolls.
    prepareSettingsCardsStickyHeaders();

    renderUsersTableSafe();
    initUsersRoleHoverTooltips();

    // Settings page: allow manually resizing User Roles table columns.
    initUsersTableColumnResizer();

    // Backlog (CRUD + comments)
    initBacklogSettingsSection(canEditBacklog);

    // Timeline audit log (Payment Orders + Income)
    if (canViewAudit) renderSettingsAuditLog();

    // Keep Settings compact via CSS max-height + per-row equal heights.
    // Do not force a single global height across all cards.

    // Keep Audit Log in sync across tabs/windows.
    const auditListEl = document.getElementById('auditLogList');
    if (auditListEl && !auditListEl.dataset.storageBound) {
      auditListEl.dataset.storageBound = '1';
      window.addEventListener('storage', (e) => {
        const key = e && typeof e.key === 'string' ? e.key : '';
        if (!key) return;
        if (key === AUTH_AUDIT_KEY || key.startsWith('payment_orders_') || key.startsWith('payment_order_income_')) {
          if (canViewAudit) renderSettingsAuditLog();
        }
        if (key === BACKLOG_KEY) {
          renderBacklogList(canEditBacklog);
        }
      });
    }

    function resetCreateUserForm() {
      const errUser = document.getElementById('error-newUsername');
      const errEmail = document.getElementById('error-newEmail');
      const errPass = document.getElementById('error-newPassword');
      const errPos = document.getElementById('error-newPosition');
      if (errUser) errUser.textContent = '';
      if (errEmail) errEmail.textContent = '';
      if (errPass) errPass.textContent = '';
      if (errPos) errPos.textContent = '';

      const newUsername = document.getElementById('newUsername');
      const newEmail = document.getElementById('newEmail');
      const newPassword = document.getElementById('newPassword');
      const newPosition = document.getElementById('newPosition');
      if (newUsername) newUsername.value = '';
      if (newEmail) newEmail.value = '';
      if (newPassword) newPassword.value = '';
      if (newPosition) newPosition.value = '';

      [
        ...PERMISSION_FORM_ROWS.flatMap((row) => [
          `perm${row.idBase}Write`,
          `perm${row.idBase}Delete`,
          `perm${row.idBase}Create`,
          `perm${row.idBase}Partial`,
          `perm${row.idBase}Read`,
        ]),
        'permAllWrite', 'permAllDelete', 'permAllCreate', 'permAllPartial', 'permAllRead',
      ].forEach((id) => {
        const el = document.getElementById(id);
        if (el) el.checked = false;
      });

      createUserForm.removeAttribute('data-mode');
      createUserForm.removeAttribute('data-edit-username');
      if (createUserModalTitle) createUserModalTitle.textContent = 'Add User';
      if (createUserSubmitBtn) createUserSubmitBtn.textContent = 'Add User';

      if (newUsername) {
        newUsername.readOnly = false;
        newUsername.removeAttribute('aria-readonly');
      }
    }

    function openCreateUserModalForUser(usernameRaw) {
      const username = normalizeUsername(usernameRaw);
      const user = getUserByUsername(username);
      if (!user || !createUserModal) {
        window.alert('Could not open the role editor for this user.');
        return;
      }

      resetCreateUserForm();

      const newUsername = document.getElementById('newUsername');
      const newEmail = document.getElementById('newEmail');
      const newPassword = document.getElementById('newPassword');
      const newPosition = document.getElementById('newPosition');

      const pw = String(user && typeof user.passwordPlain === 'string' ? user.passwordPlain : '')
        || extractLegacyPasswordPlain(user && user.passwordHash, user && user.salt);

      if (newUsername) {
        newUsername.value = username;
        newUsername.readOnly = true;
        newUsername.setAttribute('aria-readonly', 'true');
      }
      if (newEmail) newEmail.value = normalizeEmail(user && user.email);
      if (newPassword) newPassword.value = pw;
      if (newPosition) newPosition.value = String(user && user.position ? user.position : '');

      const perms = getEffectivePermissions(user);
      for (const row of PERMISSION_FORM_ROWS) {
        setModuleAccess(row.idBase, perms[row.key] || 'none');
      }

      createUserForm.dataset.mode = 'edit';
      createUserForm.dataset.editUsername = username;
      if (createUserModalTitle) createUserModalTitle.textContent = `Edit User Roles: ${username}`;
      if (createUserSubmitBtn) createUserSubmitBtn.textContent = 'Save Roles';

      openSimpleModal(createUserModal, '#newPassword');
    }

    function prepareSettingsCardsStickyHeaders() {
      const mainEl = document.querySelector('main.archive__grid');
      if (!mainEl) return;
      if (mainEl.dataset.settingsStickyPrepared) return;
      mainEl.dataset.settingsStickyPrepared = '1';

      const cards = Array.from(mainEl.querySelectorAll('section.card'));
      for (const card of cards) {
        if (card.querySelector(':scope > .settingsCardBody')) continue;

        let header = card.querySelector(':scope > .list-header');

        // Some settings cards (e.g., Payment Order Numbering) do not use .list-header;
        // treat their direct h2 (+ optional subhead) as the fixed header.
        if (!header) {
          const h2 = card.querySelector(':scope > h2');
          if (h2) {
            const subhead = h2.nextElementSibling && h2.nextElementSibling.classList && h2.nextElementSibling.classList.contains('subhead')
              ? h2.nextElementSibling
              : null;

            const wrap = document.createElement('div');
            wrap.className = 'settingsCardHeader';
            card.insertBefore(wrap, h2);
            wrap.appendChild(h2);
            if (subhead) wrap.appendChild(subhead);
            header = wrap;
          }
        }

        if (!header) continue;

        const body = document.createElement('div');
        body.className = 'settingsCardBody';

        // Move all nodes after header into the scrollable body wrapper.
        let node = header.nextSibling;
        while (node) {
          const next = node.nextSibling;
          body.appendChild(node);
          node = next;
        }

        card.appendChild(body);
      }
    }

    function installSettingsUniformCardHeightFromBacklog() {
      const mainEl = document.querySelector('main.archive__grid');
      if (!mainEl) return;
      if (mainEl.dataset.uniformHeightBound) return;

      const backlogCardEl = mainEl.querySelector('section.card[data-settings-card="backlog"]');
      if (!backlogCardEl) return;

      mainEl.dataset.uniformHeightBound = '1';

      const isMobile = () => {
        try {
          return window.matchMedia && window.matchMedia('(max-width: 720px)').matches;
        } catch {
          return false;
        }
      };

      const apply = () => {
        if (isMobile()) {
          mainEl.classList.remove('settingsUniformHeight');
          mainEl.style.removeProperty('--settings-card-height');
          return;
        }

        const rect = backlogCardEl.getBoundingClientRect();
        let h = Math.round(rect && typeof rect.height === 'number' ? rect.height : 0);
        if (!Number.isFinite(h) || h < 240) return;

        // Avoid absurd heights if the page is resized oddly.
        const cap = Math.round(window.innerHeight * 0.9);
        if (Number.isFinite(cap) && cap > 0) h = Math.min(h, cap);

        mainEl.style.setProperty('--settings-card-height', `${h}px`);
        mainEl.classList.add('settingsUniformHeight');
      };

      // Measure after layout settles (Backlog + Audit render).
      const schedule = () => {
        requestAnimationFrame(() => requestAnimationFrame(apply));
      };
      schedule();
      window.setTimeout(apply, 180);

      // Keep in sync if the window size changes.
      let t = 0;
      window.addEventListener('resize', () => {
        if (t) window.clearTimeout(t);
        t = window.setTimeout(() => {
          t = 0;
          apply();
        }, 120);
      });
    }

    function initUsersTableColumnResizer() {
      const tableEl = document.getElementById('usersTable');
      if (!tableEl) return;
      if (tableEl.dataset.colResizeBound) return;
      tableEl.dataset.colResizeBound = '1';

      const STORAGE_KEY = 'acgl_usersTable_colWidths_v2';
      const LEGACY_STORAGE_KEY = 'acgl_usersTable_colWidths_v1';

      const isNarrow = () => {
        try {
          return window.matchMedia && window.matchMedia('(max-width: 900px)').matches;
        } catch {
          return false;
        }
      };

      const clamp = (n, min, max) => Math.max(min, Math.min(max, n));

      const readWidths = () => {
        try {
          const raw = window.localStorage.getItem(STORAGE_KEY);
          if (!raw) return null;
          const arr = JSON.parse(raw);
          if (!Array.isArray(arr)) return null;
          const widths = arr.map((v) => Math.round(parseFloat(v))).filter((n) => Number.isFinite(n) && n > 0);
          return widths.length ? widths : null;
        } catch {
          return null;
        }
      };

      const writeWidths = (widths) => {
        try {
          window.localStorage.setItem(STORAGE_KEY, JSON.stringify(widths.map((n) => Math.round(n))));
        } catch {
          // ignore
        }
      };

      const clearWidths = () => {
        try {
          window.localStorage.removeItem(STORAGE_KEY);
          window.localStorage.removeItem(LEGACY_STORAGE_KEY);
        } catch {
          // ignore
        }
      };

      // Drop legacy fixed-width snapshots so the table can reflow from content.
      try {
        window.localStorage.removeItem(LEGACY_STORAGE_KEY);
      } catch {
        // ignore
      }

      const headerRow = tableEl.tHead && tableEl.tHead.rows && tableEl.tHead.rows[0] ? tableEl.tHead.rows[0] : null;
      if (!headerRow) return;
      const ths = Array.from(headerRow.cells || []);
      if (ths.length < 2) return;
      const wrapEl = tableEl.closest ? tableEl.closest('.table-wrap') : null;

      const minWidths = ths.map((th, idx) => {
        // Username column
        if (idx === 0) return 180;
        // Actions column
        if (idx === ths.length - 1) return 140;
        // Settings column is a bit wider
        if (idx === 5) return 120;
        // Permission columns
        return 72;
      });

      const ensureColGroup = () => {
        let cg = tableEl.querySelector(':scope > colgroup');
        if (!cg) {
          cg = document.createElement('colgroup');
          tableEl.insertBefore(cg, tableEl.firstChild);
        }
        while (cg.children.length < ths.length) cg.appendChild(document.createElement('col'));
        while (cg.children.length > ths.length) cg.removeChild(cg.lastChild);
        return cg;
      };

      const measureWidths = () => ths.map((th) => Math.max(1, Math.round(th.getBoundingClientRect().width || 0)));

      let widths = null;
      let colGroupEl = null;

      const fitWidthsToContainer = (nextWidths) => {
        const base = (nextWidths || []).slice(0, ths.length).map((w, i) => Math.max(minWidths[i] || 40, Math.round(w || 0)));
        while (base.length < ths.length) base.push(80);

        const available = Math.max(0, Math.floor((wrapEl && wrapEl.clientWidth) || tableEl.clientWidth || 0) - 2);
        if (!available) return base;

        const total = base.reduce((sum, n) => sum + n, 0);
        if (total <= available) return base;

        const minSum = minWidths.reduce((sum, n) => sum + (n || 40), 0);
        if (minSum >= available) {
          const scale = available / Math.max(1, minSum);
          return minWidths.map((n) => Math.max(40, Math.floor((n || 40) * scale)));
        }

        const extras = base.map((w, i) => Math.max(0, w - (minWidths[i] || 40)));
        const extraTotal = extras.reduce((sum, n) => sum + n, 0);
        if (extraTotal <= 0) return minWidths.slice(0, ths.length).map((n) => n || 40);

        const targetExtra = available - minSum;
        const scale = targetExtra / extraTotal;
        return base.map((w, i) => Math.max(minWidths[i] || 40, Math.floor((minWidths[i] || 40) + extras[i] * scale)));
      };

      const applyWidths = (nextWidths, { persist } = { persist: false }) => {
        if (isNarrow()) return;
        widths = fitWidthsToContainer(nextWidths);

        tableEl.classList.add('is-colResizable');
        colGroupEl = ensureColGroup();

        const cols = Array.from(colGroupEl.children);
        for (let i = 0; i < cols.length; i += 1) {
          const w = Math.round(widths[i]);
          cols[i].style.width = `${Math.max(minWidths[i] || 40, w)}px`;
        }

        if (persist) writeWidths(widths);
      };

      const reset = () => {
        clearWidths();
        widths = null;
        tableEl.classList.remove('is-colResizable');
        const cg = tableEl.querySelector(':scope > colgroup');
        if (cg) cg.remove();
      };

      const stored = readWidths();
      if (stored && stored.length === ths.length && !isNarrow()) {
        applyWidths(stored, { persist: false });
      } else if (stored && stored.length !== ths.length) {
        clearWidths();
      }

      let dragging = false;
      let dragIndex = -1;
      let startX = 0;
      let startLeftW = 0;
      let startRightW = 0;

      const onMove = (e) => {
        if (!dragging) return;
        const x = e && typeof e.clientX === 'number' ? e.clientX : 0;
        const delta = x - startX;

        const next = widths ? widths.slice() : measureWidths();

        const minL = minWidths[dragIndex] || 40;
        const minR = minWidths[dragIndex + 1] || 40;

        const sum = startLeftW + startRightW;
        let newLeft = clamp(startLeftW + delta, minL, sum - minR);
        let newRight = sum - newLeft;

        // Safety clamp.
        if (newRight < minR) {
          newRight = minR;
          newLeft = sum - newRight;
        }

        next[dragIndex] = Math.round(newLeft);
        next[dragIndex + 1] = Math.round(newRight);

        applyWidths(next, { persist: false });
        e.preventDefault();
      };

      const onUp = () => {
        if (!dragging) return;
        dragging = false;
        document.body.classList.remove('isTableResizing');
        window.removeEventListener('pointermove', onMove);
        window.removeEventListener('pointerup', onUp);
        if (widths) writeWidths(widths);
      };

      // Attach handles to each header cell except the last.
      for (let i = 0; i < ths.length - 1; i += 1) {
        const th = ths[i];
        if (!th || th.querySelector(':scope > .tableColResizer')) continue;
        th.style.position = 'sticky';

        const handle = document.createElement('div');
        handle.className = 'tableColResizer';
        handle.setAttribute('aria-hidden', 'true');
        handle.title = 'Drag to resize column (double-click to reset)';

        handle.addEventListener('pointerdown', (e) => {
          if (isNarrow()) return;
          dragging = true;
          dragIndex = i;
          startX = e && typeof e.clientX === 'number' ? e.clientX : 0;

          const base = widths ? widths.slice() : measureWidths();
          widths = base;

          // Make sure resize mode is active and widths are applied.
          applyWidths(base, { persist: false });

          startLeftW = widths[i] || Math.round(ths[i].getBoundingClientRect().width || 80);
          startRightW = widths[i + 1] || Math.round(ths[i + 1].getBoundingClientRect().width || 80);

          document.body.classList.add('isTableResizing');
          try {
            handle.setPointerCapture(e.pointerId);
          } catch {
            // ignore
          }
          window.addEventListener('pointermove', onMove);
          window.addEventListener('pointerup', onUp);
          e.preventDefault();
          e.stopPropagation();
        });

        handle.addEventListener('dblclick', (e) => {
          reset();
          e.preventDefault();
          e.stopPropagation();
        });

        th.appendChild(handle);
      }

      // If the viewport becomes narrow, revert to normal table layout.
      let rt = 0;
      window.addEventListener('resize', () => {
        if (rt) window.clearTimeout(rt);
        rt = window.setTimeout(() => {
          rt = 0;
          if (isNarrow()) reset();
        }, 150);
      });
    }

    function initUsersRoleHoverTooltips() {
      if (!usersTbody || usersTbody.dataset.userRoleTooltipBound) return;
      usersTbody.dataset.userRoleTooltipBound = '1';

      const bindHoverScope = (typeof bindUnifiedHoverTooltipScope === 'function')
        ? bindUnifiedHoverTooltipScope
        : () => {};

      bindHoverScope(usersTbody);
      const tableEl = document.getElementById('usersTable');
      const wrapEl = tableEl && tableEl.closest ? tableEl.closest('.table-wrap') : null;
      bindHoverScope(wrapEl);
      hideUsersRoleTooltip = (typeof window.__acglHideUnifiedHoverTooltip === 'function')
        ? window.__acglHideUnifiedHoverTooltip
        : () => {};
    }

    function initCreateUserModalTooltips(modalEl) {
      if (!modalEl || modalEl.dataset.rolesTooltipBound) return;
      modalEl.dataset.rolesTooltipBound = '1';

      const bindHoverScope = (typeof bindUnifiedHoverTooltipScope === 'function')
        ? bindUnifiedHoverTooltipScope
        : () => {};

      bindHoverScope(modalEl);
      const bodyEl = modalEl.querySelector ? modalEl.querySelector('.modal__body') : null;
      bindHoverScope(bodyEl);
      hideCreateUserTooltip = (typeof window.__acglHideUnifiedHoverTooltip === 'function')
        ? window.__acglHideUnifiedHoverTooltip
        : () => {};
    }

    function closeCreateUserModal() {
      resetCreateUserForm();
      hideCreateUserTooltip();
      closeSimpleModal(createUserModal);
    }

    if (createUserModal && !createUserModal.dataset.bound) {
      createUserModal.dataset.bound = '1';
      initCreateUserModalTooltips(createUserModal);
      createUserModal.addEventListener('click', (e) => {
        const closeBtn = e.target && e.target.closest ? e.target.closest('[data-modal-close]') : null;
        if (!closeBtn) return;
        closeCreateUserModal();
      });
    }

    if (openCreateUserBtn) {
      openCreateUserBtn.disabled = hasAnyUsers && !canEditRoles;
      if (openCreateUserBtn.disabled) {
        openCreateUserBtn.setAttribute('data-tooltip', 'View-only: your account cannot add users.');
      } else {
        openCreateUserBtn.removeAttribute('data-tooltip');
      }

      if (!openCreateUserBtn.dataset.bound) {
        openCreateUserBtn.dataset.bound = '1';
        openCreateUserBtn.addEventListener('click', () => {
          if (hasAnyUsers && !canEditRoles) {
            window.alert('This User Roles section is view only for your account.');
            return;
          }
          resetCreateUserForm();
          createUserForm.dataset.mode = 'create';
          openSimpleModal(createUserModal, '#newUsername');
        });
      }
    }

    if (usersSearchInput && !usersSearchInput.dataset.bound) {
      usersSearchInput.dataset.bound = '1';
      usersSearchInput.value = usersTableViewState.globalFilter || '';
      if (usersClearSearchBtn) usersClearSearchBtn.hidden = !usersSearchInput.value;
      usersSearchInput.addEventListener('input', () => {
        usersTableViewState.globalFilter = usersSearchInput.value;
        if (usersClearSearchBtn) usersClearSearchBtn.hidden = !usersSearchInput.value;
        renderUsersTableSafe();
      });
    }

    if (usersClearSearchBtn && usersSearchInput && !usersClearSearchBtn.dataset.bound) {
      usersClearSearchBtn.dataset.bound = '1';
      usersClearSearchBtn.addEventListener('click', () => {
        usersSearchInput.value = '';
        usersTableViewState.globalFilter = '';
        usersClearSearchBtn.hidden = true;
        renderUsersTableSafe();
        if (usersSearchInput.focus) usersSearchInput.focus();
      });
    }

    function bindExclusiveCheckboxGroup(...els) {
      const inputs = els.filter(Boolean);
      if (inputs.length < 2) return;
      for (const el of inputs) {
        el.addEventListener('change', () => {
          if (!el.checked) return;
          inputs.forEach((other) => {
            if (other !== el) other.checked = false;
          });
        });
      }
    }

    function setModuleAccess(moduleKey, level) {
      const lv = String(level || 'none');
      const w = document.getElementById(`perm${moduleKey}Write`);
      const d = document.getElementById(`perm${moduleKey}Delete`);
      const c = document.getElementById(`perm${moduleKey}Create`);
      const p = document.getElementById(`perm${moduleKey}Partial`);
      const r = document.getElementById(`perm${moduleKey}Read`);
      if (w) w.checked = lv === 'full';
      if (d) d.checked = lv === 'delete';
      if (c) c.checked = lv === 'create';
      if (p) p.checked = lv === 'write';
      if (r) r.checked = lv === 'read';
    }

    const roleInputIds = PERMISSION_FORM_ROWS.flatMap((row) => [
      `perm${row.idBase}Write`,
      `perm${row.idBase}Delete`,
      `perm${row.idBase}Create`,
      `perm${row.idBase}Partial`,
      `perm${row.idBase}Read`,
    ]);

    // Bind mutual exclusivity for each module checkbox group in the create-user form.
    for (const row of PERMISSION_FORM_ROWS) {
      bindExclusiveCheckboxGroup(
        document.getElementById(`perm${row.idBase}Write`),
        document.getElementById(`perm${row.idBase}Delete`),
        document.getElementById(`perm${row.idBase}Create`),
        document.getElementById(`perm${row.idBase}Partial`),
        document.getElementById(`perm${row.idBase}Read`)
      );
    }

    const allWrite = document.getElementById('permAllWrite');
    const allDelete = document.getElementById('permAllDelete');
    const allCreate = document.getElementById('permAllCreate');
    const allPartial = document.getElementById('permAllPartial');
    const allRead = document.getElementById('permAllRead');

    function applyRoleAccessPreset(roleName) {
      const preset = getRoleAccessPreset(roleName);
      if (!preset) return false;

      if (allWrite) allWrite.checked = false;
      if (allDelete) allDelete.checked = false;
      if (allCreate) allCreate.checked = false;
      if (allPartial) allPartial.checked = false;
      if (allRead) allRead.checked = false;

      for (const row of PERMISSION_FORM_ROWS) {
        const hasExplicit = Object.prototype.hasOwnProperty.call(preset, row.idBase);
        const level = hasExplicit
          ? preset[row.idBase]
          : ((row.key && row.key.startsWith('settings_') && Object.prototype.hasOwnProperty.call(preset, 'Settings'))
            ? preset.Settings
            : 'none');
        setModuleAccess(row.idBase, level || 'none');
      }
      return true;
    }

    if (allWrite && allRead && !allWrite.dataset.bound) {
      allWrite.dataset.bound = 'true';
      allWrite.disabled = hasAnyUsers && !canEditRoles;
      if (allDelete) allDelete.disabled = hasAnyUsers && !canEditRoles;
      if (allCreate) allCreate.disabled = hasAnyUsers && !canEditRoles;
      if (allPartial) allPartial.disabled = hasAnyUsers && !canEditRoles;
      allRead.disabled = hasAnyUsers && !canEditRoles;

      bindExclusiveCheckboxGroup(allWrite, allDelete, allCreate, allPartial, allRead);

      allWrite.addEventListener('change', () => {
        if (allWrite.checked) {
          PERMISSION_FORM_ROWS.forEach((row) => setModuleAccess(row.idBase, 'full'));
        } else {
          PERMISSION_FORM_ROWS.forEach((row) => setModuleAccess(row.idBase, 'none'));
        }
      });
      allRead.addEventListener('change', () => {
        if (allRead.checked) {
          PERMISSION_FORM_ROWS.forEach((row) => setModuleAccess(row.idBase, 'read'));
        } else {
          PERMISSION_FORM_ROWS.forEach((row) => setModuleAccess(row.idBase, 'none'));
        }
      });

      if (allDelete) {
        allDelete.addEventListener('change', () => {
          if (allDelete.checked) {
            PERMISSION_FORM_ROWS.forEach((row) => setModuleAccess(row.idBase, 'delete'));
          } else {
            PERMISSION_FORM_ROWS.forEach((row) => setModuleAccess(row.idBase, 'none'));
          }
        });
      }

      if (allCreate) {
        allCreate.addEventListener('change', () => {
          if (allCreate.checked) {
            PERMISSION_FORM_ROWS.forEach((row) => setModuleAccess(row.idBase, 'create'));
          } else {
            PERMISSION_FORM_ROWS.forEach((row) => setModuleAccess(row.idBase, 'none'));
          }
        });
      }

      if (allPartial) {
        allPartial.addEventListener('change', () => {
          if (allPartial.checked) {
            PERMISSION_FORM_ROWS.forEach((row) => setModuleAccess(row.idBase, 'write'));
          } else {
            PERMISSION_FORM_ROWS.forEach((row) => setModuleAccess(row.idBase, 'none'));
          }
        });
      }
    }

    const newPositionSelect = document.getElementById('newPosition');
    if (newPositionSelect && !newPositionSelect.dataset.autoAdminBound) {
      newPositionSelect.dataset.autoAdminBound = '1';
      newPositionSelect.addEventListener('change', () => {
        if (allWrite && allWrite.disabled) return;
        const role = String(newPositionSelect.value || '').trim();
        applyRoleAccessPreset(role);
      });
    }

    if (logoutBtn && !logoutBtn.dataset.bound) {
      logoutBtn.dataset.bound = 'true';
      logoutBtn.addEventListener('click', async () => {
        await performLogout();
        window.location.reload();
      });
    }

    createUserForm.addEventListener('submit', async (e) => {
      e.preventDefault();

      if (loadUsers().length > 0 && !canEditRoles) {
        window.alert('This User Roles section is view only for your account.');
        return;
      }

      const newUsername = document.getElementById('newUsername');
      const newEmail = document.getElementById('newEmail');
      const newPassword = document.getElementById('newPassword');
      const newPosition = document.getElementById('newPosition');
      const errUser = document.getElementById('error-newUsername');
      const errEmail = document.getElementById('error-newEmail');
      const errPass = document.getElementById('error-newPassword');
      const errPos = document.getElementById('error-newPosition');
      if (errUser) errUser.textContent = '';
      if (errEmail) errEmail.textContent = '';
      if (errPass) errPass.textContent = '';
      if (errPos) errPos.textContent = '';

      const username = newUsername ? newUsername.value : '';
      const email = newEmail ? newEmail.value : '';
      const password = newPassword ? newPassword.value : '';
      const position = newPosition ? newPosition.value : '';
      const modalMode = String(createUserForm.dataset.mode || 'create');
      const editTargetUsername = normalizeUsername(createUserForm.dataset.editUsername || '');

      const perms = {};
      for (const row of PERMISSION_FORM_ROWS) {
        const writeBox = document.getElementById(`perm${row.idBase}Write`);
        const deleteBox = document.getElementById(`perm${row.idBase}Delete`);
        const createBox = document.getElementById(`perm${row.idBase}Create`);
        const partialBox = document.getElementById(`perm${row.idBase}Partial`);
        const readBox = document.getElementById(`perm${row.idBase}Read`);
        perms[row.key] = writeBox && writeBox.checked
          ? 'full'
          : deleteBox && deleteBox.checked
            ? 'delete'
            : createBox && createBox.checked
              ? 'create'
              : partialBox && partialBox.checked
                ? 'write'
                : readBox && readBox.checked
                  ? 'read'
                  : 'none';
      }

      const hadNoUsers = loadUsers().length === 0;

      if (modalMode === 'edit') {
        if (!editTargetUsername) {
          window.alert('Could not determine which user to update.');
          return;
        }

        const currentUserRecord = getUserByUsername(editTargetUsername);
        if (!currentUserRecord) {
          window.alert('Could not find that user anymore.');
          return;
        }

        const existingPerms = getEffectivePermissions(currentUserRecord);
        const mergedPerms = { ...existingPerms, ...perms };
        const nextPassword = String(password || '').trim();
        const res = await updateUser(editTargetUsername, mergedPerms, nextPassword, email, position);

        if (!res.ok && res.reason === 'email' && errEmail) {
          errEmail.textContent = 'Enter a valid email address.';
          return;
        }
        if (!res.ok && res.reason === 'lastSettings') {
          window.alert('At least one user must keep Settings access.');
          return;
        }
        if (!res.ok && res.reason === 'wp_save_failed') {
          window.alert('Could not save users to WordPress shared storage. Changes may not be visible to other users until a Settings-authorized account saves successfully.');
          return;
        }
        if (!res.ok) {
          window.alert('Could not save user role changes.');
          return;
        }

        usersTableViewState.editingUsername = null;
        renderUsersTableSafe();
        closeCreateUserModal();

        const current = normalizeUsername(getCurrentUsername());
        if (current && current === normalizeUsername(editTargetUsername)) {
          window.location.reload();
        }
        return;
      }

      const res = await createUser(username, password, perms, email, position);
      if (!res.ok) {
        if (res.reason === 'username' && errUser) errUser.textContent = 'Username is required.';
        else if (res.reason === 'email' && errEmail) errEmail.textContent = 'Enter a valid email address.';
        else if (res.reason === 'password' && errPass) errPass.textContent = 'Password is required.';
        else if (res.reason === 'duplicate' && errUser) errUser.textContent = 'Username already exists.';
        else if (res.reason === 'wp_save_failed') {
          window.alert('Could not save users to WordPress shared storage. The new user will not be able to log in until a Settings-authorized account saves successfully.');
        }
        return;
      }

      if (newEmail) newEmail.value = '';
      if (newPassword) newPassword.value = '';
      if (newPosition) newPosition.value = '';
      [
        ...roleInputIds,
        'permAllWrite', 'permAllDelete', 'permAllCreate', 'permAllPartial', 'permAllRead',
      ].forEach((id) => {
        const el = document.getElementById(id);
        if (el) el.checked = false;
      });

      renderUsersTableSafe();

      closeCreateUserModal();

      // Auto-login the first created user to start using the app.
      if (hadNoUsers) {
        setCurrentUsername(normalizeUsername(username));
        window.location.href = firstAllowedHrefForUser(res.user, getActiveBudgetYear());
      }
    });

    usersTbody.addEventListener('click', async (e) => {
      const btn = e.target && e.target.closest ? e.target.closest('button[data-action]') : null;
      if (!btn) return;

      if (!canEditRoles) {
        window.alert('This User Roles section is view only for your account.');
        return;
      }
      const row = btn.closest('tr[data-username]');
      if (!row) return;

      const username = row.getAttribute('data-username');
      const action = btn.getAttribute('data-action');

      if (action === 'edit') {
        if (!username) return;
        usersTableViewState.editingUsername = normalizeUsername(username);
        renderUsersTableSafe();
        return;
      }

      if (action === 'cancel') {
        usersTableViewState.editingUsername = null;
        renderUsersTableSafe();
        return;
      }

      if (action === 'delete') {
        const ok = window.confirm(`Delete user "${username}"?`);
        if (!ok) return;
        const before = loadUsers();
        const res = deleteUser(username);
        if (!res.ok && res.reason === 'protected') {
          window.alert('This user is protected and cannot be deleted.');
          return;
        }
        if (!res.ok && res.reason === 'lastSettings') {
          window.alert('At least one user must keep Settings access.');
          return;
        }
        if (!res.ok) {
          window.alert('Could not delete user.');
          return;
        }

        const wpRes = await persistUsersToWpNow();
        if (wpRes && wpRes.ok === false) {
          saveUsers(before);
          window.alert('Could not save the deletion to WordPress shared storage. The user was restored.');
          renderUsersTableSafe();
          return;
        }
        if (usersTableViewState.editingUsername && normalizeUsername(username) === usersTableViewState.editingUsername) {
          usersTableViewState.editingUsername = null;
        }
        renderUsersTableSafe();
        return;
      }

      if (action === 'edit-roles') {
        if (!username) return;
        openCreateUserModalForUser(username);
        return;
      }

      if (action === 'save') {
        if (!username) return;
        if (usersTableViewState.editingUsername !== normalizeUsername(username)) return;

        const currentUserRecord = getUserByUsername(username);
        const existingPerms = getEffectivePermissions(currentUserRecord);
        const inputs = Array.from(row.querySelectorAll('input[type="checkbox"][data-perm][data-level]'));
        const perms = { budget: 'none', income: 'none', orders: 'none', ledger: 'none', settings: 'none' };
        let mergedPerms = existingPerms;
        if (inputs.length > 0) {
          for (const key of Object.keys(perms)) {
            const fullBox = inputs.find((el) => el.getAttribute('data-perm') === key && el.getAttribute('data-level') === 'full');
            const deleteBox = inputs.find((el) => el.getAttribute('data-perm') === key && el.getAttribute('data-level') === 'delete');
            const createBox = inputs.find((el) => el.getAttribute('data-perm') === key && el.getAttribute('data-level') === 'create');
            const writeBox = inputs.find((el) => el.getAttribute('data-perm') === key && el.getAttribute('data-level') === 'write');
            const readBox = inputs.find((el) => el.getAttribute('data-perm') === key && el.getAttribute('data-level') === 'read');
            perms[key] = fullBox && fullBox.checked
              ? 'full'
              : deleteBox && deleteBox.checked
                ? 'delete'
                : createBox && createBox.checked
                  ? 'create'
                  : writeBox && writeBox.checked
                    ? 'write'
                    : readBox && readBox.checked
                      ? 'read'
                      : 'none';
          }
          mergedPerms = { ...existingPerms, ...perms };
        }

        const pwEl = row.querySelector('input[data-new-password]');
        // Only treat the password as changed if the admin actually typed in the field.
        // Password managers may autofill; we ignore those values.
        const pwTouched = pwEl && pwEl.dataset && pwEl.dataset.touched === '1';
        const typedPw = pwEl ? String(pwEl.value || '') : '';
        const currentPw = String((currentUserRecord && currentUserRecord.passwordPlain) || '');
        const newPw = pwTouched && typedPw.trim() && typedPw !== currentPw ? typedPw : '';

        const emailEl = row.querySelector('input[type="email"][data-email]');
        const nextEmail = emailEl ? String(emailEl.value || '') : '';

        const roleEl = row.querySelector('select[data-role]');
        const nextRole = roleEl ? String(roleEl.value || '') : String((currentUserRecord && currentUserRecord.position) || '');
        const res = await updateUser(username, mergedPerms, newPw, nextEmail, nextRole);
        if (!res.ok && res.reason === 'lastSettings') {
          window.alert('At least one user must keep Settings access.');
          return;
        }
        if (!res.ok && res.reason === 'email') {
          window.alert('Enter a valid email address.');
          return;
        }
        if (!res.ok && res.reason === 'wp_save_failed') {
          window.alert('Could not save users to WordPress shared storage. Changes may not be visible to other users until a Settings-authorized account saves successfully.');
          return;
        }
        if (!res.ok) {
          window.alert('Could not save user changes.');
          return;
        }
        if (pwEl) pwEl.dataset.touched = '0';

        usersTableViewState.editingUsername = null;
        renderUsersTableSafe();

        const current = normalizeUsername(getCurrentUsername());
        if (current && current === normalizeUsername(username)) {
          // Refresh permissions immediately for the active user.
          window.location.reload();
        }
      }
    });

    // Mark per-user "New password" inputs as touched only when the admin types.
    // Password managers may autofill without user intent; we ignore those values.
    usersTbody.addEventListener('input', (e) => {
      const input = e.target && e.target.matches
        ? (e.target.matches('input[data-new-password]') ? e.target : null)
        : null;
      if (!input) return;
      input.dataset.touched = '1';
    });

    // Enforce mutual exclusivity for per-module checkbox pairs in the Users table.
    usersTbody.addEventListener('change', (e) => {
      const input = e.target && e.target.matches ? (e.target.matches('input[type="checkbox"][data-perm][data-level]') ? e.target : null) : null;
      if (!input) return;
      const row = input.closest('tr[data-username]');
      if (!row) return;

      const key = input.getAttribute('data-perm');
      const level = input.getAttribute('data-level');
      if (!key || !level) return;

      if (!input.checked) return;

      const levels = ['full', 'delete', 'create', 'write', 'read'];
      for (const lv of levels) {
        if (lv === level) continue;
        const other = row.querySelector(
          `input[type="checkbox"][data-perm="${CSS.escape(key)}"][data-level="${CSS.escape(lv)}"]`
        );
        if (other) other.checked = false;
      }
    });

    // Re-apply Users table cap on resize (layout changes can affect row heights).
    if (!usersTbody.dataset.usersCapResizeBound) {
      usersTbody.dataset.usersCapResizeBound = '1';
      let resizeTimer = 0;
      window.addEventListener('resize', () => {
        if (resizeTimer) window.clearTimeout(resizeTimer);
        resizeTimer = window.setTimeout(() => {
          resizeTimer = 0;
          applyMaxVisibleUsers(3);
        }, 120);
      });
    }
  }

  
  // [bundle-strip:settings-remove-workflows] removed in page-specific build.
function initBackupPage() {
    const root = document.querySelector('[data-backup]');
    if (!root) return;

    const grid = root.querySelector('[data-backup-grid]');
    const emptyEl = root.querySelector('[data-backup-empty]');
    if (!grid) return;

    const createActiveBtn = root.querySelector('[data-backup-create-active]');
    const restoreFileBtn = root.querySelector('[data-backup-restore-file-btn]');
    const restoreFileInput = root.querySelector('[data-backup-restore-file]');

    const gdriveUploadBtn = root.querySelector('[data-gdrive-upload-now]');

    const canUseGdrive = Boolean(IS_WP_SHARED_MODE);
    if (gdriveUploadBtn) gdriveUploadBtn.hidden = !canUseGdrive;

    const normalizeYear = (year) => {
      if (typeof normalizeBackupYear === 'function') return normalizeBackupYear(year);
      const y = Number(year);
      if (!Number.isInteger(y)) return null;
      if (y < 1900 || y > 2500) return null;
      return y;
    };

    const loadBackupIndexSafe = (year) => {
      if (typeof loadBackupIndex === 'function') return loadBackupIndex(year);
      return [];
    };

    const formatBackupCreatedAtSafe = (value) => {
      if (typeof formatBackupCreatedAt === 'function') return formatBackupCreatedAt(value);
      return formatIsoForList(value);
    };

    const downloadBackupByIdSafe = (year, id) => {
      if (typeof downloadBackupById === 'function') {
        downloadBackupById(year, id);
        return;
      }
      window.alert('Backup download is unavailable in this build.');
    };

    const loadBackupPayloadFromStorageSafe = (year, id) => {
      if (typeof loadBackupPayloadFromStorage === 'function') {
        return loadBackupPayloadFromStorage(year, id);
      }
      return null;
    };

    const restoreYearBackupFromPayloadSafe = (payload) => {
      if (typeof restoreYearBackupFromPayload === 'function') {
        return restoreYearBackupFromPayload(payload);
      }
      return { ok: false, error: 'restore_unavailable' };
    };

    const createYearBackupSafe = (year, reason) => {
      if (typeof createYearBackup === 'function') {
        return createYearBackup(year, reason);
      }
      return { ok: false, error: 'create_unavailable' };
    };

    function formatIsoForList(iso) {
      const s = String(iso || '').trim();
      if (!s) return '';
      return s.replace('T', ' ').replace('Z', '');
    }

    let gdriveCloudYear = null;
    let gdriveCloudStatus = '';
    /** @type {Array<{id?:string,name?:string,createdTime?:string,webViewLink?:string,size?:string|number}>} */
    let gdriveCloudFiles = [];

    function getCloudYearForUi() {
      const active = normalizeYear(getActiveBudgetYear());
      if (active) return active;
      const years = loadBudgetYears();
      const y = Array.isArray(years) && years.length > 0 ? normalizeYear(years[0]) : null;
      return y;
    }

    function filterCloudFilesForYear(files, year) {
      // Kept for compatibility when restoring from per-year backup files.
      // All-years backups (acgl-fms-backup-all-*) are shown without filtering.
      const list = Array.isArray(files) ? files : [];
      return list.filter((f) => f && typeof f === 'object');
    }

    async function fetchGdriveBackupPayloadById(fileId) {
      const id = String(fileId || '').trim();
      if (!id) return null;
      const url = `${wpJoin('acgl-fms/v1/admin/gdrive-backup/file')}?id=${encodeURIComponent(id)}`;
      const res = await wpFetchJson(url, { method: 'GET' });
      const data = await res.json().catch(() => null);
      if (!res.ok || !data || !data.ok) {
        return null;
      }
      return data;
    }

    async function refreshGdriveCloudCard() {
      if (!canUseGdrive) return;

      const y = getCloudYearForUi();
      gdriveCloudYear = y;

      if (!getWpToken()) {
        gdriveCloudStatus = 'Sign in to view cloud backups.';
        gdriveCloudFiles = [];
        render();
        return;
      }

      gdriveCloudStatus = 'Loading…';
      gdriveCloudFiles = [];
      render();

      try {
        const url = `${wpJoin('acgl-fms/v1/admin/gdrive-backup/list')}?n=50`;
        const res = await wpFetchJson(url, { method: 'GET' });
        const data = await res.json().catch(() => null);
        if (!res.ok || !data || !data.ok) {
          const err = data && data.error ? String(data.error) : `http_${res.status}`;
          gdriveCloudStatus = `Could not load cloud backups (${err}).`;
          gdriveCloudFiles = [];
          render();
          return;
        }

        gdriveCloudStatus = '';
        gdriveCloudFiles = Array.isArray(data.files) ? data.files.filter((f) => f && typeof f === 'object') : [];
        render();
      } catch {
        gdriveCloudStatus = 'Could not load cloud backups.';
        gdriveCloudFiles = [];
        render();
      }
    }

    async function runGdriveUploadNow() {
      if (!canUseGdrive) return;
      if (!getWpToken()) {
        window.alert('Please sign in.');
        return;
      }

      gdriveCloudStatus = 'Uploading…';
      render();
      try {
        const url = wpJoin('acgl-fms/v1/admin/gdrive-backup/run');
        const res = await wpFetchJson(url, { method: 'POST' });
        const data = await res.json().catch(() => null);
        if (!res.ok || !data || !data.ok) {
          const err = data && data.error ? String(data.error) : `http_${res.status}`;
          gdriveCloudStatus = `Upload failed (${err}).`;
          render();
          return;
        }
        gdriveCloudStatus = 'Uploaded.';
        render();
        await refreshGdriveCloudCard();
      } catch {
        gdriveCloudStatus = 'Upload failed.';
        render();
      }
    }

    function renderGdriveCloudCard() {
      const card = document.createElement('div');
      card.className = 'archive__card';

      const header = document.createElement('div');
      header.className = 'archive__cardHeader';

      const h = document.createElement('h3');
      h.className = 'archive__title';
      h.textContent = 'Cloud Backups (Google Drive)';
      header.appendChild(h);
      card.appendChild(header);

      if (gdriveCloudStatus) {
        const status = document.createElement('div');
        status.className = 'subhead';
        status.textContent = gdriveCloudStatus;
        card.appendChild(status);
      }

      const list = gdriveCloudFiles;
      let any = false;
      for (const f of list) {
        if (!f || typeof f !== 'object') continue;
        const id = String(f.id || '').trim();
        if (!id) continue;
        any = true;

        const row = document.createElement('div');
        row.className = 'backupRow';

        const label = document.createElement('div');
        label.className = 'muted backupRow__label';
        label.textContent = f.createdTime ? formatIsoForList(f.createdTime) : '';
        row.appendChild(label);

        const buttons = document.createElement('div');
        buttons.className = 'backupRow__buttons';

        const dl = document.createElement('button');
        dl.type = 'button';
        dl.className = 'btn btn--downloadIcon';
        dl.title = 'Download';
        dl.setAttribute('aria-label', 'Download backup');
        dl.innerHTML = DOWNLOAD_ICON_SVG;
        dl.addEventListener('click', async () => {
          if (!getWpToken()) {
            window.alert('Please sign in.');
            return;
          }
          gdriveCloudStatus = 'Downloading…';
          render();
          const data = await fetchGdriveBackupPayloadById(id);
          if (!data || !data.payload) {
            gdriveCloudStatus = 'Could not download cloud backup.';
            render();
            return;
          }
          const fileName = String((data.file && data.file.name) || '').trim() || `acgl-fms-backup-all-${id}.json`;
          const text = JSON.stringify(data.payload, null, 2);
          const blob = new Blob([text], { type: 'application/json;charset=utf-8;' });
          downloadBlob(blob, fileName);
          gdriveCloudStatus = '';
          render();
        });
        buttons.appendChild(dl);

        const rs = document.createElement('button');
        rs.type = 'button';
        rs.className = 'btn btn--restoreIcon';
        rs.title = 'Restore';
        rs.setAttribute('aria-label', 'Restore backup');
        rs.innerHTML = RESTORE_ICON_SVG;
        rs.addEventListener('click', async () => {
          if (!requireSettingsEditAccess('Backup access required to restore backups.', 'settings_backup')) return;
          if (!getWpToken()) {
            window.alert('Please sign in.');
            return;
          }
          const ok = window.confirm(`Restore all years from this cloud backup? This will overwrite all backed-up year data.`);
          if (!ok) return;

          gdriveCloudStatus = 'Restoring…';
          render();
          const data = await fetchGdriveBackupPayloadById(id);
          if (!data || !data.payload) {
            gdriveCloudStatus = 'Could not restore cloud backup.';
            render();
            return;
          }
          const res = restoreYearBackupFromPayloadSafe(data.payload);
          if (!res.ok && res.error === 'wp_login_required') {
            window.alert('Please sign in.');
            return;
          }
          if (!res.ok) {
            window.alert('Could not restore backup.');
            gdriveCloudStatus = '';
            render();
            return;
          }
          window.location.reload();
        });
        buttons.appendChild(rs);

        row.appendChild(buttons);

        card.appendChild(row);
      }

      if (!any) {
        const empty = document.createElement('p');
        empty.className = 'empty';
        empty.textContent = 'No cloud backups yet.';
        card.appendChild(empty);
      }

      return card;
    }

    function getKnownYears() {
      const years = loadBudgetYears();
      const active = normalizeYear(getActiveBudgetYear());
      const out = Array.isArray(years) ? years.slice() : [];
      if (active && !out.includes(active)) out.push(active);
      return out.filter((v) => Number.isInteger(Number(v))).sort((a, b) => b - a);
    }

    function render() {
      const years = getKnownYears();
      const activeYear = normalizeYear(getActiveBudgetYear());
      grid.innerHTML = '';

      let anyBackups = false;
      let renderedAny = false;

      function createWpYearCard(y, idx, isActiveYear) {
        const card = document.createElement('div');
        card.className = 'archive__card';
        if (!isActiveYear) card.classList.add('backupCard--belowTop');

        const header = document.createElement('div');
        header.className = 'archive__cardHeader';

        const h = document.createElement('h3');
        h.className = 'archive__title';
        h.textContent = isActiveYear
          ? `${String(y)} (WordPress - Active)`
          : `${String(y)} (WordPress)`;
        header.appendChild(h);
        card.appendChild(header);

        for (const meta of idx) {
          if (!meta || !meta.id) continue;
          const row = document.createElement('div');
          row.className = 'backupRow';

          const label = document.createElement('div');
          label.className = 'muted backupRow__label';
          label.textContent = formatBackupCreatedAtSafe(meta.createdAt);
          row.appendChild(label);

          const buttons = document.createElement('div');
          buttons.className = 'backupRow__buttons';

          const dl = document.createElement('button');
          dl.type = 'button';
          dl.className = 'btn btn--downloadIcon';
          dl.title = 'Download';
          dl.setAttribute('aria-label', 'Download backup');
          dl.innerHTML = DOWNLOAD_ICON_SVG;
          dl.addEventListener('click', () => {
            downloadBackupByIdSafe(y, meta.id);
          });
          buttons.appendChild(dl);

          const rs = document.createElement('button');
          rs.type = 'button';
          rs.className = 'btn btn--restoreIcon';
          rs.title = 'Restore';
          rs.setAttribute('aria-label', 'Restore backup');
          rs.innerHTML = RESTORE_ICON_SVG;
          rs.addEventListener('click', () => {
            if (!requireSettingsEditAccess('Backup access required to restore backups.', 'settings_backup')) return;
            const ok = window.confirm(`Restore ${String(y)} from this backup? This will overwrite ${String(y)} data.`);
            if (!ok) return;
            const payload = loadBackupPayloadFromStorageSafe(y, meta.id);
            if (!payload) {
              window.alert('Backup not found.');
              return;
            }
            const res = restoreYearBackupFromPayloadSafe(payload);
            if (!res.ok && res.error === 'wp_login_required') {
              window.alert('Please sign in.');
              return;
            }
            if (!res.ok) {
              window.alert('Could not restore backup.');
              return;
            }
            window.location.reload();
          });
          buttons.appendChild(rs);

          row.appendChild(buttons);
          card.appendChild(row);
        }

        if (idx.length === 0) {
          const empty = document.createElement('p');
          empty.className = 'empty';
          empty.textContent = isActiveYear ? 'No active-year WordPress backups yet.' : 'No WordPress backups yet.';
          card.appendChild(empty);
        }

        return card;
      }

      const otherWpCards = [];
      let activeWpCard = null;

      for (const y of years) {
        const idx = loadBackupIndexSafe(y);
        if (idx.length > 0) anyBackups = true;

        // Only render a WordPress year card if it has backups, or if it's the active year.
        const showWpYearCard = idx.length > 0 || (activeYear && y === activeYear);
        if (!showWpYearCard) continue;

        const isActiveYear = Boolean(activeYear && y === activeYear);
        const card = createWpYearCard(y, idx, isActiveYear);

        if (isActiveYear) activeWpCard = card;
        else otherWpCards.push(card);
      }

      // Priority order:
      // 1) Active-year WordPress backups
      // 2) Google Drive cloud backups
      // 3) Non-active WordPress year backups
      if (activeWpCard) {
        grid.appendChild(activeWpCard);
        renderedAny = true;
      }

      if (canUseGdrive) {
        const cloudCard = renderGdriveCloudCard();
        if (cloudCard) {
          grid.appendChild(cloudCard);
          renderedAny = true;
        }
      }

      for (const card of otherWpCards) {
        grid.appendChild(card);
        renderedAny = true;
      }

      if (emptyEl) emptyEl.hidden = renderedAny || anyBackups;
    }

    if (createActiveBtn && !createActiveBtn.dataset.bound) {
      createActiveBtn.dataset.bound = '1';
      createActiveBtn.addEventListener('click', () => {
        const y = normalizeYear(getActiveBudgetYear());
        if (!y) {
          window.alert('No active year.');
          return;
        }
        if (IS_WP_SHARED_MODE && !getWpToken()) {
          window.alert('Please sign in.');
          return;
        }
        if (!requireSettingsEditAccess('Backup access required to create backups.', 'settings_backup')) return;
        const res = createYearBackupSafe(y, 'manual');
        if (!res.ok) {
          window.alert('Could not create backup.');
          return;
        }
        render();
      });
    }

    if (restoreFileBtn && restoreFileInput && !restoreFileBtn.dataset.bound) {
      restoreFileBtn.dataset.bound = '1';
      restoreFileBtn.addEventListener('click', () => {
        if (!requireSettingsEditAccess('Backup access required to restore backups.', 'settings_backup')) return;
        restoreFileInput.value = '';
        restoreFileInput.click();
      });

      restoreFileInput.addEventListener('change', async () => {
        const file = restoreFileInput.files && restoreFileInput.files[0] ? restoreFileInput.files[0] : null;
        if (!file) return;
        try {
          const text = await file.text();
          const payload = JSON.parse(text);
          const y = normalizeYear(payload && payload.year);
          if (!y) {
            window.alert('Invalid backup file.');
            return;
          }
          const ok = window.confirm(`Restore ${String(y)} from this file? This will overwrite ${String(y)} data.`);
          if (!ok) return;
          const res = restoreYearBackupFromPayloadSafe(payload);
          if (!res.ok && res.error === 'wp_login_required') {
            window.alert('Please sign in.');
            return;
          }
          if (!res.ok) {
            window.alert('Could not restore backup.');
            return;
          }
          window.location.reload();
        } catch {
          window.alert('Could not read backup file.');
        }
      });
    }

    if (gdriveUploadBtn && !gdriveUploadBtn.dataset.bound) {
      gdriveUploadBtn.dataset.bound = '1';
      gdriveUploadBtn.addEventListener('click', () => {
        void runGdriveUploadNow();
      });
    }

    render();

    if (canUseGdrive) {
      void refreshGdriveCloudCard();
    }
  }

  // ---- Event wiring (only when the elements exist on the page) ----

  installNavAutoSync();

  // Dev-only: seed 2025 mock budget + payment orders.
  // Never let test data seeding crash page bootstrap.
  try {
    seedMockData2025IfDev();
  } catch (err) {
    try {
      if (isDevEnvironment()) console.warn('Dev seed skipped due to error:', err);
    } catch {
      // ignore
    }
  }

  // Theme toggle works on both pages
  applyTheme(getPreferredTheme());
  if (themeToggle) {
    themeToggle.addEventListener('change', () => {
      const next = themeToggle.checked ? 'dark' : 'light';
      setTheme(next);
    });
  }

  // Auto logout after 10 minutes of inactivity.
  installIdleAutoLogout();

  // Request form header auth button (index.html)
  if (authHeaderBtn) {
    syncAuthHeaderBtn();
    if (!authHeaderBtn.dataset.bound) {
      authHeaderBtn.dataset.bound = 'true';
      authHeaderBtn.addEventListener('click', (e) => {
        e.preventDefault();
        openAuthLoginOverlay();
      });
    }
  }

  for (const popoutLink of requestHeaderPopoutLinks) {
    if (!popoutLink || popoutLink.dataset.bound) continue;
    popoutLink.dataset.bound = 'true';
    popoutLink.addEventListener('click', (e) => {
      e.preventDefault();

      const rawHref = String(popoutLink.getAttribute('href') || '').trim();
      if (!rawHref) return;

      const isExternal = popoutLink.getAttribute('data-popout-external') === '1';
      const href = isExternal ? rawHref : withWpEmbedParams(rawHref);
      const winName = String(popoutLink.getAttribute('data-popout-name') || 'acglInfoPopout').trim() || 'acglInfoPopout';

      const w = 1120;
      const h = 820;
      const screenLeft = Number(window.screenLeft ?? window.screenX ?? 0) || 0;
      const screenTop = Number(window.screenTop ?? window.screenY ?? 0) || 0;
      const screenH = Number(window.screen?.height) || window.outerHeight || h;
      const left = screenLeft + 20;
      const top = Math.max(0, Math.round(screenTop + (screenH - h) / 2));
      const features = `popup=yes,toolbar=no,location=yes,status=no,menubar=no,scrollbars=yes,resizable=yes,width=${w},height=${h},left=${left},top=${top}`;

      const win = window.open(href, winName, features);
      if (!win) {
        window.location.href = href;
        return;
      }
      try {
        if (typeof win.moveTo === 'function') win.moveTo(left, top);
        if (typeof win.focus === 'function') win.focus();
      } catch {
        // ignore popup positioning limitations
      }
    });
  }

  if (downloadPdfBtn && !downloadPdfBtn.dataset.bound) {
    downloadPdfBtn.dataset.bound = '1';
    downloadPdfBtn.addEventListener('click', (e) => {
      try {
        if (e && typeof e.preventDefault === 'function') e.preventDefault();
      } catch {
        // ignore
      }
      const debug = Boolean(e && e.shiftKey);

      // Immediate feedback so it never feels like a no-op.
      const prevText = String(downloadPdfBtn.textContent || 'Download PDF');
      try {
        downloadPdfBtn.disabled = true;
        downloadPdfBtn.textContent = debug ? 'Generating calibration…' : 'Generating…';
      } catch {
        // ignore
      }

      let order = null;
      try {
        if (!form) {
          const year = getActiveBudgetYear();
          const id = currentViewedOrderId || (modal ? modal.getAttribute('data-order-id') : null);
          order = id ? getOrderById(id, year) : null;
        }
      } catch {
        order = null;
      }

      if (order && hasOrderMissingRequiredValues(order)) {
        window.alert('Complete all required fields before downloading a PDF.');
        try {
          downloadPdfBtn.disabled = false;
          downloadPdfBtn.textContent = prevText;
        } catch {
          // ignore
        }
        return;
      }

      const p = generatePaymentOrderPdfFromTemplate({ debug, order });
      if (p && typeof p.finally === 'function') {
        p.finally(() => {
          try {
            downloadPdfBtn.disabled = false;
            downloadPdfBtn.textContent = prevText;
          } catch {
            // ignore
          }
        });
      } else {
        try {
          downloadPdfBtn.disabled = false;
          downloadPdfBtn.textContent = prevText;
        } catch {
          // ignore
        }
      }
    });
  }

  // Ensure request form nav/hamburger always reflects auth state (even if the header auth button markup changes).
  syncRequestFormHamburgerVisibility();

  // Left navigation open/close (only on pages that include it)
  updateNavToggleUi();
  if (appShell && navToggleBtn) {
    navToggleBtn.addEventListener('click', () => {
      appShell.classList.toggle('appShell--navClosed');
      updateNavToggleUi();

      if (submitToken && !submitToken.hidden) positionToast(submitToken);
      if (flashToken && !flashToken.hidden) positionToast(flashToken);
    });
  }

  window.addEventListener('resize', () => {
    if (submitToken && !submitToken.hidden) positionToast(submitToken);
    if (flashToken && !flashToken.hidden) positionToast(flashToken);
  });

  // Show one-time flash token on the Payment Orders page (if present)
  if (flashToken) {
    showFlashToken(consumeFlashToken());
  }

  // Budget page editor (only runs when the table + button exist)
  if (typeof maybeAutoBackupActiveYear === 'function') maybeAutoBackupActiveYear();
  initBudgetYearNav();
  if (typeof initBudgetEditor === 'function') initBudgetEditor();
  if (typeof initBudgetDashboard === 'function') initBudgetDashboard();
  if (typeof initBudgetNumberSelect === 'function') initBudgetNumberSelect();
  if (typeof initArchivePage === 'function') initArchivePage();

  if (grandLodgeInfoForm) {
    const syncGrandLodgeImageMeta = (info) => {
      const sealSaved = Boolean(info && info.grandLodgeSealDataUrl);
      const sigSaved = Boolean(info && info.grandSecretarySignatureDataUrl);

      if (grandLodgeSealSavedMeta) {
        grandLodgeSealSavedMeta.hidden = !sealSaved;
        grandLodgeSealSavedMeta.textContent = sealSaved
          ? `Saved: ${String((info && info.grandLodgeSealFileName) || 'Grand Lodge Seal')}`
          : '';
      }

      if (grandSecretarySignatureSavedMeta) {
        grandSecretarySignatureSavedMeta.hidden = !sigSaved;
        grandSecretarySignatureSavedMeta.textContent = sigSaved
          ? `Saved: ${String((info && info.grandSecretarySignatureFileName) || "Grand Secretary's Signature")}`
          : '';
      }
    };

    const current = loadGrandLodgeInfo();
    if (grandMasterInput) grandMasterInput.value = current.grandMaster;
    if (grandSecretaryInput) grandSecretaryInput.value = current.grandSecretary;
    if (grandTreasurerInput) grandTreasurerInput.value = current.grandTreasurer;
    if (officialAddressInput) officialAddressInput.value = current.officialAddress;
    if (operationAddressInput) operationAddressInput.value = current.operationAddress;
    syncGrandLodgeImageMeta(current);

    {
      const hasAnyUsers = loadUsers().length > 0;
      const currentUser = getCurrentUser();
      const canEdit = !hasAnyUsers || (currentUser ? canWrite(currentUser, 'settings_grandlodge') : false);
      if (hasAnyUsers && !canEdit) {
        if (grandMasterInput) grandMasterInput.disabled = true;
        if (grandSecretaryInput) grandSecretaryInput.disabled = true;
        if (grandTreasurerInput) grandTreasurerInput.disabled = true;
        if (officialAddressInput) officialAddressInput.disabled = true;
        if (operationAddressInput) operationAddressInput.disabled = true;
        if (grandLodgeSealFileInput) grandLodgeSealFileInput.disabled = true;
        if (grandSecretarySignatureFileInput) grandSecretarySignatureFileInput.disabled = true;
        const submitBtn = grandLodgeInfoForm.querySelector('button[type="submit"]');
        if (submitBtn) submitBtn.disabled = true;
      }
    }

    grandLodgeInfoForm.addEventListener('submit', async (e) => {
      e.preventDefault();

      if (!requireSettingsEditAccess('GL Information is view only for your account.', 'settings_grandlodge')) return;

      const submitBtn = grandLodgeInfoForm.querySelector('button[type="submit"]');
      if (submitBtn) submitBtn.disabled = true;

      try {
        const prev = loadGrandLodgeInfo();

        const sealFile = grandLodgeSealFileInput && grandLodgeSealFileInput.files && grandLodgeSealFileInput.files[0]
          ? grandLodgeSealFileInput.files[0]
          : null;
        const sigFile = grandSecretarySignatureFileInput
          && grandSecretarySignatureFileInput.files
          && grandSecretarySignatureFileInput.files[0]
          ? grandSecretarySignatureFileInput.files[0]
          : null;

        const sealDataUrl = sealFile ? await readFileAsDataUrl(sealFile) : prev.grandLodgeSealDataUrl;
        const sealName = sealFile ? String(sealFile.name || '') : prev.grandLodgeSealFileName;
        const sigDataUrl = sigFile ? await readFileAsDataUrl(sigFile) : prev.grandSecretarySignatureDataUrl;
        const sigName = sigFile ? String(sigFile.name || '') : prev.grandSecretarySignatureFileName;

        saveGrandLodgeInfo({
          grandMaster: grandMasterInput ? grandMasterInput.value : '',
          grandSecretary: grandSecretaryInput ? grandSecretaryInput.value : '',
          grandTreasurer: grandTreasurerInput ? grandTreasurerInput.value : '',
          officialAddress: officialAddressInput ? officialAddressInput.value : '',
          operationAddress: operationAddressInput ? operationAddressInput.value : '',
          grandLodgeSealDataUrl: sealDataUrl,
          grandLodgeSealFileName: sealName,
          grandSecretarySignatureDataUrl: sigDataUrl,
          grandSecretarySignatureFileName: sigName,
        });

        // In WP shared mode, writes are queued and may not be persisted yet.
        // Flush immediately so a quick refresh doesn't "lose" recently saved images.
        if (IS_WP_SHARED_MODE && typeof window.acglFmsWpFlushNow === 'function') {
          try {
            await window.acglFmsWpFlushNow();
          } catch {
            // ignore
          }
        }
      } catch {
        window.alert('Could not save the selected file(s). If the image is large, try a smaller file and save again.');
        return;
      } finally {
        if (submitBtn) submitBtn.disabled = false;
      }

      // Sync normalized values back into the form.
      const next = loadGrandLodgeInfo();
      if (grandMasterInput) grandMasterInput.value = next.grandMaster;
      if (grandSecretaryInput) grandSecretaryInput.value = next.grandSecretary;
      if (grandTreasurerInput) grandTreasurerInput.value = next.grandTreasurer;
      if (officialAddressInput) officialAddressInput.value = next.officialAddress;
      if (operationAddressInput) operationAddressInput.value = next.operationAddress;
      syncGrandLodgeImageMeta(next);
    });
  }

  if (numberingForm) {
    const settings = loadNumberingSettings();
    initMasonicYearSelectFromBudgets(settings.year2);
    if (masonicYearInput) masonicYearInput.value = String(Number(settings.year2));
    if (firstNumberInput) firstNumberInput.value = String(settings.nextSeq);
    if (firstMoneyTransferNumberInput) firstMoneyTransferNumberInput.value = String(settings.mtNextSeq);

    let numberingSaveMode = 'po';
    if (savePoNumberingBtn) {
      savePoNumberingBtn.addEventListener('click', () => {
        numberingSaveMode = 'po';
      });
    }
    if (saveMtNumberingBtn) {
      saveMtNumberingBtn.addEventListener('click', () => {
        numberingSaveMode = 'mt';
      });
    }

    {
      const hasAnyUsers = loadUsers().length > 0;
      const currentUser = getCurrentUser();
      const canEdit = !hasAnyUsers || (currentUser ? canWrite(currentUser, 'settings_numbering') : false);
      if (hasAnyUsers && !canEdit) {
        if (masonicYearInput) masonicYearInput.disabled = true;
        if (firstNumberInput) firstNumberInput.disabled = true;
        if (firstMoneyTransferNumberInput) firstMoneyTransferNumberInput.disabled = true;
        const submitBtns = numberingForm.querySelectorAll('button[type="submit"]');
        submitBtns.forEach((b) => { b.disabled = true; });
      }
    }

    numberingForm.addEventListener('submit', async (e) => {
      e.preventDefault();

      if (!requireSettingsEditAccess('Numbering is view only for your account.', 'settings_numbering')) return;

      const yearErr = document.getElementById('error-masonicYear');
      const seqErr = document.getElementById('error-firstNumber');
      const mtSeqErr = document.getElementById('error-firstMoneyTransferNumber');
      if (yearErr) yearErr.textContent = '';
      if (seqErr) seqErr.textContent = '';
      if (mtSeqErr) mtSeqErr.textContent = '';

      const submitter = e.submitter;
      const submitMode = submitter && submitter.dataset && submitter.dataset.numberingSave
        ? String(submitter.dataset.numberingSave)
        : numberingSaveMode;

      const yearRaw = masonicYearInput ? masonicYearInput.value : '';
      const seqRaw = firstNumberInput ? firstNumberInput.value : '';
      const mtSeqRaw = firstMoneyTransferNumberInput ? firstMoneyTransferNumberInput.value : '';

      const yearNum = Number(yearRaw);
      if (!Number.isFinite(yearNum) || yearNum < 0 || yearNum > 99) {
        if (yearErr) yearErr.textContent = 'Enter a 2-digit year (0–99).';
        return;
      }

      const year2 = normalizeMasonicYear2(yearRaw);

      if (submitMode === 'mt') {
        const mtSeqNum = Number(mtSeqRaw);
        if (!Number.isFinite(mtSeqNum) || mtSeqNum < 1) {
          if (mtSeqErr) mtSeqErr.textContent = 'Enter a number of 1 or more.';
          return;
        }
        const mtNextSeq = normalizeSequence(mtSeqRaw);
        saveNumberingSettings({ year2, mtNextSeq });
      } else {
        const seqNum = Number(seqRaw);
        if (!Number.isFinite(seqNum) || seqNum < 1) {
          if (seqErr) seqErr.textContent = 'Enter a number of 1 or more.';
          return;
        }
        const nextSeq = normalizeSequence(seqRaw);
        saveNumberingSettings({ year2, nextSeq });
      }

      // Normalize field display after saving
      {
        const next = loadNumberingSettings();
        if (masonicYearInput) masonicYearInput.value = String(Number(next.year2));
        if (firstNumberInput) firstNumberInput.value = String(next.nextSeq);
        if (firstMoneyTransferNumberInput) firstMoneyTransferNumberInput.value = String(next.mtNextSeq);
      }

      // In WP shared mode, save is debounced; flush now so the value persists
      // even if the user navigates right after saving.
      if (IS_WP_SHARED_MODE && typeof window.acglFmsWpFlushNow === 'function') {
        try {
          await window.acglFmsWpFlushNow();
        } catch {
          // ignore
        }
      }
    });
  }

  if (notificationsForm) {
    const allNotificationTypeIds = NOTIFICATION_TYPES.map((t) => t.id);
    const defaultNotificationTypeId = NOTIFICATION_TYPES[0] ? NOTIFICATION_TYPES[0].id : 'new_payment_order';

    const normalizeNotificationsRecipientsMode = (modeRaw) => {
      const mode = String(modeRaw || '').trim();
      if (mode === 'all_users_with_email' || mode === 'manual_list') return mode;
      if (mode.startsWith('user:')) {
        const username = normalizeUsername(mode.slice(5));
        if (username && /^[a-z0-9._-]+$/i.test(username)) return `user:${username}`;
      }
      return 'all_users_with_email';
    };

    const notificationsUserRecipientOptions = () => {
      const users = Array.isArray(loadUsers()) ? loadUsers() : [];
      return users
        .filter((u) => {
          const username = normalizeUsername(u && u.username);
          return username && username !== normalizeUsername(HARD_CODED_ADMIN_USERNAME);
        })
        .map((u) => ({
          username: normalizeUsername(u && u.username),
          role: String((u && u.position) || '').trim(),
        }))
        .sort((a, b) => a.username.localeCompare(b.username));
    };

    const populateNotificationsRecipientOptions = () => {
      if (!notificationsRecipientsModeInput) return;
      const current = normalizeNotificationsRecipientsMode(notificationsRecipientsModeInput.value);
      Array.from(notificationsRecipientsModeInput.querySelectorAll('option[data-user-recipient="1"]')).forEach((opt) => opt.remove());

      notificationsUserRecipientOptions().forEach((u) => {
        const opt = document.createElement('option');
        opt.value = `user:${u.username}`;
        opt.textContent = `${u.role || 'User'} (${u.username})`;
        opt.dataset.userRecipient = '1';
        notificationsRecipientsModeInput.appendChild(opt);
      });

      notificationsRecipientsModeInput.value = current;
      if (notificationsRecipientsModeInput.value !== current) notificationsRecipientsModeInput.value = 'all_users_with_email';
    };

    const populateNotificationsTypeSelect = (typeIds) => {
      if (!notificationsTypeSelectEl) return;
      const ids = Array.isArray(typeIds) ? typeIds : allNotificationTypeIds;
      notificationsTypeSelectEl.innerHTML = '';
      ids.forEach((id) => {
        const t = NOTIFICATION_TYPES.find((x) => x.id === id);
        if (!t) return;
        const opt = document.createElement('option');
        opt.value = t.id;
        opt.textContent = t.label;
        notificationsTypeSelectEl.appendChild(opt);
      });
    };

    const normalizeNotificationTypeId = (typeIdRaw) => {
      const id = String(typeIdRaw || '').trim();
      return allNotificationTypeIds.includes(id) ? id : defaultNotificationTypeId;
    };

    const sanitizeNotificationInstanceId = (instanceIdRaw) => {
      const id = String(instanceIdRaw || '').trim();
      return /^[a-z0-9._:-]+$/i.test(id) ? id : '';
    };

    const createNotificationInstanceId = (typeIdRaw) => {
      const typeId = normalizeNotificationTypeId(typeIdRaw).replace(/[^a-z0-9._:-]+/gi, '_') || 'notification';
      return `${typeId}:${Date.now().toString(36)}:${Math.random().toString(36).slice(2, 8)}`;
    };

    const notificationsTypeLabelForId = (typeIdRaw) => {
      const typeId = normalizeNotificationTypeId(typeIdRaw);
      const def = NOTIFICATION_TYPES.find((t) => t.id === typeId);
      return def ? def.label : typeId;
    };

    const notificationsTypeDefaultForId = (id) => {
      const def = NOTIFICATION_TYPES.find((t) => t.id === id);
      return {
        enabled: id === 'new_payment_order' ? '1' : '0',
        subject: def ? def.defaultSubject : '',
        body: def ? def.defaultBody : '',
      };
    };

    const normalizeNotificationsTypeConfig = (id, raw) => {
      const r = raw && typeof raw === 'object' ? raw : {};
      const def = notificationsTypeDefaultForId(id);
      return {
        enabled: String(r.enabled || def.enabled) === '1' ? '1' : '0',
        subject: String(r.subject || def.subject),
        body: String(r.body || def.body),
        recipients_mode: r.recipients_mode ? normalizeNotificationsRecipientsMode(String(r.recipients_mode)) : '',
        manual_to: String(r.manual_to || ''),
      };
    };

    const notificationsInstanceDefaultForType = (typeIdRaw, instanceIdRaw = '') => {
      const typeId = normalizeNotificationTypeId(typeIdRaw);
      const def = notificationsTypeDefaultForId(typeId);
      return {
        instance_id: sanitizeNotificationInstanceId(instanceIdRaw) || createNotificationInstanceId(typeId),
        type_id: typeId,
        enabled: String(def.enabled || '0') === '1' ? '1' : '0',
        subject: String(def.subject || ''),
        body: String(def.body || ''),
        recipients_mode: '',
        manual_to: '',
      };
    };

    const normalizeNotificationsInstance = (raw, fallbackTypeId = defaultNotificationTypeId) => {
      const r = raw && typeof raw === 'object' ? raw : {};
      const typeId = normalizeNotificationTypeId(r.type_id || r.type || fallbackTypeId);
      const def = notificationsInstanceDefaultForType(typeId, r.instance_id || r.id || '');
      return {
        instance_id: sanitizeNotificationInstanceId(r.instance_id || r.id || '') || def.instance_id,
        type_id: typeId,
        enabled: String(r.enabled || def.enabled) === '1' ? '1' : '0',
        subject: String(r.subject || def.subject),
        body: String(r.body || def.body),
        recipients_mode: r.recipients_mode ? normalizeNotificationsRecipientsMode(String(r.recipients_mode)) : '',
        manual_to: String(r.manual_to || ''),
      };
    };

    const normalizeNotificationsTypesConfig = (rawMap) => {
      const map = rawMap && typeof rawMap === 'object' ? rawMap : {};
      const result = {};
      for (const t of NOTIFICATION_TYPES) {
        result[t.id] = normalizeNotificationsTypeConfig(t.id, map[t.id] || {});
      }
      return result;
    };

    const normalizeActiveTypeIds = (rawIds, normalizedTypesConfig) => {
      const src = Array.isArray(rawIds) ? rawIds : [];
      const known = new Set(allNotificationTypeIds);
      const out = [];
      src.forEach((v) => {
        const id = String(v || '').trim();
        if (!id || !known.has(id) || out.includes(id)) return;
        out.push(id);
      });
      if (out.length > 0) return out;

      const fallback = [];
      allNotificationTypeIds.forEach((id) => {
        const cfg = normalizedTypesConfig[id] || notificationsTypeDefaultForId(id);
        if (String(cfg.enabled || '0') === '1') fallback.push(id);
      });
      return fallback;
    };

    const migrateLegacyNotificationsInstances = (settingsRaw) => {
      const s = settingsRaw && typeof settingsRaw === 'object' ? settingsRaw : {};
      const typesConfig = normalizeNotificationsTypesConfig(s.types_config || {});
      const activeTypeIds = normalizeActiveTypeIds(s.active_type_ids || [], typesConfig);
      const migrated = activeTypeIds.map((typeId) => normalizeNotificationsInstance({
        instance_id: typeId,
        type_id: typeId,
        ...(typesConfig[typeId] || {}),
      }, typeId));
      return migrated.length > 0 ? migrated : [notificationsInstanceDefaultForType(defaultNotificationTypeId, defaultNotificationTypeId)];
    };

    const normalizeNotificationsInstances = (rawList, legacySource) => {
      if (!Array.isArray(rawList)) {
        return migrateLegacyNotificationsInstances(legacySource);
      }
      const out = [];
      const seen = new Set();
      rawList.forEach((entry) => {
        const normalized = normalizeNotificationsInstance(entry, entry && typeof entry === 'object' ? entry.type_id : defaultNotificationTypeId);
        let instanceId = normalized.instance_id;
        while (seen.has(instanceId)) {
          instanceId = createNotificationInstanceId(normalized.type_id);
        }
        seen.add(instanceId);
        out.push({ ...normalized, instance_id: instanceId });
      });
      return out;
    };

    const notificationsGetInstanceIndex = (settings, instanceIdRaw) => {
      const instanceId = String(instanceIdRaw || '').trim();
      const instances = Array.isArray(settings && settings.instances) ? settings.instances : [];
      return instances.findIndex((instance) => String(instance && instance.instance_id || '') === instanceId);
    };

    const notificationsGetInstance = (settings, instanceIdRaw) => {
      const idx = notificationsGetInstanceIndex(settings, instanceIdRaw);
      if (idx < 0) return null;
      const instances = Array.isArray(settings && settings.instances) ? settings.instances : [];
      return instances[idx] || null;
    };

    const describeNotificationRows = (instancesRaw) => {
      const instances = Array.isArray(instancesRaw) ? instancesRaw : [];
      const counts = {};
      instances.forEach((instance) => {
        const typeId = normalizeNotificationTypeId(instance && instance.type_id);
        counts[typeId] = (counts[typeId] || 0) + 1;
      });
      const seen = {};
      return instances.map((instance) => {
        const typeId = normalizeNotificationTypeId(instance && instance.type_id);
        const typeLabel = notificationsTypeLabelForId(typeId);
        seen[typeId] = (seen[typeId] || 0) + 1;
        const ordinal = seen[typeId];
        return {
          instance,
          typeId,
          typeLabel,
          displayLabel: counts[typeId] > 1 ? `${typeLabel} #${ordinal}` : typeLabel,
        };
      });
    };

    const notificationsDefaults = {
      recipients_mode: 'all_users_with_email',
      manual_to: '',
      reply_to: '',
      signature: 'ACGL FMS',
      instances: [notificationsInstanceDefaultForType(defaultNotificationTypeId, defaultNotificationTypeId)],
    };

    const normalizeNotificationsSettings = (settingsRaw) => {
      const s = settingsRaw && typeof settingsRaw === 'object' ? settingsRaw : {};
      const mode = normalizeNotificationsRecipientsMode(s.recipients_mode || notificationsDefaults.recipients_mode);
      return {
        recipients_mode: mode,
        manual_to: String(s.manual_to || notificationsDefaults.manual_to),
        reply_to: s.reply_to != null ? String(s.reply_to) : notificationsDefaults.reply_to,
        reply_to_cleared: Boolean(s.reply_to_cleared),
        signature: String(s.signature || notificationsDefaults.signature),
        instances: normalizeNotificationsInstances(s.instances, s),
      };
    };

    const loadNotificationsSettingsLocal = () => {
      try {
        const raw = String(localStorage.getItem(NOTIFICATIONS_SETTINGS_KEY) || '').trim();
        if (!raw) return { ...notificationsDefaults, reply_to: getGsDefaultReplyTo() };
        return normalizeNotificationsSettings(safeJsonParse(raw, notificationsDefaults));
      } catch {
        return { ...notificationsDefaults };
      }
    };

    const saveNotificationsSettingsLocal = (settingsRaw) => {
      const normalized = normalizeNotificationsSettings(settingsRaw);
      localStorage.setItem(NOTIFICATIONS_SETTINGS_KEY, JSON.stringify(normalized));
      return normalized;
    };

    const setNotificationsStatus = (msg, isError = false) => {
      if (!notificationsStatusEl) return;
      notificationsStatusEl.textContent = String(msg || '');
      notificationsStatusEl.style.color = isError ? 'var(--danger)' : '';
    };

    const setNotificationsLastTest = (msg) => {
      if (!notificationsLastTestEl) return;
      const text = String(msg || '').trim();
      notificationsLastTestEl.textContent = text;
      notificationsLastTestEl.hidden = text === '';
    };

    const notificationsSyncModeUi = () => {
      const mode = String(notificationsRecipientsModeInput && notificationsRecipientsModeInput.value || 'all_users_with_email');
      const manual = mode === 'manual_list';
      if (notificationsManualToWrap) notificationsManualToWrap.hidden = !manual;
      if (notificationsManualToInput) notificationsManualToInput.disabled = !manual;
    };

    const recipientSummary = (instanceConfig, globalSettings) => {
      const tc = instanceConfig && typeof instanceConfig === 'object' ? instanceConfig : {};
      const gs = globalSettings && typeof globalSettings === 'object' ? globalSettings : {};
      const mode = normalizeNotificationsRecipientsMode(tc.recipients_mode || gs.recipients_mode);
      if (mode === 'manual_list') {
        const raw = String(tc.manual_to || gs.manual_to || '');
        const count = raw.split(/[\n,]+/).map((s) => s.trim()).filter(Boolean).length;
        return count > 0 ? `Manual (${count})` : 'Manual (empty)';
      }
      if (mode.startsWith('user:')) {
        return mode.slice(5);
      }
      return 'All users';
    };

    let notificationsCurrentSettings = null;
    let notificationsInlineEditInstanceId = '';
    let notificationsCanEdit = false;
    let notificationsModalMode = 'edit';
    let notificationsEditingInstanceId = '';
    let notificationsModalDraft = null;
    let notificationsSearchQuery = '';

    const getGsDefaultReplyTo = () => {
      const users = Array.isArray(loadUsers()) ? loadUsers() : [];
      const gsUser = users.find((u) => /grand\s*secretary/i.test(String((u && u.position) || '')));
      return gsUser ? String(normalizeEmail(gsUser.email) || '').trim() : '';
    };

    const notificationsLoadTypeFields = () => {
      if (!notificationsCurrentSettings) return;
      const selectedTypeId = notificationsTypeSelectEl ? String(notificationsTypeSelectEl.value || '').trim() : '';
      let instance = null;
      if (notificationsModalMode === 'edit') {
        instance = notificationsGetInstance(notificationsCurrentSettings, notificationsEditingInstanceId);
      } else {
        const typeId = normalizeNotificationTypeId(selectedTypeId || (notificationsModalDraft && notificationsModalDraft.type_id) || defaultNotificationTypeId);
        instance = normalizeNotificationsInstance(notificationsModalDraft || { type_id: typeId }, typeId);
        notificationsModalDraft = instance;
        if (notificationsTypeSelectEl) notificationsTypeSelectEl.value = typeId;
      }
      if (!instance) return;
      if (notificationsTypeEnabledInput) notificationsTypeEnabledInput.checked = String(instance.enabled || '0') === '1';
      if (notificationsSubjectInput) notificationsSubjectInput.value = String(instance.subject || '');
      if (notificationsBodyInput) notificationsBodyInput.value = String(instance.body || '');
      if (notificationsRecipientsModeInput) {
        const effectiveMode = instance.recipients_mode || notificationsCurrentSettings.recipients_mode || 'all_users_with_email';
        notificationsRecipientsModeInput.value = effectiveMode;
      }
      if (notificationsManualToInput) notificationsManualToInput.value = String(instance.manual_to || '');
      notificationsSyncModeUi();
    };

    const notificationsFlushTypeFields = () => {
      const typeId = normalizeNotificationTypeId(notificationsTypeSelectEl ? notificationsTypeSelectEl.value : defaultNotificationTypeId);
      const sourceInstance = notificationsModalMode === 'edit'
        ? notificationsGetInstance(notificationsCurrentSettings, notificationsEditingInstanceId)
        : notificationsModalDraft;
      const instance = normalizeNotificationsInstance({
        ...(sourceInstance || {}),
        instance_id: sourceInstance && sourceInstance.instance_id ? sourceInstance.instance_id : createNotificationInstanceId(typeId),
        type_id: typeId,
        enabled: notificationsTypeEnabledInput && notificationsTypeEnabledInput.checked ? '1' : '0',
        subject: notificationsSubjectInput ? String(notificationsSubjectInput.value || '') : '',
        body: notificationsBodyInput ? String(notificationsBodyInput.value || '') : '',
        recipients_mode: notificationsRecipientsModeInput ? String(notificationsRecipientsModeInput.value || '') : '',
        manual_to: notificationsManualToInput ? String(notificationsManualToInput.value || '') : '',
      }, typeId);
      notificationsModalDraft = instance;
      return instance;
    };

    const notificationsReadFormPayload = () => {
      const instance = notificationsFlushTypeFields();
      const base = normalizeNotificationsSettings(notificationsCurrentSettings || notificationsDefaults);
      const instances = Array.isArray(base.instances) ? [...base.instances] : [];
      const idx = notificationsModalMode === 'edit'
        ? instances.findIndex((entry) => String(entry && entry.instance_id || '') === String(instance && instance.instance_id || ''))
        : -1;
      if (idx >= 0) {
        instances[idx] = instance;
      } else {
        instances.push(instance);
      }
      return {
        instance,
        settings: {
          recipients_mode: base.recipients_mode,
          manual_to: String(base.manual_to || ''),
          reply_to: notificationsReplyToInput ? String(notificationsReplyToInput.value || '') : '',
          reply_to_cleared: notificationsReplyToInput ? String(notificationsReplyToInput.value || '').trim() === '' : false,
          signature: notificationsSignatureInput ? String(notificationsSignatureInput.value || '') : '',
          instances,
        },
      };
    };

    const notificationsSetDisabled = (disabled) => {
      const isDisabled = Boolean(disabled);
      const controls = [
        notificationsNewBtn,
        notificationsTypeSelectEl,
        notificationsTypeEnabledInput,
        notificationsRecipientsModeInput,
        notificationsManualToInput,
        notificationsReplyToInput,
        notificationsTestToInput,
        notificationsSubjectInput,
        notificationsBodyInput,
        notificationsSignatureInput,
        notificationsTestBtn,
        notificationsSaveBtn,
      ];
      controls.forEach((el) => {
        if (el) el.disabled = isDisabled;
      });
      if (notificationsListTbody) {
        Array.from(notificationsListTbody.querySelectorAll('button,select')).forEach((el) => {
          el.disabled = isDisabled || !notificationsCanEdit;
        });
      }
      notificationsSyncModeUi();
    };

    const renderNotificationsTable = () => {
      if (!notificationsListTbody || !notificationsCurrentSettings) return;
      const rows = describeNotificationRows(notificationsCurrentSettings.instances || []);
      const query = String(notificationsSearchInput ? notificationsSearchInput.value || '' : notificationsSearchQuery).trim().toLowerCase();
      notificationsSearchQuery = query;

      if (notificationsClearSearchBtn) {
        const hasSearch = query.length > 0;
        notificationsClearSearchBtn.hidden = !hasSearch;
        notificationsClearSearchBtn.disabled = !hasSearch;
      }

      notificationsListTbody.innerHTML = '';

      const filteredRows = rows.filter((row) => {
        if (!query) return true;
        const status = String(row.instance && row.instance.enabled) === '1' ? 'enabled' : 'disabled';
        const recipient = recipientSummary(row.instance, notificationsCurrentSettings);
        const haystack = `${recipient} ${row.displayLabel} ${status}`.toLowerCase();
        return haystack.includes(query);
      });

      filteredRows.forEach((row) => {
        const instance = row.instance;
        if (!instance) return;
        const instanceId = String(instance.instance_id || '');
        const recipient = recipientSummary(instance, notificationsCurrentSettings);
        const isInline = notificationsInlineEditInstanceId === instanceId;
        const tr = document.createElement('tr');
        tr.innerHTML = isInline
          ? `
            <td>${escapeHtml(recipient)}</td>
            <td>${escapeHtml(row.displayLabel)}</td>
            <td>
              <select data-notifications-inline-status="${escapeHtml(instanceId)}">
                <option value="1" ${String(instance.enabled) === '1' ? 'selected' : ''}>Enabled</option>
                <option value="0" ${String(instance.enabled) !== '1' ? 'selected' : ''}>Disabled</option>
              </select>
            </td>
            <td>
              <button type="button" class="btn btn--viewGrey" data-notifications-inline-save="${escapeHtml(instanceId)}">Save</button>
              <button type="button" class="btn btn--ghost" data-notifications-inline-cancel="${escapeHtml(instanceId)}">Cancel</button>
              <button type="button" class="btn btn--editIcon" data-notifications-open-edit="${escapeHtml(instanceId)}" aria-label="Edit"><svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path d="M15.502 1.94a.5.5 0 0 1 0 .706L14.459 3.69l-2-2L13.502.646a.5.5 0 0 1 .707 0l1.293 1.293zm-1.75 2.456-2-2L4.939 9.21a.5.5 0 0 0-.121.196l-.805 2.414a.25.25 0 0 0 .316.316l2.414-.805a.5.5 0 0 0 .196-.12l6.813-6.814z"/><path fill-rule="evenodd" d="M1 13.5A1.5 1.5 0 0 0 2.5 15h11a1.5 1.5 0 0 0 1.5-1.5v-6a.5.5 0 0 0-1 0v6a.5.5 0 0 1-.5.5h-11a.5.5 0 0 1-.5-.5v-11a.5.5 0 0 1 .5-.5H9a.5.5 0 0 0 0-1H2.5A1.5 1.5 0 0 0 1 2.5z"/></svg></button>
            </td>
          `
          : `
            <td>${escapeHtml(recipient)}</td>
            <td>${escapeHtml(row.displayLabel)}</td>
            <td>${String(instance.enabled) === '1' ? 'Enabled' : 'Disabled'}</td>
            <td>
              <button type="button" class="btn btn--editIcon" data-notifications-inline-edit="${escapeHtml(instanceId)}" aria-label="Edit"><svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path d="M15.502 1.94a.5.5 0 0 1 0 .706L14.459 3.69l-2-2L13.502.646a.5.5 0 0 1 .707 0l1.293 1.293zm-1.75 2.456-2-2L4.939 9.21a.5.5 0 0 0-.121.196l-.805 2.414a.25.25 0 0 0 .316.316l2.414-.805a.5.5 0 0 0 .196-.12l6.813-6.814z"/><path fill-rule="evenodd" d="M1 13.5A1.5 1.5 0 0 0 2.5 15h11a1.5 1.5 0 0 0 1.5-1.5v-6a.5.5 0 0 0-1 0v6a.5.5 0 0 1-.5.5h-11a.5.5 0 0 1-.5-.5v-11a.5.5 0 0 1 .5-.5H9a.5.5 0 0 0 0-1H2.5A1.5 1.5 0 0 0 1 2.5z"/></svg></button>
              <button type="button" class="btn btn--x" data-notifications-delete="${escapeHtml(instanceId)}" aria-label="Delete notification"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path d="M5.5 5.5A.5.5 0 0 1 6 6v5a.5.5 0 0 1-1 0V6a.5.5 0 0 1 .5-.5m2.5 0A.5.5 0 0 1 8.5 6v5a.5.5 0 0 1-1 0V6a.5.5 0 0 1 .5-.5m3 .5a.5.5 0 0 0-1 0v5a.5.5 0 0 0 1 0z"/><path d="M14.5 3a1 1 0 0 1-1 1H13l-.777 9.33A2 2 0 0 1 10.23 15H5.77a2 2 0 0 1-1.993-1.67L3 4h-.5a1 1 0 1 1 0-2H5a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1h2.5a1 1 0 0 1 1 1M6 2v1h4V2zm-2 2 .774 9.287A1 1 0 0 0 5.77 14h4.46a1 1 0 0 0 .996-.713L12 4z"/></svg></button>
            </td>
          `;
        notificationsListTbody.appendChild(tr);
      });

      if (notificationsEmptyState) {
        const hasRows = rows.length > 0;
        const hasMatches = filteredRows.length > 0;
        notificationsEmptyState.textContent = hasRows
          ? 'No notifications match your search.'
          : 'No notifications created yet.';
        notificationsEmptyState.hidden = hasMatches;
      }
      notificationsSetDisabled(!notificationsCanEdit);
    };

    const notificationsApplySettings = (settingsRaw) => {
      const s = normalizeNotificationsSettings(settingsRaw);
      notificationsCurrentSettings = s;
      populateNotificationsRecipientOptions();
      if (notificationsRecipientsModeInput) notificationsRecipientsModeInput.value = s.recipients_mode;
      if (notificationsManualToInput) notificationsManualToInput.value = String(s.manual_to || '');
      if (notificationsReplyToInput) {
        const gsReplyTo = getGsDefaultReplyTo();
        const effectiveReplyTo = s.reply_to || (!s.reply_to_cleared ? gsReplyTo : '');
        notificationsReplyToInput.value = String(effectiveReplyTo || '');
        notificationsReplyToInput.placeholder = 'email@example.org';
      }
      if (notificationsSignatureInput) notificationsSignatureInput.value = String(s.signature || '');
      notificationsLoadTypeFields();
      notificationsSyncModeUi();
      renderNotificationsTable();
    };

    const saveNotificationsSettings = async (settingsRaw) => {
      const payload = normalizeNotificationsSettings(settingsRaw);

      if (!IS_WP_SHARED_MODE) {
        const saved = saveNotificationsSettingsLocal(payload);
        notificationsApplySettings(saved);
        setNotificationsStatus('Saved (local mode).');
        return true;
      }

      const url = wpJoin('acgl-fms/v1/admin/notifications-settings');
      const res = await wpFetchJson(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      let data = null;
      try { data = await res.json(); } catch { data = null; }

      if (!res.ok || !data || !data.ok) {
        const msg = data && data.error ? String(data.error) : 'Could not save notification settings.';
        setNotificationsStatus(msg, true);
        return false;
      }

      notificationsApplySettings(data.settings || payload);
      setNotificationsStatus('Saved.');
      return true;
    };

    const openNotificationsModal = (typeId, mode) => {
      if (!notificationsModal || !notificationsCurrentSettings) return;
      notificationsModalMode = mode === 'create' ? 'create' : 'edit';
      if (notificationsModalTitle) {
        notificationsModalTitle.textContent = notificationsModalMode === 'create' ? 'Create New Notification' : 'Edit Notification';
      }

      notificationsEditingInstanceId = '';
      notificationsModalDraft = null;
      if (notificationsModalMode === 'create') {
        const pickId = normalizeNotificationTypeId(typeId || defaultNotificationTypeId);
        notificationsModalDraft = notificationsInstanceDefaultForType(pickId);
        populateNotificationsTypeSelect(allNotificationTypeIds);
        if (notificationsTypeSelectEl) {
          notificationsTypeSelectEl.disabled = false;
          notificationsTypeSelectEl.value = pickId;
        }
      } else {
        const instance = notificationsGetInstance(notificationsCurrentSettings, typeId);
        if (!instance) return;
        notificationsEditingInstanceId = String(instance.instance_id || '');
        populateNotificationsTypeSelect([instance.type_id]);
        if (notificationsTypeSelectEl) {
          notificationsTypeSelectEl.disabled = true;
          notificationsTypeSelectEl.value = String(instance.type_id || defaultNotificationTypeId);
        }
      }
      notificationsLoadTypeFields();
      notificationsSyncModeUi();
      openSimpleModal(notificationsModal, '#notificationsTypeSelect');
    };

    const closeNotificationsModal = () => {
      notificationsEditingInstanceId = '';
      notificationsModalDraft = null;
      if (notificationsTypeSelectEl) notificationsTypeSelectEl.disabled = false;
      closeSimpleModal(notificationsModal);
    };

    const loadNotificationsSettingsFromWp = async () => {
      if (!IS_WP_SHARED_MODE) {
        const localSettings = loadNotificationsSettingsLocal();
        notificationsApplySettings(localSettings);
        const hasAnyUsers = loadUsers().length > 0;
        const currentUser = getCurrentUser();
        notificationsCanEdit = !hasAnyUsers || (currentUser ? canWrite(currentUser, 'settings_email_notifications') : false);
        notificationsSetDisabled(!notificationsCanEdit);
        setNotificationsStatus(notificationsCanEdit ? 'Loaded (local mode).' : 'View only for your account.');
        return;
      }

      if (!getWpToken()) {
        notificationsCanEdit = false;
        notificationsSetDisabled(true);
        setNotificationsStatus('Please sign in to load notification settings.', true);
        return;
      }

      setNotificationsStatus('Loading...');
      setNotificationsLastTest('');
      try {
        const url = wpJoin('acgl-fms/v1/admin/notifications-settings');
        const res = await wpFetchJson(url, { method: 'GET' });
        let data = null;
        try { data = await res.json(); } catch { data = null; }

        if (!res.ok || !data || !data.ok) {
          const msg = data && data.error ? String(data.error) : 'Could not load notification settings.';
          notificationsCanEdit = false;
          notificationsSetDisabled(true);
          setNotificationsStatus(msg, true);
          return;
        }

        const wpSettings = data.settings || {};
        notificationsApplySettings(wpSettings);
        const hasAnyUsers = loadUsers().length > 0;
        const currentUser = getCurrentUser();
        notificationsCanEdit = !hasAnyUsers || (currentUser ? canWrite(currentUser, 'settings_email_notifications') : false);
        notificationsSetDisabled(!notificationsCanEdit);
        setNotificationsStatus(notificationsCanEdit ? 'Loaded.' : 'View only for your account.');
      } catch {
        notificationsCanEdit = false;
        notificationsSetDisabled(true);
        setNotificationsStatus('Could not load notification settings.', true);
      }
    };

    if (notificationsRecipientsModeInput && !notificationsRecipientsModeInput.dataset.bound) {
      notificationsRecipientsModeInput.dataset.bound = '1';
      notificationsRecipientsModeInput.addEventListener('change', notificationsSyncModeUi);
    }

    if (notificationsTypeSelectEl && !notificationsTypeSelectEl.dataset.bound) {
      notificationsTypeSelectEl.dataset.bound = '1';
      notificationsTypeSelectEl.addEventListener('change', notificationsLoadTypeFields);
    }

    if (notificationsNewBtn && !notificationsNewBtn.dataset.bound) {
      notificationsNewBtn.dataset.bound = '1';
      notificationsNewBtn.addEventListener('click', () => {
        if (!requireSettingsEditAccess('Email Notifications is view only for your account.', 'settings_email_notifications')) return;
        openNotificationsModal('', 'create');
      });
    }

    if (notificationsSearchInput && !notificationsSearchInput.dataset.bound) {
      notificationsSearchInput.dataset.bound = '1';
      notificationsSearchInput.addEventListener('input', () => {
        notificationsSearchQuery = String(notificationsSearchInput.value || '').trim().toLowerCase();
        renderNotificationsTable();
      });
    }

    if (notificationsClearSearchBtn && notificationsSearchInput && !notificationsClearSearchBtn.dataset.bound) {
      notificationsClearSearchBtn.dataset.bound = '1';
      notificationsClearSearchBtn.addEventListener('click', () => {
        notificationsSearchInput.value = '';
        notificationsSearchQuery = '';
        notificationsClearSearchBtn.hidden = true;
        notificationsClearSearchBtn.disabled = true;
        notificationsSearchInput.focus();
        renderNotificationsTable();
      });
    }

    if (notificationsListTbody && !notificationsListTbody.dataset.bound) {
      notificationsListTbody.dataset.bound = '1';
      notificationsListTbody.addEventListener('click', async (e) => {
        if (!requireSettingsEditAccess('Email Notifications is view only for your account.', 'settings_email_notifications')) return;
        const inlineEditBtn = e.target.closest('[data-notifications-inline-edit]');
        const inlineCancelBtn = e.target.closest('[data-notifications-inline-cancel]');
        const inlineSaveBtn = e.target.closest('[data-notifications-inline-save]');
        const deleteBtn = e.target.closest('[data-notifications-delete]');
        const openEditBtn = e.target.closest('[data-notifications-open-edit]');

        if (inlineEditBtn) {
          notificationsInlineEditInstanceId = String(inlineEditBtn.getAttribute('data-notifications-inline-edit') || '');
          renderNotificationsTable();
          return;
        }

        if (inlineCancelBtn) {
          notificationsInlineEditInstanceId = '';
          renderNotificationsTable();
          return;
        }

        if (openEditBtn) {
          const id = String(openEditBtn.getAttribute('data-notifications-open-edit') || '');
          openNotificationsModal(id, 'edit');
          return;
        }

        if (inlineSaveBtn && notificationsCurrentSettings) {
          const id = String(inlineSaveBtn.getAttribute('data-notifications-inline-save') || '');
          const statusEl = notificationsListTbody.querySelector(`[data-notifications-inline-status="${CSS.escape(id)}"]`);
          if (!statusEl) return;
          const next = normalizeNotificationsSettings({ ...notificationsCurrentSettings });
          const instanceIdx = notificationsGetInstanceIndex(next, id);
          if (instanceIdx < 0) return;
          next.instances[instanceIdx] = {
            ...next.instances[instanceIdx],
            enabled: String(statusEl.value || '0') === '1' ? '1' : '0',
          };
          notificationsSetDisabled(true);
          const ok = await saveNotificationsSettings(next);
          notificationsSetDisabled(!notificationsCanEdit);
          if (ok) {
            notificationsInlineEditInstanceId = '';
            renderNotificationsTable();
          }
          return;
        }

        if (deleteBtn && notificationsCurrentSettings) {
          const id = String(deleteBtn.getAttribute('data-notifications-delete') || '');
          if (!id) return;
          const ok = window.confirm('Delete this notification?');
          if (!ok) return;
          const next = normalizeNotificationsSettings({ ...notificationsCurrentSettings });
          next.instances = (next.instances || []).filter((instance) => String(instance && instance.instance_id || '') !== id);
          notificationsSetDisabled(true);
          const saved = await saveNotificationsSettings(next);
          notificationsSetDisabled(!notificationsCanEdit);
          if (saved) {
            notificationsInlineEditInstanceId = '';
            renderNotificationsTable();
          }
        }
      });
    }

    if (notificationsForm && !notificationsForm.dataset.bound) {
      notificationsForm.dataset.bound = '1';
      notificationsForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        if (!requireSettingsEditAccess('Email Notifications is view only for your account.', 'settings_email_notifications')) return;
        if (!notificationsCurrentSettings) return;

        const formState = notificationsReadFormPayload();
        const payload = formState.settings;

        notificationsSetDisabled(true);
        const ok = await saveNotificationsSettings(payload);
        notificationsSetDisabled(!notificationsCanEdit);
        if (ok) {
          notificationsInlineEditInstanceId = '';
          closeNotificationsModal();
          renderNotificationsTable();
        }
      });
    }

    if (notificationsTestBtn && !notificationsTestBtn.dataset.bound) {
      notificationsTestBtn.dataset.bound = '1';
      notificationsTestBtn.addEventListener('click', async () => {
        if (!requireSettingsEditAccess('Email Notifications is view only for your account.', 'settings_email_notifications')) return;
        if (!IS_WP_SHARED_MODE) {
          setNotificationsStatus('Test send is available in WordPress shared mode only.');
          return;
        }

        const formState = notificationsReadFormPayload();
        const typeId = String(formState.instance && formState.instance.type_id || defaultNotificationTypeId);
        const payload = {
          to: notificationsTestToInput ? String(notificationsTestToInput.value || '') : '',
          type: typeId,
          instance_id: String(formState.instance && formState.instance.instance_id || ''),
          settings: formState.settings,
        };

        notificationsSetDisabled(true);
        setNotificationsStatus('Sending test email...');
        setNotificationsLastTest('');

        try {
          const url = wpJoin('acgl-fms/v1/admin/notifications-settings/test');
          const res = await wpFetchJson(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
          });
          let data = null;
          try { data = await res.json(); } catch { data = null; }

          notificationsSetDisabled(!notificationsCanEdit);

          if (!res.ok || !data || !data.ok) {
            const msg = data && data.error ? String(data.error) : 'Could not send test email.';
            setNotificationsStatus(msg, true);
            return;
          }

          const sent = Number(data.sent || 0);
          setNotificationsStatus(sent > 0 ? `Test email sent to ${sent} recipient(s).` : 'Test email sent.');
          const recipients = Array.isArray(data.to)
            ? data.to.map((v) => String(v || '').trim()).filter(Boolean)
            : [];
          const recipientText = recipients.length > 0
            ? (recipients.length <= 3 ? recipients.join(', ') : `${recipients.slice(0, 3).join(', ')}, +${recipients.length - 3} more`)
            : `${sent} recipient(s)`;
          setNotificationsLastTest(`Last test: ${new Date().toLocaleString()} | To: ${recipientText}`);
        } catch {
          notificationsSetDisabled(!notificationsCanEdit);
          setNotificationsStatus('Could not send test email.', true);
        }
      });
    }

    if (notificationsModal && !notificationsModal.dataset.bound) {
      notificationsModal.dataset.bound = '1';
      notificationsModal.addEventListener('click', (e) => {
        const closeTarget = e.target.closest('[data-notifications-modal-close]');
        if (closeTarget) closeNotificationsModal();
      });
    }

    notificationsSyncModeUi();
    void loadNotificationsSettingsFromWp();
  }

  if (backupOpenWpAdminLink) {
    const adminUrl = getWpAdminSettingsUrl();
    if (adminUrl) {
      backupOpenWpAdminLink.href = adminUrl;
      backupOpenWpAdminLink.hidden = false;
      if (backupWpAdminUnavailable) backupWpAdminUnavailable.hidden = true;
    } else {
      backupOpenWpAdminLink.hidden = true;
      if (backupWpAdminUnavailable) backupWpAdminUnavailable.hidden = false;
    }
  }

  // Settings page roles management
  if (typeof initRolesSettingsPage === 'function') initRolesSettingsPage();
  if (typeof initBackupPage === 'function') initBackupPage();

  // [bundle-strip:settings-remove-request-form] removed in page-specific build.

  document.addEventListener('keydown', (e) => {
    if (e.key !== 'Escape') return;

    const milageViewModal = document.getElementById('milageViewModal');
    if (milageViewModal && milageViewModal.classList.contains('is-open')) {
      closeMilageViewModal();
      return;
    }
    const milageModal = document.getElementById('milageModal');
    if (milageModal && milageModal.classList.contains('is-open')) {
      closeMilageModal();
      return;
    }

    const itemModal = document.getElementById('itemModal');
    if (itemModal && itemModal.classList.contains('is-open')) {
      closeItemModal();
      return;
    }

    const backlogCommentModal = document.getElementById('backlogCommentModal');
    if (backlogCommentModal && backlogCommentModal.classList.contains('is-open')) {
      closeBacklogCommentModal();
      return;
    }
    const backlogItemModal = document.getElementById('backlogItemModal');
    if (backlogItemModal && backlogItemModal.classList.contains('is-open')) {
      closeBacklogItemModal();
      return;
    }

    if (modal && modal.classList.contains('is-open')) closeModal();
  });

  // Initial render for list page
  if (tbody) {
    initPaymentOrdersListPage();
    initPaymentOrdersHeaderFilters();
    seedMockOrdersIfDev();
    applyPaymentOrdersView();

    try {
      const params = new URLSearchParams(window.location.search || '');
      const targetId = String(params.get('orderId') || '').trim();
      const targetYearRaw = String(params.get('year') || '').trim();
      const targetYear = /^\d{4}$/.test(targetYearRaw) ? Number(targetYearRaw) : getActiveBudgetYear();
      if (targetId) {
        const order = loadOrders(targetYear).find((o) => String((o && o.id) || '') === targetId);
        if (order) {
          openModalWithOrder(order);
        }
      }
    } catch {
      // ignore
    }
  }

  if (newPoBtn) {
    newPoBtn.addEventListener('click', () => {
      window.location.href = withWpEmbedParams('index.html?new=1');
    });
  }

  if (reconcileTbody) {
    initReconciliationListPage();
  }

  if (incomeTbody) {
    initIncomeListPage();
  }

  if (wiseEurTbody) {
    initWiseEurListPage();
  }

  if (wiseUsdTbody) {
    initWiseUsdListPage();
  }

  if (gsLedgerTbody) {
    initGsLedgerListPage();
  }

  if (moneyTransfersTbody) {
    initMoneyTransfersListPage();
  }

  if (mtBuilderTbody) {
    initMoneyTransferBuilderPage();
  }

  await initSharedTableEnhancements();

  
  // [bundle-strip:settings-remove-itemize] removed in page-specific build.


  // [bundle-fix:income-key-helper] Income section is stripped in this bundle,
  // but dev seeding still references this helper during startup.
  function getIncomeKeyForYear(year) {
    const y = Number(year);
    if (!Number.isInteger(y)) return null;
    return `payment_order_income_${y}_v1`;
  }

})().catch((err) => {
  try {
    console.error('App bootstrap failed', err);
  } catch {
    // ignore
  }

  try {
    const h = String(window.location.hostname || '').toLowerCase();
    const isDev = h === 'localhost' || h === '127.0.0.1' || h === '0.0.0.0';
    if (!isDev) return;

    const msg = err && typeof err === 'object'
      ? String(err.stack || err.message || err)
      : String(err);
    window.alert(`App crashed during startup (dev):\n\n${msg}`);
  } catch {
    // ignore
  }
});
