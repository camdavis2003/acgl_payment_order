/* Generated from app.js by generate-page-bundles.js: menu. Do not edit manually. */
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

  function syncBudgetFromLedgerSafe(year, sourceLabel) {
    try {
      return syncBudgetFromLedger(year);
    } catch (err) {
      console.error('[Budget Sync] Failed', {
        source: sourceLabel || 'unknown',
        year,
        error: err,
      });
      return { ok: false, reason: 'exception' };
    }
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
  const backToFormLink = document.getElementById('backToFormLink');

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

  const PAYMENT_ORDERS_COL_TYPES = {
    paymentOrderNo: 'text',
    date: 'date',
    source: 'text',
    name: 'text',
    euro: 'number',
    usd: 'number',
    budgetNumber: 'text',
    purpose: 'text',
    with: 'text',
    status: 'text',
  };

  const paymentOrdersViewState = {
    globalFilter: '',
    filters: {
      paymentOrderNo: '',
      date: { kind: 'dateRange', from: '', to: '' },
      source: '',
      name: '',
      euro: '',
      usd: '',
      budgetNumber: '',
      purpose: '',
      with: { kind: 'multiselect', mode: 'include', values: [] },
      status: { kind: 'multiselect', mode: 'include', values: [] },
    },
    sortKey: null,
    sortDir: 'asc',
    defaultEmptyText: null,
  };

  function ensurePaymentOrdersDefaultEmptyText() {
    if (!emptyState) return;
    if (paymentOrdersViewState.defaultEmptyText !== null) return;
    paymentOrdersViewState.defaultEmptyText = emptyState.textContent || 'No requests submitted yet.';
  }

  function normalizeTextForSearch(value) {
    return String(value ?? '')
      // Normalize common formatting characters so search is forgiving.
      .replace(/\u00A0/g, ' ') // NBSP
      .replace(/[\u2010\u2011\u2012\u2013\u2014\u2015\u2212]/g, '-') // hyphen/dash/minus variants
      .toLowerCase()
      // Treat spacing around dashes as equivalent (e.g. "26 - 02" == "26-02").
      .replace(/\s*-\s*/g, '-')
      .replace(/\s+/g, ' ')
      .trim();
  }

  function getOrderDisplayValueForColumn(order, colKey) {
    if (!order) return '';
    switch (colKey) {
      case 'paymentOrderNo':
        return formatPaymentOrderNoForDisplay(order.paymentOrderNo);
      case 'date':
        return formatDate(order.date);
      case 'source':
        return String(order.source || '').trim();
      case 'name':
        return order.name || '';
      case 'euro':
        return formatCurrency(order.euro, 'EUR');
      case 'usd':
        return formatCurrency(order.usd, 'USD');
      case 'budgetNumber':
        return formatBudgetNumberForDisplay(order.budgetNumber);
      case 'purpose':
        return order.purpose || '';
      case 'with':
        return getOrderWithLabel(order);
      case 'status':
        return getOrderStatusLabel(order);
      default:
        return '';
    }
  }

  function getOrderSortValueForColumn(order, colKey, colType) {
    if (!order) return null;
    if (colType === 'number') {
      const raw = colKey === 'euro' ? order.euro : colKey === 'usd' ? order.usd : null;
      const num = raw === null || raw === undefined || raw === '' ? null : Number(raw);
      return Number.isFinite(num) ? num : null;
    }
    if (colType === 'date') {
      // Stored dates are ISO yyyy-mm-dd; lexical sort matches chronological.
      const d = order.date || '';
      return String(d);
    }
    return normalizeTextForSearch(getOrderDisplayValueForColumn(order, colKey));
  }

  function sortOrdersForView(orders, sortKey, sortDir) {
    const dir = sortDir === 'desc' ? -1 : 1;

    // Default sort: latest payment order number first.
    if (!sortKey) {
      const withIndex = orders.map((order, index) => ({ order, index }));
      withIndex.sort((a, b) => {
        const ap = getPaymentOrderNoSortParts(a.order && a.order.paymentOrderNo);
        const bp = getPaymentOrderNoSortParts(b.order && b.order.paymentOrderNo);

        if (ap && bp) {
          if (ap.year2 !== bp.year2) return bp.year2 - ap.year2;
          if (ap.seq !== bp.seq) return bp.seq - ap.seq;
        } else if (ap) {
          return -1;
        } else if (bp) {
          return 1;
        }

        const createdCmp = String(b.order.createdAt).localeCompare(String(a.order.createdAt));
        return createdCmp === 0 ? a.index - b.index : createdCmp;
      });
      return withIndex.map((x) => x.order);
    }

    const colType = PAYMENT_ORDERS_COL_TYPES[sortKey] || 'text';

    const withIndex = orders.map((order, index) => ({ order, index }));
    withIndex.sort((a, b) => {
      const av = getOrderSortValueForColumn(a.order, sortKey, colType);
      const bv = getOrderSortValueForColumn(b.order, sortKey, colType);

      if (av === null && bv === null) return a.index - b.index;
      if (av === null) return 1;
      if (bv === null) return -1;

      if (colType === 'number') {
        const cmp = av === bv ? 0 : av < bv ? -1 : 1;
        return cmp === 0 ? a.index - b.index : cmp * dir;
      }

      const cmp = String(av).localeCompare(String(bv));
      return cmp === 0 ? a.index - b.index : cmp * dir;
    });

    return withIndex.map((x) => x.order);
  }

  function hasActiveFilterValue(filterValue) {
    if (!filterValue) return false;
    if (typeof filterValue === 'string') return normalizeTextForSearch(filterValue) !== '';
    if (typeof filterValue !== 'object') return false;

    if (filterValue.kind === 'dateRange') {
      const from = String(filterValue.from || '').trim();
      const to = String(filterValue.to || '').trim();
      return Boolean(from || to);
    }

    if (filterValue.kind === 'multiselect') {
      return Array.isArray(filterValue.values) && filterValue.values.length > 0;
    }

    return false;
  }

  function filterOrdersForView(orders, filters, globalFilter) {
    const activeColumnFilters = Object.entries(filters || {}).filter(([, v]) => hasActiveFilterValue(v));
    const globalNeedle = normalizeTextForSearch(globalFilter);
    const anyGlobal = globalNeedle !== '';
    if (activeColumnFilters.length === 0 && !anyGlobal) return orders;

    const allFilterableCols = Object.keys(PAYMENT_ORDERS_COL_TYPES);

    return (orders || []).filter((o) => {
      if (anyGlobal) {
        const matchesAny = allFilterableCols.some((colKey) => {
          const hay = normalizeTextForSearch(getOrderDisplayValueForColumn(o, colKey));
          return hay.includes(globalNeedle);
        });
        if (!matchesAny) return false;
      }

      return activeColumnFilters.every(([colKey, filterValue]) => {
        if (typeof filterValue === 'string') {
          const needle = normalizeTextForSearch(filterValue);
          const haystack = normalizeTextForSearch(getOrderDisplayValueForColumn(o, colKey));
          return haystack.includes(needle);
        }

        if (!filterValue || typeof filterValue !== 'object') return true;

        if (filterValue.kind === 'dateRange') {
          const from = String(filterValue.from || '').trim();
          const to = String(filterValue.to || '').trim();
          const d = String((o && o.date) || '').trim();
          if (!d) return false;
          if (from && d < from) return false;
          if (to && d > to) return false;
          return true;
        }

        if (filterValue.kind === 'multiselect') {
          const values = Array.isArray(filterValue.values) ? filterValue.values : [];
          if (values.length === 0) return true;

          const mode = filterValue.mode === 'exclude' ? 'exclude' : 'include';
          const cell = normalizeTextForSearch(getOrderDisplayValueForColumn(o, colKey));
          const selected = values.map((v) => normalizeTextForSearch(v));
          const isSelected = selected.includes(cell);
          return mode === 'exclude' ? !isSelected : isSelected;
        }

        return true;
      });
    });
  }

  function updatePaymentOrdersSortIndicators() {
    if (!tbody) return;
    const table = tbody.closest('table');
    if (!table) return;

    const sortKey = paymentOrdersViewState.sortKey;
    const sortDir = paymentOrdersViewState.sortDir === 'desc' ? 'desc' : 'asc';

    const ths = Array.from(table.querySelectorAll('thead th[data-sort-key]'));
    for (const th of ths) {
      const colKey = th.getAttribute('data-sort-key');
      let aria = 'none';
      if (colKey && sortKey === colKey) {
        aria = sortDir === 'desc' ? 'descending' : 'ascending';
      }
      th.setAttribute('aria-sort', aria);
    }
  }

  function initPaymentOrdersColumnSorting() {
    if (!tbody) return;
    const table = tbody.closest('table');
    if (!table) return;
    if (table.dataset.sortBound === '1') return;

    const ths = Array.from(table.querySelectorAll('thead th[data-sort-key]'));
    if (ths.length === 0) return;

    table.dataset.sortBound = '1';

    function applySortForKey(colKey) {
      if (!colKey) return;

      if (paymentOrdersViewState.sortKey === colKey) {
        paymentOrdersViewState.sortDir = paymentOrdersViewState.sortDir === 'asc' ? 'desc' : 'asc';
      } else {
        paymentOrdersViewState.sortKey = colKey;
        paymentOrdersViewState.sortDir = 'asc';
      }

      applyPaymentOrdersView();
    }

    for (const th of ths) {
      th.classList.add('is-sortable');
      if (!th.hasAttribute('tabindex')) th.setAttribute('tabindex', '0');
      if (!th.hasAttribute('aria-sort')) th.setAttribute('aria-sort', 'none');

      th.addEventListener('click', () => {
        const colKey = th.getAttribute('data-sort-key');
        applySortForKey(colKey);
      });

      th.addEventListener('keydown', (e) => {
        if (e.key !== 'Enter' && e.key !== ' ') return;
        e.preventDefault();
        const colKey = th.getAttribute('data-sort-key');
        applySortForKey(colKey);
      });
    }

    updatePaymentOrdersHeaderIndicators();
  }

  const PAYMENT_ORDER_PROGRESS_WITH_STEPS = ['Requestor', 'Grand Secretary', 'Grand Master', 'Grand Treasurer', 'Archives'];

  function getPaymentOrderProgressLastTouchedEvent(order, withLabel) {
    const effectiveWith = normalizeWith(withLabel);
    const tl = Array.isArray(order && order.timeline) ? order.timeline : [];

    for (let i = tl.length - 1; i >= 0; i -= 1) {
      const evt = tl[i];
      if (!evt) continue;
      const actorWith = normalizeWith(evt.actorWith);
      if (actorWith && actorWith === effectiveWith) {
        return {
          at: String(evt.at || ''),
          status: normalizeOrderStatus(evt.actorStatus),
          comment: String(evt.comment || ''),
          user: String(evt.user || ''),
          actorWith,
          with: normalizeWith(evt.with),
        };
      }

      const evtWith = normalizeWith(evt.with);
      if (evtWith === effectiveWith) {
        return {
          at: String(evt.at || ''),
          status: normalizeOrderStatus(evt.status),
          comment: String(evt.comment || ''),
          user: String(evt.user || ''),
          actorWith: normalizeWith(evt.actorWith),
          with: evtWith,
        };
      }
    }

    return {
      at: String((order && order.updatedAt) || (order && order.createdAt) || ''),
      status: normalizeOrderStatus(order && order.status),
      comment: '',
      user: '',
      actorWith: '',
      with: effectiveWith,
    };
  }

  function initUnifiedHoverTooltips() {
    if (window.ACGLHoverPopup && typeof window.ACGLHoverPopup.init === 'function') {
      window.ACGLHoverPopup.init();
    }
  }

  function bindUnifiedHoverTooltipScope(scopeEl) {
    if (window.ACGLHoverPopup && typeof window.ACGLHoverPopup.bindScope === 'function') {
      window.ACGLHoverPopup.bindScope(scopeEl);
      return;
    }
    initUnifiedHoverTooltips();
  }

  function initPoProgressStatusTooltips(progressRoot) {
    bindUnifiedHoverTooltipScope(progressRoot);
    hidePoProgressTooltip = (typeof window.__acglHideUnifiedHoverTooltip === 'function')
      ? window.__acglHideUnifiedHoverTooltip
      : () => {};
  }

  function initBudgetCodeHoverTooltips() {
    initUnifiedHoverTooltips();
  }

  initBudgetCodeHoverTooltips();

  function getPaymentOrderProgressStepAbbrev(step) {
    const s = normalizeWith(step);
    if (s === 'Grand Secretary') return 'GS';
    if (s === 'Grand Master') return 'GM';
    if (s === 'Grand Treasurer') return 'GT';
    if (s === 'Requestor') return 'REQ';
    if (s === 'Archives') return 'ARC';
    return String(step || '').trim().slice(0, 3).toUpperCase();
  }

  function renderPaymentOrderProgressGraphHtml({ order, withLabel, statusLabel, actorOverride }) {
    const effectiveWith = normalizeWith(withLabel);
    const idxRaw = PAYMENT_ORDER_PROGRESS_WITH_STEPS.findIndex((w) => w === effectiveWith);
    const activeIdx = idxRaw >= 0 ? idxRaw : 0;
    const activeStatus = normalizeOrderStatus(statusLabel);

    const tl = Array.isArray(order && order.timeline) ? order.timeline : [];
    let maxReachedIdx = activeIdx;
    for (let i = 0; i < tl.length; i += 1) {
      const evt = tl[i];
      if (!evt) continue;
      const labels = [evt.with, evt.actorWith];
      for (const lbl of labels) {
        const w = normalizeWith(lbl);
        const idx = PAYMENT_ORDER_PROGRESS_WITH_STEPS.findIndex((x) => x === w);
        if (idx > maxReachedIdx) maxReachedIdx = idx;
      }
    }

    // Progressive + monotonic: show steps up to the farthest stage ever reached.
    // If the PO is Returned, do not remove later bubbles.
    const occurred = PAYMENT_ORDER_PROGRESS_WITH_STEPS.slice(0, maxReachedIdx + 1);

    const pieces = [];
    for (let i = 0; i < occurred.length; i += 1) {
      const step = occurred[i];
      const state = i === activeIdx ? 'is-active' : 'is-done';

      const touched = getPaymentOrderProgressLastTouchedEvent(order, step);
      const overrideForStep = actorOverride
        && normalizeWith(actorOverride.with) === normalizeWith(step)
        && String(actorOverride.status || '').trim()
        ? actorOverride
        : null;

      const metaStatus = i === activeIdx
        ? activeStatus
        : (overrideForStep ? normalizeOrderStatus(overrideForStep.status) : (touched.status || '—'));
      const metaDate = formatIsoDateOnly(overrideForStep ? overrideForStep.at : touched.at);

      const statusTooltipText = (() => {
        const st = normalizeOrderStatus(metaStatus);
        if (st !== 'Returned' && st !== 'Rejected') return '';

        const who = normalizeWith(touched && touched.actorWith);
        const whoUser = String((touched && touched.user) || '').trim();
        const whoLabel = who ? (whoUser ? `${who} (${whoUser})` : who) : (whoUser || '');

        if (st === 'Returned') {
          const returnedTo = normalizeWith(touched && touched.with) || normalizeWith(step) || '—';
          const returnedBy = who || '—';
          const comment = String((touched && touched.comment) || '').replace(/\s+/g, ' ').trim() || '—';
          return `Returned to the ${returnedTo} by the ${returnedBy} for the following reason: ${comment}`;
        }

        if (st === 'Rejected') {
          const comment = String((touched && touched.comment) || '').replace(/\s+/g, ' ').trim();
          const base = whoLabel ? `Rejected by ${whoLabel}` : 'Rejected';
          return comment ? `${base}: ${comment}` : base;
        }

        return '';
      })();

      const statusText = escapeHtml(metaStatus || '—');
      const statusHtml = statusTooltipText
        ? `<span class="poProgress__status" data-po-tooltip="${escapeHtml(statusTooltipText)}" tabindex="0">${statusText}</span>`
        : statusText;

      const meta = `<div class="poProgress__meta"><div>${statusHtml}</div><div>${escapeHtml(metaDate || '—')}</div></div>`;

      pieces.push(`
        <div class="poProgress__node ${state}" role="listitem">
          <div class="poProgress__pill" title="${escapeHtml(step)}" aria-label="${escapeHtml(step)}">${escapeHtml(getPaymentOrderProgressStepAbbrev(step))}</div>
          ${meta}
        </div>
      `);

      if (i !== occurred.length - 1) {
        pieces.push('<div class="poProgress__connector" aria-hidden="true"></div>');
      }
    }

    return `
      <div class="poProgress__track" role="list" aria-label="Payment Order workflow progress">
        ${pieces.join('')}
      </div>
    `;
  }

  function updatePaymentOrdersHeaderIndicators() {
    const menus = Array.from(document.querySelectorAll('[data-th-menu][data-col-key]'));
    for (const menu of menus) {
      const colKey = menu.getAttribute('data-col-key');
      const btn = menu.querySelector('[data-th-menu-btn]');
      if (!btn) continue;

      const hasFilter = colKey && hasActiveFilterValue(paymentOrdersViewState.filters[colKey]);
      const isSorted = paymentOrdersViewState.sortKey === colKey;
      btn.classList.toggle('is-active', hasFilter || isSorted);
    }

    updatePaymentOrdersSortIndicators();

    const globalInput = document.getElementById('ordersGlobalSearch');
    if (globalInput) {
      globalInput.classList.toggle(
        'input-active',
        normalizeTextForSearch(paymentOrdersViewState.globalFilter) !== ''
      );
    }

    if (ordersClearSearchBtn) {
      const hasSearch = normalizeTextForSearch(paymentOrdersViewState.globalFilter) !== '';
      ordersClearSearchBtn.hidden = !hasSearch;
      ordersClearSearchBtn.disabled = !hasSearch;
    }
  }

  function updatePaymentOrdersTotals(orders) {
    const grandEuroEl = document.getElementById('ordersTotalGrandEuro');
    const grandUsdEl = document.getElementById('ordersTotalGrandUsd');
    const approvedEuroEl = document.getElementById('ordersTotalApprovedEuro');
    const approvedUsdEl = document.getElementById('ordersTotalApprovedUsd');
    const unapprovedEuroEl = document.getElementById('ordersTotalUnapprovedEuro');
    const unapprovedUsdEl = document.getElementById('ordersTotalUnapprovedUsd');

    if (
      !grandEuroEl &&
      !grandUsdEl &&
      !approvedEuroEl &&
      !approvedUsdEl &&
      !unapprovedEuroEl &&
      !unapprovedUsdEl
    ) {
      return;
    }

    let grandEuro = 0;
    let grandUsd = 0;
    let approvedEuro = 0;
    let approvedUsd = 0;
    let unapprovedEuro = 0;
    let unapprovedUsd = 0;

    for (const o of orders || []) {
      const e = Number(o && o.euro);
      const u = Number(o && o.usd);
      const euro = Number.isFinite(e) ? e : 0;
      const usd = Number.isFinite(u) ? u : 0;

      grandEuro += euro;
      grandUsd += usd;

      const status = normalizeOrderStatus(o && o.status);
      const isApprovedOrPaid = status === 'Approved' || status === 'Paid';

      if (isApprovedOrPaid) {
        approvedEuro += euro;
        approvedUsd += usd;
      } else {
        unapprovedEuro += euro;
        unapprovedUsd += usd;
      }
    }

    if (grandEuroEl) grandEuroEl.textContent = formatCurrency(grandEuro, 'EUR');
    if (grandUsdEl) grandUsdEl.textContent = formatCurrency(grandUsd, 'USD');
    if (approvedEuroEl) approvedEuroEl.textContent = formatCurrency(approvedEuro, 'EUR');
    if (approvedUsdEl) approvedUsdEl.textContent = formatCurrency(approvedUsd, 'USD');
    if (unapprovedEuroEl) unapprovedEuroEl.textContent = formatCurrency(unapprovedEuro, 'EUR');
    if (unapprovedUsdEl) unapprovedUsdEl.textContent = formatCurrency(unapprovedUsd, 'USD');
  }

  function applyPaymentOrdersView() {
    if (!tbody || !emptyState) return;
    ensurePaymentOrdersDefaultEmptyText();

    const year = getActiveBudgetYear();
    const allOrders = loadOrders(year);
    const filtered = filterOrdersForView(
      allOrders,
      paymentOrdersViewState.filters,
      paymentOrdersViewState.globalFilter
    );
    const sorted = sortOrdersForView(filtered, paymentOrdersViewState.sortKey, paymentOrdersViewState.sortDir);

    const anyFilter =
      normalizeTextForSearch(paymentOrdersViewState.globalFilter) !== '' ||
      Object.values(paymentOrdersViewState.filters).some((v) => hasActiveFilterValue(v));
    if (anyFilter && allOrders.length > 0 && sorted.length === 0) {
      emptyState.textContent = 'No payment orders match your search.';
    } else {
      emptyState.textContent = paymentOrdersViewState.defaultEmptyText;
    }

    renderOrders(sorted);
    updatePaymentOrdersTotals(sorted);
    updatePaymentOrdersHeaderIndicators();
  }

  function initPaymentOrdersHeaderFilters() {
    initPaymentOrdersColumnSorting();

    const globalInput = document.getElementById('ordersGlobalSearch');
    if (globalInput) {
      globalInput.value = paymentOrdersViewState.globalFilter || '';
      globalInput.addEventListener('input', () => {
        paymentOrdersViewState.globalFilter = globalInput.value;
        applyPaymentOrdersView();
      });
    }

    if (ordersClearSearchBtn && globalInput && !ordersClearSearchBtn.dataset.bound) {
      ordersClearSearchBtn.dataset.bound = 'true';
      ordersClearSearchBtn.addEventListener('click', () => {
        globalInput.value = '';
        paymentOrdersViewState.globalFilter = '';
        applyPaymentOrdersView();
        if (globalInput.focus) globalInput.focus();
      });
    }

    const menus = Array.from(document.querySelectorAll('[data-th-menu][data-col-key]'));
    if (menus.length === 0) {
      updatePaymentOrdersHeaderIndicators();
      return;
    }

    let openMenu = null;

    function closeMenu(menu) {
      if (!menu) return;
      const panel = menu.querySelector('[data-th-menu-panel]');
      const btn = menu.querySelector('[data-th-menu-btn]');
      if (panel) panel.setAttribute('hidden', '');
      if (btn) btn.setAttribute('aria-expanded', 'false');
      if (openMenu === menu) openMenu = null;
    }

    function openMenuFor(menu) {
      if (!menu) return;
      if (openMenu && openMenu !== menu) closeMenu(openMenu);
      const panel = menu.querySelector('[data-th-menu-panel]');
      const btn = menu.querySelector('[data-th-menu-btn]');
      if (panel) panel.removeAttribute('hidden');
      if (btn) btn.setAttribute('aria-expanded', 'true');
      openMenu = menu;

      const focusTarget =
        menu.querySelector('input[data-th-search]') ||
        menu.querySelector('input[data-th-date-from]') ||
        menu.querySelector('input[data-th-multi-exclude]') ||
        menu.querySelector('[data-th-menu-panel] input, [data-th-menu-panel] button');
      if (focusTarget && focusTarget.focus) focusTarget.focus();
    }

    function toggleMenuFor(menu) {
      if (!menu) return;
      const panel = menu.querySelector('[data-th-menu-panel]');
      const isOpen = panel && !panel.hasAttribute('hidden');
      if (isOpen) closeMenu(menu);
      else openMenuFor(menu);
    }

    document.addEventListener('click', (e) => {
      if (!openMenu) return;
      const clickedInside = e.target && openMenu.contains(e.target);
      if (!clickedInside) closeMenu(openMenu);
    });

    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && openMenu) {
        closeMenu(openMenu);
      }
    });

    for (const menu of menus) {
      const colKey = menu.getAttribute('data-col-key');
      const btn = menu.querySelector('[data-th-menu-btn]');
      const panel = menu.querySelector('[data-th-menu-panel]');
      const input = menu.querySelector('input[data-th-search]');

      const dateFrom = menu.querySelector('input[data-th-date-from]');
      const dateTo = menu.querySelector('input[data-th-date-to]');

      const multiOptions = menu.querySelector('[data-th-multi-options]');
      const multiExclude = menu.querySelector('input[data-th-multi-exclude]');

      if (input && colKey && paymentOrdersViewState.filters[colKey] !== undefined) {
        input.value = typeof paymentOrdersViewState.filters[colKey] === 'string' ? paymentOrdersViewState.filters[colKey] || '' : '';
        input.addEventListener('input', () => {
          paymentOrdersViewState.filters[colKey] = input.value;
          applyPaymentOrdersView();
        });
      }

      if (colKey === 'date' && dateFrom && dateTo) {
        const state = paymentOrdersViewState.filters.date;
        if (state && typeof state === 'object' && state.kind === 'dateRange') {
          dateFrom.value = String(state.from || '');
          dateTo.value = String(state.to || '');
        }

        const onDateChange = () => {
          paymentOrdersViewState.filters.date = {
            kind: 'dateRange',
            from: String(dateFrom.value || '').trim(),
            to: String(dateTo.value || '').trim(),
          };
          applyPaymentOrdersView();
        };

        dateFrom.addEventListener('change', onDateChange);
        dateTo.addEventListener('change', onDateChange);
        dateFrom.addEventListener('input', onDateChange);
        dateTo.addEventListener('input', onDateChange);
      }

      if ((colKey === 'status' || colKey === 'with') && multiOptions) {
        const optionList = colKey === 'status' ? ORDER_STATUSES : WITH_OPTIONS;

        // Ensure state shape exists
        const existing = paymentOrdersViewState.filters[colKey];
        if (!existing || typeof existing !== 'object' || existing.kind !== 'multiselect') {
          paymentOrdersViewState.filters[colKey] = { kind: 'multiselect', mode: 'include', values: [] };
        }

        const state = paymentOrdersViewState.filters[colKey];
        const selectedValues =
          state && typeof state === 'object' && state.kind === 'multiselect' && Array.isArray(state.values)
            ? state.values
            : [];

        multiOptions.innerHTML = optionList
          .map((opt) => {
            const isChecked = selectedValues.includes(opt) ? ' checked' : '';
            const safe = escapeHtml(opt);
            const id = `thMulti-${colKey}-${normalizeTextForSearch(opt).replace(/[^a-z0-9]+/g, '-')}`;
            return `
              <label class="thMenu__check" for="${escapeHtml(id)}">
                <input id="${escapeHtml(id)}" class="cb" type="checkbox" value="${safe}"${isChecked} />
                <span>${safe}</span>
              </label>
            `.trim();
          })
          .join('');

        if (multiExclude) {
          const currentMode = state && typeof state === 'object' && state.kind === 'multiselect' ? state.mode : 'include';
          multiExclude.checked = currentMode === 'exclude';
          multiExclude.addEventListener('change', () => {
            const next = paymentOrdersViewState.filters[colKey];
            if (next && typeof next === 'object' && next.kind === 'multiselect') {
              next.mode = multiExclude.checked ? 'exclude' : 'include';
            }
            applyPaymentOrdersView();
          });
        }

        multiOptions.addEventListener('change', () => {
          const checked = Array.from(multiOptions.querySelectorAll('input[type="checkbox"]'))
            .filter((el) => el && el.checked)
            .map((el) => el.value);

          const next = paymentOrdersViewState.filters[colKey];
          if (next && typeof next === 'object' && next.kind === 'multiselect') {
            next.values = checked;
          }
          applyPaymentOrdersView();
        });
      }

      if (btn) {
        btn.addEventListener('click', (e) => {
          e.preventDefault();
          toggleMenuFor(menu);
        });
      }

      if (panel) {
        panel.addEventListener('click', (e) => {
          const target = e.target;
          const sortBtn = target && target.closest && target.closest('button[data-th-sort]');
          const clearBtn = target && target.closest && target.closest('button[data-th-clear]');

          if (sortBtn && colKey) {
            const dir = sortBtn.getAttribute('data-th-sort') === 'desc' ? 'desc' : 'asc';
            paymentOrdersViewState.sortKey = colKey;
            paymentOrdersViewState.sortDir = dir;
            applyPaymentOrdersView();
            closeMenu(menu);
            return;
          }

          if (clearBtn && colKey) {
            if (colKey === 'date') {
              paymentOrdersViewState.filters.date = { kind: 'dateRange', from: '', to: '' };
              if (dateFrom) dateFrom.value = '';
              if (dateTo) dateTo.value = '';
            } else if (colKey === 'status' || colKey === 'with') {
              paymentOrdersViewState.filters[colKey] = { kind: 'multiselect', mode: 'include', values: [] };
              if (multiExclude) multiExclude.checked = false;
              if (multiOptions) {
                const boxes = Array.from(multiOptions.querySelectorAll('input[type="checkbox"]'));
                boxes.forEach((el) => {
                  el.checked = false;
                });
              }
            } else {
              paymentOrdersViewState.filters[colKey] = '';
              if (input) input.value = '';
            }

            if (paymentOrdersViewState.sortKey === colKey) {
              paymentOrdersViewState.sortKey = null;
              paymentOrdersViewState.sortDir = 'asc';
            }
            applyPaymentOrdersView();
            closeMenu(menu);
          }
        });
      }
    }

    updatePaymentOrdersHeaderIndicators();
  }

  function openModalWithOrder(order) {
    if (!modal || !modalBody) return;
    // Backfill/persist an initial timeline entry for older records.
    let orderForView = order;
    if (!Array.isArray(orderForView.timeline) || orderForView.timeline.length === 0) {
      const seeded = ensureOrderTimeline(orderForView);
      orderForView = { ...orderForView, timeline: seeded };
      const year = getActiveBudgetYear();
      upsertOrder(orderForView, year);
    }

    currentViewedOrderId = orderForView.id;
    modal.setAttribute('data-order-id', String(orderForView.id));

    const modalHeaderPo = modal.querySelector('#modalHeaderPo');
    if (modalHeaderPo) {
      modalHeaderPo.textContent = `Payment Order No. ${formatPaymentOrderNoForDisplay(orderForView.paymentOrderNo) || ''}`;
    }

    const modalHeaderDate = modal.querySelector('#modalHeaderDate');
    if (modalHeaderDate) {
      const d = formatDate(orderForView.date);
      modalHeaderDate.textContent = `Request Date: ${d || '—'}`;
    }

    const modalHeaderBudget = modal.querySelector('#modalHeaderBudget');
    if (modalHeaderBudget) {
      const year = getActiveBudgetYear();
      const budgetDisplay = formatBudgetNumberForDisplay(orderForView.budgetNumber);
      const budgetHtml = renderOutBudgetNumberHtml(orderForView.budgetNumber, year, budgetDisplay);
      modalHeaderBudget.innerHTML = `Budget Nr.: ${budgetHtml || '—'}`;
    }

    const currentStatus = getOrderStatusLabel(orderForView);
    const currentWith = getOrderWithLabel(orderForView);
    const allowedStatusesForCurrentWith = getAllowedOrderStatusesForWith(currentWith);
    const selectedStatus = allowedStatusesForCurrentWith.includes(currentStatus) ? currentStatus : 'Review';
    const statusOptions = allowedStatusesForCurrentWith.map((s) => {
      const selected = s === selectedStatus ? ' selected' : '';
      return `<option value="${escapeHtml(s)}"${selected}>${escapeHtml(s)}</option>`;
    }).join('');

    const withPlaceholderSelected = !String(currentWith || '').trim() ? ' selected' : '';
    const withOptions = [
      `<option value=""${withPlaceholderSelected}>— Select —</option>`,
      ...WITH_OPTIONS.map((w) => {
        const selected = w === currentWith ? ' selected' : '';
        return `<option value="${escapeHtml(w)}"${selected}>${escapeHtml(w)}</option>`;
      }),
    ].join('');

    const currentUser = getCurrentUser();
    const canEditBudgetNumberInView = Boolean(currentUser && hasModuleAccessLevel(currentUser, 'orders', 'full'));
    const budgetNumberOptions = canEditBudgetNumberInView
      ? buildBudgetNumberOptionsHtml(orderForView.budgetNumber, getActiveBudgetYear())
      : '';
    const budgetRowHtml = canEditBudgetNumberInView
      ? `
        <dt class="kv__center kv__gapTop">Budget Nr.</dt>
        <dd class="kv__gapTop">
          <select id="modalBudgetNumberSelect" aria-label="Budget Number">
            ${budgetNumberOptions}
          </select>
        </dd>
      `
      : '';

    const currentSourceRaw = String(orderForView.source || '').trim();
    const hasSource = currentSourceRaw !== '';
    let currentSource = normalizeOrderSource(currentSourceRaw);
    let sourceRowHtml = '';
    if (!hasSource) {
      const sourceChoices = [...SOURCE_OPTIONS];
      if (currentSourceRaw && !sourceChoices.some((opt) => opt.toLowerCase() === currentSourceRaw.toLowerCase())) {
        sourceChoices.push(currentSourceRaw);
      }
      if (!currentSource) currentSource = sourceChoices[0] || '';
      const sourceOptions = sourceChoices.map((s) => {
        const selected = s === currentSource ? ' selected' : '';
        return `<option value="${escapeHtml(s)}"${selected}>${escapeHtml(s)}</option>`;
      }).join('');
      sourceRowHtml = `
        <dt class="kv__center kv__gapTop">Source</dt>
        <dd class="kv__gapTop">
          <select id="modalSourceSelect" aria-label="Source">
            ${sourceOptions}
          </select>
        </dd>
      `;
    }

    const euroText = formatCurrency(orderForView.euro, 'EUR');
    const usdText = formatCurrency(orderForView.usd, 'USD');
    const euroRowHtml = euroText ? `<dt>Euro (€)</dt><dd>${escapeHtml(euroText)}</dd>` : '';
    const usdRowHtml = usdText ? `<dt>USD ($)</dt><dd>${escapeHtml(usdText)}</dd>` : '';

    modalBody.innerHTML = `
      <dl class="kv">
        <dt class="modal__nameLabel">Name</dt><dd class="modal__nameValue">${escapeHtml(orderForView.name)}</dd>
        ${euroRowHtml}
        ${usdRowHtml}
        <dt class="kv__center kv__gapTop">With</dt>
        <dd class="kv__gapTop">
          <select id="modalWithSelect" aria-label="With">
            ${withOptions}
          </select>
        </dd>
        <dt class="kv__center kv__gapTop">Status</dt>
        <dd class="kv__gapTop">
          <select id="modalStatusSelect" aria-label="Status">
            ${statusOptions}
          </select>
        </dd>
        ${budgetRowHtml}
        ${sourceRowHtml}
        <dt class="kv__gapTop">Address</dt><dd class="kv__pre kv__gapTop">${escapeHtml(orderForView.address)}</dd>
        <dt>${orderForView.bankDetailsMode === 'US' ? 'Account' : 'IBAN'}</dt><dd>${escapeHtml(orderForView.iban)}</dd>
        <dt>${orderForView.bankDetailsMode === 'US' ? 'Routing' : 'BIC'}</dt><dd>${escapeHtml(orderForView.bic)}</dd>
        ${orderForView.bankDetailsMode === 'US' ? `<dt>Account Type</dt><dd>${escapeHtml(orderForView.usAccountType || '')}</dd>` : ''}
        <dt>Special Instructions</dt><dd class="kv__pre">${escapeHtml(orderForView.specialInstructions)}</dd>
        <dt>Purpose</dt><dd class="kv__pre">${escapeHtml(orderForView.purpose)}</dd>
        <dt>Attachments</dt>
        <dd>
          <div id="modalAttachments" class="modalAttList">
            <div class="muted">Loading…</div>
          </div>
        </dd>
        <dt>Created</dt><dd>${escapeHtml(orderForView.createdAt)}</dd>
        <dt class="kv__gapTop">Comments</dt>
        <dd class="kv__gapTop">
          <textarea id="modalComments" rows="4" aria-label="Comments"></textarea>
          <div class="error" id="error-modalComments" role="alert" aria-live="polite"></div>
        </dd>
      </dl>
      ${renderTimelineGraph(orderForView)}
    `.trim();

    const progressHost = modal.querySelector('#modalPoProgress');
    if (progressHost) {
      progressHost.innerHTML = renderPaymentOrderProgressGraphHtml({
        order: orderForView,
        withLabel: (currentStatus === 'Paid') ? 'Archives' : currentWith,
        statusLabel: currentStatus,
        actorOverride: null,
      });
      initPoProgressStatusTooltips(progressHost);
    }

    // Populate attachments asynchronously.
    (async () => {
      const container = modalBody.querySelector('#modalAttachments');
      if (!container) return;
      try {
        const attachments = await listAttachments(`order:${orderForView.id}`);
        container.innerHTML = renderModalAttachments(attachments);
      } catch {
        container.innerHTML = '<div class="muted">Attachments unavailable in this browser.</div>';
      }
    })();

    // Attachment actions (view/download) inside modal.
    const modalAttachments = modalBody.querySelector('#modalAttachments');
    if (modalAttachments) {
      modalAttachments.addEventListener('click', async (e) => {
        const btn = e.target.closest('button[data-modal-attachment-action]');
        if (!btn) return;
        const row = btn.closest('[data-attachment-id]');
        if (!row) return;
        const id = row.getAttribute('data-attachment-id');
        const action = btn.getAttribute('data-modal-attachment-action');
        try {
          const att = await getAttachmentById(id);
          if (!att) return;
          if (action === 'view') openBlobInNewTab(att.blob);
          if (action === 'download') downloadBlob(att.blob, att.name);
        } catch {
          // ignore
        }
      });
    }

    // Save state for this modal session (only persisted when clicking Save)
    modal.setAttribute('data-original-with', currentWith);
    modal.setAttribute('data-original-status', currentStatus);
    if (!hasSource) modal.setAttribute('data-original-source', currentSource);

    const commentsEl = modalBody.querySelector('#modalComments');
    const commentsErrEl = modalBody.querySelector('#error-modalComments');

    const updateCommentsRequirement = () => {
      const ss = modalBody.querySelector('#modalStatusSelect');
      const statusNow = ss ? normalizeOrderStatus(ss.value) : currentStatus;
      const required = statusNow === 'Returned' || statusNow === 'Rejected';
      if (!commentsEl) return;

      if (required) {
        commentsEl.setAttribute('required', 'required');
        commentsEl.setAttribute('aria-required', 'true');
      } else {
        commentsEl.removeAttribute('required');
        commentsEl.setAttribute('aria-required', 'false');
        if (commentsErrEl) commentsErrEl.textContent = '';
      }
    };

    if (commentsEl) {
      commentsEl.addEventListener('input', () => {
        if (!commentsErrEl) return;
        const ss = modalBody.querySelector('#modalStatusSelect');
        const statusNow = ss ? normalizeOrderStatus(ss.value) : currentStatus;
        const required = statusNow === 'Returned' || statusNow === 'Rejected';
        if (!required) {
          commentsErrEl.textContent = '';
          return;
        }
        const comment = String(commentsEl.value || '').trim();
        if (comment) commentsErrEl.textContent = '';
      });
    }

    updateCommentsRequirement();

    const refreshPoProgress = () => {
      const progressEl = modal.querySelector('#modalPoProgress');
      if (!progressEl) return;

      const ss = modalBody.querySelector('#modalStatusSelect');
      const ws = modalBody.querySelector('#modalWithSelect');
      const statusNow = ss ? normalizeOrderStatus(ss.value) : currentStatus;

      let withNow = ws ? normalizeWith(ws.value) : currentWith;
      if (!String(withNow || '').trim() && statusNow === 'Returned') {
        withNow = normalizeWith(modal.getAttribute('data-original-with') || currentWith);
      }
      if (statusNow === 'Rejected') withNow = 'Requestor';
      if (statusNow === 'Paid') withNow = 'Archives';

      const actorOverride = (() => {
        const ow = normalizeWith(modal.getAttribute('data-pending-actor-with') || '');
        const os = normalizeOrderStatus(modal.getAttribute('data-pending-actor-status') || '');
        const at = String(modal.getAttribute('data-pending-actor-at') || '').trim();
        if (!ow || !os) return null;
        return { with: ow, status: os, at: at || new Date().toISOString() };
      })();

      progressEl.innerHTML = renderPaymentOrderProgressGraphHtml({
        order: orderForView,
        withLabel: withNow,
        statusLabel: statusNow,
        actorOverride,
      });
      initPoProgressStatusTooltips(progressEl);
    };

    const statusSelect = modalBody.querySelector('#modalStatusSelect');
    if (statusSelect) {
      statusSelect.addEventListener('change', () => {
      let nextStatus = normalizeOrderStatus(statusSelect.value);

        // Capture what the current "With" selected BEFORE workflow auto-changes.
        const wsEarly = modalBody.querySelector('#modalWithSelect');
        const actorWithEarly = wsEarly ? normalizeWith(wsEarly.value) : currentWith;
        modal.setAttribute('data-pending-actor-with', actorWithEarly);
        modal.setAttribute('data-pending-actor-status', nextStatus);
        modal.setAttribute('data-pending-actor-at', new Date().toISOString());

        // Guardrail: cannot set Approved/Paid unless a valid Budget Nr. exists.
        const outCode = extractOutCodeFromBudgetNumberText(orderForView.budgetNumber);
        const isImpact = nextStatus === 'Approved' || nextStatus === 'Paid';
        if (isImpact && !/^\d{4}$/.test(outCode)) {
          window.alert('Budget Nr. is required before setting Status to Approved or Paid. Edit the order and set Budget Nr. first.');
          statusSelect.value = normalizeOrderStatus(currentStatus);
          modal.removeAttribute('data-pending-status');
          return;
        }

        statusSelect.value = nextStatus;
        modal.setAttribute('data-pending-status', nextStatus);
  updateCommentsRequirement();

        const ws = modalBody.querySelector('#modalWithSelect');
        if (!ws) return;

        if (nextStatus === 'Rejected') {
          ws.value = 'Requestor';
          modal.setAttribute('data-pending-with', 'Requestor');
          refreshPoProgress();
          return;
        }

        if (nextStatus === 'Returned') {
          ws.value = '';
          modal.setAttribute('data-pending-with', '');
          try {
            ws.focus();
          } catch {
            // ignore
          }
          refreshPoProgress();
          return;
        }

        if (nextStatus === 'Paid') {
          ws.value = 'Archives';
          modal.setAttribute('data-pending-with', 'Archives');
          refreshPoProgress();
          return;
        }

        if (nextStatus === 'Approved') {
          const currentWithNow = normalizeWith(ws.value);
          if (currentWithNow === 'Grand Secretary') {
            ws.value = 'Grand Master';
            modal.setAttribute('data-pending-with', 'Grand Master');
            statusSelect.value = 'Review';
            modal.setAttribute('data-pending-status', 'Review');
            refreshPoProgress();
            return;
          }
          if (currentWithNow === 'Grand Master') {
            ws.value = 'Grand Treasurer';
            modal.setAttribute('data-pending-with', 'Grand Treasurer');
            statusSelect.value = 'Review';
            modal.setAttribute('data-pending-status', 'Review');
          }
        }

        refreshPoProgress();
      });
    }

    const withSelect = modalBody.querySelector('#modalWithSelect');
    if (withSelect) {
      withSelect.addEventListener('change', () => {
        // Capture the user's pre-workflow intent for the bubble corresponding to who currently has it.
        const actorWithEarly = normalizeWith(modal.getAttribute('data-original-with') || withSelect.value);
        const actorStatusEarly = statusSelect ? normalizeOrderStatus(statusSelect.value) : currentStatus;
        modal.setAttribute('data-pending-actor-with', actorWithEarly);
        modal.setAttribute('data-pending-actor-status', actorStatusEarly);
        modal.setAttribute('data-pending-actor-at', new Date().toISOString());

        const raw = String(withSelect.value || '').trim();
        const nextWith = raw ? normalizeWith(raw) : '';
        withSelect.value = nextWith;
        modal.setAttribute('data-pending-with', nextWith);

        if (statusSelect) {
          const allowedStatuses = getAllowedOrderStatusesForWith(nextWith || currentWith);
          const currentStatusValue = normalizeOrderStatus(statusSelect.value);
          const selectedStatus = allowedStatuses.includes(currentStatusValue) ? currentStatusValue : 'Review';
          const currentOptions = new Set(Array.from(statusSelect.options).map((opt) => String(opt.value || '')));
          const needsRebuild =
            statusSelect.options.length !== allowedStatuses.length ||
            allowedStatuses.some((s) => !currentOptions.has(s));
          if (needsRebuild) {
            statusSelect.innerHTML = allowedStatuses
              .map((s) => `<option value="${escapeHtml(s)}">${escapeHtml(s)}</option>`)
              .join('');
          }
          statusSelect.value = selectedStatus;
          modal.setAttribute('data-pending-status', selectedStatus);
        }

        updateCommentsRequirement();

        if (!statusSelect) {
          refreshPoProgress();
          return;
        }

        const currentStatus = normalizeOrderStatus(statusSelect.value);

        // Status-driven workflow rules should always win.
        if (currentStatus === 'Rejected') {
          withSelect.value = 'Requestor';
          modal.setAttribute('data-pending-with', 'Requestor');
          refreshPoProgress();
          return;
        }

        if (currentStatus === 'Paid') {
          withSelect.value = 'Archives';
          modal.setAttribute('data-pending-with', 'Archives');
          refreshPoProgress();
          return;
        }

        // With-driven workflow rules
        if (nextWith === 'Grand Secretary' && currentStatus !== 'Returned') {
          if (currentStatus === 'Approved') {
            withSelect.value = 'Grand Master';
            modal.setAttribute('data-pending-with', 'Grand Master');
            statusSelect.value = 'Review';
            modal.setAttribute('data-pending-status', 'Review');
          } else if (currentStatus !== 'Review') {
            statusSelect.value = 'Review';
            modal.setAttribute('data-pending-status', 'Review');
          }
        } else if (nextWith === 'Grand Master' && currentStatus === 'Approved') {
          withSelect.value = 'Grand Treasurer';
          modal.setAttribute('data-pending-with', 'Grand Treasurer');
          statusSelect.value = 'Review';
          modal.setAttribute('data-pending-status', 'Review');
        }

        refreshPoProgress();
      });
    }

    const sourceSelect = modalBody.querySelector('#modalSourceSelect');
    if (sourceSelect) {
      sourceSelect.addEventListener('change', () => {
        const nextSource = normalizeOrderSource(sourceSelect.value);
        sourceSelect.value = nextSource || sourceSelect.value;
        modal.setAttribute('data-pending-source', nextSource);
      });
    }

    // Access rules:
    // - Orders Write-or-higher can update Source from this View modal.
    // - Approval workflow: With and Status are only editable by roles authorized
    //   for the current 'With' stage (or the internal admin).
    const canEditOrders = currentUser ? canWriteOrCreate(currentUser, 'orders') : false;
    const canViewWrite = currentUser ? canOrdersViewEdit(currentUser) : false;

    const withEditable = Boolean(currentUser && canChangeWithField(currentUser, currentWith));
    const statusEditable = Boolean(currentUser && canChangeStatusField(currentUser, currentWith));

    if (statusSelect) statusSelect.disabled = !statusEditable;
    if (withSelect) withSelect.disabled = !withEditable;
    if (sourceSelect) sourceSelect.disabled = !canViewWrite;
    const budgetNumberSelect = modalBody.querySelector('#modalBudgetNumberSelect');
    if (budgetNumberSelect) budgetNumberSelect.disabled = !canEditBudgetNumberInView;

    if (editOrderBtn) {
      editOrderBtn.setAttribute('aria-disabled', canEditOrders ? 'false' : 'true');
      if (!canEditOrders) editOrderBtn.setAttribute('data-tooltip', 'Read-only access for Payment Orders.');
      else editOrderBtn.removeAttribute('data-tooltip');
    }
    if (saveOrderBtn) {
      saveOrderBtn.disabled = !canViewWrite;
      if (!canViewWrite) saveOrderBtn.setAttribute('data-tooltip', 'Read only access.');
      else saveOrderBtn.removeAttribute('data-tooltip');
    }

    modal.classList.add('is-open');
    modal.setAttribute('aria-hidden', 'false');

    // Focus the close button for accessibility
    const closeBtn = modal.querySelector('button[data-modal-close]');
    if (closeBtn) closeBtn.focus();
  }

  function closeModal() {
    if (!modal || !modalBody) return;
    hidePoProgressTooltip();
    modal.classList.remove('is-open');
    modal.setAttribute('aria-hidden', 'true');
    modalBody.innerHTML = '';
    const modalHeaderPo = modal.querySelector('#modalHeaderPo');
    if (modalHeaderPo) modalHeaderPo.textContent = '';
    const modalHeaderBudget = modal.querySelector('#modalHeaderBudget');
    if (modalHeaderBudget) modalHeaderBudget.textContent = '';
    const modalHeaderDate = modal.querySelector('#modalHeaderDate');
    if (modalHeaderDate) modalHeaderDate.textContent = '';
    const modalPoProgress = modal.querySelector('#modalPoProgress');
    if (modalPoProgress) modalPoProgress.innerHTML = '';
    currentViewedOrderId = null;
    modal.removeAttribute('data-order-id');
    modal.removeAttribute('data-pending-with');
    modal.removeAttribute('data-pending-status');
    modal.removeAttribute('data-pending-source');
    modal.removeAttribute('data-original-with');
    modal.removeAttribute('data-original-status');
    modal.removeAttribute('data-original-source');
    modal.removeAttribute('data-pending-actor-with');
    modal.removeAttribute('data-pending-actor-status');
    modal.removeAttribute('data-pending-actor-at');
  }

  function beginEditingOrder(order) {
    if (!order) return;

    // Store draft fields (currency fields will be re-synced from items)
    saveDraft({
      paymentOrderNo: order.paymentOrderNo || '',
      date: order.date || '',
      name: order.name || '',
      euro: order.euro === null || order.euro === undefined ? '' : String(order.euro),
      usd: order.usd === null || order.usd === undefined ? '' : String(order.usd),
      address: order.address || '',
      iban: order.iban || '',
      bic: order.bic || '',
      usAccountType: order.usAccountType || '',
      specialInstructions: order.specialInstructions || '',
      budgetNumber: order.budgetNumber || '',
      purpose: order.purpose || '',
    });

    saveDraftItems(Array.isArray(order.items) ? order.items : []);
    setEditOrderId(order.id);
  }

  function deleteOrderById(id) {
    const year = getActiveBudgetYear();
    const orders = loadOrders(year);
    const target = orders.find((o) => o && o.id === id);
    const next = orders.filter((o) => o.id !== id);
    saveOrders(next, year);
    if (target) {
      const po = formatPaymentOrderNoForDisplay(target.paymentOrderNo);
      const record = `${po}${target.name ? ` — ${String(target.name).trim()}` : ''}`.trim() || String(id || 'Payment Order');
      appendAppAuditEvent(`Payment Orders (${year})`, record, 'Deleted', []);
    }
    applyPaymentOrdersView();
  }

  function clearAll() {
    const year = getActiveBudgetYear();
    const orders = loadOrders(year);
    if (orders.length === 0) return;
    const ok = window.confirm('Clear all payment orders? This cannot be undone.');
    if (!ok) return;
    saveOrders([], year);
    appendAppAuditEvent(`Payment Orders (${year})`, `All Payment Orders (${orders.length})`, 'Deleted', []);
    applyPaymentOrdersView();
  }

  function initPaymentOrdersListPage() {
    if (!tbody) return;
    const year = getActiveBudgetYear();
    const currentUser = getCurrentUser();
    const canOpenReconciliation = Boolean(currentUser && hasPermission(currentUser, 'orders_reconciliation'));

    // Ensure the year is present in the URL for consistent nav highlighting.
    const fromUrl = getBudgetYearFromUrl();
    if (!fromUrl && getBasename(window.location.pathname) === 'menu.html') {
      try {
        const url = new URL(window.location.href);
        url.searchParams.set('year', String(year));
        window.history.replaceState(null, '', url.toString());
      } catch {
        // ignore
      }
    }

    const titleEl = document.querySelector('[data-payment-orders-title]');
    if (titleEl) titleEl.textContent = `${year} Payment Orders`;

    const listTitleEl = document.querySelector('[data-payment-orders-list-title]');
    if (listTitleEl) listTitleEl.textContent = `${year} Payment Orders`;

    if (reconciliationBtn) {
      reconciliationBtn.hidden = !canOpenReconciliation;
      reconciliationBtn.disabled = !canOpenReconciliation;
      if (canOpenReconciliation && !reconciliationBtn.dataset.bound) {
        reconciliationBtn.dataset.bound = '1';
        reconciliationBtn.addEventListener('click', () => {
          const y = getActiveBudgetYear();
          window.location.href = `reconciliation.html?year=${encodeURIComponent(String(y))}`;
        });
      }
    }

    applyAppTabTitle();
  }

  
  // [bundle-strip:menu-remove-reconciliation-page] removed in page-specific build.

  // [bundle-strip:menu-remove-settings] removed in page-specific build.
// ---- Income (year-scoped) ----

  function getIncomeKeyForYear(year) {
    const y = Number(year);
    if (!Number.isInteger(y)) return null;
    return `payment_order_income_${y}_v1`;
  }

  function ensureIncomeListExistsForYear(year) {
    const key = getIncomeKeyForYear(year);
    if (!key) return { ok: false, created: false };
    try {
      const existing = localStorage.getItem(key);
      if (existing !== null) return { ok: true, created: false };
      localStorage.setItem(key, JSON.stringify([]));
      return { ok: true, created: true };
    } catch {
      return { ok: false, created: false };
    }
  }

  // ---- wiseEUR (year-scoped) ----

  const WISE_EUR_DEFAULT_YEAR = 2026;

  function getWiseEurKeyForYear(year) {
    const y = Number(year);
    if (!Number.isInteger(y)) return null;
    return `payment_order_wise_eur_${y}_v1`;
  }

  function ensureWiseEurListExistsForYear(year) {
    const key = getWiseEurKeyForYear(year);
    if (!key) return { ok: false, created: false };
    try {
      const existing = localStorage.getItem(key);
      if (existing !== null) return { ok: true, created: false };
      localStorage.setItem(key, JSON.stringify([]));
      return { ok: true, created: true };
    } catch {
      return { ok: false, created: false };
    }
  }

  function getWiseEurYearFromUrl() {
    try {
      const params = new URLSearchParams(window.location.search || '');
      const y = Number(params.get('year'));
      return Number.isInteger(y) ? y : null;
    } catch {
      return null;
    }
  }

  function getWiseEurYear() {
    return getWiseEurYearFromUrl() ?? WISE_EUR_DEFAULT_YEAR;
  }

  /** @returns {Array<Object>} */
  function loadWiseEur(year) {
    const resolvedYear = Number.isInteger(Number(year)) ? Number(year) : getWiseEurYear();
    const key = getWiseEurKeyForYear(resolvedYear);
    if (!key) return [];
    try {
      const raw = localStorage.getItem(key);
      if (!raw) return [];
      const parsed = JSON.parse(raw);
      return Array.isArray(parsed) ? parsed : [];
    } catch {
      return [];
    }
  }

  /** @param {Array<Object>} entries */
  function saveWiseEur(entries, year) {
    const resolvedYear = Number.isInteger(Number(year)) ? Number(year) : getWiseEurYear();
    const key = getWiseEurKeyForYear(resolvedYear);
    if (!key) return;
    const before = loadWiseEur(resolvedYear);
    const safe = Array.isArray(entries) ? entries : [];
    localStorage.setItem(key, JSON.stringify(safe));
    appendCollectionAuditEvents({
      module: 'Wise EUR',
      year: resolvedYear,
      beforeList: before,
      afterList: safe,
      idKeys: ['id', 'idTrack'],
      recordLabelFn: (e) => String((e && (e.idTrack || e.id)) || '').trim(),
    });

    // Budget updates are ledger-driven only.
    syncBudgetFromLedgerSafe(resolvedYear, 'wiseEUR');
  }

  function upsertWiseEurEntry(entry, year) {
    if (!entry || !entry.id) return;
    const y = Number.isInteger(Number(year)) ? Number(year) : getWiseEurYear();
    const all = loadWiseEur(y);
    const idx = all.findIndex((e) => e && e.id === entry.id);
    const next = idx >= 0 ? all.map((e) => (e && e.id === entry.id ? entry : e)) : [entry, ...all];
    saveWiseEur(next, y);
  }

  function deleteWiseEurEntryById(id, year) {
    if (!id) return;
    const y = Number.isInteger(Number(year)) ? Number(year) : getWiseEurYear();
    const all = loadWiseEur(y);
    const next = all.filter((e) => e && e.id !== id);
    saveWiseEur(next, y);
  }

  // ---- wiseUSD (year-scoped) ----

  const WISE_USD_DEFAULT_YEAR = 2026;

  function getWiseUsdKeyForYear(year) {
    const y = Number(year);
    if (!Number.isInteger(y)) return null;
    return `payment_order_wise_usd_${y}_v1`;
  }

  function ensureWiseUsdListExistsForYear(year) {
    const key = getWiseUsdKeyForYear(year);
    if (!key) return { ok: false, created: false };
    try {
      const existing = localStorage.getItem(key);
      if (existing !== null) return { ok: true, created: false };
      localStorage.setItem(key, JSON.stringify([]));
      return { ok: true, created: true };
    } catch {
      return { ok: false, created: false };
    }
  }

  function getWiseUsdYearFromUrl() {
    try {
      const params = new URLSearchParams(window.location.search || '');
      const y = Number(params.get('year'));
      return Number.isInteger(y) ? y : null;
    } catch {
      return null;
    }
  }

  function getWiseUsdYear() {
    return getWiseUsdYearFromUrl() ?? WISE_USD_DEFAULT_YEAR;
  }

  /** @returns {Array<Object>} */
  function loadWiseUsd(year) {
    const resolvedYear = Number.isInteger(Number(year)) ? Number(year) : getWiseUsdYear();
    const key = getWiseUsdKeyForYear(resolvedYear);
    if (!key) return [];
    try {
      const raw = localStorage.getItem(key);
      if (!raw) return [];
      const parsed = JSON.parse(raw);
      return Array.isArray(parsed) ? parsed : [];
    } catch {
      return [];
    }
  }

  /** @param {Array<Object>} entries */
  function saveWiseUsd(entries, year) {
    const resolvedYear = Number.isInteger(Number(year)) ? Number(year) : getWiseUsdYear();
    const key = getWiseUsdKeyForYear(resolvedYear);
    if (!key) return;
    const before = loadWiseUsd(resolvedYear);
    const safe = Array.isArray(entries) ? entries : [];
    localStorage.setItem(key, JSON.stringify(safe));
    appendCollectionAuditEvents({
      module: 'Wise USD',
      year: resolvedYear,
      beforeList: before,
      afterList: safe,
      idKeys: ['id', 'idTrack'],
      recordLabelFn: (e) => String((e && (e.idTrack || e.id)) || '').trim(),
    });

    // Budget updates are ledger-driven only.
    syncBudgetFromLedgerSafe(resolvedYear, 'wiseUSD');
  }

  function upsertWiseUsdEntry(entry, year) {
    if (!entry || !entry.id) return;
    const y = Number.isInteger(Number(year)) ? Number(year) : getWiseUsdYear();
    const all = loadWiseUsd(y);
    const idx = all.findIndex((e) => e && e.id === entry.id);
    const next = idx >= 0 ? all.map((e) => (e && e.id === entry.id ? entry : e)) : [entry, ...all];
    saveWiseUsd(next, y);
  }

  function deleteWiseUsdEntryById(id, year) {
    if (!id) return;
    const y = Number.isInteger(Number(year)) ? Number(year) : getWiseUsdYear();
    const all = loadWiseUsd(y);
    const next = all.filter((e) => e && e.id !== id);
    saveWiseUsd(next, y);
  }

  // ---- Grand Secretary Ledger (year-scoped; derived from Income + Payment Orders) ----

  function getGsLedgerVerifiedKeyForYear(year) {
    const y = Number(year);
    if (!Number.isInteger(y)) return null;
    return `payment_order_gs_ledger_verified_${y}_v1`;
  }

  function ensureGsLedgerVerifiedStoreExistsForYear(year) {
    const key = getGsLedgerVerifiedKeyForYear(year);
    if (!key) return { ok: false, created: false };
    try {
      const existing = localStorage.getItem(key);
      if (existing !== null) return { ok: true, created: false };
      localStorage.setItem(key, JSON.stringify({}));
      return { ok: true, created: true };
    } catch {
      return { ok: false, created: false };
    }
  }

  function loadGsLedgerVerifiedMap(year) {
    const key = getGsLedgerVerifiedKeyForYear(year);
    if (!key) return {};
    try {
      const raw = localStorage.getItem(key);
      if (!raw) return {};
      const parsed = JSON.parse(raw);
      return parsed && typeof parsed === 'object' ? parsed : {};
    } catch {
      return {};
    }
  }

  function saveGsLedgerVerifiedMap(map, year) {
    const key = getGsLedgerVerifiedKeyForYear(year);
    if (!key) return;
    const prev = loadGsLedgerVerifiedMap(year);
    const safe = map && typeof map === 'object' ? map : {};
    localStorage.setItem(key, JSON.stringify(safe));
    if (auditStableStringify(prev) !== auditStableStringify(safe)) {
      appendAppAuditEvent(
        `Ledger Verification (${Number(year)})`,
        `Verified map ${Number(year)}`,
        'Modified',
        [{ field: 'Entries', from: `${Object.keys(prev || {}).length} item(s)`, to: `${Object.keys(safe || {}).length} item(s)` }]
      );
    }
  }

  function buildGsLedgerRowsForYear(year) {
    const verified = loadGsLedgerVerifiedMap(year);
    const rows = [];

    const linkedWiseEurEntryIds = new Set();
    const linkedWiseUsdEntryIds = new Set();
    const paymentOrderNos = new Set();

    // Income rows
    const incomeEntries = loadIncome(year);
    for (const inc of Array.isArray(incomeEntries) ? incomeEntries : []) {
      if (!inc || !inc.id) continue;

      const euroNum = Number(inc.euro);
      if (!(Number.isFinite(euroNum) && euroNum > 0)) continue;

      const budgetCode = extractInCodeFromBudgetNumberText(inc.budgetNumber);
      if (!/^[0-9]{4}$/.test(String(budgetCode || ''))) continue;

      const ledgerId = `inc:${String(inc.id)}`;
      rows.push({
        ledgerId,
        date: String(inc.date || ''),
        budgetNumber: budgetCode,
        source: 'Commerzbank',
        creditorDebtor: String(inc.remitter || ''),
        paymentOrderNo: '',
        euro: euroNum,
        usd: null,
        verified: Boolean(verified[ledgerId]),
        with: '',
        status: '',
        details: String(inc.description || ''),
      });
    }

    // Payment Order rows (Approved or Paid only)
    const orders = loadOrders(year);
    for (const o of Array.isArray(orders) ? orders : []) {
      if (!o || !o.id) continue;

      const poNoKey = String(o.paymentOrderNo || '').trim();
      if (poNoKey) paymentOrderNos.add(poNoKey);

      const src = String(o.source || '').trim();
      const srcEntryId = String(o.sourceEntryId || '').trim();
      if (src === 'wiseEUR' && srcEntryId) linkedWiseEurEntryIds.add(srcEntryId);
      if (src === 'wiseUSD' && srcEntryId) linkedWiseUsdEntryIds.add(srcEntryId);

      const statusLabel = normalizeOrderStatus(o.status);
      const withLabel = normalizeWith(o.with);
      const statusRaw = String(statusLabel || '').trim().toLowerCase();
      const isApprovedOrPaid = statusRaw === 'approved' || statusRaw === 'paid';
      const isGtReviewWithGmApproved = statusRaw === 'review' && withLabel === 'Grand Treasurer' && hasPaymentOrderGrandMasterApproval(o);
      if (!isApprovedOrPaid && !isGtReviewWithGmApproved) continue;
      const ledgerId = `po:${String(o.id)}`;

      const euroRaw = String(o.euro ?? '').trim();
      const usdRaw = String(o.usd ?? '').trim();
      const euroNum = euroRaw === '' ? Number.NaN : Number(euroRaw);
      const usdNum = usdRaw === '' ? Number.NaN : Number(usdRaw);

      rows.push({
        ledgerId,
        date: String(o.date || ''),
        budgetNumber: extractInCodeFromBudgetNumberText(o.budgetNumber),
        source: String(o.source || '').trim() || 'Commerzbank',
        creditorDebtor: String(o.name || ''),
        paymentOrderNo: String(o.paymentOrderNo || ''),
        euro: Number.isFinite(euroNum) ? -Math.abs(euroNum) : null,
        usd: Number.isFinite(usdNum) ? -Math.abs(usdNum) : null,
        verified: Boolean(verified[ledgerId]),
        with: withLabel,
        status: String(o.status || ''),
        details: String(o.purpose || ''),
      });
    }

    // wiseEUR rows (Receipts only; requires Budget #; exclude items already moved/reconciled into Payment Orders)
    const wiseEurEntries = loadWiseEur(year);
    for (const e of Array.isArray(wiseEurEntries) ? wiseEurEntries : []) {
      if (!e || !e.id) continue;

      const entryId = String(e.id).trim();
      if (!entryId) continue;
      if (linkedWiseEurEntryIds.has(entryId)) continue;

      const idTrack = String(e.idTrack || '').trim();
      if (idTrack && paymentOrderNos.has(idTrack)) continue;

      const receipts = getWiseEurReceipts(e);
      const disburse = getWiseEurDisburse(e);
      // Only positive items should be surfaced directly in the Ledger.
      // Disbursements are expected to flow through Reconciliation -> Payment Orders.
      if (!(Number.isFinite(receipts) && receipts > 0)) continue;
      if (Number.isFinite(disburse) && disburse > 0) continue;

      const budgetCode = extractInCodeFromBudgetNumberText(e.budgetNo);
      if (!/^[0-9]{4}$/.test(String(budgetCode || ''))) continue;

      const ledgerId = `weur:${entryId}`;
      rows.push({
        ledgerId,
        date: String(e.datePL || e.date || ''),
        budgetNumber: budgetCode,
        source: 'wiseEUR',
        creditorDebtor: String(e.receivedFromDisbursedTo || e.party || ''),
        paymentOrderNo: idTrack ? formatPaymentOrderNoForDisplay(idTrack) : '',
        euro: receipts,
        usd: null,
        verified: Boolean(verified[ledgerId]),
        with: '',
        status: '',
        details: String(e.description || e.reference || ''),
      });
    }

    // wiseUSD rows (Receipts only; requires Budget #; exclude items already moved/reconciled into Payment Orders)
    const wiseUsdEntries = loadWiseUsd(year);
    for (const e of Array.isArray(wiseUsdEntries) ? wiseUsdEntries : []) {
      if (!e || !e.id) continue;

      const entryId = String(e.id).trim();
      if (!entryId) continue;
      if (linkedWiseUsdEntryIds.has(entryId)) continue;

      const idTrack = String(e.idTrack || '').trim();
      if (idTrack && paymentOrderNos.has(idTrack)) continue;

      const receipts = getWiseUsdReceipts(e);
      const disburse = getWiseUsdDisburse(e);
      if (!(Number.isFinite(receipts) && receipts > 0)) continue;
      if (Number.isFinite(disburse) && disburse > 0) continue;

      const budgetCode = extractInCodeFromBudgetNumberText(e.budgetNo);
      if (!/^[0-9]{4}$/.test(String(budgetCode || ''))) continue;

      const ledgerId = `wusd:${entryId}`;
      rows.push({
        ledgerId,
        date: String(e.datePL || e.date || ''),
        budgetNumber: budgetCode,
        source: 'wiseUSD',
        creditorDebtor: String(e.receivedFromDisbursedTo || e.party || ''),
        paymentOrderNo: idTrack ? formatPaymentOrderNoForDisplay(idTrack) : '',
        euro: null,
        usd: receipts,
        verified: Boolean(verified[ledgerId]),
        with: '',
        status: '',
        details: String(e.description || e.reference || ''),
      });
    }

    return rows;
  }

  const GS_LEDGER_COL_TYPES = {
    date: 'date',
    budgetNumber: 'text',
    source: 'text',
    creditorDebtor: 'text',
    paymentOrderNo: 'text',
    euro: 'number',
    usd: 'number',
    verified: 'boolean',
    status: 'text',
    details: 'text',
  };

  const gsLedgerViewState = {
    globalFilter: '',
    sortKey: 'date',
    sortDir: 'desc',
    defaultEmptyText: null,
    canVerify: false,
  };

  function ensureGsLedgerDefaultEmptyText() {
    if (!gsLedgerEmptyState) return;
    if (gsLedgerViewState.defaultEmptyText !== null) return;
    gsLedgerViewState.defaultEmptyText = gsLedgerEmptyState.textContent || 'No ledger entries yet.';
  }

  function getGsLedgerDisplayValueForColumn(row, colKey) {
    if (!row) return '';
    switch (colKey) {
      case 'date':
        return formatDate(row.date);
      case 'budgetNumber':
        return row.budgetNumber || '';
      case 'source':
        return row.source || '';
      case 'creditorDebtor':
        return row.creditorDebtor || '';
      case 'paymentOrderNo':
        // Document Nr.: Payment Order No for payment orders, else Money Transfer No (if entry is part of a Money Transfer).
        return row.paymentOrderNo || getMoneyTransferNoForLedgerRow(getActiveBudgetYear(), row) || '';
      case 'euro':
        return row.euro === null || row.euro === undefined || row.euro === '' ? '' : formatCurrency(row.euro, 'EUR');
      case 'usd':
        return row.usd === null || row.usd === undefined || row.usd === '' ? '' : formatCurrency(row.usd, 'USD');
      case 'verified':
        return row.verified ? 'Yes' : '';
      case 'status':
        return row.status || '';
      case 'details':
        return row.details || '';
      default:
        return '';
    }
  }

  function getMoneyTransferForLedgerRow(year, row) {
    const ledgerId = String(row && row.ledgerId ? row.ledgerId : '');
    if (ledgerId.startsWith('po:')) return null;

    const d = String(row && row.date ? row.date : '').trim();
    if (!isIsoDateOnly(d)) return null;

    const e = Number(row && row.euro);
    const u = Number(row && row.usd);
    const isPositive = (Number.isFinite(e) && e > 0) || (Number.isFinite(u) && u > 0);
    if (!isPositive) return null;

    const y = Number.isInteger(Number(year)) ? Number(year) : getActiveBudgetYear();
    const transfers = ensureMoneyTransfersHaveIdsForYear(y);
    for (const t of Array.isArray(transfers) ? transfers : []) {
      const no = String(t && (t.moneyTransferNo || t.mtNo || t.no) ? (t.moneyTransferNo || t.mtNo || t.no) : '').trim();
      if (!no) continue;

      const explicitIds = normalizeMoneyTransferEntryLedgerIds(t);
      if (explicitIds.includes(ledgerId)) return t;
    }
    return null;
  }

  function getMoneyTransferNoForLedgerRow(year, row) {
    const mt = getMoneyTransferForLedgerRow(year, row);
    if (!mt) return '';
    return String(mt.moneyTransferNo || mt.mtNo || mt.no || '').trim();
  }

  function getGsLedgerSortValueForColumn(row, colKey, colType) {
    if (!row) return null;
    if (colType === 'number') {
      const raw = colKey === 'usd' ? row.usd : row.euro;
      const num = raw === null || raw === undefined || raw === '' ? null : Number(raw);
      return Number.isFinite(num) ? num : null;
    }
    if (colType === 'date') {
      const raw = String(row.date || '').trim();
      return raw ? raw : null;
    }
    if (colType === 'boolean') {
      return row.verified ? 1 : 0;
    }
    return normalizeTextForSearch(getGsLedgerDisplayValueForColumn(row, colKey));
  }

  function filterGsLedgerForView(rows, globalFilter) {
    const needle = normalizeTextForSearch(globalFilter);
    if (!needle) return rows || [];

    const cols = Object.keys(GS_LEDGER_COL_TYPES);
    return (rows || []).filter((r) => cols.some((k) => normalizeTextForSearch(getGsLedgerDisplayValueForColumn(r, k)).includes(needle)));
  }

  function sortGsLedgerForView(rows, sortKey, sortDir) {
    const dir = sortDir === 'desc' ? -1 : 1;
    const key = sortKey || 'date';
    const colType = GS_LEDGER_COL_TYPES[key] || 'text';
    const withIndex = (rows || []).map((row, index) => ({ row, index }));
    withIndex.sort((a, b) => {
      const av = getGsLedgerSortValueForColumn(a.row, key, colType);
      const bv = getGsLedgerSortValueForColumn(b.row, key, colType);

      if (av === null && bv === null) return a.index - b.index;
      if (av === null) return 1;
      if (bv === null) return -1;

      if (colType === 'number' || colType === 'boolean') {
        const cmp = av === bv ? 0 : av < bv ? -1 : 1;
        return cmp === 0 ? a.index - b.index : cmp * dir;
      }

      const cmp = String(av).localeCompare(String(bv));
      return cmp === 0 ? a.index - b.index : cmp * dir;
    });
    return withIndex.map((x) => x.row);
  }

  function renderGsLedgerRows(rows) {
    if (!gsLedgerTbody) return;
    const canVerify = Boolean(gsLedgerViewState.canVerify);
    const year = getActiveBudgetYear();
    const html = (rows || [])
      .map((r) => {
        const ledgerId = escapeHtml(r.ledgerId);
        const statusLabel = String(r && r.status ? r.status : '').trim();
        const withLabel = normalizeWith(r && r.with ? r.with : '');
        const isApproved = statusLabel.toLowerCase() === 'approved';
        const isGtReview = statusLabel.toLowerCase() === 'review' && withLabel.toLowerCase() === 'grand treasurer';
        const rowClasses = [];
        if (isApproved) rowClasses.push('gsLedgerRow--approved');
        else if (isGtReview) rowClasses.push('gsLedgerRow--gtReview');
        const date = escapeHtml(getGsLedgerDisplayValueForColumn(r, 'date'));
        const budgetCode = getGsLedgerDisplayValueForColumn(r, 'budgetNumber');
        const code = extractInCodeFromBudgetNumberText(budgetCode);
        const outMap = getOutDescMapForYear(year);
        const inMap = getInDescMapForYear(year);
        const desc = (code && outMap ? outMap.get(code) : '') || (code && inMap ? inMap.get(code) : '') || (code ? BUDGET_DESC_BY_CODE.get(code) : '') || inferDescFromBudgetNumberText(budgetCode);
        const budgetNumber = renderBudgetNumberSpanHtml(code || budgetCode, desc);
        const source = escapeHtml(getGsLedgerDisplayValueForColumn(r, 'source'));
        const creditorDebtor = escapeHtml(getGsLedgerDisplayValueForColumn(r, 'creditorDebtor'));
        const poNo = escapeHtml(String(r && r.paymentOrderNo ? r.paymentOrderNo : ''));
        const euro = escapeHtml(getGsLedgerDisplayValueForColumn(r, 'euro'));
        const usd = escapeHtml(getGsLedgerDisplayValueForColumn(r, 'usd'));
        const statusRaw = String(getGsLedgerDisplayValueForColumn(r, 'status') || '').trim();
        const statusNorm = normalizeOrderStatus(statusRaw);
        const statusText = escapeHtml(statusRaw);
        const statusHtml = statusNorm === 'Review'
          ? `<span class="poProgress__status" data-po-tooltip="Approved by the Grand Master" tabindex="0">${statusText}</span>`
          : statusText;
        const details = escapeHtml(getGsLedgerDisplayValueForColumn(r, 'details'));
        const orderIdRaw = String(r && r.ledgerId ? r.ledgerId : '').startsWith('po:') ? String(r.ledgerId).slice(3) : '';
        const orderId = escapeHtml(orderIdRaw);
        const poNoHtml = orderIdRaw && poNo
          ? `<a href="#" class="poNoDownloadLink" data-action="downloadPdf" data-order-id="${orderId}" title="Download PDF">${poNo}</a>`
          : poNo;

        const mtRecord = getMoneyTransferForLedgerRow(year, r);
        const mtNo = String(mtRecord && (mtRecord.moneyTransferNo || mtRecord.mtNo || mtRecord.no) ? (mtRecord.moneyTransferNo || mtRecord.mtNo || mtRecord.no) : '').trim();
        let mtNoHtml = '';
        if (mtNo) {
          const mtId = normalizeMoneyTransferId(mtRecord && mtRecord.id);
          if (mtId) {
            const mtParams = new URLSearchParams();
            mtParams.set('year', String(year));
            mtParams.set('mode', 'view');
            mtParams.set('id', mtId);
            const mtDate = normalizeMoneyTransferDate(mtRecord);
            if (mtDate) mtParams.set('mtDate', mtDate);
            const mtHref = withWpEmbedParams(`money_transfer.html?${mtParams.toString()}`);
            mtNoHtml = `<a href="${escapeHtml(mtHref)}" title="View Money Transfer">${escapeHtml(mtNo)}</a>`;
          } else {
            mtNoHtml = escapeHtml(mtNo);
          }
        }
        const isMissingMtNo = isMtEligibleLedgerIncomeRow(r) && !mtNo;
        if (isMissingMtNo) rowClasses.push('gsLedgerRow--missingMt');

        const docNrHtml = poNoHtml || mtNoHtml;

        return `
          <tr data-ledger-id="${ledgerId}" class="${rowClasses.join(' ')}">
            <td>${date}</td>
            <td>${budgetNumber}</td>
            <td>${source}</td>
            <td>${creditorDebtor}</td>
            <td>${docNrHtml}</td>
            <td class="num">${euro}</td>
            <td class="num">${usd}</td>
            <td>${statusHtml}</td>
            <td>${details}</td>
          </tr>
        `.trim();
      })
      .join('');

    gsLedgerTbody.innerHTML = html;
    initPoProgressStatusTooltips(gsLedgerTbody);
  }

  function updateGsLedgerSortIndicators() {
    if (!gsLedgerTbody) return;
    const table = gsLedgerTbody.closest('table');
    if (!table) return;

    const sortKey = gsLedgerViewState.sortKey;
    const sortDir = gsLedgerViewState.sortDir === 'desc' ? 'desc' : 'asc';

    const ths = Array.from(table.querySelectorAll('thead th[data-sort-key]'));
    for (const th of ths) {
      const colKey = th.getAttribute('data-sort-key');
      let aria = 'none';
      if (colKey && sortKey === colKey) {
        aria = sortDir === 'desc' ? 'descending' : 'ascending';
      }
      th.setAttribute('aria-sort', aria);
    }
  }

  function initGsLedgerColumnSorting() {
    if (!gsLedgerTbody) return;
    const table = gsLedgerTbody.closest('table');
    if (!table) return;
    if (table.dataset.sortBound === '1') return;

    const ths = Array.from(table.querySelectorAll('thead th[data-sort-key]'));
    if (ths.length === 0) return;
    table.dataset.sortBound = '1';

    function applySortForKey(colKey) {
      if (!colKey) return;
      if (gsLedgerViewState.sortKey === colKey) {
        gsLedgerViewState.sortDir = gsLedgerViewState.sortDir === 'asc' ? 'desc' : 'asc';
      } else {
        gsLedgerViewState.sortKey = colKey;
        gsLedgerViewState.sortDir = 'asc';
      }
      applyGsLedgerView();
    }

    for (const th of ths) {
      th.classList.add('is-sortable');
      if (!th.hasAttribute('tabindex')) th.setAttribute('tabindex', '0');
      if (!th.hasAttribute('aria-sort')) th.setAttribute('aria-sort', 'none');

      th.addEventListener('click', () => applySortForKey(th.getAttribute('data-sort-key')));
      th.addEventListener('keydown', (e) => {
        if (e.key !== 'Enter' && e.key !== ' ') return;
        e.preventDefault();
        applySortForKey(th.getAttribute('data-sort-key'));
      });
    }

    updateGsLedgerSortIndicators();
  }

  function applyGsLedgerView() {
    if (!gsLedgerTbody || !gsLedgerEmptyState) return;
    ensureGsLedgerDefaultEmptyText();

    const year = getActiveBudgetYear();
    const all = buildGsLedgerRowsForYear(year);
    const filtered = filterGsLedgerForView(all, gsLedgerViewState.globalFilter);
    const sorted = sortGsLedgerForView(filtered, gsLedgerViewState.sortKey, gsLedgerViewState.sortDir);

    if (normalizeTextForSearch(gsLedgerViewState.globalFilter) !== '' && all.length > 0 && sorted.length === 0) {
      gsLedgerEmptyState.textContent = 'No ledger entries match your search.';
    } else {
      gsLedgerEmptyState.textContent = gsLedgerViewState.defaultEmptyText;
    }

    gsLedgerEmptyState.hidden = sorted.length > 0;
    renderGsLedgerRows(sorted);
    updateGsLedgerTotals(sorted);
    updateGsLedgerSortIndicators();
  }

  function updateGsLedgerTotals(rows) {
    const euroEl = document.getElementById('gsLedgerTotalEuro');
    const usdEl = document.getElementById('gsLedgerTotalUsd');
    const poCountEl = document.getElementById('gsLedgerTotalPaymentOrders');
    const mtCountEl = document.getElementById('gsLedgerTotalMoneyTransfers');
    if (!euroEl && !usdEl && !poCountEl && !mtCountEl) return;

    const year = getActiveBudgetYear();

    let totalEuro = 0;
    let totalUsd = 0;
    let paymentOrderCount = 0;
    const moneyTransferNos = new Set();
    for (const r of rows || []) {
      const e = Number(r && r.euro);
      const u = Number(r && r.usd);
      if (Number.isFinite(e)) totalEuro += e;
      if (Number.isFinite(u)) totalUsd += u;

      const ledgerId = String(r && r.ledgerId ? r.ledgerId : '');
      if (ledgerId.startsWith('po:')) paymentOrderCount += 1;

      const mtNo = getMoneyTransferNoForLedgerRow(year, r);
      if (mtNo) moneyTransferNos.add(String(mtNo));
    }

    if (euroEl) euroEl.textContent = formatCurrency(totalEuro, 'EUR');
    if (usdEl) usdEl.textContent = formatCurrency(totalUsd, 'USD');
    if (poCountEl) poCountEl.textContent = String(paymentOrderCount);
    if (mtCountEl) mtCountEl.textContent = String(moneyTransferNos.size);
  }

  function initGsLedgerListPage() {
    if (!gsLedgerTbody || !gsLedgerEmptyState) return;
    const year = getActiveBudgetYear();

    const user = getCurrentUser();
    gsLedgerViewState.canVerify = Boolean(user && canWrite(user, 'ledger'));

    const exportCsvLink = document.getElementById('gsLedgerExportCsvLink');
    const gsLedgerBankEurBtn = document.getElementById('gsLedgerBankEurBtn');
    const gsLedgerWiseEurBtn = document.getElementById('gsLedgerWiseEurBtn');
    const gsLedgerWiseUsdBtn = document.getElementById('gsLedgerWiseUsdBtn');
    const menuBtn = document.getElementById('gsLedgerActionsMenuBtn');
    const menuPanel = document.getElementById('gsLedgerActionsMenu');
    const canViewBankEurBtn = hasPermission(user, 'income_bankeur');
    const canViewWiseEurBtn = hasPermission(user, 'ledger_wiseeur');
    const canViewWiseUsdBtn = hasPermission(user, 'ledger_wiseusd');

    if (gsLedgerBankEurBtn) gsLedgerBankEurBtn.hidden = !canViewBankEurBtn;
    if (gsLedgerWiseEurBtn) gsLedgerWiseEurBtn.hidden = !canViewWiseEurBtn;
    if (gsLedgerWiseUsdBtn) gsLedgerWiseUsdBtn.hidden = !canViewWiseUsdBtn;

    if (canViewBankEurBtn && gsLedgerBankEurBtn && !gsLedgerBankEurBtn.dataset.bound) {
      gsLedgerBankEurBtn.dataset.bound = '1';
      gsLedgerBankEurBtn.addEventListener('click', () => {
        window.location.href = `income.html?year=${encodeURIComponent(String(year))}`;
      });
    }

    if (gsLedgerBankEurBtn) {
      gsLedgerBankEurBtn.textContent = `${year} BankEUR`;
      gsLedgerBankEurBtn.title = `Open the ${year} BankEUR grid`;
    }

    if (canViewWiseEurBtn && gsLedgerWiseEurBtn && !gsLedgerWiseEurBtn.dataset.bound) {
      gsLedgerWiseEurBtn.dataset.bound = '1';
      gsLedgerWiseEurBtn.addEventListener('click', () => {
        window.location.href = `wise_eur.html?year=${encodeURIComponent(String(year))}`;
      });
    }

    if (gsLedgerWiseEurBtn) {
      gsLedgerWiseEurBtn.textContent = `${year} wiseEUR`;
      gsLedgerWiseEurBtn.title = `Open the ${year} wiseEUR grid`;
    }

    if (canViewWiseUsdBtn && gsLedgerWiseUsdBtn && !gsLedgerWiseUsdBtn.dataset.bound) {
      gsLedgerWiseUsdBtn.dataset.bound = '1';
      gsLedgerWiseUsdBtn.addEventListener('click', () => {
        window.location.href = `wise_usd.html?year=${encodeURIComponent(String(year))}`;
      });
    }

    if (gsLedgerWiseUsdBtn) {
      gsLedgerWiseUsdBtn.textContent = `${year} wiseUSD`;
      gsLedgerWiseUsdBtn.title = `Open the ${year} wiseUSD grid`;
    }

    // Ensure the year is present in the URL for consistent nav highlighting.
    const fromUrl = getBudgetYearFromUrl();
    if (!fromUrl && getBasename(window.location.pathname) === 'grand_secretary_ledger.html') {
      try {
        const url = new URL(window.location.href);
        url.searchParams.set('year', String(year));
        window.history.replaceState(null, '', url.toString());
      } catch {
        // ignore
      }
    }

    ensureIncomeListExistsForYear(year);
    ensureGsLedgerVerifiedStoreExistsForYear(year);

    const titleEl = document.querySelector('[data-gs-ledger-title]');
    if (titleEl) titleEl.textContent = `${year} Ledger`;
    const listTitleEl = document.querySelector('[data-gs-ledger-list-title]');
    if (listTitleEl) listTitleEl.textContent = `${year} Ledger`;
    const subheadEl = document.querySelector('[data-gs-ledger-subhead]');
    if (subheadEl) subheadEl.textContent = `Consolidated ledger for ${year} (Income + Approved/Paid Payment Orders).`;
    applyAppTabTitle();

    initGsLedgerColumnSorting();

    const globalInput = document.getElementById('gsLedgerGlobalSearch');
    if (globalInput) {
      globalInput.value = gsLedgerViewState.globalFilter || '';
      globalInput.addEventListener('input', () => {
        gsLedgerViewState.globalFilter = globalInput.value;
        if (gsLedgerClearSearchBtn) {
          const hasSearch = normalizeTextForSearch(gsLedgerViewState.globalFilter) !== '';
          gsLedgerClearSearchBtn.hidden = !hasSearch;
          gsLedgerClearSearchBtn.disabled = !hasSearch;
        }
        applyGsLedgerView();
      });
    }

    if (gsLedgerClearSearchBtn && globalInput) {
      const hasSearch = normalizeTextForSearch(gsLedgerViewState.globalFilter) !== '';
      gsLedgerClearSearchBtn.hidden = !hasSearch;
      gsLedgerClearSearchBtn.disabled = !hasSearch;
      if (!gsLedgerClearSearchBtn.dataset.bound) {
        gsLedgerClearSearchBtn.dataset.bound = 'true';
        gsLedgerClearSearchBtn.addEventListener('click', () => {
          globalInput.value = '';
          gsLedgerViewState.globalFilter = '';
          gsLedgerClearSearchBtn.hidden = true;
          gsLedgerClearSearchBtn.disabled = true;
          applyGsLedgerView();
          if (globalInput.focus) globalInput.focus();
        });
      }
    }

    // Persist Verified checkbox state per source record.
    if (!gsLedgerTbody.dataset.verifiedBound) {
      gsLedgerTbody.dataset.verifiedBound = '1';
      gsLedgerTbody.addEventListener('change', (e) => {
        const input = e.target && e.target.matches ? (e.target.matches('input[type="checkbox"][data-ledger-verify]') ? e.target : null) : null;
        if (!input) return;

        // Ledger Partial/Read access: verify is read-only.
        if (!gsLedgerViewState.canVerify) {
          input.checked = !input.checked;
          return;
        }

        if (!requireWriteAccess('ledger', 'Ledger is read only for your account.')) {
          input.checked = !input.checked;
          return;
        }
        const ledgerId = String(input.getAttribute('data-ledger-id') || '').trim();
        if (!ledgerId) return;

        const map = loadGsLedgerVerifiedMap(year);
        map[ledgerId] = Boolean(input.checked);
        saveGsLedgerVerifiedMap(map, year);

        // Keep sort/search values consistent.
        applyGsLedgerView();
      });
    }

    if (!gsLedgerTbody.dataset.downloadBound) {
      gsLedgerTbody.dataset.downloadBound = '1';
      gsLedgerTbody.addEventListener('click', (e) => {
        const link = e.target && e.target.closest ? e.target.closest('a[data-action="downloadPdf"][data-order-id]') : null;
        if (!link) return;
        e.preventDefault();

        const orderId = String(link.getAttribute('data-order-id') || '').trim();
        if (!orderId) return;

        const order = loadOrders(year).find((o) => o && String(o.id) === orderId);
        if (!order) return;
        if (hasOrderMissingRequiredValues(order)) {
          window.alert('Complete all required fields before downloading a PDF.');
          return;
        }
        generatePaymentOrderPdfFromTemplate({ order });
      });
    }

    function escapeCsvValue(value) {
      const s = String(value ?? '');
      const normalized = s.replace(/\u00A0/g, ' ').replace(/\r\n|\r|\n/g, ' ').trim();
      const mustQuote = /[",\n\r]/.test(normalized);
      const escaped = normalized.replace(/"/g, '""');
      return mustQuote ? `"${escaped}"` : escaped;
    }

    function downloadCsvFile(csvText, fileName) {
      const blob = new Blob([csvText], { type: 'text/csv;charset=utf-8;' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = fileName;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    }

    function getTodayStamp() {
      const d = new Date();
      const yyyy = d.getFullYear();
      const mm = String(d.getMonth() + 1).padStart(2, '0');
      const dd = String(d.getDate()).padStart(2, '0');
      return `${yyyy}-${mm}-${dd}`;
    }

    function exportGsLedgerToCsv() {
      const header = ['Date', 'Budget Nr.', 'Counterparty', 'Payment Order Nr.', 'Euro (€)', 'USD ($)', 'Verified', 'With', 'Status', 'Details'];
      const all = buildGsLedgerRowsForYear(year);
      const sorted = sortGsLedgerForView(all, 'date', 'desc');
      const lines = [];
      lines.push(header.map(escapeCsvValue).join(','));

      for (const r of sorted) {
        const values = [
          String(r && r.date ? r.date : ''),
          String(r && r.budgetNumber ? r.budgetNumber : ''),
          String(r && r.creditorDebtor ? r.creditorDebtor : ''),
          String(r && r.paymentOrderNo ? r.paymentOrderNo : ''),
          r && r.euro !== null && r.euro !== undefined && r.euro !== '' ? String(r.euro) : '',
          r && r.usd !== null && r.usd !== undefined && r.usd !== '' ? String(r.usd) : '',
          r && r.verified ? 'TRUE' : 'FALSE',
          String(r && r.with ? r.with : ''),
          String(r && r.status ? r.status : ''),
          String(r && r.details ? r.details : ''),
        ];
        lines.push(values.map(escapeCsvValue).join(','));
      }

      const csv = `\uFEFF${lines.join('\r\n')}\r\n`;
      downloadCsvFile(csv, `ledger_${year}_${getTodayStamp()}.csv`);
    }

    if (exportCsvLink) {
      exportCsvLink.addEventListener('click', (e) => {
        e.preventDefault();
        exportGsLedgerToCsv();
        if (menuPanel && menuBtn) {
          menuPanel.setAttribute('hidden', '');
          menuBtn.setAttribute('aria-expanded', 'false');
        }
      });
    }

    if (menuBtn) {
      const MENU_CLOSE_DELAY_MS = 250;
      let menuCloseTimer = 0;

      function isMenuOpen() {
        return Boolean(menuPanel && !menuPanel.hasAttribute('hidden'));
      }

      function closeMenu() {
        if (!menuPanel || !menuBtn) return;
        menuPanel.setAttribute('hidden', '');
        menuBtn.setAttribute('aria-expanded', 'false');
      }

      function openMenu() {
        if (!menuPanel || !menuBtn) return;
        menuPanel.removeAttribute('hidden');
        menuBtn.setAttribute('aria-expanded', 'true');
      }

      function toggleMenu() {
        if (isMenuOpen()) closeMenu();
        else openMenu();
      }

      function cancelScheduledClose() {
        if (!menuCloseTimer) return;
        clearTimeout(menuCloseTimer);
        menuCloseTimer = 0;
      }

      function scheduleClose() {
        cancelScheduledClose();
        if (!isMenuOpen()) return;
        menuCloseTimer = window.setTimeout(() => {
          closeMenu();
          menuCloseTimer = 0;
        }, MENU_CLOSE_DELAY_MS);
      }

      menuBtn.addEventListener('click', () => {
        toggleMenu();
      });

      menuBtn.addEventListener('mouseenter', cancelScheduledClose);
      menuBtn.addEventListener('mouseleave', scheduleClose);

      if (menuPanel) {
        menuPanel.addEventListener('mouseenter', cancelScheduledClose);
        menuPanel.addEventListener('mouseleave', scheduleClose);
      }

      document.addEventListener('click', (e) => {
        if (!isMenuOpen()) return;
        const menuRoot = e.target?.closest ? e.target.closest('[data-gs-ledger-menu]') : null;
        if (menuRoot) return;
        cancelScheduledClose();
        closeMenu();
      });

      document.addEventListener('keydown', (e) => {
        if (!isMenuOpen()) return;
        if (e.key === 'Escape') {
          cancelScheduledClose();
          closeMenu();
        }
      });
    }

    // Keep the ledger in sync across tabs/windows.
    if (!gsLedgerTbody.dataset.storageBound) {
      gsLedgerTbody.dataset.storageBound = '1';
      window.addEventListener('storage', (e) => {
        const key = e && typeof e.key === 'string' ? e.key : '';
        if (!key) return;
        if (
          key.startsWith('payment_orders_')
          || key.startsWith('payment_order_income_')
          || key.startsWith('payment_order_gs_ledger_verified_')
          || key.startsWith('payment_order_wise_eur_')
          || key.startsWith('payment_order_wise_usd_')
        ) {
          applyGsLedgerView();
        }
      });
    }

    applyGsLedgerView();
  }

  
  // [bundle-strip:menu-remove-money-transfers] removed in page-specific build.
function loadIncome(year) {
    const resolvedYear = Number.isInteger(Number(year)) ? Number(year) : getActiveBudgetYear();
    const key = getIncomeKeyForYear(resolvedYear);
    if (!key) return [];
    try {
      const raw = localStorage.getItem(key);
      if (!raw) return [];
      const parsed = JSON.parse(raw);
      return Array.isArray(parsed) ? parsed : [];
    } catch {
      return [];
    }
  }

  /** @param {Array<Object>} entries */
  function saveIncome(entries, year) {
    const resolvedYear = Number.isInteger(Number(year)) ? Number(year) : getActiveBudgetYear();
    const key = getIncomeKeyForYear(resolvedYear);
    if (!key) return;
    localStorage.setItem(key, JSON.stringify(entries || []));

    // Budget updates are ledger-driven only.
    syncBudgetFromLedgerSafe(resolvedYear, 'income');
  }

  function upsertIncomeEntry(entry, year) {
    if (!entry || !entry.id) return;
    const y = Number.isInteger(Number(year)) ? Number(year) : getActiveBudgetYear();
    const all = loadIncome(y);
    const idx = all.findIndex((e) => e && e.id === entry.id);
    const next = idx >= 0 ? all.map((e) => (e && e.id === entry.id ? entry : e)) : [entry, ...all];
    saveIncome(next, y);
  }

  function deleteIncomeEntryById(id, year) {
    if (!id) return;
    const y = Number.isInteger(Number(year)) ? Number(year) : getActiveBudgetYear();
    const all = loadIncome(y);
    const target = all.find((e) => e && e.id === id);
    const next = all.filter((e) => e && e.id !== id);
    saveIncome(next, y);
    if (target) {
      const tx = formatDate(target.date);
      const remitter = String(target.remitter || '').trim();
      const record = `${tx}${remitter ? ` — ${remitter}` : ''}`.trim() || String(id || 'Income');
      appendAppAuditEvent(`Income (${y})`, record, 'Deleted', []);
    }
  }

  const INCOME_COL_TYPES = {
    date: 'date',
    remitter: 'text',
    budgetNumber: 'text',
    euro: 'number',
    description: 'text',
  };

  const incomeViewState = {
    globalFilter: '',
    sortKey: 'date',
    sortDir: 'desc',
    defaultEmptyText: null,
  };

  function ensureIncomeDefaultEmptyText() {
    if (!incomeEmptyState) return;
    if (incomeViewState.defaultEmptyText !== null) return;
    incomeViewState.defaultEmptyText = incomeEmptyState.textContent || 'No income entries yet.';
  }

  function getIncomeDisplayValueForColumn(entry, colKey, year) {
    if (!entry) return '';
    switch (colKey) {
      case 'date':
        return formatDate(entry.date);
      case 'remitter':
        return entry.remitter || '';
      case 'budgetNumber':
        return extractInCodeFromBudgetNumberText(entry.budgetNumber);
      case 'euro':
        return formatCurrency(entry.euro, 'EUR');
      case 'description':
        return entry.description || '';
      default:
        return '';
    }
  }

  function getIncomeSortValueForColumn(entry, colKey, colType, year) {
    if (!entry) return null;
    if (colType === 'number') {
      const raw = entry.euro;
      const num = raw === null || raw === undefined || raw === '' ? null : Number(raw);
      return Number.isFinite(num) ? num : null;
    }
    if (colType === 'date') {
      const raw = String(entry.date || '').trim();
      return raw ? raw : null;
    }
    return normalizeTextForSearch(getIncomeDisplayValueForColumn(entry, colKey, year));
  }

  function sortIncomeForView(entries, sortKey, sortDir, year) {
    const dir = sortDir === 'desc' ? -1 : 1;
    if (!sortKey) {
      return [...(entries || [])].sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)));
    }

    const colType = INCOME_COL_TYPES[sortKey] || 'text';
    const withIndex = (entries || []).map((entry, index) => ({ entry, index }));
    withIndex.sort((a, b) => {
      const av = getIncomeSortValueForColumn(a.entry, sortKey, colType, year);
      const bv = getIncomeSortValueForColumn(b.entry, sortKey, colType, year);

      if (av === null && bv === null) return a.index - b.index;
      if (av === null) return 1;
      if (bv === null) return -1;

      if (colType === 'number') {
        const cmp = av === bv ? 0 : av < bv ? -1 : 1;
        return cmp === 0 ? a.index - b.index : cmp * dir;
      }

      const cmp = String(av).localeCompare(String(bv));
      return cmp === 0 ? a.index - b.index : cmp * dir;
    });
    return withIndex.map((x) => x.entry);
  }

  function filterIncomeForView(entries, globalFilter, year) {
    const needle = normalizeTextForSearch(globalFilter);
    if (!needle) return entries || [];

    const cols = Object.keys(INCOME_COL_TYPES);
    return (entries || []).filter((e) => {
      return cols.some((colKey) => normalizeTextForSearch(getIncomeDisplayValueForColumn(e, colKey, year)).includes(needle));
    });
  }

  function renderIncomeRows(entries, year) {
    if (!incomeTbody) return;

    const currentUser = getCurrentUser();
    const canEditIncome = Boolean(currentUser && canWriteOrCreate(currentUser, 'income_bankeur'));
    const canDeleteIncome = Boolean(currentUser && canDelete(currentUser, 'income_bankeur'));
    const editDisabledAttr = '';
    const editAriaDisabled = canEditIncome ? 'false' : 'true';
    const editTooltipAttr = canEditIncome ? '' : ' data-tooltip="Edit and create access required for Income."';
    const deleteDisabledAttr = '';
    const deleteAriaDisabled = canDeleteIncome ? 'false' : 'true';
    const deleteTooltipAttr = canDeleteIncome ? '' : ' data-tooltip="Requires Delete access for Income."';

    const ordersBySourceEntryId = new Map();
    const ordersByPoCanon = new Map();
    const orderIds = new Set();
    {
      const orders = loadOrders(year);
      for (const o of orders || []) {
        if (!o || typeof o !== 'object') continue;

        const oid = String(o.id || '').trim();
        if (oid) orderIds.add(oid);

        const poCanon = canonicalizePaymentOrderNo(o.paymentOrderNo);
        if (poCanon && !ordersByPoCanon.has(poCanon)) ordersByPoCanon.set(poCanon, o);

        const sourceEntryId = String(o.sourceEntryId || '').trim();
        if (!sourceEntryId) continue;
        if (!ordersBySourceEntryId.has(sourceEntryId)) {
          ordersBySourceEntryId.set(sourceEntryId, o);
          continue;
        }
        // Prefer an order that has a PO number assigned.
        const existing = ordersBySourceEntryId.get(sourceEntryId);
        const existingPoNo = String(existing && existing.paymentOrderNo ? existing.paymentOrderNo : '').trim();
        const nextPoNo = String(o && o.paymentOrderNo ? o.paymentOrderNo : '').trim();
        if (!existingPoNo && nextPoNo) ordersBySourceEntryId.set(sourceEntryId, o);
      }
    }

    const reconcileBySourceEntryId = new Map();
    const reconcileByPoCanon = new Map();
    {
      const rec = loadReconciliationOrders(year);
      for (const o of rec || []) {
        if (!o || typeof o !== 'object') continue;
        const poCanon = canonicalizePaymentOrderNo(o.paymentOrderNo);
        if (poCanon && !reconcileByPoCanon.has(poCanon)) reconcileByPoCanon.set(poCanon, o);

        const sourceEntryId = String(o.sourceEntryId || '').trim();
        if (!sourceEntryId) continue;
        if (!reconcileBySourceEntryId.has(sourceEntryId)) reconcileBySourceEntryId.set(sourceEntryId, o);
      }
    }

    const rowsHtml = (entries || [])
      .map((e) => {
        const id = escapeHtml(e.id);
        const isMissingBudget = String(e && e.budgetNumber ? e.budgetNumber : '').trim() === '';
        const rowClass = isMissingBudget ? ' class="incomeRow--missingBudget"' : '';
        const date = escapeHtml(getIncomeDisplayValueForColumn(e, 'date', year));
        const remitter = escapeHtml(getIncomeDisplayValueForColumn(e, 'remitter', year));
        const budgetCode = getIncomeDisplayValueForColumn(e, 'budgetNumber', year);
        const budget = renderInBudgetNumberHtml(budgetCode, year);
        const euro = escapeHtml(getIncomeDisplayValueForColumn(e, 'euro', year));
        const descRaw = String(e && e.description ? e.description : '');
        const strippedDescRaw = descRaw
          // Avoid duplicating legacy/free-typed converted markers.
          .replace(/\s*\(\s*converted\s+to\s+PO\s+\d{2}\s*-\s*\d{1,3}\s*\)\s*\.?\s*$/i, '')
          .replace(/\s*converted\s+to\s+PO\s+\d{2}\s*-\s*\d{1,3}\s*\.?\s*$/i, '')
          .replace(/\s*\(\s*pending\s+Payment\s+Order\s+Reconciliation\s*\)\s*\.?\s*$/i, '')
          .trim();
        const descText = escapeHtml(strippedDescRaw);

        const euroRaw = Number(e && e.euro);
        const isNegative = Number.isFinite(euroRaw) && euroRaw < 0;
        const srcEntryId = isNegative ? `inc:${String(e.id || '')}` : '';
        const match = srcEntryId
          ? (ordersBySourceEntryId.get(srcEntryId) || reconcileBySourceEntryId.get(srcEntryId))
          : null;

        // Determine the PO number to display/link.
        const poFromMatch = String(match && match.paymentOrderNo ? match.paymentOrderNo : '').trim();
        const poFromIdTrack = String(e && e.idTrack ? e.idTrack : '').trim();
        const poFromDescMatch = descRaw.match(/\bPO\s*\d{2}\s*-\s*\d{1,3}\b/i);
        const poFromDesc = poFromDescMatch ? String(poFromDescMatch[0] || '').trim() : '';

        const poCandidate = poFromMatch || poFromIdTrack || poFromDesc;
        const poCanon = canonicalizePaymentOrderNo(poCandidate);
        const poOrder = poCanon
          ? (ordersByPoCanon.get(poCanon) || reconcileByPoCanon.get(poCanon))
          : null;

        const orderForLink = match || poOrder;
        const isOnPaymentOrdersTable = Boolean(orderForLink && orderForLink.id && orderIds.has(String(orderForLink.id)));
        const isOnReconciliationTable = Boolean(orderForLink && orderForLink.id && !isOnPaymentOrdersTable);
        const orderIdForLink = orderForLink && orderForLink.id ? escapeHtml(String(orderForLink.id)) : '';
        const orderScopeForLink = isOnPaymentOrdersTable ? 'orders' : 'reconciliation';
        const poDisplayRaw = formatPaymentOrderNoForDisplay(orderForLink && orderForLink.paymentOrderNo ? orderForLink.paymentOrderNo : poCandidate);
        const poDisplay = poDisplayRaw ? escapeHtml(poDisplayRaw) : '';

        const convertedHtml = (isNegative && isOnPaymentOrdersTable && poDisplay)
          ? (orderIdForLink
            ? ` (converted to <a href="#" class="poNoDownloadLink" data-action="downloadPdf" data-order-id="${orderIdForLink}" data-order-scope="${escapeHtml(orderScopeForLink)}" title="Download PDF">${poDisplay}</a>)`
            : ` (converted to ${poDisplay})`)
          : (isNegative && isOnReconciliationTable ? ' (pending Payment Order Reconciliation).' : '');

        const desc = `${descText}${convertedHtml}`;

        return `
          <tr${rowClass} data-income-id="${id}">
            <td>${date}</td>
            <td>${remitter}</td>
            <td>${budget}</td>
            <td class="num">${euro}</td>
            <td>${desc}</td>
            <td class="actions">
              <button type="button" class="btn btn--editIcon" data-income-action="edit" aria-label="Edit" title="${canEditIncome ? 'Edit' : 'Read-only access for Income.'}" aria-disabled="${editAriaDisabled}"${editDisabledAttr}${editTooltipAttr}><svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path d="M15.502 1.94a.5.5 0 0 1 0 .706L14.459 3.69l-2-2L13.502.646a.5.5 0 0 1 .707 0l1.293 1.293zm-1.75 2.456-2-2L4.939 9.21a.5.5 0 0 0-.121.196l-.805 2.414a.25.25 0 0 0 .316.316l2.414-.805a.5.5 0 0 0 .196-.12l6.813-6.814z"/><path fill-rule="evenodd" d="M1 13.5A1.5 1.5 0 0 0 2.5 15h11a1.5 1.5 0 0 0 1.5-1.5v-6a.5.5 0 0 0-1 0v6a.5.5 0 0 1-.5.5h-11a.5.5 0 0 1-.5-.5v-11a.5.5 0 0 1 .5-.5H9a.5.5 0 0 0 0-1H2.5A1.5 1.5 0 0 0 1 2.5z"/></svg></button>
              <button type="button" class="btn btn--x" data-income-action="delete" aria-label="Delete entry" title="${canDeleteIncome ? 'Delete' : 'Requires Delete access for Income.'}" aria-disabled="${deleteAriaDisabled}"${deleteDisabledAttr}${deleteTooltipAttr}><svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path d="M6.5 1h3a.5.5 0 0 1 .5.5v1H6v-1a.5.5 0 0 1 .5-.5M11 2.5v-1A1.5 1.5 0 0 0 9.5 0h-3A1.5 1.5 0 0 0 5 1.5v1H1.5a.5.5 0 0 0 0 1h.538l.853 10.66A2 2 0 0 0 4.885 16h6.23a2 2 0 0 0 1.994-1.84l.853-10.66h.538a.5.5 0 0 0 0-1zm1.958 1-.846 10.58a1 1 0 0 1-.997.92h-6.23a1 1 0 0 1-.997-.92L3.042 3.5zm-7.487 1a.5.5 0 0 1 .528.47l.5 8.5a.5.5 0 0 1-.998.06L6 5a.5.5 0 0 1 .471-.53zm5.058 0a.5.5 0 0 1 .47.53l-.5 8.5a.5.5 0 0 1-.998-.06l.5-8.5a.5.5 0 0 1 .528-.47M8 4.5a.5.5 0 0 1 .5.5v8.5a.5.5 0 0 1-1 0V5a.5.5 0 0 1 .5-.5"/></svg></button>
            </td>
          </tr>
        `.trim();
      })
      .join('');

    incomeTbody.innerHTML = rowsHtml;
  }

  function updateIncomeSortIndicators() {
    if (!incomeTbody) return;
    const table = incomeTbody.closest('table');
    if (!table) return;

    const sortKey = incomeViewState.sortKey;
    const sortDir = incomeViewState.sortDir === 'desc' ? 'desc' : 'asc';

    const ths = Array.from(table.querySelectorAll('thead th[data-sort-key]'));
    for (const th of ths) {
      const colKey = th.getAttribute('data-sort-key');
      let aria = 'none';
      if (colKey && sortKey === colKey) {
        aria = sortDir === 'desc' ? 'descending' : 'ascending';
      }
      th.setAttribute('aria-sort', aria);
    }
  }

  function initIncomeColumnSorting() {
    if (!incomeTbody) return;
    const table = incomeTbody.closest('table');
    if (!table) return;
    if (table.dataset.sortBound === '1') return;

    const ths = Array.from(table.querySelectorAll('thead th[data-sort-key]'));
    if (ths.length === 0) return;
    table.dataset.sortBound = '1';

    function applySortForKey(colKey) {
      if (!colKey) return;
      if (incomeViewState.sortKey === colKey) {
        incomeViewState.sortDir = incomeViewState.sortDir === 'asc' ? 'desc' : 'asc';
      } else {
        incomeViewState.sortKey = colKey;
        incomeViewState.sortDir = 'asc';
      }
      applyIncomeView();
    }

    for (const th of ths) {
      th.classList.add('is-sortable');
      if (!th.hasAttribute('tabindex')) th.setAttribute('tabindex', '0');
      if (!th.hasAttribute('aria-sort')) th.setAttribute('aria-sort', 'none');

      th.addEventListener('click', () => applySortForKey(th.getAttribute('data-sort-key')));
      th.addEventListener('keydown', (e) => {
        if (e.key !== 'Enter' && e.key !== ' ') return;
        e.preventDefault();
        applySortForKey(th.getAttribute('data-sort-key'));
      });
    }

    updateIncomeSortIndicators();
  }

  function populateIncomeBudgetSelect(select, year) {
    if (!select) return;

    const prev = String(select.value || '').trim();
    select.innerHTML = '';

    const placeholder = document.createElement('option');
    placeholder.value = '';
    placeholder.selected = true;
    placeholder.textContent = 'Select a budget number (restricted)…';
    select.appendChild(placeholder);

    const inAccounts = readInAccountsFromBudgetYear(year);
    if (inAccounts.length === 0) {
      const none = document.createElement('option');
      none.value = '__none__';
      none.disabled = true;
      none.textContent = 'No IN accounts found in the active budget';
      select.appendChild(none);
      return;
    }

    for (const item of inAccounts) {
      const opt = document.createElement('option');
      opt.value = item.inCode;
      opt.textContent = item.desc ? `${item.inCode} - ${item.desc}` : item.inCode;
      select.appendChild(opt);
    }

    if (prev && inAccounts.some((x) => x.inCode === prev)) {
      select.value = prev;
    }
  }

  let currentIncomeId = null;

  function openIncomeModal(entry, year) {
    if (!incomeModal || !incomeModalBody) return;
    const y = Number.isInteger(Number(year)) ? Number(year) : getActiveBudgetYear();
    currentIncomeId = entry && entry.id ? entry.id : null;

    // Backfill/persist an initial timeline entry for older records.
    let entryForView = entry;
    if (currentIncomeId && entryForView && (!Array.isArray(entryForView.timeline) || entryForView.timeline.length === 0)) {
      const seeded = ensureIncomeTimeline(entryForView);
      entryForView = { ...entryForView, timeline: seeded };
      upsertIncomeEntry(entryForView, y);
    }

    const titleEl = incomeModal.querySelector('#incomeModalTitle');
    const subheadEl = incomeModal.querySelector('#incomeModalSubhead');
    if (titleEl) titleEl.textContent = currentIncomeId ? 'Income (Edit)' : 'Income (New)';
    if (subheadEl) subheadEl.textContent = `${y} Income`;

    const safeDate = escapeHtml(entryForView && entryForView.date ? entryForView.date : '');
    const safeRemitter = escapeHtml(entryForView && entryForView.remitter ? entryForView.remitter : '');
    const safeEuro =
      entryForView && entryForView.euro !== null && entryForView.euro !== undefined && entryForView.euro !== '' ? escapeHtml(String(entryForView.euro)) : '';
    const safeDesc = escapeHtml(entryForView && entryForView.description ? entryForView.description : '');
    const safeBudget = escapeHtml(entryForView && entryForView.budgetNumber ? entryForView.budgetNumber : '');

    const timelineHtml = currentIncomeId && entryForView ? renderIncomeTimelineGraph(entryForView) : '';

    incomeModalBody.innerHTML = `
      <form id="incomeModalForm" novalidate>
        <div class="grid">
          <div class="field">
            <label for="incomeDate">Transaction Date<span class="req" aria-hidden="true">*</span></label>
            <input id="incomeDate" name="incomeDate" type="date" required value="${safeDate}" />
            <div class="error" id="error-incomeDate" role="alert" aria-live="polite"></div>
          </div>

          <div class="field">
            <label for="incomeEuro">Euro (€)<span class="req" aria-hidden="true">*</span></label>
            <input id="incomeEuro" name="incomeEuro" type="number" inputmode="decimal" step="0.01" required value="${safeEuro}" />
            <div class="error" id="error-incomeEuro" role="alert" aria-live="polite"></div>
          </div>

          <div class="field">
            <label for="incomeRemitter">Remitter<span class="req" aria-hidden="true">*</span></label>
            <input id="incomeRemitter" name="incomeRemitter" type="text" autocomplete="off" required value="${safeRemitter}" />
            <div class="error" id="error-incomeRemitter" role="alert" aria-live="polite"></div>
          </div>

          <div class="field field--span2">
            <label for="incomeBudgetNumber">Budget Nr.</label>
            <select id="incomeBudgetNumber" name="incomeBudgetNumber">
              <option value="" selected>Select a budget number (restricted)…</option>
            </select>
            <div class="error" id="error-incomeBudgetNumber" role="alert" aria-live="polite"></div>
          </div>

          <div class="field field--span2">
            <label for="incomeDescription">Description<span class="req" aria-hidden="true">*</span></label>
            <textarea id="incomeDescription" name="incomeDescription" rows="3" required>${safeDesc}</textarea>
            <div class="error" id="error-incomeDescription" role="alert" aria-live="polite"></div>
          </div>
        </div>
      </form>
      ${timelineHtml}
    `.trim();

    const select = incomeModalBody.querySelector('#incomeBudgetNumber');
    if (select) {
      populateIncomeBudgetSelect(select, y);
      if (safeBudget) select.value = safeBudget;
    }

    incomeModal.classList.add('is-open');
    incomeModal.setAttribute('aria-hidden', 'false');

    const focusTarget = incomeModalBody.querySelector('#incomeDate');
    if (focusTarget && focusTarget.focus) focusTarget.focus();
  }

  function closeIncomeModal() {
    if (!incomeModal || !incomeModalBody) return;
    incomeModal.classList.remove('is-open');
    incomeModal.setAttribute('aria-hidden', 'true');
    incomeModalBody.innerHTML = '';
    currentIncomeId = null;
  }

  function clearIncomeModalErrors() {
    if (!incomeModalBody) return;
    const errors = Array.from(incomeModalBody.querySelectorAll('.error'));
    for (const el of errors) el.textContent = '';
  }

  function showIncomeModalErrors(errors) {
    if (!incomeModalBody || !errors) return;
    const map = {
      date: '#error-incomeDate',
      euro: '#error-incomeEuro',
      remitter: '#error-incomeRemitter',
      budgetNumber: '#error-incomeBudgetNumber',
      description: '#error-incomeDescription',
    };
    for (const [k, sel] of Object.entries(map)) {
      const el = incomeModalBody.querySelector(sel);
      if (el) el.textContent = errors[k] || '';
    }
  }

  function validateIncomeModalValues() {
    if (!incomeModalBody) return { ok: false };
    const dateEl = incomeModalBody.querySelector('#incomeDate');
    const euroEl = incomeModalBody.querySelector('#incomeEuro');
    const remitterEl = incomeModalBody.querySelector('#incomeRemitter');
    const budgetEl = incomeModalBody.querySelector('#incomeBudgetNumber');
    const descEl = incomeModalBody.querySelector('#incomeDescription');

    const values = {
      date: dateEl ? String(dateEl.value || '').trim() : '',
      euro: euroEl ? String(euroEl.value || '').trim() : '',
      remitter: remitterEl ? String(remitterEl.value || '').trim() : '',
      budgetNumber: budgetEl ? String(budgetEl.value || '').trim() : '',
      description: descEl ? String(descEl.value || '').trim() : '',
    };

    const errors = {};
    if (!values.date) errors.date = 'This field is required.';
    if (!values.remitter) errors.remitter = 'This field is required.';
    if (!values.description) errors.description = 'This field is required.';

    const euroNum = Number(values.euro);
    if (String(values.euro || '').trim() === '') errors.euro = 'This field is required.';
    else if (!Number.isFinite(euroNum)) errors.euro = 'Enter a valid amount.';

    if (Object.keys(errors).length > 0) return { ok: false, errors };
    return {
      ok: true,
      values: {
        date: values.date,
        remitter: values.remitter,
        budgetNumber: values.budgetNumber,
        euro: euroNum,
        description: values.description,
      },
    };
  }

  function applyIncomeView() {
    if (!incomeTbody || !incomeEmptyState) return;
    ensureIncomeDefaultEmptyText();

    const year = getActiveBudgetYear();
    const all = loadIncome(year);
    const filtered = filterIncomeForView(all, incomeViewState.globalFilter, year);
    const sorted = sortIncomeForView(filtered, incomeViewState.sortKey, incomeViewState.sortDir, year);

    if (normalizeTextForSearch(incomeViewState.globalFilter) !== '' && all.length > 0 && sorted.length === 0) {
      incomeEmptyState.textContent = 'No income entries match your search.';
    } else {
      incomeEmptyState.textContent = incomeViewState.defaultEmptyText;
    }

    incomeEmptyState.hidden = sorted.length > 0;
    renderIncomeRows(sorted, year);
    updateIncomeTotals(sorted);
    updateIncomeSortIndicators();
  }

  function updateIncomeTotals(entries) {
    const totalEuroEl = document.getElementById('incomeTotalEuro');
    if (!totalEuroEl) return;

    let total = 0;
    for (const e of entries || []) {
      const n = Number(e && e.euro);
      if (Number.isFinite(n)) total += n;
    }
    totalEuroEl.textContent = formatCurrency(total, 'EUR');
  }

  function initIncomeListPage() {
    if (!incomeTbody || !incomeEmptyState) return;
    const year = getActiveBudgetYear();

    const currentUser = getCurrentUser();
    const hasIncomeCreateAccess = Boolean(currentUser && canCreate(currentUser, 'income_bankeur'));

    const incomeNewLink = document.getElementById('incomeNewLink');
    const incomeExportCsvLink = document.getElementById('incomeExportCsvLink');
    const incomeDownloadTemplateLink = document.getElementById('incomeDownloadTemplateLink');
    const incomeImportCsvLink = document.getElementById('incomeImportCsvLink');
    const incomeMenuBtn = document.getElementById('incomeActionsMenuBtn');
    const incomeMenuPanel = document.getElementById('incomeActionsMenu');
    const incomeBackToLedgerLink = document.getElementById('incomeBackToLedgerLink');

    function setLinkDisabled(linkEl, disabled) {
      if (!linkEl) return;
      linkEl.setAttribute('aria-disabled', disabled ? 'true' : 'false');
      if (disabled) linkEl.setAttribute('tabindex', '-1');
      else linkEl.removeAttribute('tabindex');
    }

    // Ensure the year is present in the URL for consistent nav highlighting.
    const fromUrl = getBudgetYearFromUrl();
    if (!fromUrl && getBasename(window.location.pathname) === 'income.html') {
      try {
        const url = new URL(window.location.href);
        url.searchParams.set('year', String(year));
        window.history.replaceState(null, '', url.toString());
      } catch {
        // ignore
      }
    }

    ensureIncomeListExistsForYear(year);

    const titleEl = document.querySelector('[data-income-title]');
    const incomeTitle = `${year} BankEUR (Commerzbank)`;
    if (titleEl) titleEl.textContent = incomeTitle;
    const listTitleEl = document.querySelector('[data-income-list-title]');
    if (listTitleEl) listTitleEl.textContent = incomeTitle;
    if (incomeBackToLedgerLink) {
      incomeBackToLedgerLink.href = `grand_secretary_ledger.html?year=${encodeURIComponent(String(year))}`;
      incomeBackToLedgerLink.textContent = `← Back to ${year} Ledger`;
    }
    applyAppTabTitle();

    initIncomeColumnSorting();

    // Partial access for Income = full access except New Income and Import CSV.
    setLinkDisabled(incomeNewLink, !hasIncomeCreateAccess);
    if (incomeNewLink && !hasIncomeCreateAccess) {
      incomeNewLink.setAttribute(
        'data-tooltip',
        'Requires Create access for Income. Write access can edit existing entries, but cannot create new ones.'
      );
    }
    setLinkDisabled(incomeImportCsvLink, !hasIncomeCreateAccess);
    if (incomeImportCsvLink && !hasIncomeCreateAccess) {
      incomeImportCsvLink.setAttribute(
        'data-tooltip',
        'Requires Create access for Income. Write access can edit existing entries, but cannot import new ones.'
      );
    }

    const globalInput = document.getElementById('incomeGlobalSearch');
    if (globalInput) {
      globalInput.value = incomeViewState.globalFilter || '';
      globalInput.addEventListener('input', () => {
        incomeViewState.globalFilter = globalInput.value;
        if (incomeClearSearchBtn) {
          const hasSearch = normalizeTextForSearch(incomeViewState.globalFilter) !== '';
          incomeClearSearchBtn.hidden = !hasSearch;
          incomeClearSearchBtn.disabled = !hasSearch;
        }
        applyIncomeView();
      });
    }

    if (incomeClearSearchBtn && globalInput) {
      const hasSearch = normalizeTextForSearch(incomeViewState.globalFilter) !== '';
      incomeClearSearchBtn.hidden = !hasSearch;
      incomeClearSearchBtn.disabled = !hasSearch;
      if (!incomeClearSearchBtn.dataset.bound) {
        incomeClearSearchBtn.dataset.bound = 'true';
        incomeClearSearchBtn.addEventListener('click', () => {
          globalInput.value = '';
          incomeViewState.globalFilter = '';
          incomeClearSearchBtn.hidden = true;
          incomeClearSearchBtn.disabled = true;
          applyIncomeView();
          if (globalInput.focus) globalInput.focus();
        });
      }
    }

    if (incomeNewLink) {
      incomeNewLink.addEventListener('click', (e) => {
        e.preventDefault();
        if (incomeNewLink.getAttribute('aria-disabled') === 'true') {
          alertDisabledAction(incomeNewLink);
          return;
        }
        if (!requireCreateAccess('income_bankeur', 'Create access is required for Income.')) return;
        openIncomeModal(null, year);
        if (incomeMenuPanel && incomeMenuBtn) {
          incomeMenuPanel.setAttribute('hidden', '');
          incomeMenuBtn.setAttribute('aria-expanded', 'false');
        }
      });
    }

    if (incomeClearAllBtn) {
      incomeClearAllBtn.addEventListener('click', () => {
        if (!requireDeleteAccess('income_bankeur', 'Delete access is required for Income.')) return;
        const all = loadIncome(year);
        if (all.length === 0) return;
        const ok = window.confirm('Clear all income entries? This cannot be undone.');
        if (!ok) return;

        saveIncome([], year);
        applyIncomeView();
      });
    }

    function escapeCsvValue(value) {
      const s = String(value ?? '');
      const normalized = s.replace(/\u00A0/g, ' ').replace(/\r\n|\r|\n/g, ' ').trim();
      const mustQuote = /[",\n\r]/.test(normalized);
      const escaped = normalized.replace(/"/g, '""');
      return mustQuote ? `"${escaped}"` : escaped;
    }

    function downloadCsvFile(csvText, fileName) {
      const blob = new Blob([csvText], { type: 'text/csv;charset=utf-8;' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = fileName;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    }

    function getTodayStamp() {
      const d = new Date();
      const yyyy = d.getFullYear();
      const mm = String(d.getMonth() + 1).padStart(2, '0');
      const dd = String(d.getDate()).padStart(2, '0');
      return `${yyyy}-${mm}-${dd}`;
    }

    function exportIncomeToCsv() {
      const header = ['Transaction Date', 'Remitter', 'Budget Nr.', 'Euro', 'Description'];
      const entries = loadIncome(year);
      const lines = [];
      lines.push(header.map(escapeCsvValue).join(','));

      // Export sorted newest-first by date (stable if any missing date)
      const sorted = sortIncomeForView(entries, 'date', 'desc', year);
      for (const e of sorted) {
        const values = [
          String(e && e.date ? e.date : ''),
          String(e && e.remitter ? e.remitter : ''),
          String(e && e.budgetNumber ? e.budgetNumber : ''),
          e && e.euro !== null && e.euro !== undefined && e.euro !== '' ? String(e.euro) : '',
          String(e && e.description ? e.description : ''),
        ];
        lines.push(values.map(escapeCsvValue).join(','));
      }

      const csv = `\uFEFF${lines.join('\r\n')}\r\n`;
      downloadCsvFile(csv, `income_${year}_${getTodayStamp()}.csv`);
    }

    function downloadIncomeCsvTemplate() {
      const header = ['Transaction Date', 'Remitter', 'Budget Nr.', 'Euro', 'Description'];
      // Include a valid ISO date example so imports succeed without guesswork.
      const example = [getTodayStamp(), 'Example Remitter', '', '0.00', 'Example description'];
      const lines = [];
      lines.push(header.map(escapeCsvValue).join(','));
      lines.push(example.map(escapeCsvValue).join(','));
      const csv = `\uFEFF${lines.join('\r\n')}\r\n`;
      downloadCsvFile(csv, `income_template_${year}_${getTodayStamp()}.csv`);
    }

    function parseCsvText(text) {
      const rows = [];
      const s = String(text ?? '');
      let row = [];
      let field = '';
      let inQuotes = false;

      for (let i = 0; i < s.length; i += 1) {
        const ch = s[i];

        if (inQuotes) {
          if (ch === '"') {
            const next = s[i + 1];
            if (next === '"') {
              field += '"';
              i += 1;
            } else {
              inQuotes = false;
            }
          } else {
            field += ch;
          }
          continue;
        }

        if (ch === '"') {
          inQuotes = true;
          continue;
        }

        if (ch === ',') {
          row.push(field);
          field = '';
          continue;
        }

        if (ch === '\n') {
          row.push(field);
          field = '';
          rows.push(row);
          row = [];
          continue;
        }

        if (ch === '\r') {
          continue;
        }

        field += ch;
      }

      row.push(field);
      rows.push(row);

      while (rows.length > 0) {
        const last = rows[rows.length - 1];
        const isEmpty = last.every((c) => String(c ?? '').trim() === '');
        if (!isEmpty) break;
        rows.pop();
      }

      return rows;
    }

    function normalizeHeaderName(name) {
      return String(name ?? '')
        .replace(/\uFEFF/g, '')
        .replace(/\u00A0/g, ' ')
        .trim()
        .toLowerCase();
    }

    function normalizeCsvDate(raw) {
      const s = String(raw ?? '').trim();
      if (!s) return '';
      if (/^\d{4}-\d{2}-\d{2}$/.test(s)) return s;

      // Accept common US-style formats like M/D/YYYY or MM/DD/YYYY (also with '-' separators).
      const mdy = s.match(/^\s*(\d{1,2})[\/\-](\d{1,2})[\/\-](\d{4})\s*$/);
      if (mdy) {
        const mm = Number(mdy[1]);
        const dd = Number(mdy[2]);
        const yyyy = Number(mdy[3]);
        if (!Number.isInteger(mm) || !Number.isInteger(dd) || !Number.isInteger(yyyy)) return '';
        if (yyyy < 1000 || yyyy > 9999) return '';
        if (mm < 1 || mm > 12) return '';
        if (dd < 1 || dd > 31) return '';

        // Validate actual calendar date.
        const d = new Date(yyyy, mm - 1, dd);
        if (d.getFullYear() !== yyyy || d.getMonth() !== mm - 1 || d.getDate() !== dd) return '';

        const mmText = String(mm).padStart(2, '0');
        const ddText = String(dd).padStart(2, '0');
        return `${yyyy}-${mmText}-${ddText}`;
      }

      const ms = Date.parse(s);
      if (!Number.isFinite(ms)) return '';
      const d = new Date(ms);
      const yyyy = d.getFullYear();
      const mm = String(d.getMonth() + 1).padStart(2, '0');
      const dd = String(d.getDate()).padStart(2, '0');
      return `${yyyy}-${mm}-${dd}`;
    }

    function parseEuroAmount(raw) {
      const s = String(raw ?? '').replace(/\u00A0/g, ' ').trim();
      if (!s) return null;
      const cleaned = s.replace(/[^0-9.,\-]/g, '').replace(/,/g, '');
      const n = Number(cleaned);
      if (!Number.isFinite(n) || n < 0) return null;
      return n;
    }

    function parseSignedEuroAmount(raw) {
      const s = String(raw ?? '').replace(/\u00A0/g, ' ').trim();
      if (!s) return null;
      const cleaned = s.replace(/[^0-9.,\-]/g, '').replace(/,/g, '');
      const n = Number(cleaned);
      if (!Number.isFinite(n)) return null;
      return n;
    }

    function findHeaderIndex(headerNames, candidates) {
      const names = Array.isArray(headerNames) ? headerNames : [];
      const cands = (Array.isArray(candidates) ? candidates : []).map(normalizeHeaderName).filter(Boolean);
      if (cands.length === 0) return -1;

      for (const c of cands) {
        const exact = names.indexOf(c);
        if (exact !== -1) return exact;
      }

      for (let i = 0; i < names.length; i += 1) {
        const h = String(names[i] ?? '').trim();
        if (!h) continue;
        if (cands.some((c) => h === c || h.startsWith(`${c} `) || h.startsWith(`${c}(`) || h.startsWith(`${c}—`) || h.startsWith(`${c}-`) || h.startsWith(c))) {
          return i;
        }
      }

      return -1;
    }

    function importIncomeFromCsvText(csvText, fileName) {
      const ok = window.confirm(
        `Importing a CSV will add entries to the current income list for ${year}. Continue?\n\nFile: ${fileName || 'CSV'}`
      );
      if (!ok) return;

      const rows = parseCsvText(csvText);
      if (rows.length === 0) {
        window.alert('CSV is empty.');
        return;
      }

      const header = rows[0].map(normalizeHeaderName);
      const dataRows = rows.slice(1).filter((r) => r.some((c) => String(c ?? '').trim() !== ''));

      const idx = {
        date: findHeaderIndex(header, ['transaction date', 'date']),
        remitter: findHeaderIndex(header, ['remitter']),
        budgetNumber: findHeaderIndex(header, ['budget number', 'budget']),
        euro: findHeaderIndex(header, ['euro', 'eur', 'euro (€)', 'euro (eur)']),
        description: findHeaderIndex(header, ['description', 'details', 'memo', 'reference']),
      };

      const hasHeaders = idx.remitter !== -1 && idx.euro !== -1 && idx.description !== -1 && idx.date !== -1;
      if (!hasHeaders && header.length >= 3) {
        // Allow headerless CSV by treating first row as data in the expected order.
        dataRows.unshift(rows[0]);
        idx.date = 0;
        idx.remitter = 1;
        idx.budgetNumber = 2;
        idx.euro = 3;
        idx.description = 4;
      }

      const nowIso = new Date().toISOString();
      const timelineUser = getTimelineUsername();
      const imported = [];
      const createdReconciliationOrders = [];
      const errors = [];

      for (let rowIndex = 0; rowIndex < dataRows.length; rowIndex += 1) {
        const r = dataRows[rowIndex];
        const get = (i) => (i >= 0 ? (r[i] ?? '') : '');

        const date = normalizeCsvDate(get(idx.date));
        const remitter = String(get(idx.remitter)).trim();
        const budgetNumber = String(get(idx.budgetNumber)).trim();
        const euroSigned = parseSignedEuroAmount(get(idx.euro));
        const description = String(get(idx.description)).trim();

        const rowNo = rowIndex + 2; // 1-based + header row
        if (!date) errors.push(`Row ${rowNo}: invalid Transaction Date.`);
        if (!remitter) errors.push(`Row ${rowNo}: Remitter is required.`);
        if (euroSigned === null) errors.push(`Row ${rowNo}: Euro is required and must be a valid number.`);
        if (!description) errors.push(`Row ${rowNo}: Description is required.`);
        if (!date || !remitter || euroSigned === null || !description) continue;

        // Negative amounts are expenditures: also create Payment Orders in Reconciliation.
        if (euroSigned < 0) {
          const absEuro = Math.abs(euroSigned);
          const itemTitle = description || 'Imported from Income CSV';
          const po = buildPaymentOrder({
            source: 'Commerzbank',
            paymentOrderNo: '',
            date,
            name: remitter,
            euro: absEuro,
            usd: null,
            items: [
              {
                id: (crypto?.randomUUID ? crypto.randomUUID() : `it_${Date.now()}_${Math.random().toString(16).slice(2)}`),
                title: itemTitle,
                euro: absEuro,
                usd: null,
              },
            ],
            address: '',
            iban: '',
            bic: '',
            specialInstructions: '',
            budgetNumber: '',
            purpose: description,
            with: 'Grand Secretary',
            status: 'Submitted',
          });

          po.updatedAt = po.createdAt;

          createdReconciliationOrders.push(po);
        }

        const inc = {
          id: (crypto?.randomUUID ? crypto.randomUUID() : `inc_${Date.now()}_${Math.random().toString(16).slice(2)}`),
          createdAt: nowIso,
          updatedAt: nowIso,
          date,
          remitter,
          budgetNumber,
          euro: euroSigned,
          description,
        };

        // Timeline: treat CSV import as a "Created" event by the importing user.
        inc.timeline = [
          {
            at: nowIso,
            user: timelineUser,
            action: 'Created',
            changes: computeIncomeAuditChanges(null, inc),
          },
        ];

        imported.push(inc);
      }

      if (imported.length === 0 && createdReconciliationOrders.length === 0) {
        window.alert(
          errors.length
            ? `No rows were imported or converted:\n\n${errors.slice(0, 15).join('\n')}`
            : 'No rows were imported or converted.'
        );
        return;
      }

      if (errors.length > 0) {
        const proceed = window.confirm(
          `Some rows could not be processed. Continue with ${imported.length} income row(s) and ${createdReconciliationOrders.length} payment order(s) in Reconciliation?\n\n${errors
            .slice(0, 15)
            .join('\n')}${errors.length > 15 ? '\n…' : ''}`
        );
        if (!proceed) return;
      }

      if (createdReconciliationOrders.length > 0) {
        ensurePaymentOrdersReconciliationListExistsForYear(year);
        const existingOrders = loadReconciliationOrders(year);
        const mergedOrders = [...createdReconciliationOrders, ...(Array.isArray(existingOrders) ? existingOrders : [])];
        saveReconciliationOrders(mergedOrders, year);
      }

      if (imported.length > 0) {
        const existing = loadIncome(year);
        const merged = [...imported, ...(Array.isArray(existing) ? existing : [])];
        saveIncome(merged, year);
      }
      applyIncomeView();

      if (typeof showFlashToken === 'function') {
        showFlashToken(
          `Imported ${imported.length} income row(s). Added ${createdReconciliationOrders.length} payment order(s) to Reconciliation from negative amounts.`
        );
      }
    }

    if (incomeExportCsvLink) {
      incomeExportCsvLink.addEventListener('click', (e) => {
        e.preventDefault();
        exportIncomeToCsv();
      });
    }
    if (incomeDownloadTemplateLink) {
      incomeDownloadTemplateLink.addEventListener('click', (e) => {
        e.preventDefault();
        downloadIncomeCsvTemplate();
      });
    }
    if (incomeImportCsvLink) {
      const input = document.createElement('input');
      input.type = 'file';
      input.accept = '.csv,text/csv';
      input.style.display = 'none';
      document.body.appendChild(input);

      incomeImportCsvLink.addEventListener('click', (e) => {
        e.preventDefault();
        if (incomeImportCsvLink.getAttribute('aria-disabled') === 'true') {
          alertDisabledAction(incomeImportCsvLink);
          return;
        }
        if (!requireCreateAccess('income_bankeur', 'Create access is required for Income.')) return;
        input.value = '';
        input.click();
      });

      input.addEventListener('change', () => {
        const file = input.files && input.files[0];
        if (!file) return;
        const reader = new FileReader();
        reader.onload = () => {
          importIncomeFromCsvText(reader.result, file.name);
        };
        reader.onerror = () => {
          window.alert('Could not read CSV file.');
        };
        reader.readAsText(file);
      });
    }

    if (incomeMenuBtn) {
      const MENU_CLOSE_DELAY_MS = 250;
      let menuCloseTimer = 0;

      function isMenuOpen() {
        return Boolean(incomeMenuPanel && !incomeMenuPanel.hasAttribute('hidden'));
      }

      function closeMenu() {
        if (!incomeMenuPanel || !incomeMenuBtn) return;
        incomeMenuPanel.setAttribute('hidden', '');
        incomeMenuBtn.setAttribute('aria-expanded', 'false');
      }

      function openMenu() {
        if (!incomeMenuPanel || !incomeMenuBtn) return;
        incomeMenuPanel.removeAttribute('hidden');
        incomeMenuBtn.setAttribute('aria-expanded', 'true');
      }

      function toggleMenu() {
        if (isMenuOpen()) closeMenu();
        else openMenu();
      }

      function cancelScheduledClose() {
        if (!menuCloseTimer) return;
        clearTimeout(menuCloseTimer);
        menuCloseTimer = 0;
      }

      function scheduleClose() {
        cancelScheduledClose();
        if (!isMenuOpen()) return;
        menuCloseTimer = window.setTimeout(() => {
          closeMenu();
          menuCloseTimer = 0;
        }, MENU_CLOSE_DELAY_MS);
      }

      incomeMenuBtn.addEventListener('click', () => {
        toggleMenu();
      });

      incomeMenuBtn.addEventListener('mouseenter', cancelScheduledClose);
      incomeMenuBtn.addEventListener('mouseleave', scheduleClose);

      if (incomeMenuPanel) {
        incomeMenuPanel.addEventListener('mouseenter', cancelScheduledClose);
        incomeMenuPanel.addEventListener('mouseleave', scheduleClose);
      }

      document.addEventListener('click', (e) => {
        if (!isMenuOpen()) return;
        const menuRoot = e.target?.closest ? e.target.closest('[data-income-menu]') : null;
        if (menuRoot) return;
        cancelScheduledClose();
        closeMenu();
      });

      document.addEventListener('keydown', (e) => {
        if (!isMenuOpen()) return;
        if (e.key === 'Escape') {
          cancelScheduledClose();
          closeMenu();
        }
      });
    }

    incomeTbody.addEventListener('click', (e) => {
      const dl = e.target && e.target.closest ? e.target.closest('a[data-action="downloadPdf"][data-order-id]') : null;
      if (dl) {
        e.preventDefault();
        const orderId = String(dl.getAttribute('data-order-id') || '').trim();
        const scope = String(dl.getAttribute('data-order-scope') || '').trim().toLowerCase();
        if (!orderId) return;

        const order = scope === 'reconciliation'
          ? loadReconciliationOrders(year).find((o) => o && String(o.id) === orderId)
          : loadOrders(year).find((o) => o && String(o.id) === orderId);
        if (!order) return;
        if (hasOrderMissingRequiredValues(order)) {
          window.alert('Complete all required fields before downloading a PDF.');
          return;
        }
        generatePaymentOrderPdfFromTemplate({ order });
        return;
      }

      const btn = e.target.closest('button[data-income-action]');
      if (!btn) return;
      const row = btn.closest('tr[data-income-id]');
      if (!row) return;
      const id = row.getAttribute('data-income-id');
      const action = btn.getAttribute('data-income-action');

      if (action === 'delete') {
        if (!requireDeleteAccess('income_bankeur', 'Delete access is required for Income.')) return;
        const ok = window.confirm('Delete this income entry?');
        if (!ok) return;

        deleteIncomeEntryById(id, year);
        applyIncomeView();
        return;
      }

      if (action === 'edit') {
        if (!requireIncomeEditAccess('Income is read only for your account.')) return;
        const all = loadIncome(year);
        const entry = all.find((x) => x && x.id === id);
        if (!entry) return;
        openIncomeModal(entry, year);
      }
    });

    if (incomeModal) {
      incomeModal.addEventListener('click', (e) => {
        const closeTarget = e.target.closest('[data-income-modal-close]');
        if (closeTarget) closeIncomeModal();
      });
    }

    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && incomeModal && incomeModal.classList.contains('is-open')) {
        closeIncomeModal();
      }
    });

    if (incomeSaveBtn) {
      incomeSaveBtn.addEventListener('click', () => {
        try {
          if (!requireIncomeEditAccess('Income is read only for your account.')) return;
          if (!hasIncomeCreateAccess && !currentIncomeId) {
            window.alert('Requires Full access for Income to create a new income entry.');
            return;
          }
          clearIncomeModalErrors();
          const res = validateIncomeModalValues();
          if (!res.ok) {
            showIncomeModalErrors(res.errors);
            return;
          }

          const nowIso = new Date().toISOString();
          const timelineUser = getTimelineUsername();
          const id =
            currentIncomeId ||
            (crypto?.randomUUID ? crypto.randomUUID() : `inc_${Date.now()}_${Math.random().toString(16).slice(2)}`);
          const existing = currentIncomeId ? loadIncome(year).find((x) => x && x.id === currentIncomeId) : null;

          const entry = {
            id,
            createdAt: existing && existing.createdAt ? existing.createdAt : nowIso,
            updatedAt: nowIso,
            ...res.values,
            idTrack: existing && existing.idTrack ? existing.idTrack : '',
          };

          // Timeline
          if (existing) {
            entry.timeline = appendIncomeTimelineEvent(existing, {
              at: nowIso,
              user: timelineUser,
              action: 'Edited',
              changes: computeIncomeAuditChanges(existing, entry),
            });
          } else {
            entry.timeline = [
              {
                at: nowIso,
                user: timelineUser,
                action: 'Created',
                changes: computeIncomeAuditChanges(null, entry),
              },
            ];
          }

          upsertIncomeEntry(entry, year);

          if (!existing) {
            void fireNotificationEvent('new_bank_eur', {
              date: String(entry.date || ''),
              description: String(entry.description || ''),
              amount: String(entry.euro || ''),
              year: String(year),
              directLink: String(window.location.href || ''),
            });
          }

          // Keep negative BankEUR entries in sync with Reconciliation.
          // Negative amounts are expenditures: create/update a reconciliation order while still displaying the entry.
          const euroNum = Number(entry.euro);
          const sourceEntryId = `inc:${String(id)}`;
          if (Number.isFinite(euroNum) && euroNum < 0) {
            ensurePaymentOrdersReconciliationListExistsForYear(year);
            const absEuro = Math.abs(euroNum);
            const itemTitle = String(entry.description || '').trim() || 'Imported from BankEUR';
            const po = {
              id: (crypto?.randomUUID ? crypto.randomUUID() : `po_${Date.now()}_${Math.random().toString(16).slice(2)}`),
              createdAt: nowIso,
              updatedAt: nowIso,
              source: 'Commerzbank',
              sourceEntryId,
              paymentOrderNo: '',
              date: String(entry.date || '').trim(),
              name: String(entry.remitter || '').trim(),
              euro: absEuro,
              usd: null,
              items: [
                {
                  id: (crypto?.randomUUID ? crypto.randomUUID() : `it_${Date.now()}_${Math.random().toString(16).slice(2)}`),
                  title: itemTitle,
                  euro: absEuro,
                  usd: null,
                },
              ],
              address: '',
              iban: '',
              bic: '',
              specialInstructions: '',
              budgetNumber: String(entry.budgetNumber || '').trim(),
              purpose: String(entry.description || '').trim(),
              with: 'Grand Secretary',
              status: 'Submitted',
            };
            upsertReconciliationOrderBySource(po, year);
          } else {
            removeReconciliationOrderBySource('Commerzbank', sourceEntryId, year);
          }

          closeIncomeModal();
          applyIncomeView();
        } catch (err) {
          console.error('[Income Save] Failed', err);
          window.alert(`Unable to save Income entry. ${err && err.message ? err.message : 'Check console for details.'}`);
        }
      });
    }

    window.addEventListener('storage', (e) => {
      const key = e && typeof e.key === 'string' ? e.key : '';
      if (key === ACTIVE_BUDGET_YEAR_KEY || key === BUDGET_YEARS_KEY || key.startsWith('payment_order_budget_table_html_')) {
        applyIncomeView();
      }
    });

    applyIncomeView();
  }

  // ---- wiseEUR (year-scoped) ----

  const WISE_EUR_COL_TYPES = {
    budgetNo: 'text',
    datePL: 'date',
    idTrack: 'text',
    receivedFromDisbursedTo: 'text',
    receipts: 'number',
    disburse: 'number',
    description: 'text',
    issuanceDateBank: 'date',
    verified: 'number',
    checksum: 'number',
    bankStatements: 'text',
    remarks: 'text',
  };

  const wiseEurViewState = {
    globalFilter: '',
    sortKey: 'datePL',
    sortDir: 'asc',
    defaultEmptyText: null,
    canVerify: false,
    canDelete: false,
  };

  function ensureWiseEurDefaultEmptyText() {
    if (!wiseEurEmptyState) return;
    if (wiseEurViewState.defaultEmptyText !== null) return;
    wiseEurViewState.defaultEmptyText = wiseEurEmptyState.textContent || 'No wiseEUR entries yet.';
  }

  function getWiseEurReceipts(entry) {
    const n = Number(entry && entry.receipts);
    return Number.isFinite(n) && n > 0 ? n : 0;
  }

  function getWiseEurDisburse(entry) {
    const n = Number(entry && entry.disburse);
    return Number.isFinite(n) && n > 0 ? n : 0;
  }

  function getWiseEurVerified(entry) {
    if (!entry) return false;
    if (typeof entry.verified === 'boolean') return entry.verified;
    const raw = entry.verified !== undefined ? entry.verified : entry.checkedByGTREAS;
    if (raw === null || raw === undefined) return false;
    const s = String(raw).trim().toLowerCase();
    if (!s) return false;
    if (s === '0' || s === 'false' || s === 'no' || s === 'n' || s === 'off') return false;
    return true;
  }

  function computeWiseEurNet(entry) {
    return getWiseEurReceipts(entry) - getWiseEurDisburse(entry);
  }

  function hasWiseEurMissingRequiredValues(entry) {
    if (!entry) return true;
    const date = String(entry.datePL || entry.date || '').trim();
    const party = String(entry.receivedFromDisbursedTo || entry.party || '').trim();
    const description = String(entry.description || entry.reference || '').trim();

    const receipts = getWiseEurReceipts(entry);
    const disburse = getWiseEurDisburse(entry);
    const hasReceipts = Number.isFinite(receipts) && receipts > 0;
    const hasDisburse = Number.isFinite(disburse) && disburse > 0;
    const hasOneAmount = (hasReceipts && !hasDisburse) || (!hasReceipts && hasDisburse);

    const rawBudgetNo = String(entry.budgetNo || '').trim();
    const hasBudget = Boolean(extractInCodeFromBudgetNumberText(rawBudgetNo) || extractOutCodeFromBudgetNumberText(rawBudgetNo));

    if (!date) return true;
    if (!party) return true;
    if (!description) return true;
    if (!hasOneAmount) return true;
    if (!hasBudget) return true;
    return false;
  }

  function buildReconciliationOrderFromWiseEurEntry(entry, year) {
    if (!entry || !entry.id) return null;
    const absEuro = getWiseEurDisburse(entry);
    if (!(Number.isFinite(absEuro) && absEuro > 0)) return null;

    const date = String(entry.datePL || entry.date || '').trim();
    const party = String(entry.receivedFromDisbursedTo || entry.party || '').trim();
    const purpose = String(entry.description || entry.reference || '').trim() || 'wiseEUR disbursement';
    const budgetNumber = String(entry.budgetNo || '').trim();
    const itemTitle = purpose;

    const po = buildPaymentOrder({
      source: 'wiseEUR',
      sourceEntryId: entry.id,
      sourceEntryYear: year,
      paymentOrderNo: '',
      date,
      name: party,
      euro: absEuro,
      usd: null,
      items: [
        {
          id: (crypto?.randomUUID ? crypto.randomUUID() : `it_${Date.now()}_${Math.random().toString(16).slice(2)}`),
          title: itemTitle,
          euro: absEuro,
          usd: null,
        },
      ],
      address: '',
      iban: '',
      bic: '',
      specialInstructions: '',
      budgetNumber,
      purpose,
      with: 'Grand Secretary',
      status: 'Submitted',
    });
    po.updatedAt = po.createdAt;
    return po;
  }

  function getWiseEurDisplayValueForColumn(entry, colKey) {
    if (!entry) return '';
    switch (colKey) {
      case 'budgetNo':
        return entry.budgetNo || '';
      case 'datePL':
        return formatDate(entry.datePL || entry.date);
      case 'idTrack':
        return entry.idTrack ? formatPaymentOrderNoForDisplay(entry.idTrack) : '';
      case 'receivedFromDisbursedTo':
        return entry.receivedFromDisbursedTo || entry.party || '';
      case 'receipts': {
        const n = getWiseEurReceipts(entry);
        return n ? formatCurrency(n, 'EUR') : '';
      }
      case 'disburse': {
        const n = getWiseEurDisburse(entry);
        return n ? formatCurrency(n, 'EUR') : '';
      }
      case 'description':
        return entry.description || entry.reference || '';
      case 'issuanceDateBank':
        return entry.issuanceDateBank ? formatDate(entry.issuanceDateBank) : '';
      case 'verified':
        return getWiseEurVerified(entry) ? 'Yes' : '';
      case 'checksum': {
        const n = Number(entry && entry.checksum);
        return Number.isFinite(n) ? formatCurrency(n, 'EUR') : entry.checksum || '';
      }
      case 'bankStatements':
        return entry.bankStatements || '';
      case 'remarks':
        return entry.remarks || '';
      default:
        return '';
    }
  }

  function getWiseEurSortValueForColumn(entry, colKey, colType) {
    if (!entry) return null;
    if (colType === 'number') {
      if (colKey === 'receipts') return getWiseEurReceipts(entry);
      if (colKey === 'disburse') return getWiseEurDisburse(entry);
      if (colKey === 'verified') return getWiseEurVerified(entry) ? 1 : 0;
      if (colKey === 'checksum') {
        const n = Number(entry && entry.checksum);
        return Number.isFinite(n) ? n : null;
      }
      return null;
    }
    if (colType === 'date') {
      const raw =
        colKey === 'datePL'
          ? String(entry.datePL || entry.date || '').trim()
          : colKey === 'issuanceDateBank'
            ? String(entry.issuanceDateBank || '').trim()
            : '';
      return raw ? raw : null;
    }
    return normalizeTextForSearch(getWiseEurDisplayValueForColumn(entry, colKey));
  }

  function filterWiseEurForView(entries, globalFilter) {
    const needle = normalizeTextForSearch(globalFilter);
    if (!needle) return entries || [];

    const cols = Object.keys(WISE_EUR_COL_TYPES);
    return (entries || []).filter((e) => cols.some((k) => normalizeTextForSearch(getWiseEurDisplayValueForColumn(e, k)).includes(needle)));
  }

  function sortWiseEurForView(entries, sortKey, sortDir) {
    const dir = sortDir === 'desc' ? -1 : 1;
    const key = sortKey || 'datePL';
    const colType = WISE_EUR_COL_TYPES[key] || 'text';
    const withIndex = (entries || []).map((entry, index) => ({ entry, index }));
    withIndex.sort((a, b) => {
      const av = getWiseEurSortValueForColumn(a.entry, key, colType);
      const bv = getWiseEurSortValueForColumn(b.entry, key, colType);

      if (av === null && bv === null) return a.index - b.index;
      if (av === null) return 1;
      if (bv === null) return -1;

      if (colType === 'number') {
        const cmp = av === bv ? 0 : av < bv ? -1 : 1;
        return cmp === 0 ? a.index - b.index : cmp * dir;
      }

      const cmp = String(av).localeCompare(String(bv));
      return cmp === 0 ? a.index - b.index : cmp * dir;
    });
    return withIndex.map((x) => x.entry);
  }

  function renderWiseEurRows(entries) {
    if (!wiseEurTbody) return;
    const canVerify = Boolean(wiseEurViewState.canVerify);
    const canDeleteRows = Boolean(wiseEurViewState.canDelete);
    const deleteAriaDisabled = canDeleteRows ? 'false' : 'true';
    const deleteTooltipAttr = canDeleteRows ? '' : ' data-tooltip="Requires Delete access for wiseEUR."';
    const year = getActiveBudgetYear();
    const activeYear = getActiveBudgetYear();
    const inMap = getInDescMapForYear(activeYear);
    const outMap = getOutDescMapForYear(activeYear);
    const ordersBySourceEntryKey = new Map();
    const reconcileBySourceEntryKey = new Map();
    const ordersByPoCanon = new Map();
    const reconcileByPoCanon = new Map();
    const orderIds = new Set();
    const sourceEntryKey = (sourceRaw, sourceEntryIdRaw) => {
      const source = String(sourceRaw || '').trim().toLowerCase();
      const sourceEntryId = String(sourceEntryIdRaw || '').trim();
      if (!source || !sourceEntryId) return '';
      return `${source}::${sourceEntryId}`;
    };
    {
      const orders = loadOrders(year);
      for (const o of orders || []) {
        if (!o || typeof o !== 'object') continue;

        const oid = String(o.id || '').trim();
        if (oid) orderIds.add(oid);

        const poCanon = canonicalizePaymentOrderNo(o.paymentOrderNo);
        if (poCanon && !ordersByPoCanon.has(poCanon)) ordersByPoCanon.set(poCanon, o);

        const key = sourceEntryKey(o.source, o.sourceEntryId);
        if (!key) continue;
        if (!ordersBySourceEntryKey.has(key)) {
          ordersBySourceEntryKey.set(key, o);
          continue;
        }
        // Prefer an order that has a PO number assigned.
        const existing = ordersBySourceEntryKey.get(key);
        const existingPoNo = String(existing && existing.paymentOrderNo ? existing.paymentOrderNo : '').trim();
        const nextPoNo = String(o && o.paymentOrderNo ? o.paymentOrderNo : '').trim();
        if (!existingPoNo && nextPoNo) ordersBySourceEntryKey.set(key, o);
      }
    }
    {
      const rec = loadReconciliationOrders(year);
      for (const o of rec || []) {
        if (!o || typeof o !== 'object') continue;
        const poCanon = canonicalizePaymentOrderNo(o.paymentOrderNo);
        if (poCanon && !reconcileByPoCanon.has(poCanon)) reconcileByPoCanon.set(poCanon, o);

        const key = sourceEntryKey(o.source, o.sourceEntryId);
        if (!key) continue;
        if (!reconcileBySourceEntryKey.has(key)) reconcileBySourceEntryKey.set(key, o);
      }
    }
    const html = (entries || [])
      .map((e) => {
        const id = escapeHtml(e.id);
        const isMissingRequired = hasWiseEurMissingRequiredValues(e);
        const rowClass = isMissingRequired ? ' class="ordersRow--missingRequired"' : '';
        const rawBudgetNo = getWiseEurDisplayValueForColumn(e, 'budgetNo');
        const receiptsAmt = getWiseEurReceipts(e);
        const disburseAmt = getWiseEurDisburse(e);
        let budgetNo = '';
        if (receiptsAmt > 0 && disburseAmt <= 0) {
          const code = extractInCodeFromBudgetNumberText(rawBudgetNo) || String(rawBudgetNo || '').trim();
          const desc = (code && inMap ? inMap.get(code) : '') || (code ? BUDGET_DESC_BY_CODE.get(code) : '') || inferDescFromBudgetNumberText(rawBudgetNo);
          budgetNo = renderBudgetNumberSpanHtml(code || rawBudgetNo, desc);
        } else if (disburseAmt > 0 && receiptsAmt <= 0) {
          const code = extractOutCodeFromBudgetNumberText(rawBudgetNo) || String(rawBudgetNo || '').trim();
          const desc = (code && outMap ? outMap.get(code) : '') || (code ? BUDGET_DESC_BY_CODE.get(code) : '') || inferDescFromBudgetNumberText(rawBudgetNo);
          budgetNo = renderBudgetNumberSpanHtml(code || rawBudgetNo, desc);
        } else {
          const code =
            extractInCodeFromBudgetNumberText(rawBudgetNo) ||
            extractOutCodeFromBudgetNumberText(rawBudgetNo) ||
            String(rawBudgetNo || '').trim();
          const desc =
            (code && outMap ? outMap.get(code) : '') ||
            (code && inMap ? inMap.get(code) : '') ||
            (code ? BUDGET_DESC_BY_CODE.get(code) : '') ||
            inferDescFromBudgetNumberText(rawBudgetNo);
          budgetNo = renderBudgetNumberSpanHtml(code || rawBudgetNo, desc);
        }
        const datePL = escapeHtml(getWiseEurDisplayValueForColumn(e, 'datePL'));
        const idTrack = escapeHtml(getWiseEurDisplayValueForColumn(e, 'idTrack'));
        const receivedFromDisbursedTo = escapeHtml(getWiseEurDisplayValueForColumn(e, 'receivedFromDisbursedTo'));
        const receipts = escapeHtml(getWiseEurDisplayValueForColumn(e, 'receipts'));
        const disburse = escapeHtml(getWiseEurDisplayValueForColumn(e, 'disburse'));
        const descRaw = String(getWiseEurDisplayValueForColumn(e, 'description') || '');
        const strippedDescRaw = descRaw
          .replace(/\s*\(\s*converted\s+to\s+PO\s+\d{2}\s*-\s*\d{1,3}\s*\)\s*\.?\s*$/i, '')
          .replace(/\s*converted\s+to\s+PO\s+\d{2}\s*-\s*\d{1,3}\s*\.?\s*$/i, '')
          .replace(/\s*\(\s*pending\s+Payment\s+Order\s+Reconciliation\s*\)\s*\.?\s*$/i, '')
          .trim();
        const descText = escapeHtml(strippedDescRaw);

        const isDisbursement = Number.isFinite(disburseAmt) && disburseAmt > 0;
        const srcKey = isDisbursement ? sourceEntryKey('wiseEUR', e.id) : '';
        const match = srcKey
          ? (ordersBySourceEntryKey.get(srcKey) || reconcileBySourceEntryKey.get(srcKey))
          : null;

        const poFromMatch = String(match && match.paymentOrderNo ? match.paymentOrderNo : '').trim();
        const poFromIdTrack = String(e && e.idTrack ? e.idTrack : '').trim();
        const poFromDescMatch = descRaw.match(/\bPO\s*\d{2}\s*-\s*\d{1,3}\b/i);
        const poFromDesc = poFromDescMatch ? String(poFromDescMatch[0] || '').trim() : '';

        const poCandidate = poFromMatch || poFromIdTrack || poFromDesc;
        const poCanon = canonicalizePaymentOrderNo(poCandidate);
        const poOrder = poCanon
          ? (ordersByPoCanon.get(poCanon) || reconcileByPoCanon.get(poCanon))
          : null;

        const orderForLink = match || poOrder;
        const isOnPaymentOrdersTable = Boolean(orderForLink && orderForLink.id && orderIds.has(String(orderForLink.id)));
        const isOnReconciliationTable = Boolean(orderForLink && orderForLink.id && !isOnPaymentOrdersTable);
        const orderIdForLink = orderForLink && orderForLink.id ? escapeHtml(String(orderForLink.id)) : '';
        const orderScopeForLink = isOnPaymentOrdersTable ? 'orders' : 'reconciliation';
        const poDisplayRaw = formatPaymentOrderNoForDisplay(orderForLink && orderForLink.paymentOrderNo ? orderForLink.paymentOrderNo : poCandidate);
        const poDisplay = poDisplayRaw ? escapeHtml(poDisplayRaw) : '';

        const convertedHtml = (isDisbursement && isOnPaymentOrdersTable && poDisplay)
          ? (orderIdForLink
            ? ` (converted to <a href="#" class="poNoDownloadLink" data-action="downloadPdf" data-order-id="${orderIdForLink}" data-order-scope="${escapeHtml(orderScopeForLink)}" title="Download PDF">${poDisplay}</a>)`
            : ` (converted to ${poDisplay})`)
          : (isDisbursement && isOnReconciliationTable ? ' (pending Payment Order Reconciliation).' : '');
        const description = `${descText}${convertedHtml}`;
        const issuanceDateBank = escapeHtml(getWiseEurDisplayValueForColumn(e, 'issuanceDateBank'));
        const verifiedChecked = getWiseEurVerified(e) ? 'checked' : '';
        const verifyDisabled = canVerify ? '' : 'disabled';
        const checksum = escapeHtml(getWiseEurDisplayValueForColumn(e, 'checksum'));
        const bankStatements = escapeHtml(getWiseEurDisplayValueForColumn(e, 'bankStatements'));

        return `
          <tr data-wise-eur-id="${id}"${rowClass}>
            <td>${budgetNo}</td>
            <td>${datePL}</td>
            <td>${idTrack}</td>
            <td class="wiseEurCol--receivedFrom">${receivedFromDisbursedTo}</td>
            <td class="num">${receipts}</td>
            <td class="num">${disburse}</td>
            <td>${description}</td>
            <td>${issuanceDateBank}</td>
            <td class="num">
              <input type="checkbox" data-wise-eur-verify="1" data-wise-eur-id="${id}" aria-label="Verified" ${verifiedChecked} ${verifyDisabled} />
            </td>
            <td class="num">${checksum}</td>
            <td>${bankStatements}</td>
            <td class="actions">
              <button type="button" class="btn btn--editIcon" data-wise-eur-action="edit" aria-label="Edit"><svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path d="M15.502 1.94a.5.5 0 0 1 0 .706L14.459 3.69l-2-2L13.502.646a.5.5 0 0 1 .707 0l1.293 1.293zm-1.75 2.456-2-2L4.939 9.21a.5.5 0 0 0-.121.196l-.805 2.414a.25.25 0 0 0 .316.316l2.414-.805a.5.5 0 0 0 .196-.12l6.813-6.814z"/><path fill-rule="evenodd" d="M1 13.5A1.5 1.5 0 0 0 2.5 15h11a1.5 1.5 0 0 0 1.5-1.5v-6a.5.5 0 0 0-1 0v6a.5.5 0 0 1-.5.5h-11a.5.5 0 0 1-.5-.5v-11a.5.5 0 0 1 .5-.5H9a.5.5 0 0 0 0-1H2.5A1.5 1.5 0 0 0 1 2.5z"/></svg></button>
              <button type="button" class="btn btn--x" data-wise-eur-action="delete" aria-label="Delete entry" title="${canDeleteRows ? 'Delete' : 'Requires Delete access for wiseEUR.'}" aria-disabled="${deleteAriaDisabled}"${deleteTooltipAttr}><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path d="M5.5 5.5A.5.5 0 0 1 6 6v5a.5.5 0 0 1-1 0V6a.5.5 0 0 1 .5-.5m2.5 0A.5.5 0 0 1 8.5 6v5a.5.5 0 0 1-1 0V6a.5.5 0 0 1 .5-.5m3 .5a.5.5 0 0 0-1 0v5a.5.5 0 0 0 1 0z"/><path d="M14.5 3a1 1 0 0 1-1 1H13l-.777 9.33A2 2 0 0 1 10.23 15H5.77a2 2 0 0 1-1.993-1.67L3 4h-.5a1 1 0 1 1 0-2H5a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1h2.5a1 1 0 0 1 1 1M6 2v1h4V2zm-2 2 .774 9.287A1 1 0 0 0 5.77 14h4.46a1 1 0 0 0 .996-.713L12 4z"/></svg></button>
            </td>
          </tr>
        `.trim();
      })
      .join('');

    wiseEurTbody.innerHTML = html;
  }

  function updateWiseEurTotals(entries) {
    const receiptsEl = document.getElementById('wiseEurTotalReceipts');
    const disburseEl = document.getElementById('wiseEurTotalDisburse');
    const netEl = document.getElementById('wiseEurTotalReceiptsMinusDisburse');

    if (!receiptsEl && !disburseEl && !netEl) return;

    let totalReceipts = 0;
    let totalDisburse = 0;
    for (const e of entries || []) {
      totalReceipts += getWiseEurReceipts(e);
      totalDisburse += getWiseEurDisburse(e);
    }

    const net = totalReceipts - totalDisburse;

    if (receiptsEl) receiptsEl.textContent = formatCurrency(totalReceipts, 'EUR');
    if (disburseEl) disburseEl.textContent = formatCurrency(totalDisburse, 'EUR');
    if (netEl) {
      netEl.textContent = formatCurrency(net, 'EUR');
      netEl.classList.toggle('is-negative', net < 0);
    }
  }

  function updateWiseEurSortIndicators() {
    if (!wiseEurTbody) return;
    const table = wiseEurTbody.closest('table');
    if (!table) return;

    const sortKey = wiseEurViewState.sortKey;
    const sortDir = wiseEurViewState.sortDir === 'desc' ? 'desc' : 'asc';

    const ths = Array.from(table.querySelectorAll('thead th[data-sort-key]'));
    for (const th of ths) {
      const colKey = th.getAttribute('data-sort-key');
      let aria = 'none';
      if (colKey && sortKey === colKey) {
        aria = sortDir === 'desc' ? 'descending' : 'ascending';
      }
      th.setAttribute('aria-sort', aria);
    }
  }

  function initWiseEurColumnSorting() {
    if (!wiseEurTbody) return;
    const table = wiseEurTbody.closest('table');
    if (!table) return;
    if (table.dataset.sortBound === '1') return;

    const ths = Array.from(table.querySelectorAll('thead th[data-sort-key]'));
    if (ths.length === 0) return;
    table.dataset.sortBound = '1';

    function applySortForKey(colKey) {
      if (!colKey) return;
      if (wiseEurViewState.sortKey === colKey) {
        wiseEurViewState.sortDir = wiseEurViewState.sortDir === 'asc' ? 'desc' : 'asc';
      } else {
        wiseEurViewState.sortKey = colKey;
        wiseEurViewState.sortDir = 'asc';
      }
      applyWiseEurView();
    }

    for (const th of ths) {
      th.classList.add('is-sortable');
      if (!th.hasAttribute('tabindex')) th.setAttribute('tabindex', '0');
      if (!th.hasAttribute('aria-sort')) th.setAttribute('aria-sort', 'none');

      th.addEventListener('click', () => applySortForKey(th.getAttribute('data-sort-key')));
      th.addEventListener('keydown', (e) => {
        if (e.key !== 'Enter' && e.key !== ' ') return;
        e.preventDefault();
        applySortForKey(th.getAttribute('data-sort-key'));
      });
    }

    updateWiseEurSortIndicators();
  }

  let currentWiseEurId = null;

  function getWiseEurBudgetFlowKindFromAmountStrings(receiptsRaw, disburseRaw) {
    const r = String(receiptsRaw || '').trim();
    const d = String(disburseRaw || '').trim();
    const receiptsNum = r === '' ? null : Number(r);
    const disburseNum = d === '' ? null : Number(d);

    const receiptsHas = Number.isFinite(receiptsNum) && receiptsNum > 0;
    const disburseHas = Number.isFinite(disburseNum) && disburseNum > 0;

    if (receiptsHas && !disburseHas) return 'in';
    if (disburseHas && !receiptsHas) return 'out';
    if (!receiptsHas && !disburseHas) return null;
    return 'both';
  }

  function syncWiseEurBudgetNoSelect(selectEl, receiptsEl, disburseEl, initialBudgetNo) {
    if (!selectEl) return;

    const kind = getWiseEurBudgetFlowKindFromAmountStrings(receiptsEl && receiptsEl.value, disburseEl && disburseEl.value);
    const activeYear = getActiveBudgetYear();

    // Preserve current selection when possible.
    const prevValue = String(selectEl.value || '').trim();
    const preferred = prevValue || String(initialBudgetNo || '').trim();

    // Reset options.
    selectEl.innerHTML = '';

    const placeholder = document.createElement('option');
    placeholder.value = '';

    if (kind === 'both') {
      placeholder.textContent = 'Enter only one: Receipts or Disburse';
      placeholder.disabled = true;
      placeholder.selected = true;
      selectEl.appendChild(placeholder);
      selectEl.disabled = true;
      return;
    }

    if (!kind) {
      placeholder.textContent = 'Enter Receipts or Disburse first';
      placeholder.disabled = true;
      placeholder.selected = true;
      selectEl.appendChild(placeholder);
      selectEl.disabled = true;
      return;
    }

    placeholder.textContent = 'Select a Budget #';
    selectEl.appendChild(placeholder);
    selectEl.disabled = false;

    const accounts = kind === 'in' ? readInAccountsFromBudgetYear(activeYear) : readOutAccountsFromBudgetYear(activeYear);
    const items = Array.isArray(accounts) ? accounts : [];

    if (items.length === 0) {
      const none = document.createElement('option');
      none.value = '__none__';
      none.disabled = true;
      none.textContent = kind === 'in' ? 'No IN accounts found in the active budget' : 'No OUT accounts found in the active budget';
      selectEl.appendChild(none);
      selectEl.value = '';
      return;
    }

    const codes = [];
    for (const item of items) {
      const code = String(kind === 'in' ? item && item.inCode : item && item.outCode).trim();
      if (!/^\d{4}$/.test(code)) continue;
      const desc = String(item && item.desc ? item.desc : '').trim();
      codes.push({ code, desc });
    }

    codes.sort((a, b) => String(a.code).localeCompare(String(b.code), undefined, { numeric: true, sensitivity: 'base' }));

    const allowed = new Set();
    for (const { code, desc } of codes) {
      allowed.add(code);
      const opt = document.createElement('option');
      opt.value = code;
      opt.textContent = desc ? `${code} - ${desc}` : code;
      selectEl.appendChild(opt);
    }

    if (preferred && allowed.has(preferred)) selectEl.value = preferred;
    else selectEl.value = '';
  }

  function openWiseEurModal(entry, year) {
    if (!wiseEurModal || !wiseEurModalBody) return;
    const y = Number.isInteger(Number(year)) ? Number(year) : getWiseEurYear();
    currentWiseEurId = entry && entry.id ? entry.id : null;

    const titleEl = wiseEurModal.querySelector('#wiseEurModalTitle');
    const subheadEl = wiseEurModal.querySelector('#wiseEurModalSubhead');
    if (titleEl) titleEl.textContent = currentWiseEurId ? 'wiseEUR (Edit)' : 'wiseEUR (New)';
    if (subheadEl) subheadEl.textContent = `${y} wiseEUR`;

    const budgetNoRaw = entry && entry.budgetNo ? String(entry.budgetNo).trim() : '';
    const safeDatePL = escapeHtml(entry && (entry.datePL || entry.date) ? (entry.datePL || entry.date) : '');
    const safeReceivedFrom = escapeHtml(entry && (entry.receivedFromDisbursedTo || entry.party) ? (entry.receivedFromDisbursedTo || entry.party) : '');
    const safeDescription = escapeHtml(entry && (entry.description || entry.reference) ? (entry.description || entry.reference) : '');
    const safeIssuanceDateBank = escapeHtml(entry && entry.issuanceDateBank ? entry.issuanceDateBank : '');
    const canVerify = canIncomeEdit(getCurrentUser());
    const verifiedChecked = getWiseEurVerified(entry) ? 'checked' : '';
    const verifiedDisabled = canVerify ? '' : 'disabled';

    const checksum = entry && entry.checksum !== null && entry.checksum !== undefined && entry.checksum !== '' ? Number(entry.checksum) : null;
    const safeChecksum = Number.isFinite(checksum) ? escapeHtml(String(checksum)) : '';

    const safeBankStatements = escapeHtml(entry && entry.bankStatements ? entry.bankStatements : '');
    const safeRemarks = escapeHtml(entry && entry.remarks ? entry.remarks : '');

    const receipts = entry && entry.receipts !== null && entry.receipts !== undefined && entry.receipts !== '' ? Number(entry.receipts) : null;
    const disburse = entry && entry.disburse !== null && entry.disburse !== undefined && entry.disburse !== '' ? Number(entry.disburse) : null;
    const safeReceipts = Number.isFinite(receipts) && receipts > 0 ? escapeHtml(String(receipts)) : '';
    const safeDisburse = Number.isFinite(disburse) && disburse > 0 ? escapeHtml(String(disburse)) : '';

    wiseEurModalBody.innerHTML = `
      <form id="wiseEurModalForm" novalidate>
        <div class="grid">
          <div class="field">
            <label for="wiseEurBudgetNo">Budget #</label>
            <select id="wiseEurBudgetNo" name="wiseEurBudgetNo"></select>
            <div class="error" id="error-wiseEurBudgetNo" role="alert" aria-live="polite"></div>
          </div>

          <div class="field">
            <label for="wiseEurDatePL">ACTION DATE<span class="req" aria-hidden="true">*</span></label>
            <input id="wiseEurDatePL" name="wiseEurDatePL" type="date" required value="${safeDatePL}" />
            <div class="error" id="error-wiseEurDatePL" role="alert" aria-live="polite"></div>
          </div>

          <div class="field field--span2">
            <label for="wiseEurReceivedFrom">RECEIVED FROM - DISBURSED TO:<span class="req" aria-hidden="true">*</span></label>
            <input id="wiseEurReceivedFrom" name="wiseEurReceivedFrom" type="text" autocomplete="off" required value="${safeReceivedFrom}" />
            <div class="error" id="error-wiseEurReceivedFrom" role="alert" aria-live="polite"></div>
          </div>

          <div class="field">
            <label for="wiseEurReceipts">RECEIPTS €<span class="req" aria-hidden="true">*</span></label>
            <input id="wiseEurReceipts" name="wiseEurReceipts" type="number" inputmode="decimal" step="0.01" min="0" value="${safeReceipts}" />
            <div class="error" id="error-wiseEurReceipts" role="alert" aria-live="polite"></div>
          </div>

          <div class="field">
            <label for="wiseEurDisburse">DISBURSE €<span class="req" aria-hidden="true">*</span></label>
            <input id="wiseEurDisburse" name="wiseEurDisburse" type="number" inputmode="decimal" step="0.01" min="0" value="${safeDisburse}" />
            <div class="error" id="error-wiseEurDisburse" role="alert" aria-live="polite"></div>
          </div>

          <div class="field field--span2">
            <label for="wiseEurDescription">DESCRIPTION<span class="req" aria-hidden="true">*</span></label>
            <textarea id="wiseEurDescription" name="wiseEurDescription" rows="3" required>${safeDescription}</textarea>
            <div class="error" id="error-wiseEurDescription" role="alert" aria-live="polite"></div>
          </div>

          <div class="field">
            <label for="wiseEurIssuanceDateBank">Issuance Date Bank</label>
            <input id="wiseEurIssuanceDateBank" name="wiseEurIssuanceDateBank" type="date" value="${safeIssuanceDateBank}" />
            <div class="error" id="error-wiseEurIssuanceDateBank" role="alert" aria-live="polite"></div>
          </div>

          <div class="field">
            <label for="wiseEurVerified">Verified</label>
            <div>
              <input id="wiseEurVerified" name="wiseEurVerified" type="checkbox" ${verifiedChecked} ${verifiedDisabled} />
            </div>
          </div>

          <div class="field">
            <label for="wiseEurChecksum">Checksum</label>
            <input id="wiseEurChecksum" name="wiseEurChecksum" type="number" inputmode="decimal" step="0.01" value="${safeChecksum}" />
            <div class="error" id="error-wiseEurChecksum" role="alert" aria-live="polite"></div>
          </div>

          <div class="field">
            <label for="wiseEurBankStatements">Bank Statements</label>
            <input id="wiseEurBankStatements" name="wiseEurBankStatements" type="text" autocomplete="off" value="${safeBankStatements}" />
            <div class="error" id="error-wiseEurBankStatements" role="alert" aria-live="polite"></div>
          </div>

          <div class="field field--span2">
            <label for="wiseEurRemarks">Remarks</label>
            <textarea id="wiseEurRemarks" name="wiseEurRemarks" rows="2">${safeRemarks}</textarea>
            <div class="error" id="error-wiseEurRemarks" role="alert" aria-live="polite"></div>
          </div>
        </div>
      </form>
    `.trim();

    wiseEurModal.classList.add('is-open');
    wiseEurModal.setAttribute('aria-hidden', 'false');

    const budgetNoEl = wiseEurModalBody.querySelector('#wiseEurBudgetNo');
    const receiptsEl = wiseEurModalBody.querySelector('#wiseEurReceipts');
    const disburseEl = wiseEurModalBody.querySelector('#wiseEurDisburse');
    syncWiseEurBudgetNoSelect(budgetNoEl, receiptsEl, disburseEl, budgetNoRaw);
    if (receiptsEl) receiptsEl.addEventListener('input', () => syncWiseEurBudgetNoSelect(budgetNoEl, receiptsEl, disburseEl, budgetNoRaw));
    if (disburseEl) disburseEl.addEventListener('input', () => syncWiseEurBudgetNoSelect(budgetNoEl, receiptsEl, disburseEl, budgetNoRaw));

    const focusTarget = wiseEurModalBody.querySelector('#wiseEurDatePL');
    if (focusTarget && focusTarget.focus) focusTarget.focus();
  }

  function closeWiseEurModal() {
    if (!wiseEurModal || !wiseEurModalBody) return;
    wiseEurModal.classList.remove('is-open');
    wiseEurModal.setAttribute('aria-hidden', 'true');
    wiseEurModalBody.innerHTML = '';
    currentWiseEurId = null;
  }

  function clearWiseEurModalErrors() {
    if (!wiseEurModalBody) return;
    const errors = Array.from(wiseEurModalBody.querySelectorAll('.error'));
    for (const el of errors) el.textContent = '';
  }

  function showWiseEurModalErrors(errors) {
    if (!wiseEurModalBody || !errors) return;
    const map = {
      budgetNo: '#error-wiseEurBudgetNo',
      datePL: '#error-wiseEurDatePL',
      receivedFromDisbursedTo: '#error-wiseEurReceivedFrom',
      receipts: '#error-wiseEurReceipts',
      disburse: '#error-wiseEurDisburse',
      description: '#error-wiseEurDescription',
      issuanceDateBank: '#error-wiseEurIssuanceDateBank',
      checksum: '#error-wiseEurChecksum',
      bankStatements: '#error-wiseEurBankStatements',
      remarks: '#error-wiseEurRemarks',
    };
    for (const [k, sel] of Object.entries(map)) {
      const el = wiseEurModalBody.querySelector(sel);
      if (el) el.textContent = errors[k] || '';
    }
  }

  function validateWiseEurModalValues() {
    if (!wiseEurModalBody) return { ok: false };
    const budgetNoEl = wiseEurModalBody.querySelector('#wiseEurBudgetNo');
    const datePLEl = wiseEurModalBody.querySelector('#wiseEurDatePL');
    const receivedFromEl = wiseEurModalBody.querySelector('#wiseEurReceivedFrom');
    const receiptsEl = wiseEurModalBody.querySelector('#wiseEurReceipts');
    const disburseEl = wiseEurModalBody.querySelector('#wiseEurDisburse');
    const descriptionEl = wiseEurModalBody.querySelector('#wiseEurDescription');
    const issuanceDateBankEl = wiseEurModalBody.querySelector('#wiseEurIssuanceDateBank');
    const verifiedEl = wiseEurModalBody.querySelector('#wiseEurVerified');
    const checksumEl = wiseEurModalBody.querySelector('#wiseEurChecksum');
    const bankStatementsEl = wiseEurModalBody.querySelector('#wiseEurBankStatements');
    const remarksEl = wiseEurModalBody.querySelector('#wiseEurRemarks');

    const values = {
      budgetNo: budgetNoEl ? String(budgetNoEl.value || '').trim() : '',
      datePL: datePLEl ? String(datePLEl.value || '').trim() : '',
      receivedFromDisbursedTo: receivedFromEl ? String(receivedFromEl.value || '').trim() : '',
      receipts: receiptsEl ? String(receiptsEl.value || '').trim() : '',
      disburse: disburseEl ? String(disburseEl.value || '').trim() : '',
      description: descriptionEl ? String(descriptionEl.value || '').trim() : '',
      issuanceDateBank: issuanceDateBankEl ? String(issuanceDateBankEl.value || '').trim() : '',
      verified: verifiedEl ? Boolean(verifiedEl.checked) : false,
      checksum: checksumEl ? String(checksumEl.value || '').trim() : '',
      bankStatements: bankStatementsEl ? String(bankStatementsEl.value || '').trim() : '',
      remarks: remarksEl ? String(remarksEl.value || '').trim() : '',
    };

    const errors = {};
    if (!values.datePL) errors.datePL = 'This field is required.';
    if (!values.receivedFromDisbursedTo) errors.receivedFromDisbursedTo = 'This field is required.';
    if (!values.description) errors.description = 'This field is required.';

    const receiptsNum = values.receipts === '' ? null : Number(values.receipts);
    const disburseNum = values.disburse === '' ? null : Number(values.disburse);
    const checksumNum = values.checksum === '' ? null : Number(values.checksum);

    if (receiptsNum !== null && (!Number.isFinite(receiptsNum) || receiptsNum < 0)) errors.receipts = 'Enter a valid amount.';
    if (disburseNum !== null && (!Number.isFinite(disburseNum) || disburseNum < 0)) errors.disburse = 'Enter a valid amount.';
    if (checksumNum !== null && !Number.isFinite(checksumNum)) errors.checksum = 'Enter a valid amount.';

    const receiptsHas = Number.isFinite(receiptsNum) && receiptsNum > 0;
    const disburseHas = Number.isFinite(disburseNum) && disburseNum > 0;
    if (!receiptsHas && !disburseHas) {
      errors.receipts = 'Enter a Receipts or Disburse amount.';
      errors.disburse = 'Enter a Receipts or Disburse amount.';
    }
    if (receiptsHas && disburseHas) {
      errors.receipts = 'Enter only one: Receipts or Disburse.';
      errors.disburse = 'Enter only one: Receipts or Disburse.';
    }

    const kind = receiptsHas && !disburseHas ? 'in' : disburseHas && !receiptsHas ? 'out' : null;
    if (kind && values.budgetNo) {
      const activeYear = getActiveBudgetYear();
      const allowed = new Set();
      const items = kind === 'in' ? readInAccountsFromBudgetYear(activeYear) : readOutAccountsFromBudgetYear(activeYear);
      for (const item of items || []) {
        const code = String(kind === 'in' ? item && item.inCode : item && item.outCode).trim();
        if (/^\d{4}$/.test(code)) allowed.add(code);
      }

      if (!/^\d{4}$/.test(values.budgetNo)) {
        errors.budgetNo = 'Select a valid budget number.';
      } else if (allowed.size > 0 && !allowed.has(values.budgetNo)) {
        errors.budgetNo = kind === 'in' ? 'Select an IN budget number from the active budget.' : 'Select an OUT budget number from the active budget.';
      }
    }

    if (Object.keys(errors).length > 0) return { ok: false, errors };
    return {
      ok: true,
      values: {
        budgetNo: values.budgetNo,
        datePL: values.datePL,
        receivedFromDisbursedTo: values.receivedFromDisbursedTo,
        receipts: receiptsHas ? receiptsNum : null,
        disburse: disburseHas ? disburseNum : null,
        description: values.description,
        issuanceDateBank: values.issuanceDateBank,
        verified: values.verified ? 1 : 0,
        checksum: checksumNum,
        bankStatements: values.bankStatements,
        remarks: values.remarks,
      },
    };
  }

  function applyWiseEurView() {
    if (!wiseEurTbody || !wiseEurEmptyState) return;
    ensureWiseEurDefaultEmptyText();

    const year = getWiseEurYear();
    const all = loadWiseEur(year);
    const filtered = filterWiseEurForView(all, wiseEurViewState.globalFilter);
    const sorted = sortWiseEurForView(filtered, wiseEurViewState.sortKey, wiseEurViewState.sortDir);

    if (normalizeTextForSearch(wiseEurViewState.globalFilter) !== '' && all.length > 0 && sorted.length === 0) {
      wiseEurEmptyState.textContent = 'No wiseEUR entries match your search.';
    } else {
      wiseEurEmptyState.textContent = wiseEurViewState.defaultEmptyText;
    }

    wiseEurEmptyState.hidden = sorted.length > 0;
    renderWiseEurRows(sorted);
    updateWiseEurTotals(sorted);
    updateWiseEurSortIndicators();
  }

  function normalizeWiseMatchValue(value) {
    return normalizeTextForSearch(String(value ?? '').trim());
  }

  function wiseAmountsMatch(aRaw, bRaw) {
    const a = Number(aRaw);
    const b = Number(bRaw);
    if (!Number.isFinite(a) || !Number.isFinite(b)) return false;
    return Math.abs(a - b) < 0.005;
  }

  function findUniqueWiseOrderMatch(orders, target) {
    const dateNeed = normalizeWiseMatchValue(target.date);
    const partyNeed = normalizeWiseMatchValue(target.party);
    const amountNeed = target.amount;
    if (!dateNeed || !partyNeed || !Number.isFinite(Number(amountNeed))) return null;

    const matches = (orders || []).filter((order) => {
      const orderDate = normalizeWiseMatchValue(order && order.date);
      const orderParty = normalizeWiseMatchValue(order && order.name);
      const orderAmount = order && order.amount;
      if (!wiseAmountsMatch(amountNeed, orderAmount)) return false;
      if (orderDate !== dateNeed) return false;
      if (orderParty !== partyNeed) return false;
      return true;
    });

    return matches.length === 1 ? matches[0] : null;
  }

  function findUniqueWiseEntryMatch(entries, target, kind) {
    const dateNeed = normalizeWiseMatchValue(target.date);
    const partyNeed = normalizeWiseMatchValue(target.party);
    const amountNeed = target.amount;
    if (!dateNeed || !partyNeed || !Number.isFinite(Number(amountNeed))) return null;

    const matches = (entries || []).filter((entry) => {
      const entryDate = normalizeWiseMatchValue(entry && (entry.datePL || entry.date));
      const entryParty = normalizeWiseMatchValue(entry && (entry.receivedFromDisbursedTo || entry.party));
      const entryAmount = kind === 'usd' ? getWiseUsdDisburse(entry) : getWiseEurDisburse(entry);
      if (!wiseAmountsMatch(amountNeed, entryAmount)) return false;
      if (entryDate !== dateNeed) return false;
      if (entryParty !== partyNeed) return false;
      return true;
    });

    return matches.length === 1 ? matches[0] : null;
  }

  function backfillWiseEurIdTrackFromOrders(year) {
    const flagKey = `payment_order_wise_eur_idtrack_backfill_${year}_v1`;
    if (localStorage.getItem(flagKey) === '1') return false;

    ensurePaymentOrdersListExistsForYear(year);
    const orders = (loadOrders(year) || [])
      .filter((o) => o && String(o.source || '').trim() === 'wiseEUR')
      .map((o) => ({
        id: o.id,
        paymentOrderNo: o.paymentOrderNo,
        date: o.date,
        name: o.name,
        amount: o.euro,
      }));

    const entries = loadWiseEur(year);
    let updated = false;
    const nowIso = new Date().toISOString();

    for (const entry of entries || []) {
      if (!entry || String(entry.idTrack || '').trim()) continue;
      const amount = getWiseEurDisburse(entry);
      const match = findUniqueWiseOrderMatch(orders, {
        date: entry.datePL || entry.date,
        party: entry.receivedFromDisbursedTo || entry.party,
        amount,
      });
      if (!match || !String(match.paymentOrderNo || '').trim()) continue;
      entry.idTrack = String(match.paymentOrderNo).trim();
      entry.updatedAt = nowIso;
      upsertWiseEurEntry(entry, year);
      updated = true;
    }

    localStorage.setItem(flagKey, '1');
    return updated;
  }

  function backfillWiseEurBudgetNoFromOrders(year) {
    const flagKey = `payment_order_wise_eur_budget_backfill_${year}_v1`;
    if (localStorage.getItem(flagKey) === '1') return false;

    ensurePaymentOrdersListExistsForYear(year);
    const orders = (loadOrders(year) || [])
      .filter((o) => o && String(o.source || '').trim() === 'wiseEUR')
      .map((o) => ({
        id: o.id,
        budgetNumber: o.budgetNumber,
        date: o.date,
        name: o.name,
        amount: o.euro,
      }));

    const entries = loadWiseEur(year);
    let updated = false;
    const nowIso = new Date().toISOString();

    for (const entry of entries || []) {
      if (!entry || String(entry.budgetNo || '').trim()) continue;
      const amount = getWiseEurDisburse(entry);
      const match = findUniqueWiseOrderMatch(orders, {
        date: entry.datePL || entry.date,
        party: entry.receivedFromDisbursedTo || entry.party,
        amount,
      });
      if (!match || !String(match.budgetNumber || '').trim()) continue;
      entry.budgetNo = String(match.budgetNumber).trim();
      entry.updatedAt = nowIso;
      upsertWiseEurEntry(entry, year);
      updated = true;
    }

    localStorage.setItem(flagKey, '1');
    return updated;
  }

  function backfillWiseUsdIdTrackFromOrders(year) {
    const flagKey = `payment_order_wise_usd_idtrack_backfill_${year}_v1`;
    if (localStorage.getItem(flagKey) === '1') return false;

    ensurePaymentOrdersListExistsForYear(year);
    const orders = (loadOrders(year) || [])
      .filter((o) => o && String(o.source || '').trim() === 'wiseUSD')
      .map((o) => ({
        id: o.id,
        paymentOrderNo: o.paymentOrderNo,
        date: o.date,
        name: o.name,
        amount: o.usd,
      }));

    const entries = loadWiseUsd(year);
    let updated = false;
    const nowIso = new Date().toISOString();

    for (const entry of entries || []) {
      if (!entry || String(entry.idTrack || '').trim()) continue;
      const amount = getWiseUsdDisburse(entry);
      const match = findUniqueWiseOrderMatch(orders, {
        date: entry.datePL || entry.date,
        party: entry.receivedFromDisbursedTo || entry.party,
        amount,
      });
      if (!match || !String(match.paymentOrderNo || '').trim()) continue;
      entry.idTrack = String(match.paymentOrderNo).trim();
      entry.updatedAt = nowIso;
      upsertWiseUsdEntry(entry, year);
      updated = true;
    }

    localStorage.setItem(flagKey, '1');
    return updated;
  }

  function backfillWiseUsdBudgetNoFromOrders(year) {
    const flagKey = `payment_order_wise_usd_budget_backfill_${year}_v1`;
    if (localStorage.getItem(flagKey) === '1') return false;

    ensurePaymentOrdersListExistsForYear(year);
    const orders = (loadOrders(year) || [])
      .filter((o) => o && String(o.source || '').trim() === 'wiseUSD')
      .map((o) => ({
        id: o.id,
        budgetNumber: o.budgetNumber,
        date: o.date,
        name: o.name,
        amount: o.usd,
      }));

    const entries = loadWiseUsd(year);
    let updated = false;
    const nowIso = new Date().toISOString();

    for (const entry of entries || []) {
      if (!entry || String(entry.budgetNo || '').trim()) continue;
      const amount = getWiseUsdDisburse(entry);
      const match = findUniqueWiseOrderMatch(orders, {
        date: entry.datePL || entry.date,
        party: entry.receivedFromDisbursedTo || entry.party,
        amount,
      });
      if (!match || !String(match.budgetNumber || '').trim()) continue;
      entry.budgetNo = String(match.budgetNumber).trim();
      entry.updatedAt = nowIso;
      upsertWiseUsdEntry(entry, year);
      updated = true;
    }

    localStorage.setItem(flagKey, '1');
    return updated;
  }

  function initWiseEurListPage() {
    if (!wiseEurTbody || !wiseEurEmptyState) return;
    const year = getWiseEurYear();

    const currentUser = getCurrentUser();
    const incomeLevel = currentUser ? getEffectivePermissions(currentUser).income : 'none';
    const hasIncomeFullAccess = currentUser ? canWrite(currentUser, 'income_bankeur') : false;

    // Verified checkbox should be editable for Income Write/Partial.
    wiseEurViewState.canVerify = currentUser ? canIncomeEdit(currentUser) : false;
    wiseEurViewState.canDelete = currentUser ? canDelete(currentUser, 'income_wise_eur') : false;

    const wiseEurNewLink = document.getElementById('wiseEurNewLink');
    const wiseEurExportCsvLink = document.getElementById('wiseEurExportCsvLink');
    const wiseEurDownloadTemplateLink = document.getElementById('wiseEurDownloadTemplateLink');
    const wiseEurImportCsvLink = document.getElementById('wiseEurImportCsvLink');
    const wiseEurMenuBtn = document.getElementById('wiseEurActionsMenuBtn');
    const wiseEurMenuPanel = document.getElementById('wiseEurActionsMenu');
    const wiseEurBackToIncomeLink = document.getElementById('wiseEurBackToIncomeLink');

    function setLinkDisabled(linkEl, disabled) {
      if (!linkEl) return;
      linkEl.setAttribute('aria-disabled', disabled ? 'true' : 'false');
      if (disabled) linkEl.setAttribute('tabindex', '-1');
      else linkEl.removeAttribute('tabindex');
    }

    // Ensure the year is present in the URL for consistent nav highlighting.
    const fromUrl = getWiseEurYearFromUrl();
    if (!fromUrl && getBasename(window.location.pathname) === 'wise_eur.html') {
      try {
        const url = new URL(window.location.href);
        url.searchParams.set('year', String(year));
        window.history.replaceState(null, '', url.toString());
      } catch {
        // ignore
      }
    }

    ensureWiseEurListExistsForYear(year);
    backfillWiseEurIdTrackFromOrders(year);
    backfillWiseEurBudgetNoFromOrders(year);

    const titleEl = document.querySelector('[data-wise-eur-title]');
    if (titleEl) titleEl.textContent = `${year} wiseEUR`;
    const listTitleEl = document.querySelector('[data-wise-eur-list-title]');
    if (listTitleEl) listTitleEl.textContent = `${year} wiseEUR`;
    if (wiseEurBackToIncomeLink) {
      wiseEurBackToIncomeLink.href = `grand_secretary_ledger.html?year=${encodeURIComponent(String(year))}`;
      wiseEurBackToIncomeLink.textContent = `← Back to ${year} Ledger`;
    }
    applyAppTabTitle();

    initWiseEurColumnSorting();

    // Partial access for Income = full access except New Income and Import CSV.
    setLinkDisabled(wiseEurNewLink, !hasIncomeFullAccess);
    if (wiseEurNewLink && !hasIncomeFullAccess) {
      wiseEurNewLink.setAttribute(
        'data-tooltip',
        'Requires Full access for Income. Partial access can edit existing wiseEUR entries, but cannot create New Income entries.'
      );
    }
    setLinkDisabled(wiseEurImportCsvLink, !hasIncomeFullAccess);
    if (wiseEurImportCsvLink && !hasIncomeFullAccess) {
      wiseEurImportCsvLink.setAttribute(
        'data-tooltip',
        'Requires Full access for Income. Partial access can edit existing wiseEUR entries, but cannot Import CSV.'
      );
    }

    const globalInput = document.getElementById('wiseEurGlobalSearch');
    if (globalInput) {
      globalInput.value = wiseEurViewState.globalFilter || '';
      globalInput.addEventListener('input', () => {
        wiseEurViewState.globalFilter = globalInput.value;
        if (wiseEurClearSearchBtn) {
          const hasSearch = normalizeTextForSearch(wiseEurViewState.globalFilter) !== '';
          wiseEurClearSearchBtn.hidden = !hasSearch;
          wiseEurClearSearchBtn.disabled = !hasSearch;
        }
        applyWiseEurView();
      });
    }

    if (wiseEurClearSearchBtn && globalInput) {
      const hasSearch = normalizeTextForSearch(wiseEurViewState.globalFilter) !== '';
      wiseEurClearSearchBtn.hidden = !hasSearch;
      wiseEurClearSearchBtn.disabled = !hasSearch;
      if (!wiseEurClearSearchBtn.dataset.bound) {
        wiseEurClearSearchBtn.dataset.bound = 'true';
        wiseEurClearSearchBtn.addEventListener('click', () => {
          globalInput.value = '';
          wiseEurViewState.globalFilter = '';
          wiseEurClearSearchBtn.hidden = true;
          wiseEurClearSearchBtn.disabled = true;
          applyWiseEurView();
          if (globalInput.focus) globalInput.focus();
        });
      }
    }

    if (wiseEurNewLink) {
      wiseEurNewLink.addEventListener('click', (e) => {
        e.preventDefault();
        if (wiseEurNewLink.getAttribute('aria-disabled') === 'true') {
          alertDisabledAction(wiseEurNewLink);
          return;
        }
        if (!requireWriteAccess('income_bankeur', 'Income is read only for your account.')) return;
        openWiseEurModal(null, year);
        if (wiseEurMenuPanel && wiseEurMenuBtn) {
          wiseEurMenuPanel.setAttribute('hidden', '');
          wiseEurMenuBtn.setAttribute('aria-expanded', 'false');
        }
      });
    }

    function escapeCsvValue(value) {
      const s = String(value ?? '');
      const normalized = s.replace(/\u00A0/g, ' ').replace(/\r\n|\r|\n/g, ' ').trim();
      const mustQuote = /[",\n\r]/.test(normalized);
      const escaped = normalized.replace(/"/g, '""');
      return mustQuote ? `"${escaped}"` : escaped;
    }

    function downloadCsvFile(csvText, fileName) {
      const blob = new Blob([csvText], { type: 'text/csv;charset=utf-8;' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = fileName;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    }

    function getTodayStamp() {
      const d = new Date();
      const yyyy = d.getFullYear();
      const mm = String(d.getMonth() + 1).padStart(2, '0');
      const dd = String(d.getDate()).padStart(2, '0');
      return `${yyyy}-${mm}-${dd}`;
    }

    function exportWiseEurToCsv() {
      const header = [
        'Budget #',
        'ACTION DATE',
        '# ID-TRACK',
        'RECEIVED FROM - DISBURSED TO:',
        'RECEIPTS €',
        'DISBURSE €',
        'DESCRIPTION',
        'Issuance Date Bank',
        'Verified',
        'Checksum',
        'Bank Statements',
        'Remarks',
      ];
      const entries = loadWiseEur(year);
      const sorted = sortWiseEurForView(entries, 'datePL', 'asc');
      const lines = [];
      lines.push(header.map(escapeCsvValue).join(','));
      for (const e of sorted) {
        const receipts = getWiseEurReceipts(e);
        const disburse = getWiseEurDisburse(e);
        const checksumVal = e && e.checksum !== null && e.checksum !== undefined && String(e.checksum).trim() !== '' ? e.checksum : '';
        const values = [
          String(e && e.budgetNo ? e.budgetNo : ''),
          String(e && (e.datePL || e.date) ? (e.datePL || e.date) : ''),
          String(e && e.idTrack ? e.idTrack : ''),
          String(e && (e.receivedFromDisbursedTo || e.party) ? (e.receivedFromDisbursedTo || e.party) : ''),
          receipts ? String(receipts) : '',
          disburse ? String(disburse) : '',
          String(e && (e.description || e.reference) ? (e.description || e.reference) : ''),
          String(e && e.issuanceDateBank ? e.issuanceDateBank : ''),
          getWiseEurVerified(e) ? '1' : '',
          String(checksumVal),
          String(e && e.bankStatements ? e.bankStatements : ''),
          String(e && e.remarks ? e.remarks : ''),
        ];
        lines.push(values.map(escapeCsvValue).join(','));
      }
      const csv = `\uFEFF${lines.join('\r\n')}\r\n`;
      downloadCsvFile(csv, `wise_eur_${year}_${getTodayStamp()}.csv`);
    }

    function downloadWiseEurCsvTemplate() {
      const header = [
        'Budget #',
        'ACTION DATE',
        '# ID-TRACK',
        'RECEIVED FROM - DISBURSED TO:',
        'RECEIPTS €',
        'DISBURSE €',
        'DESCRIPTION',
        'Issuance Date Bank',
        'Verified',
        'Checksum',
        'Bank Statements',
        'Remarks',
      ];
      const example = ['', getTodayStamp(), '', 'Example Party', '100.00', '', 'Example description', '', '1', '', '', ''];
      const lines = [];
      lines.push(header.map(escapeCsvValue).join(','));
      lines.push(example.map(escapeCsvValue).join(','));
      const csv = `\uFEFF${lines.join('\r\n')}\r\n`;
      downloadCsvFile(csv, `wise_eur_template_${year}_${getTodayStamp()}.csv`);
    }

    function parseCsvText(text) {
      const rows = [];
      const s = String(text ?? '');
      let row = [];
      let field = '';
      let inQuotes = false;

      for (let i = 0; i < s.length; i += 1) {
        const ch = s[i];
        if (inQuotes) {
          if (ch === '"') {
            const next = s[i + 1];
            if (next === '"') {
              field += '"';
              i += 1;
            } else {
              inQuotes = false;
            }
          } else {
            field += ch;
          }
          continue;
        }

        if (ch === '"') {
          inQuotes = true;
          continue;
        }

        if (ch === ',') {
          row.push(field);
          field = '';
          continue;
        }

        if (ch === '\n') {
          row.push(field);
          field = '';
          rows.push(row);
          row = [];
          continue;
        }

        if (ch === '\r') continue;
        field += ch;
      }

      row.push(field);
      rows.push(row);

      while (rows.length > 0) {
        const last = rows[rows.length - 1];
        const isEmpty = last.every((c) => String(c ?? '').trim() === '');
        if (!isEmpty) break;
        rows.pop();
      }

      return rows;
    }

    function normalizeHeaderName(name) {
      return String(name ?? '')
        .replace(/\uFEFF/g, '')
        .replace(/\u00A0/g, ' ')
        .trim()
        .toLowerCase();
    }

    function normalizeCsvDate(raw) {
      const s = String(raw ?? '').trim();
      if (!s) return '';
      if (/^\d{4}-\d{2}-\d{2}$/.test(s)) return s;

      const mdy = s.match(/^\s*(\d{1,2})[\/\-](\d{1,2})[\/\-](\d{4})\s*$/);
      if (mdy) {
        const mm = Number(mdy[1]);
        const dd = Number(mdy[2]);
        const yyyy = Number(mdy[3]);
        if (!Number.isInteger(mm) || !Number.isInteger(dd) || !Number.isInteger(yyyy)) return '';
        if (yyyy < 1000 || yyyy > 9999) return '';
        if (mm < 1 || mm > 12) return '';
        if (dd < 1 || dd > 31) return '';
        const d = new Date(yyyy, mm - 1, dd);
        if (d.getFullYear() !== yyyy || d.getMonth() !== mm - 1 || d.getDate() !== dd) return '';
        return `${yyyy}-${String(mm).padStart(2, '0')}-${String(dd).padStart(2, '0')}`;
      }

      const ms = Date.parse(s);
      if (!Number.isFinite(ms)) return '';
      const d = new Date(ms);
      return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
    }

    function parseNonNegativeAmount(raw) {
      const s = String(raw ?? '').replace(/\u00A0/g, ' ').trim();
      if (!s) return null;
      const cleaned = s.replace(/[^0-9.,\-]/g, '').replace(/,/g, '');
      const n = Number(cleaned);
      if (!Number.isFinite(n) || n < 0) return null;
      return n;
    }

    function parseSignedAmount(raw) {
      const s = String(raw ?? '').replace(/\u00A0/g, ' ').trim();
      if (!s) return null;
      const cleaned = s.replace(/[^0-9.,\-]/g, '').replace(/,/g, '');
      const n = Number(cleaned);
      if (!Number.isFinite(n)) return null;
      return n;
    }

    function findHeaderIndex(headerNames, candidates) {
      const names = Array.isArray(headerNames) ? headerNames : [];
      const cands = (Array.isArray(candidates) ? candidates : []).map(normalizeHeaderName).filter(Boolean);
      if (cands.length === 0) return -1;
      for (const c of cands) {
        const exact = names.indexOf(c);
        if (exact !== -1) return exact;
      }
      for (let i = 0; i < names.length; i += 1) {
        const h = String(names[i] ?? '').trim();
        if (!h) continue;
        if (cands.some((c) => h === c || h.startsWith(`${c} `) || h.startsWith(`${c}(`) || h.startsWith(`${c}—`) || h.startsWith(`${c}-`) || h.startsWith(c))) {
          return i;
        }
      }
      return -1;
    }

    function parseWiseEurCsvTextToEntries(csvText, options) {
      const opts = options && typeof options === 'object' ? options : {};
      const relaxRequired = !!opts.relaxRequired;

      function parseCsvBooleanish(value) {
        const s = String(value ?? '').trim().toLowerCase();
        if (!s) return false;
        if (s === '1' || s === 'true' || s === 'yes' || s === 'y' || s === 'on' || s === 'checked' || s === 'x') return true;
        if (s === '0' || s === 'false' || s === 'no' || s === 'n' || s === 'off') return false;
        // Legacy Checked-by text (e.g., initials) should count as verified.
        return true;
      }

      const rows = parseCsvText(csvText);
      if (rows.length === 0) {
        return { isEmpty: true, imported: [], errors: [] };
      }

      const header = rows[0].map(normalizeHeaderName);
      const dataRows = rows.slice(1).filter((r) => r.some((c) => String(c ?? '').trim() !== ''));

      const idx = {
        budgetNo: findHeaderIndex(header, ['budget #', 'budget', 'budget no', 'budget number']),
        datePL: findHeaderIndex(header, ['action date', 'date p-l', 'date pl', 'date']),
        idTrack: findHeaderIndex(header, ['# id-track', 'id-track', 'id track', 'track', 'tracking']),
        receivedFromDisbursedTo: findHeaderIndex(header, [
          'received from - disbursed to:',
          'received from - disbursed to',
          'received from',
          'disbursed to',
          'party',
          'payee',
          'remitter',
          'name',
          'merchant',
        ]),
        receipts: findHeaderIndex(header, ['receipts €', 'receipts', 'receipt', 'credit', 'received', 'in']),
        disburse: findHeaderIndex(header, ['disburse €', 'disburse', 'disbursement', 'debit', 'paid', 'payment', 'out', 'sent']),
        description: findHeaderIndex(header, ['description', 'reference', 'details', 'memo', 'note']),
        issuanceDateBank: findHeaderIndex(header, ['issuance date bank', 'issuance date', 'bank issuance date']),
        verified: findHeaderIndex(header, ['verified', 'checked by gtreas', 'checked by', 'gtreas']),
        checksum: findHeaderIndex(header, ['checksum', 'balance']),
        bankStatements: findHeaderIndex(header, ['bank statements', 'bank statement']),
        remarks: findHeaderIndex(header, ['remarks', 'remark']),
        amount: findHeaderIndex(header, ['amount', 'euro', 'eur', 'value']),
        currency: findHeaderIndex(header, ['currency', 'ccy']),
      };

      const hasHeaders =
        idx.datePL !== -1 &&
        (idx.receivedFromDisbursedTo !== -1 || idx.description !== -1) &&
        (idx.receipts !== -1 || idx.disburse !== -1 || idx.amount !== -1);

      if (!hasHeaders && header.length >= 3) {
        // Allow headerless CSV: DATE P-L, RECEIVED FROM - DISBURSED TO, DESCRIPTION, RECEIPTS, DISBURSE
        dataRows.unshift(rows[0]);
        idx.datePL = 0;
        idx.receivedFromDisbursedTo = 1;
        idx.description = 2;
        idx.receipts = 3;
        idx.disburse = 4;
        idx.amount = 5;
      }

      const nowIso = new Date().toISOString();
      const imported = [];
      const errors = [];

      for (let rowIndex = 0; rowIndex < dataRows.length; rowIndex += 1) {
        const r = dataRows[rowIndex];
        const get = (i) => (i >= 0 ? (r[i] ?? '') : '');

        const rowNo = rowIndex + 2;
        const budgetNo = String(get(idx.budgetNo)).trim();
        const datePL = normalizeCsvDate(get(idx.datePL));
        const idTrack = String(get(idx.idTrack)).trim();
        const receivedFromDisbursedTo = String(get(idx.receivedFromDisbursedTo)).trim();
        const description = String(get(idx.description)).trim();
        const issuanceDateBank = normalizeCsvDate(get(idx.issuanceDateBank));
        const verifiedRaw = String(get(idx.verified)).trim();
        const verified = parseCsvBooleanish(verifiedRaw);
        const bankStatements = String(get(idx.bankStatements)).trim();
        const remarks = String(get(idx.remarks)).trim();

        const hasAnyText =
          !!budgetNo ||
          !!datePL ||
          !!idTrack ||
          !!receivedFromDisbursedTo ||
          !!description ||
          !!issuanceDateBank ||
          !!verifiedRaw ||
          !!bankStatements ||
          !!remarks;

        const checksumRaw = String(get(idx.checksum)).trim();
        const checksumNum = parseSignedAmount(checksumRaw);
        const checksum = checksumNum === null ? checksumRaw : checksumNum;

        const currency = idx.currency !== -1 ? String(get(idx.currency)).trim().toUpperCase() : '';
        if (currency && currency !== 'EUR' && currency !== '€') {
          errors.push(`Row ${rowNo}: currency is not EUR.`);
          continue;
        }

        const receiptsRaw = String(get(idx.receipts)).trim();
        const disburseRaw = String(get(idx.disburse)).trim();
        let receipts = parseNonNegativeAmount(receiptsRaw);
        let disburse = parseNonNegativeAmount(disburseRaw);

        if (receipts === null && disburse === null) {
          const amount = parseSignedAmount(get(idx.amount));
          if (amount === null) {
            if (!relaxRequired && (receiptsRaw || disburseRaw || String(get(idx.amount)).trim())) {
              errors.push(`Row ${rowNo}: missing amount.`);
            }
          } else if (amount > 0) {
            receipts = amount;
            disburse = null;
          } else if (amount < 0) {
            receipts = null;
            disburse = Math.abs(amount);
          } else {
            receipts = null;
            disburse = null;
            if (!relaxRequired) errors.push(`Row ${rowNo}: amount is 0.`);
          }
        }

        const receiptsHas = Number.isFinite(receipts) && receipts > 0;
        const disburseHas = Number.isFinite(disburse) && disburse > 0;

        // If the row is completely blank (no meaningful text, no amounts, no checksum), skip silently.
        const hasAnyAmount = receiptsHas || disburseHas || (checksumRaw && String(checksumRaw).trim() !== '');
        if (!hasAnyText && !hasAnyAmount) continue;

        if (!relaxRequired) {
          if (!datePL) errors.push(`Row ${rowNo}: invalid Action Date.`);
          if (!receivedFromDisbursedTo) errors.push(`Row ${rowNo}: Received From - Disbursed To is required.`);
          if (!receiptsHas && !disburseHas) errors.push(`Row ${rowNo}: enter a Receipts or Disburse amount.`);
          if (receiptsHas && disburseHas) errors.push(`Row ${rowNo}: enter only one: Receipts or Disburse.`);

          // Description is optional for import.
          if (!datePL || !receivedFromDisbursedTo || (!receiptsHas && !disburseHas) || (receiptsHas && disburseHas)) continue;
        } else {
          if (receiptsHas && disburseHas) {
            errors.push(`Row ${rowNo}: enter only one: Receipts or Disburse.`);
            continue;
          }
        }

        imported.push({
          id: (crypto?.randomUUID ? crypto.randomUUID() : `we_${Date.now()}_${Math.random().toString(16).slice(2)}`),
          createdAt: nowIso,
          updatedAt: nowIso,
          budgetNo,
          datePL,
          idTrack,
          receivedFromDisbursedTo,
          receipts: receiptsHas ? receipts : null,
          disburse: disburseHas ? disburse : null,
          description,
          issuanceDateBank,
          verified: verified ? 1 : 0,
          checksum,
          bankStatements,
          remarks,
        });
      }

      return { isEmpty: false, imported, errors };
    }

    function importWiseEurFromCsvText(csvText, fileName) {
      const ok = window.confirm(
        `Importing a CSV will add entries to the wiseEUR list for ${year}. Continue?\n\nFile: ${fileName || 'CSV'}`
      );
      if (!ok) return;

      const existingBefore = loadWiseEur(year);
      const relaxRequired = !Array.isArray(existingBefore) || existingBefore.length === 0;
      const parsed = parseWiseEurCsvTextToEntries(csvText, { relaxRequired });
      if (parsed.isEmpty) {
        window.alert('CSV is empty.');
        return;
      }

      const imported = parsed.imported;
      const errors = parsed.errors;

      if (imported.length === 0) {
        window.alert(errors.length ? `No rows were imported:\n\n${errors.slice(0, 15).join('\n')}` : 'No rows were imported.');
        return;
      }

      if (errors.length > 0) {
        const proceed = window.confirm(
          `Some rows could not be processed. Continue with ${imported.length} imported row(s)?\n\n${errors
            .slice(0, 15)
            .join('\n')}${errors.length > 15 ? '\n…' : ''}`
        );
        if (!proceed) return;
      }

      const positiveImported = imported.filter((e) => computeWiseEurNet(e) > 0);
      const negativeImported = imported.filter((e) => computeWiseEurNet(e) < 0);

      if (negativeImported.length > 0) {
        ensurePaymentOrdersReconciliationListExistsForYear(year);
        for (const e of negativeImported) {
          const po = buildReconciliationOrderFromWiseEurEntry(e, year);
          if (po) upsertReconciliationOrderBySource(po, year);
        }
      }

      const existing = existingBefore;
      const merged = [...positiveImported, ...(Array.isArray(existing) ? existing : [])];
      saveWiseEur(merged, year);
      applyWiseEurView();

      if (typeof showFlashToken === 'function') {
        showFlashToken(`Imported ${positiveImported.length} wiseEUR row(s). Moved ${negativeImported.length} row(s) to Reconciliation.`);
      }
    }

    async function tryAutoSeedWiseEurFromCsvFile() {
      if (Number(year) !== 2026) return false;

      const seedFlagKey = `payment_order_wise_eur_seeded_${year}_v1`;
      if (localStorage.getItem(seedFlagKey) === '1') return false;

      const existing = loadWiseEur(year);
      if (Array.isArray(existing) && existing.length > 0) return false;

      let resp;
      try {
        resp = await fetch('wise_eur_2026_seed.csv', { cache: 'no-store' });
      } catch (e) {
        return false;
      }

      if (!resp || !resp.ok) return false;

      const text = await resp.text();
      const parsed = parseWiseEurCsvTextToEntries(text, { relaxRequired: true });
      if (parsed.isEmpty || !Array.isArray(parsed.imported) || parsed.imported.length === 0) return false;

      saveWiseEur(parsed.imported, year);
      localStorage.setItem(seedFlagKey, '1');

      if (typeof showFlashToken === 'function') {
        showFlashToken(`Seeded ${parsed.imported.length} wiseEUR row(s) for ${year}.`);
      }

      return true;
    }

    if (wiseEurExportCsvLink) {
      wiseEurExportCsvLink.addEventListener('click', (e) => {
        e.preventDefault();
        exportWiseEurToCsv();
      });
    }
    if (wiseEurDownloadTemplateLink) {
      wiseEurDownloadTemplateLink.addEventListener('click', (e) => {
        e.preventDefault();
        downloadWiseEurCsvTemplate();
      });
    }
    if (wiseEurImportCsvLink) {
      const input = document.createElement('input');
      input.type = 'file';
      input.accept = '.csv,text/csv';
      input.style.display = 'none';
      document.body.appendChild(input);

      wiseEurImportCsvLink.addEventListener('click', (e) => {
        e.preventDefault();
        if (wiseEurImportCsvLink.getAttribute('aria-disabled') === 'true') {
          alertDisabledAction(wiseEurImportCsvLink);
          return;
        }
        if (!requireWriteAccess('income_bankeur', 'Income is read only for your account.')) return;
        input.value = '';
        input.click();
      });

      input.addEventListener('change', () => {
        const file = input.files && input.files[0];
        if (!file) return;
        const reader = new FileReader();
        reader.onload = () => {
          importWiseEurFromCsvText(reader.result, file.name);
        };
        reader.onerror = () => {
          window.alert('Could not read CSV file.');
        };
        reader.readAsText(file);
      });
    }

    if (wiseEurMenuBtn) {
      const MENU_CLOSE_DELAY_MS = 250;
      let menuCloseTimer = 0;

      function isMenuOpen() {
        return Boolean(wiseEurMenuPanel && !wiseEurMenuPanel.hasAttribute('hidden'));
      }

      function closeMenu() {
        if (!wiseEurMenuPanel || !wiseEurMenuBtn) return;
        wiseEurMenuPanel.setAttribute('hidden', '');
        wiseEurMenuBtn.setAttribute('aria-expanded', 'false');
      }

      function openMenu() {
        if (!wiseEurMenuPanel || !wiseEurMenuBtn) return;
        wiseEurMenuPanel.removeAttribute('hidden');
        wiseEurMenuBtn.setAttribute('aria-expanded', 'true');
      }

      function toggleMenu() {
        if (isMenuOpen()) closeMenu();
        else openMenu();
      }

      function cancelScheduledClose() {
        if (!menuCloseTimer) return;
        clearTimeout(menuCloseTimer);
        menuCloseTimer = 0;
      }

      function scheduleClose() {
        cancelScheduledClose();
        if (!isMenuOpen()) return;
        menuCloseTimer = window.setTimeout(() => {
          closeMenu();
          menuCloseTimer = 0;
        }, MENU_CLOSE_DELAY_MS);
      }

      wiseEurMenuBtn.addEventListener('click', () => {
        toggleMenu();
      });

      wiseEurMenuBtn.addEventListener('mouseenter', cancelScheduledClose);
      wiseEurMenuBtn.addEventListener('mouseleave', scheduleClose);

      if (wiseEurMenuPanel) {
        wiseEurMenuPanel.addEventListener('mouseenter', cancelScheduledClose);
        wiseEurMenuPanel.addEventListener('mouseleave', scheduleClose);
      }

      document.addEventListener('click', (e) => {
        if (!isMenuOpen()) return;
        const menuRoot = e.target?.closest ? e.target.closest('[data-wise-eur-menu]') : null;
        if (menuRoot) return;
        cancelScheduledClose();
        closeMenu();
      });

      document.addEventListener('keydown', (e) => {
        if (!isMenuOpen()) return;
        if (e.key === 'Escape') {
          cancelScheduledClose();
          closeMenu();
        }
      });
    }

    wiseEurTbody.addEventListener('click', (e) => {
      const dl = e.target && e.target.closest ? e.target.closest('a[data-action="downloadPdf"][data-order-id]') : null;
      if (dl) {
        e.preventDefault();
        const orderId = String(dl.getAttribute('data-order-id') || '').trim();
        const scope = String(dl.getAttribute('data-order-scope') || '').trim().toLowerCase();
        if (!orderId) return;

        const order = scope === 'reconciliation'
          ? loadReconciliationOrders(year).find((o) => o && String(o.id) === orderId)
          : loadOrders(year).find((o) => o && String(o.id) === orderId);
        if (!order) return;
        if (hasOrderMissingRequiredValues(order)) {
          window.alert('Complete all required fields before downloading a PDF.');
          return;
        }
        generatePaymentOrderPdfFromTemplate({ order });
        return;
      }

      const btn = e.target.closest('button[data-wise-eur-action]');
      if (!btn) return;
      const row = btn.closest('tr[data-wise-eur-id]');
      if (!row) return;
      const id = row.getAttribute('data-wise-eur-id');
      const action = btn.getAttribute('data-wise-eur-action');

      if (action === 'delete') {
        if (btn.getAttribute('aria-disabled') === 'true') {
          alertDisabledAction(btn, 'Requires Delete access for wiseEUR.');
          return;
        }
        if (!requireDeleteAccess('income_wise_eur', 'Delete access is required for wiseEUR.')) return;
        const ok = window.confirm('Delete this wiseEUR entry?');
        if (!ok) return;
        deleteWiseEurEntryById(id, year);
        applyWiseEurView();
        return;
      }

      if (action === 'edit') {
        if (!requireIncomeEditAccess('Income is read only for your account.')) return;
        const all = loadWiseEur(year);
        const entry = all.find((x) => x && x.id === id);
        if (!entry) return;
        openWiseEurModal(entry, year);
      }
    });

    // Persist Verified checkbox state per wiseEUR entry.
    if (!wiseEurTbody.dataset.verifiedBound) {
      wiseEurTbody.dataset.verifiedBound = '1';
      wiseEurTbody.addEventListener('change', (e) => {
        const input =
          e.target && e.target.matches
            ? e.target.matches('input[type="checkbox"][data-wise-eur-verify]')
              ? e.target
              : null
            : null;
        if (!input) return;

        if (!wiseEurViewState.canVerify) {
          input.checked = !input.checked;
          return;
        }

        if (!requireIncomeEditAccess('Income is read only for your account.')) {
          input.checked = !input.checked;
          return;
        }

        const id = String(input.getAttribute('data-wise-eur-id') || '').trim();
        if (!id) return;
        const all = loadWiseEur(year);
        const entry = all.find((x) => x && x.id === id);
        if (!entry) return;

        entry.verified = input.checked ? 1 : 0;
        if ('checkedByGTREAS' in entry) delete entry.checkedByGTREAS;
        entry.updatedAt = new Date().toISOString();
        upsertWiseEurEntry(entry, year);

        // Keep sort/search values consistent.
        applyWiseEurView();
      });
    }

    if (wiseEurModal && !wiseEurModal.dataset.bound) {
      wiseEurModal.dataset.bound = '1';
      wiseEurModal.addEventListener('click', (e) => {
        const closeTarget = e.target.closest('[data-wise-eur-modal-close]');
        if (closeTarget) closeWiseEurModal();
      });
    }

    if (!document.body.dataset.wiseEurEscBound) {
      document.body.dataset.wiseEurEscBound = '1';
      document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && wiseEurModal && wiseEurModal.classList.contains('is-open')) {
          closeWiseEurModal();
        }
      });
    }

    if (wiseEurSaveBtn && !wiseEurSaveBtn.dataset.bound) {
      wiseEurSaveBtn.dataset.bound = '1';
      wiseEurSaveBtn.addEventListener('click', () => {
        try {
          if (!requireIncomeEditAccess('Income is read only for your account.')) return;
          if (!hasIncomeFullAccess && !currentWiseEurId) {
            window.alert('Requires Full access for Income to create a new wiseEUR entry.');
            return;
          }
          clearWiseEurModalErrors();
          const res = validateWiseEurModalValues();
          if (!res.ok) {
            showWiseEurModalErrors(res.errors);
            return;
          }

          const nowIso = new Date().toISOString();
          const id =
            currentWiseEurId ||
            (crypto?.randomUUID ? crypto.randomUUID() : `we_${Date.now()}_${Math.random().toString(16).slice(2)}`);
          const existing = currentWiseEurId ? loadWiseEur(year).find((x) => x && x.id === currentWiseEurId) : null;

          const entry = {
            id,
            createdAt: existing && existing.createdAt ? existing.createdAt : nowIso,
            updatedAt: nowIso,
            ...res.values,
            idTrack: existing && existing.idTrack ? existing.idTrack : '',
          };

          const net = computeWiseEurNet(entry);
          if (net < 0) {
            const po = buildReconciliationOrderFromWiseEurEntry(entry, year);
            if (po) {
              ensurePaymentOrdersReconciliationListExistsForYear(year);
              upsertReconciliationOrderBySource(po, year);
            }
            if (existing) deleteWiseEurEntryById(entry.id, year);
          } else {
            removeReconciliationOrderBySource('wiseEUR', entry.id, year);
            upsertWiseEurEntry(entry, year);
            if (!existing) {
              void fireNotificationEvent('new_wise_eur', {
                date: String(entry.date || ''),
                party: String(entry.receivedFromDisbursedTo || ''),
                amount: String(entry.totalAmountInEuro || entry.euroAmount || ''),
                year: String(year),
                directLink: String(window.location.href || ''),
              });
            }
          }
          closeWiseEurModal();
          applyWiseEurView();
        } catch (err) {
          console.error('[WiseEUR Save] Failed', err);
          window.alert(`Unable to save wiseEUR entry. ${err && err.message ? err.message : 'Check console for details.'}`);
        }
      });
    }

    if (!wiseEurTbody.dataset.storageBound) {
      wiseEurTbody.dataset.storageBound = '1';
      window.addEventListener('storage', (e) => {
        const key = e && typeof e.key === 'string' ? e.key : '';
        if (!key) return;
        if (key.startsWith('payment_order_wise_eur_')) {
          applyWiseEurView();
        }
      });
    }

    tryAutoSeedWiseEurFromCsvFile()
      .then((didSeed) => {
        if (didSeed) applyWiseEurView();
      })
      .catch(() => {});

    applyWiseEurView();
  }

  // ---- wiseUSD (year-scoped) ----

  const WISE_USD_COL_TYPES = {
    budgetNo: 'text',
    datePL: 'date',
    idTrack: 'text',
    receivedFromDisbursedTo: 'text',
    receipts: 'number',
    disburse: 'number',
    description: 'text',
    issuanceDateBank: 'date',
    verified: 'number',
    checksum: 'number',
    bankStatements: 'text',
    remarks: 'text',
  };

  const wiseUsdViewState = {
    globalFilter: '',
    sortKey: 'datePL',
    sortDir: 'asc',
    defaultEmptyText: null,
    canVerify: false,
    canDelete: false,
  };

  function ensureWiseUsdDefaultEmptyText() {
    if (!wiseUsdEmptyState) return;
    if (wiseUsdViewState.defaultEmptyText !== null) return;
    wiseUsdViewState.defaultEmptyText = wiseUsdEmptyState.textContent || 'No wiseUSD entries yet.';
  }

  function getWiseUsdReceipts(entry) {
    const n = Number(entry && entry.receipts);
    return Number.isFinite(n) && n > 0 ? n : 0;
  }

  function getWiseUsdDisburse(entry) {
    const n = Number(entry && entry.disburse);
    return Number.isFinite(n) && n > 0 ? n : 0;
  }

  function getWiseUsdVerified(entry) {
    if (!entry) return false;
    if (typeof entry.verified === 'boolean') return entry.verified;
    const raw = entry.verified !== undefined ? entry.verified : entry.checkedByGTREAS;
    if (raw === null || raw === undefined) return false;
    const s = String(raw).trim().toLowerCase();
    if (!s) return false;
    if (s === '0' || s === 'false' || s === 'no' || s === 'n' || s === 'off') return false;
    return true;
  }

  function computeWiseUsdNet(entry) {
    return getWiseUsdReceipts(entry) - getWiseUsdDisburse(entry);
  }

  function hasWiseUsdMissingRequiredValues(entry) {
    if (!entry) return true;
    const date = String(entry.datePL || entry.date || '').trim();
    const party = String(entry.receivedFromDisbursedTo || entry.party || '').trim();
    const description = String(entry.description || entry.reference || '').trim();

    const receipts = getWiseUsdReceipts(entry);
    const disburse = getWiseUsdDisburse(entry);
    const hasReceipts = Number.isFinite(receipts) && receipts > 0;
    const hasDisburse = Number.isFinite(disburse) && disburse > 0;
    const hasOneAmount = (hasReceipts && !hasDisburse) || (!hasReceipts && hasDisburse);

    const rawBudgetNo = String(entry.budgetNo || '').trim();
    const hasBudget = Boolean(extractInCodeFromBudgetNumberText(rawBudgetNo) || extractOutCodeFromBudgetNumberText(rawBudgetNo));

    if (!date) return true;
    if (!party) return true;
    if (!description) return true;
    if (!hasOneAmount) return true;
    if (!hasBudget) return true;
    return false;
  }

  function buildReconciliationOrderFromWiseUsdEntry(entry, year) {
    if (!entry || !entry.id) return null;
    const absUsd = getWiseUsdDisburse(entry);
    if (!(Number.isFinite(absUsd) && absUsd > 0)) return null;

    const date = String(entry.datePL || entry.date || '').trim();
    const party = String(entry.receivedFromDisbursedTo || entry.party || '').trim();
    const purpose = String(entry.description || entry.reference || '').trim() || 'wiseUSD disbursement';
    const budgetNumber = String(entry.budgetNo || '').trim();
    const itemTitle = purpose;

    const po = buildPaymentOrder({
      source: 'wiseUSD',
      sourceEntryId: entry.id,
      sourceEntryYear: year,
      paymentOrderNo: '',
      date,
      name: party,
      euro: null,
      usd: absUsd,
      items: [
        {
          id: (crypto?.randomUUID ? crypto.randomUUID() : `it_${Date.now()}_${Math.random().toString(16).slice(2)}`),
          title: itemTitle,
          euro: null,
          usd: absUsd,
        },
      ],
      address: '',
      iban: '',
      bic: '',
      specialInstructions: '',
      budgetNumber,
      purpose,
      with: 'Grand Secretary',
      status: 'Submitted',
    });
    po.updatedAt = po.createdAt;
    return po;
  }

  function getWiseUsdDisplayValueForColumn(entry, colKey) {
    if (!entry) return '';
    switch (colKey) {
      case 'budgetNo':
        return entry.budgetNo || '';
      case 'datePL':
        return formatDate(entry.datePL || entry.date);
      case 'idTrack':
        return entry.idTrack ? formatPaymentOrderNoForDisplay(entry.idTrack) : '';
      case 'receivedFromDisbursedTo':
        return entry.receivedFromDisbursedTo || entry.party || '';
      case 'receipts': {
        const n = getWiseUsdReceipts(entry);
        return n ? formatCurrency(n, 'USD') : '';
      }
      case 'disburse': {
        const n = getWiseUsdDisburse(entry);
        return n ? formatCurrency(n, 'USD') : '';
      }
      case 'description':
        return entry.description || entry.reference || '';
      case 'issuanceDateBank':
        return entry.issuanceDateBank ? formatDate(entry.issuanceDateBank) : '';
      case 'verified':
        return getWiseUsdVerified(entry) ? 'Yes' : '';
      case 'checksum': {
        const n = Number(entry && entry.checksum);
        return Number.isFinite(n) ? formatCurrency(n, 'USD') : entry.checksum || '';
      }
      case 'bankStatements':
        return entry.bankStatements || '';
      case 'remarks':
        return entry.remarks || '';
      default:
        return '';
    }
  }

  function getWiseUsdSortValueForColumn(entry, colKey, colType) {
    if (!entry) return null;
    if (colType === 'number') {
      if (colKey === 'receipts') return getWiseUsdReceipts(entry);
      if (colKey === 'disburse') return getWiseUsdDisburse(entry);
      if (colKey === 'verified') return getWiseUsdVerified(entry) ? 1 : 0;
      if (colKey === 'checksum') {
        const n = Number(entry && entry.checksum);
        return Number.isFinite(n) ? n : null;
      }
      return null;
    }
    if (colType === 'date') {
      const raw =
        colKey === 'datePL'
          ? String(entry.datePL || entry.date || '').trim()
          : colKey === 'issuanceDateBank'
            ? String(entry.issuanceDateBank || '').trim()
            : '';
      return raw ? raw : null;
    }
    return normalizeTextForSearch(getWiseUsdDisplayValueForColumn(entry, colKey));
  }

  function filterWiseUsdForView(entries, globalFilter) {
    const needle = normalizeTextForSearch(globalFilter);
    if (!needle) return entries || [];

    const cols = Object.keys(WISE_USD_COL_TYPES);
    return (entries || []).filter((e) => cols.some((k) => normalizeTextForSearch(getWiseUsdDisplayValueForColumn(e, k)).includes(needle)));
  }

  function sortWiseUsdForView(entries, sortKey, sortDir) {
    const dir = sortDir === 'desc' ? -1 : 1;
    const key = sortKey || 'datePL';
    const colType = WISE_USD_COL_TYPES[key] || 'text';
    const withIndex = (entries || []).map((entry, index) => ({ entry, index }));
    withIndex.sort((a, b) => {
      const av = getWiseUsdSortValueForColumn(a.entry, key, colType);
      const bv = getWiseUsdSortValueForColumn(b.entry, key, colType);

      if (av === null && bv === null) return a.index - b.index;
      if (av === null) return 1;
      if (bv === null) return -1;

      if (colType === 'number') {
        const cmp = av === bv ? 0 : av < bv ? -1 : 1;
        return cmp === 0 ? a.index - b.index : cmp * dir;
      }

      const cmp = String(av).localeCompare(String(bv));
      return cmp === 0 ? a.index - b.index : cmp * dir;
    });
    return withIndex.map((x) => x.entry);
  }

  function renderWiseUsdRows(entries) {
    if (!wiseUsdTbody) return;
    const canVerify = Boolean(wiseUsdViewState.canVerify);
    const canDeleteRows = Boolean(wiseUsdViewState.canDelete);
    const deleteAriaDisabled = canDeleteRows ? 'false' : 'true';
    const deleteTooltipAttr = canDeleteRows ? '' : ' data-tooltip="Requires Delete access for wiseUSD."';
    const year = getActiveBudgetYear();
    const activeYear = getActiveBudgetYear();
    const inMap = getInDescMapForYear(activeYear);
    const outMap = getOutDescMapForYear(activeYear);
    const ordersBySourceEntryKey = new Map();
    const reconcileBySourceEntryKey = new Map();
    const ordersByPoCanon = new Map();
    const reconcileByPoCanon = new Map();
    const orderIds = new Set();
    const sourceEntryKey = (sourceRaw, sourceEntryIdRaw) => {
      const source = String(sourceRaw || '').trim().toLowerCase();
      const sourceEntryId = String(sourceEntryIdRaw || '').trim();
      if (!source || !sourceEntryId) return '';
      return `${source}::${sourceEntryId}`;
    };
    {
      const orders = loadOrders(year);
      for (const o of orders || []) {
        if (!o || typeof o !== 'object') continue;

        const oid = String(o.id || '').trim();
        if (oid) orderIds.add(oid);

        const poCanon = canonicalizePaymentOrderNo(o.paymentOrderNo);
        if (poCanon && !ordersByPoCanon.has(poCanon)) ordersByPoCanon.set(poCanon, o);

        const key = sourceEntryKey(o.source, o.sourceEntryId);
        if (!key) continue;
        if (!ordersBySourceEntryKey.has(key)) {
          ordersBySourceEntryKey.set(key, o);
          continue;
        }
        // Prefer an order that has a PO number assigned.
        const existing = ordersBySourceEntryKey.get(key);
        const existingPoNo = String(existing && existing.paymentOrderNo ? existing.paymentOrderNo : '').trim();
        const nextPoNo = String(o && o.paymentOrderNo ? o.paymentOrderNo : '').trim();
        if (!existingPoNo && nextPoNo) ordersBySourceEntryKey.set(key, o);
      }
    }
    {
      const rec = loadReconciliationOrders(year);
      for (const o of rec || []) {
        if (!o || typeof o !== 'object') continue;
        const poCanon = canonicalizePaymentOrderNo(o.paymentOrderNo);
        if (poCanon && !reconcileByPoCanon.has(poCanon)) reconcileByPoCanon.set(poCanon, o);

        const key = sourceEntryKey(o.source, o.sourceEntryId);
        if (!key) continue;
        if (!reconcileBySourceEntryKey.has(key)) reconcileBySourceEntryKey.set(key, o);
      }
    }
    const html = (entries || [])
      .map((e) => {
        const id = escapeHtml(e.id);
        const isMissingRequired = hasWiseUsdMissingRequiredValues(e);
        const rowClass = isMissingRequired ? ' class="ordersRow--missingRequired"' : '';
        const rawBudgetNo = getWiseUsdDisplayValueForColumn(e, 'budgetNo');
        const receiptsAmt = getWiseUsdReceipts(e);
        const disburseAmt = getWiseUsdDisburse(e);
        let budgetNo = '';
        if (receiptsAmt > 0 && disburseAmt <= 0) {
          const code = extractInCodeFromBudgetNumberText(rawBudgetNo) || String(rawBudgetNo || '').trim();
          const desc = (code && inMap ? inMap.get(code) : '') || (code ? BUDGET_DESC_BY_CODE.get(code) : '') || inferDescFromBudgetNumberText(rawBudgetNo);
          budgetNo = renderBudgetNumberSpanHtml(code || rawBudgetNo, desc);
        } else if (disburseAmt > 0 && receiptsAmt <= 0) {
          const code = extractOutCodeFromBudgetNumberText(rawBudgetNo) || String(rawBudgetNo || '').trim();
          const desc = (code && outMap ? outMap.get(code) : '') || (code ? BUDGET_DESC_BY_CODE.get(code) : '') || inferDescFromBudgetNumberText(rawBudgetNo);
          budgetNo = renderBudgetNumberSpanHtml(code || rawBudgetNo, desc);
        } else {
          const code =
            extractInCodeFromBudgetNumberText(rawBudgetNo) ||
            extractOutCodeFromBudgetNumberText(rawBudgetNo) ||
            String(rawBudgetNo || '').trim();
          const desc =
            (code && outMap ? outMap.get(code) : '') ||
            (code && inMap ? inMap.get(code) : '') ||
            (code ? BUDGET_DESC_BY_CODE.get(code) : '') ||
            inferDescFromBudgetNumberText(rawBudgetNo);
          budgetNo = renderBudgetNumberSpanHtml(code || rawBudgetNo, desc);
        }
        const datePL = escapeHtml(getWiseUsdDisplayValueForColumn(e, 'datePL'));
        const idTrack = escapeHtml(getWiseUsdDisplayValueForColumn(e, 'idTrack'));
        const receivedFromDisbursedTo = escapeHtml(getWiseUsdDisplayValueForColumn(e, 'receivedFromDisbursedTo'));
        const receipts = escapeHtml(getWiseUsdDisplayValueForColumn(e, 'receipts'));
        const disburse = escapeHtml(getWiseUsdDisplayValueForColumn(e, 'disburse'));
        const descRaw = String(getWiseUsdDisplayValueForColumn(e, 'description') || '');
        const strippedDescRaw = descRaw
          .replace(/\s*\(\s*converted\s+to\s+PO\s+\d{2}\s*-\s*\d{1,3}\s*\)\s*\.?\s*$/i, '')
          .replace(/\s*converted\s+to\s+PO\s+\d{2}\s*-\s*\d{1,3}\s*\.?\s*$/i, '')
          .replace(/\s*\(\s*pending\s+Payment\s+Order\s+Reconciliation\s*\)\s*\.?\s*$/i, '')
          .trim();
        const descText = escapeHtml(strippedDescRaw);

        const isDisbursement = Number.isFinite(disburseAmt) && disburseAmt > 0;
        const srcKey = isDisbursement ? sourceEntryKey('wiseUSD', e.id) : '';
        const match = srcKey
          ? (ordersBySourceEntryKey.get(srcKey) || reconcileBySourceEntryKey.get(srcKey))
          : null;

        const poFromMatch = String(match && match.paymentOrderNo ? match.paymentOrderNo : '').trim();
        const poFromIdTrack = String(e && e.idTrack ? e.idTrack : '').trim();
        const poFromDescMatch = descRaw.match(/\bPO\s*\d{2}\s*-\s*\d{1,3}\b/i);
        const poFromDesc = poFromDescMatch ? String(poFromDescMatch[0] || '').trim() : '';

        const poCandidate = poFromMatch || poFromIdTrack || poFromDesc;
        const poCanon = canonicalizePaymentOrderNo(poCandidate);
        const poOrder = poCanon
          ? (ordersByPoCanon.get(poCanon) || reconcileByPoCanon.get(poCanon))
          : null;

        const orderForLink = match || poOrder;
        const isOnPaymentOrdersTable = Boolean(orderForLink && orderForLink.id && orderIds.has(String(orderForLink.id)));
        const isOnReconciliationTable = Boolean(orderForLink && orderForLink.id && !isOnPaymentOrdersTable);
        const orderIdForLink = orderForLink && orderForLink.id ? escapeHtml(String(orderForLink.id)) : '';
        const orderScopeForLink = isOnPaymentOrdersTable ? 'orders' : 'reconciliation';
        const poDisplayRaw = formatPaymentOrderNoForDisplay(orderForLink && orderForLink.paymentOrderNo ? orderForLink.paymentOrderNo : poCandidate);
        const poDisplay = poDisplayRaw ? escapeHtml(poDisplayRaw) : '';

        const convertedHtml = (isDisbursement && isOnPaymentOrdersTable && poDisplay)
          ? (orderIdForLink
            ? ` (converted to <a href="#" class="poNoDownloadLink" data-action="downloadPdf" data-order-id="${orderIdForLink}" data-order-scope="${escapeHtml(orderScopeForLink)}" title="Download PDF">${poDisplay}</a>)`
            : ` (converted to ${poDisplay})`)
          : (isDisbursement && isOnReconciliationTable ? ' (pending Payment Order Reconciliation).' : '');
        const description = `${descText}${convertedHtml}`;
        const issuanceDateBank = escapeHtml(getWiseUsdDisplayValueForColumn(e, 'issuanceDateBank'));
        const verifiedChecked = getWiseUsdVerified(e) ? 'checked' : '';
        const verifyDisabled = canVerify ? '' : 'disabled';
        const checksum = escapeHtml(getWiseUsdDisplayValueForColumn(e, 'checksum'));
        const bankStatements = escapeHtml(getWiseUsdDisplayValueForColumn(e, 'bankStatements'));

        return `
          <tr data-wise-usd-id="${id}"${rowClass}>
            <td>${budgetNo}</td>
            <td>${datePL}</td>
            <td>${idTrack}</td>
            <td class="wiseUsdCol--receivedFrom">${receivedFromDisbursedTo}</td>
            <td class="num">${receipts}</td>
            <td class="num">${disburse}</td>
            <td>${description}</td>
            <td>${issuanceDateBank}</td>
            <td class="num">
              <input type="checkbox" data-wise-usd-verify="1" data-wise-usd-id="${id}" aria-label="Verified" ${verifiedChecked} ${verifyDisabled} />
            </td>
            <td class="num">${checksum}</td>
            <td>${bankStatements}</td>
            <td class="actions">
              <button type="button" class="btn btn--editIcon" data-wise-usd-action="edit" aria-label="Edit"><svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path d="M15.502 1.94a.5.5 0 0 1 0 .706L14.459 3.69l-2-2L13.502.646a.5.5 0 0 1 .707 0l1.293 1.293zm-1.75 2.456-2-2L4.939 9.21a.5.5 0 0 0-.121.196l-.805 2.414a.25.25 0 0 0 .316.316l2.414-.805a.5.5 0 0 0 .196-.12l6.813-6.814z"/><path fill-rule="evenodd" d="M1 13.5A1.5 1.5 0 0 0 2.5 15h11a1.5 1.5 0 0 0 1.5-1.5v-6a.5.5 0 0 0-1 0v6a.5.5 0 0 1-.5.5h-11a.5.5 0 0 1-.5-.5v-11a.5.5 0 0 1 .5-.5H9a.5.5 0 0 0 0-1H2.5A1.5 1.5 0 0 0 1 2.5z"/></svg></button>
              <button type="button" class="btn btn--x" data-wise-usd-action="delete" aria-label="Delete entry" title="${canDeleteRows ? 'Delete' : 'Requires Delete access for wiseUSD.'}" aria-disabled="${deleteAriaDisabled}"${deleteTooltipAttr}><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path d="M5.5 5.5A.5.5 0 0 1 6 6v5a.5.5 0 0 1-1 0V6a.5.5 0 0 1 .5-.5m2.5 0A.5.5 0 0 1 8.5 6v5a.5.5 0 0 1-1 0V6a.5.5 0 0 1 .5-.5m3 .5a.5.5 0 0 0-1 0v5a.5.5 0 0 0 1 0z"/><path d="M14.5 3a1 1 0 0 1-1 1H13l-.777 9.33A2 2 0 0 1 10.23 15H5.77a2 2 0 0 1-1.993-1.67L3 4h-.5a1 1 0 1 1 0-2H5a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1h2.5a1 1 0 0 1 1 1M6 2v1h4V2zm-2 2 .774 9.287A1 1 0 0 0 5.77 14h4.46a1 1 0 0 0 .996-.713L12 4z"/></svg></button>
            </td>
          </tr>
        `.trim();
      })
      .join('');

    wiseUsdTbody.innerHTML = html;
  }

  function updateWiseUsdTotals(entries) {
    const receiptsEl = document.getElementById('wiseUsdTotalReceipts');
    const disburseEl = document.getElementById('wiseUsdTotalDisburse');
    const netEl = document.getElementById('wiseUsdTotalReceiptsMinusDisburse');

    if (!receiptsEl && !disburseEl && !netEl) return;

    let totalReceipts = 0;
    let totalDisburse = 0;
    for (const e of entries || []) {
      totalReceipts += getWiseUsdReceipts(e);
      totalDisburse += getWiseUsdDisburse(e);
    }

    const net = totalReceipts - totalDisburse;

    if (receiptsEl) receiptsEl.textContent = formatCurrency(totalReceipts, 'USD');
    if (disburseEl) disburseEl.textContent = formatCurrency(totalDisburse, 'USD');
    if (netEl) {
      netEl.textContent = formatCurrency(net, 'USD');
      netEl.classList.toggle('is-negative', net < 0);
    }
  }

  function updateWiseUsdSortIndicators() {
    if (!wiseUsdTbody) return;
    const table = wiseUsdTbody.closest('table');
    if (!table) return;

    const sortKey = wiseUsdViewState.sortKey;
    const sortDir = wiseUsdViewState.sortDir === 'desc' ? 'desc' : 'asc';

    const ths = Array.from(table.querySelectorAll('thead th[data-sort-key]'));
    for (const th of ths) {
      const colKey = th.getAttribute('data-sort-key');
      let aria = 'none';
      if (colKey && sortKey === colKey) {
        aria = sortDir === 'desc' ? 'descending' : 'ascending';
      }
      th.setAttribute('aria-sort', aria);
    }
  }

  function initWiseUsdColumnSorting() {
    if (!wiseUsdTbody) return;
    const table = wiseUsdTbody.closest('table');
    if (!table) return;
    if (table.dataset.sortBound === '1') return;

    const ths = Array.from(table.querySelectorAll('thead th[data-sort-key]'));
    if (ths.length === 0) return;
    table.dataset.sortBound = '1';

    function applySortForKey(colKey) {
      if (!colKey) return;
      if (wiseUsdViewState.sortKey === colKey) {
        wiseUsdViewState.sortDir = wiseUsdViewState.sortDir === 'asc' ? 'desc' : 'asc';
      } else {
        wiseUsdViewState.sortKey = colKey;
        wiseUsdViewState.sortDir = 'asc';
      }
      applyWiseUsdView();
    }

    for (const th of ths) {
      th.classList.add('is-sortable');
      if (!th.hasAttribute('tabindex')) th.setAttribute('tabindex', '0');
      if (!th.hasAttribute('aria-sort')) th.setAttribute('aria-sort', 'none');

      th.addEventListener('click', () => applySortForKey(th.getAttribute('data-sort-key')));
      th.addEventListener('keydown', (e) => {
        if (e.key !== 'Enter' && e.key !== ' ') return;
        e.preventDefault();
        applySortForKey(th.getAttribute('data-sort-key'));
      });
    }

    updateWiseUsdSortIndicators();
  }

  let currentWiseUsdId = null;

  function getWiseUsdBudgetFlowKindFromAmountStrings(receiptsRaw, disburseRaw) {
    const r = String(receiptsRaw || '').trim();
    const d = String(disburseRaw || '').trim();
    const receiptsNum = r === '' ? null : Number(r);
    const disburseNum = d === '' ? null : Number(d);

    const receiptsHas = Number.isFinite(receiptsNum) && receiptsNum > 0;
    const disburseHas = Number.isFinite(disburseNum) && disburseNum > 0;

    if (receiptsHas && !disburseHas) return 'in';
    if (disburseHas && !receiptsHas) return 'out';
    if (!receiptsHas && !disburseHas) return null;
    return 'both';
  }

  function syncWiseUsdBudgetNoSelect(selectEl, receiptsEl, disburseEl, initialBudgetNo) {
    if (!selectEl) return;

    const kind = getWiseUsdBudgetFlowKindFromAmountStrings(receiptsEl && receiptsEl.value, disburseEl && disburseEl.value);
    const activeYear = getActiveBudgetYear();

    // Preserve current selection when possible.
    const prevValue = String(selectEl.value || '').trim();
    const preferred = prevValue || String(initialBudgetNo || '').trim();

    // Reset options.
    selectEl.innerHTML = '';

    const placeholder = document.createElement('option');
    placeholder.value = '';

    if (kind === 'both') {
      placeholder.textContent = 'Enter only one: Receipts or Disburse';
      placeholder.disabled = true;
      placeholder.selected = true;
      selectEl.appendChild(placeholder);
      selectEl.disabled = true;
      return;
    }

    if (!kind) {
      placeholder.textContent = 'Enter Receipts or Disburse first';
      placeholder.disabled = true;
      placeholder.selected = true;
      selectEl.appendChild(placeholder);
      selectEl.disabled = true;
      return;
    }

    placeholder.textContent = 'Select a Budget #';
    selectEl.appendChild(placeholder);
    selectEl.disabled = false;

    const accounts = kind === 'in' ? readInAccountsFromBudgetYear(activeYear) : readOutAccountsFromBudgetYear(activeYear);
    const items = Array.isArray(accounts) ? accounts : [];

    if (items.length === 0) {
      const none = document.createElement('option');
      none.value = '__none__';
      none.disabled = true;
      none.textContent = kind === 'in' ? 'No IN accounts found in the active budget' : 'No OUT accounts found in the active budget';
      selectEl.appendChild(none);
      selectEl.value = '';
      return;
    }

    const codes = [];
    for (const item of items) {
      const code = String(kind === 'in' ? item && item.inCode : item && item.outCode).trim();
      if (!/^\d{4}$/.test(code)) continue;
      const desc = String(item && item.desc ? item.desc : '').trim();
      codes.push({ code, desc });
    }

    codes.sort((a, b) => String(a.code).localeCompare(String(b.code), undefined, { numeric: true, sensitivity: 'base' }));

    const allowed = new Set();
    for (const { code, desc } of codes) {
      allowed.add(code);
      const opt = document.createElement('option');
      opt.value = code;
      opt.textContent = desc ? `${code} - ${desc}` : code;
      selectEl.appendChild(opt);
    }

    if (preferred && allowed.has(preferred)) selectEl.value = preferred;
    else selectEl.value = '';
  }

  function openWiseUsdModal(entry, year) {
    if (!wiseUsdModal || !wiseUsdModalBody) return;
    const y = Number.isInteger(Number(year)) ? Number(year) : getWiseUsdYear();
    currentWiseUsdId = entry && entry.id ? entry.id : null;

    const titleEl = wiseUsdModal.querySelector('#wiseUsdModalTitle');
    const subheadEl = wiseUsdModal.querySelector('#wiseUsdModalSubhead');
    if (titleEl) titleEl.textContent = currentWiseUsdId ? 'wiseUSD (Edit)' : 'wiseUSD (New)';
    if (subheadEl) subheadEl.textContent = `${y} wiseUSD`;

    const budgetNoRaw = entry && entry.budgetNo ? String(entry.budgetNo).trim() : '';
    const safeDatePL = escapeHtml(entry && (entry.datePL || entry.date) ? (entry.datePL || entry.date) : '');
    const safeReceivedFrom = escapeHtml(entry && (entry.receivedFromDisbursedTo || entry.party) ? (entry.receivedFromDisbursedTo || entry.party) : '');
    const safeDescription = escapeHtml(entry && (entry.description || entry.reference) ? (entry.description || entry.reference) : '');
    const safeIssuanceDateBank = escapeHtml(entry && entry.issuanceDateBank ? entry.issuanceDateBank : '');
    const canVerify = canIncomeEdit(getCurrentUser());
    const verifiedChecked = getWiseUsdVerified(entry) ? 'checked' : '';
    const verifiedDisabled = canVerify ? '' : 'disabled';

    const checksum = entry && entry.checksum !== null && entry.checksum !== undefined && entry.checksum !== '' ? Number(entry.checksum) : null;
    const safeChecksum = Number.isFinite(checksum) ? escapeHtml(String(checksum)) : '';

    const safeBankStatements = escapeHtml(entry && entry.bankStatements ? entry.bankStatements : '');
    const safeRemarks = escapeHtml(entry && entry.remarks ? entry.remarks : '');

    const receipts = entry && entry.receipts !== null && entry.receipts !== undefined && entry.receipts !== '' ? Number(entry.receipts) : null;
    const disburse = entry && entry.disburse !== null && entry.disburse !== undefined && entry.disburse !== '' ? Number(entry.disburse) : null;
    const safeReceipts = Number.isFinite(receipts) && receipts > 0 ? escapeHtml(String(receipts)) : '';
    const safeDisburse = Number.isFinite(disburse) && disburse > 0 ? escapeHtml(String(disburse)) : '';

    wiseUsdModalBody.innerHTML = `
      <form id="wiseUsdModalForm" novalidate>
        <div class="grid">
          <div class="field">
            <label for="wiseUsdBudgetNo">Budget #</label>
            <select id="wiseUsdBudgetNo" name="wiseUsdBudgetNo"></select>
            <div class="error" id="error-wiseUsdBudgetNo" role="alert" aria-live="polite"></div>
          </div>

          <div class="field">
            <label for="wiseUsdDatePL">ACTION DATE<span class="req" aria-hidden="true">*</span></label>
            <input id="wiseUsdDatePL" name="wiseUsdDatePL" type="date" required value="${safeDatePL}" />
            <div class="error" id="error-wiseUsdDatePL" role="alert" aria-live="polite"></div>
          </div>

          <div class="field field--span2">
            <label for="wiseUsdReceivedFrom">RECEIVED FROM - DISBURSED TO:<span class="req" aria-hidden="true">*</span></label>
            <input id="wiseUsdReceivedFrom" name="wiseUsdReceivedFrom" type="text" autocomplete="off" required value="${safeReceivedFrom}" />
            <div class="error" id="error-wiseUsdReceivedFrom" role="alert" aria-live="polite"></div>
          </div>

          <div class="field">
            <label for="wiseUsdReceipts">RECEIPTS $<span class="req" aria-hidden="true">*</span></label>
            <input id="wiseUsdReceipts" name="wiseUsdReceipts" type="number" inputmode="decimal" step="0.01" min="0" value="${safeReceipts}" />
            <div class="error" id="error-wiseUsdReceipts" role="alert" aria-live="polite"></div>
          </div>

          <div class="field">
            <label for="wiseUsdDisburse">DISBURSE $<span class="req" aria-hidden="true">*</span></label>
            <input id="wiseUsdDisburse" name="wiseUsdDisburse" type="number" inputmode="decimal" step="0.01" min="0" value="${safeDisburse}" />
            <div class="error" id="error-wiseUsdDisburse" role="alert" aria-live="polite"></div>
          </div>

          <div class="field field--span2">
            <label for="wiseUsdDescription">DESCRIPTION<span class="req" aria-hidden="true">*</span></label>
            <textarea id="wiseUsdDescription" name="wiseUsdDescription" rows="3" required>${safeDescription}</textarea>
            <div class="error" id="error-wiseUsdDescription" role="alert" aria-live="polite"></div>
          </div>

          <div class="field">
            <label for="wiseUsdIssuanceDateBank">Issuance Date Bank</label>
            <input id="wiseUsdIssuanceDateBank" name="wiseUsdIssuanceDateBank" type="date" value="${safeIssuanceDateBank}" />
            <div class="error" id="error-wiseUsdIssuanceDateBank" role="alert" aria-live="polite"></div>
          </div>

          <div class="field">
            <label for="wiseUsdVerified">Verified</label>
            <div>
              <input id="wiseUsdVerified" name="wiseUsdVerified" type="checkbox" ${verifiedChecked} ${verifiedDisabled} />
            </div>
          </div>

          <div class="field">
            <label for="wiseUsdChecksum">Checksum</label>
            <input id="wiseUsdChecksum" name="wiseUsdChecksum" type="number" inputmode="decimal" step="0.01" value="${safeChecksum}" />
            <div class="error" id="error-wiseUsdChecksum" role="alert" aria-live="polite"></div>
          </div>

          <div class="field">
            <label for="wiseUsdBankStatements">Bank Statements</label>
            <input id="wiseUsdBankStatements" name="wiseUsdBankStatements" type="text" autocomplete="off" value="${safeBankStatements}" />
            <div class="error" id="error-wiseUsdBankStatements" role="alert" aria-live="polite"></div>
          </div>

          <div class="field field--span2">
            <label for="wiseUsdRemarks">Remarks</label>
            <textarea id="wiseUsdRemarks" name="wiseUsdRemarks" rows="2">${safeRemarks}</textarea>
            <div class="error" id="error-wiseUsdRemarks" role="alert" aria-live="polite"></div>
          </div>
        </div>
      </form>
    `.trim();

    wiseUsdModal.classList.add('is-open');
    wiseUsdModal.setAttribute('aria-hidden', 'false');

    const budgetNoEl = wiseUsdModalBody.querySelector('#wiseUsdBudgetNo');
    const receiptsEl = wiseUsdModalBody.querySelector('#wiseUsdReceipts');
    const disburseEl = wiseUsdModalBody.querySelector('#wiseUsdDisburse');
    syncWiseUsdBudgetNoSelect(budgetNoEl, receiptsEl, disburseEl, budgetNoRaw);
    if (receiptsEl) receiptsEl.addEventListener('input', () => syncWiseUsdBudgetNoSelect(budgetNoEl, receiptsEl, disburseEl, budgetNoRaw));
    if (disburseEl) disburseEl.addEventListener('input', () => syncWiseUsdBudgetNoSelect(budgetNoEl, receiptsEl, disburseEl, budgetNoRaw));

    const focusTarget = wiseUsdModalBody.querySelector('#wiseUsdDatePL');
    if (focusTarget && focusTarget.focus) focusTarget.focus();
  }

  function closeWiseUsdModal() {
    if (!wiseUsdModal || !wiseUsdModalBody) return;
    wiseUsdModal.classList.remove('is-open');
    wiseUsdModal.setAttribute('aria-hidden', 'true');
    wiseUsdModalBody.innerHTML = '';
    currentWiseUsdId = null;
  }

  function clearWiseUsdModalErrors() {
    if (!wiseUsdModalBody) return;
    const errors = Array.from(wiseUsdModalBody.querySelectorAll('.error'));
    for (const el of errors) el.textContent = '';
  }

  function showWiseUsdModalErrors(errors) {
    if (!wiseUsdModalBody || !errors) return;
    const map = {
      budgetNo: '#error-wiseUsdBudgetNo',
      datePL: '#error-wiseUsdDatePL',
      receivedFromDisbursedTo: '#error-wiseUsdReceivedFrom',
      receipts: '#error-wiseUsdReceipts',
      disburse: '#error-wiseUsdDisburse',
      description: '#error-wiseUsdDescription',
      issuanceDateBank: '#error-wiseUsdIssuanceDateBank',
      checksum: '#error-wiseUsdChecksum',
      bankStatements: '#error-wiseUsdBankStatements',
      remarks: '#error-wiseUsdRemarks',
    };
    for (const [k, sel] of Object.entries(map)) {
      const el = wiseUsdModalBody.querySelector(sel);
      if (el) el.textContent = errors[k] || '';
    }
  }

  function validateWiseUsdModalValues() {
    if (!wiseUsdModalBody) return { ok: false };
    const budgetNoEl = wiseUsdModalBody.querySelector('#wiseUsdBudgetNo');
    const datePLEl = wiseUsdModalBody.querySelector('#wiseUsdDatePL');
    const receivedFromEl = wiseUsdModalBody.querySelector('#wiseUsdReceivedFrom');
    const receiptsEl = wiseUsdModalBody.querySelector('#wiseUsdReceipts');
    const disburseEl = wiseUsdModalBody.querySelector('#wiseUsdDisburse');
    const descriptionEl = wiseUsdModalBody.querySelector('#wiseUsdDescription');
    const issuanceDateBankEl = wiseUsdModalBody.querySelector('#wiseUsdIssuanceDateBank');
    const verifiedEl = wiseUsdModalBody.querySelector('#wiseUsdVerified');
    const checksumEl = wiseUsdModalBody.querySelector('#wiseUsdChecksum');
    const bankStatementsEl = wiseUsdModalBody.querySelector('#wiseUsdBankStatements');
    const remarksEl = wiseUsdModalBody.querySelector('#wiseUsdRemarks');

    const values = {
      budgetNo: budgetNoEl ? String(budgetNoEl.value || '').trim() : '',
      datePL: datePLEl ? String(datePLEl.value || '').trim() : '',
      receivedFromDisbursedTo: receivedFromEl ? String(receivedFromEl.value || '').trim() : '',
      receipts: receiptsEl ? String(receiptsEl.value || '').trim() : '',
      disburse: disburseEl ? String(disburseEl.value || '').trim() : '',
      description: descriptionEl ? String(descriptionEl.value || '').trim() : '',
      issuanceDateBank: issuanceDateBankEl ? String(issuanceDateBankEl.value || '').trim() : '',
      verified: verifiedEl ? Boolean(verifiedEl.checked) : false,
      checksum: checksumEl ? String(checksumEl.value || '').trim() : '',
      bankStatements: bankStatementsEl ? String(bankStatementsEl.value || '').trim() : '',
      remarks: remarksEl ? String(remarksEl.value || '').trim() : '',
    };

    const errors = {};
    if (!values.datePL) errors.datePL = 'This field is required.';
    if (!values.receivedFromDisbursedTo) errors.receivedFromDisbursedTo = 'This field is required.';
    if (!values.description) errors.description = 'This field is required.';

    const receiptsNum = values.receipts === '' ? null : Number(values.receipts);
    const disburseNum = values.disburse === '' ? null : Number(values.disburse);
    const checksumNum = values.checksum === '' ? null : Number(values.checksum);

    if (receiptsNum !== null && (!Number.isFinite(receiptsNum) || receiptsNum < 0)) errors.receipts = 'Enter a valid amount.';
    if (disburseNum !== null && (!Number.isFinite(disburseNum) || disburseNum < 0)) errors.disburse = 'Enter a valid amount.';
    if (checksumNum !== null && !Number.isFinite(checksumNum)) errors.checksum = 'Enter a valid amount.';

    const receiptsHas = Number.isFinite(receiptsNum) && receiptsNum > 0;
    const disburseHas = Number.isFinite(disburseNum) && disburseNum > 0;
    if (!receiptsHas && !disburseHas) {
      errors.receipts = 'Enter a Receipts or Disburse amount.';
      errors.disburse = 'Enter a Receipts or Disburse amount.';
    }
    if (receiptsHas && disburseHas) {
      errors.receipts = 'Enter only one: Receipts or Disburse.';
      errors.disburse = 'Enter only one: Receipts or Disburse.';
    }

    const kind = receiptsHas && !disburseHas ? 'in' : disburseHas && !receiptsHas ? 'out' : null;
    if (kind && values.budgetNo) {
      const activeYear = getActiveBudgetYear();
      const allowed = new Set();
      const items = kind === 'in' ? readInAccountsFromBudgetYear(activeYear) : readOutAccountsFromBudgetYear(activeYear);
      for (const item of items || []) {
        const code = String(kind === 'in' ? item && item.inCode : item && item.outCode).trim();
        if (/^\d{4}$/.test(code)) allowed.add(code);
      }

      if (!/^\d{4}$/.test(values.budgetNo)) {
        errors.budgetNo = 'Select a valid budget number.';
      } else if (allowed.size > 0 && !allowed.has(values.budgetNo)) {
        errors.budgetNo = kind === 'in' ? 'Select an IN budget number from the active budget.' : 'Select an OUT budget number from the active budget.';
      }
    }

    if (Object.keys(errors).length > 0) return { ok: false, errors };
    return {
      ok: true,
      values: {
        budgetNo: values.budgetNo,
        datePL: values.datePL,
        receivedFromDisbursedTo: values.receivedFromDisbursedTo,
        receipts: receiptsHas ? receiptsNum : null,
        disburse: disburseHas ? disburseNum : null,
        description: values.description,
        issuanceDateBank: values.issuanceDateBank,
        verified: values.verified ? 1 : 0,
        checksum: checksumNum,
        bankStatements: values.bankStatements,
        remarks: values.remarks,
      },
    };
  }

  function applyWiseUsdView() {
    if (!wiseUsdTbody || !wiseUsdEmptyState) return;
    ensureWiseUsdDefaultEmptyText();

    const year = getWiseUsdYear();
    const all = loadWiseUsd(year);
    const filtered = filterWiseUsdForView(all, wiseUsdViewState.globalFilter);
    const sorted = sortWiseUsdForView(filtered, wiseUsdViewState.sortKey, wiseUsdViewState.sortDir);

    if (normalizeTextForSearch(wiseUsdViewState.globalFilter) !== '' && all.length > 0 && sorted.length === 0) {
      wiseUsdEmptyState.textContent = 'No wiseUSD entries match your search.';
    } else {
      wiseUsdEmptyState.textContent = wiseUsdViewState.defaultEmptyText;
    }

    wiseUsdEmptyState.hidden = sorted.length > 0;
    renderWiseUsdRows(sorted);
    updateWiseUsdTotals(sorted);
    updateWiseUsdSortIndicators();
  }

  function initWiseUsdListPage() {
    if (!wiseUsdTbody || !wiseUsdEmptyState) return;
    const year = getWiseUsdYear();

    const currentUser = getCurrentUser();
    const incomeLevel = currentUser ? getEffectivePermissions(currentUser).income : 'none';
    const hasIncomeFullAccess = currentUser ? canWrite(currentUser, 'income_bankeur') : false;

    // Verified checkbox should be editable for Income Write/Partial.
    wiseUsdViewState.canVerify = currentUser ? canIncomeEdit(currentUser) : false;
    wiseUsdViewState.canDelete = currentUser ? canDelete(currentUser, 'income_wise_usd') : false;

    const wiseUsdNewLink = document.getElementById('wiseUsdNewLink');
    const wiseUsdExportCsvLink = document.getElementById('wiseUsdExportCsvLink');
    const wiseUsdDownloadTemplateLink = document.getElementById('wiseUsdDownloadTemplateLink');
    const wiseUsdImportCsvLink = document.getElementById('wiseUsdImportCsvLink');
    const wiseUsdMenuBtn = document.getElementById('wiseUsdActionsMenuBtn');
    const wiseUsdMenuPanel = document.getElementById('wiseUsdActionsMenu');
    const wiseUsdBackToIncomeLink = document.getElementById('wiseUsdBackToIncomeLink');

    function setLinkDisabled(linkEl, disabled) {
      if (!linkEl) return;
      linkEl.setAttribute('aria-disabled', disabled ? 'true' : 'false');
      if (disabled) linkEl.setAttribute('tabindex', '-1');
      else linkEl.removeAttribute('tabindex');
    }

    // Ensure the year is present in the URL for consistent nav highlighting.
    const fromUrl = getWiseUsdYearFromUrl();
    if (!fromUrl && getBasename(window.location.pathname) === 'wise_usd.html') {
      try {
        const url = new URL(window.location.href);
        url.searchParams.set('year', String(year));
        window.history.replaceState(null, '', url.toString());
      } catch {
        // ignore
      }
    }

    ensureWiseUsdListExistsForYear(year);
    backfillWiseUsdIdTrackFromOrders(year);
    backfillWiseUsdBudgetNoFromOrders(year);

    const titleEl = document.querySelector('[data-wise-usd-title]');
    if (titleEl) titleEl.textContent = `${year} wiseUSD`;
    const listTitleEl = document.querySelector('[data-wise-usd-list-title]');
    if (listTitleEl) listTitleEl.textContent = `${year} wiseUSD`;
    if (wiseUsdBackToIncomeLink) {
      wiseUsdBackToIncomeLink.href = `grand_secretary_ledger.html?year=${encodeURIComponent(String(year))}`;
      wiseUsdBackToIncomeLink.textContent = `← Back to ${year} Ledger`;
    }
    applyAppTabTitle();

    initWiseUsdColumnSorting();

    // Partial access for Income = full access except New Income and Import CSV.
    setLinkDisabled(wiseUsdNewLink, !hasIncomeFullAccess);
    if (wiseUsdNewLink && !hasIncomeFullAccess) {
      wiseUsdNewLink.setAttribute(
        'data-tooltip',
        'Requires Full access for Income. Partial access can edit existing wiseUSD entries, but cannot create New Income entries.'
      );
    }
    setLinkDisabled(wiseUsdImportCsvLink, !hasIncomeFullAccess);
    if (wiseUsdImportCsvLink && !hasIncomeFullAccess) {
      wiseUsdImportCsvLink.setAttribute(
        'data-tooltip',
        'Requires Full access for Income. Partial access can edit existing wiseUSD entries, but cannot Import CSV.'
      );
    }

    const globalInput = document.getElementById('wiseUsdGlobalSearch');
    if (globalInput) {
      globalInput.value = wiseUsdViewState.globalFilter || '';
      globalInput.addEventListener('input', () => {
        wiseUsdViewState.globalFilter = globalInput.value;
        if (wiseUsdClearSearchBtn) {
          const hasSearch = normalizeTextForSearch(wiseUsdViewState.globalFilter) !== '';
          wiseUsdClearSearchBtn.hidden = !hasSearch;
          wiseUsdClearSearchBtn.disabled = !hasSearch;
        }
        applyWiseUsdView();
      });
    }

    if (wiseUsdClearSearchBtn && globalInput) {
      const hasSearch = normalizeTextForSearch(wiseUsdViewState.globalFilter) !== '';
      wiseUsdClearSearchBtn.hidden = !hasSearch;
      wiseUsdClearSearchBtn.disabled = !hasSearch;
      if (!wiseUsdClearSearchBtn.dataset.bound) {
        wiseUsdClearSearchBtn.dataset.bound = 'true';
        wiseUsdClearSearchBtn.addEventListener('click', () => {
          globalInput.value = '';
          wiseUsdViewState.globalFilter = '';
          wiseUsdClearSearchBtn.hidden = true;
          wiseUsdClearSearchBtn.disabled = true;
          applyWiseUsdView();
          if (globalInput.focus) globalInput.focus();
        });
      }
    }

    if (wiseUsdNewLink) {
      wiseUsdNewLink.addEventListener('click', (e) => {
        e.preventDefault();
        if (wiseUsdNewLink.getAttribute('aria-disabled') === 'true') {
          alertDisabledAction(wiseUsdNewLink);
          return;
        }
        if (!requireWriteAccess('income_bankeur', 'Income is read only for your account.')) return;
        openWiseUsdModal(null, year);
        if (wiseUsdMenuPanel && wiseUsdMenuBtn) {
          wiseUsdMenuPanel.setAttribute('hidden', '');
          wiseUsdMenuBtn.setAttribute('aria-expanded', 'false');
        }
      });
    }

    function escapeCsvValue(value) {
      const s = String(value ?? '');
      const normalized = s.replace(/\u00A0/g, ' ').replace(/\r\n|\r|\n/g, ' ').trim();
      const mustQuote = /[",\n\r]/.test(normalized);
      const escaped = normalized.replace(/"/g, '""');
      return mustQuote ? `"${escaped}"` : escaped;
    }

    function downloadCsvFile(csvText, fileName) {
      const blob = new Blob([csvText], { type: 'text/csv;charset=utf-8;' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = fileName;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    }

    function getTodayStamp() {
      const d = new Date();
      const yyyy = d.getFullYear();
      const mm = String(d.getMonth() + 1).padStart(2, '0');
      const dd = String(d.getDate()).padStart(2, '0');
      return `${yyyy}-${mm}-${dd}`;
    }

    function exportWiseUsdToCsv() {
      const header = [
        'Budget #',
        'ACTION DATE',
        '# ID-TRACK',
        'RECEIVED FROM - DISBURSED TO:',
        'RECEIPTS $',
        'DISBURSE $',
        'DESCRIPTION',
        'Issuance Date Bank',
        'Verified',
        'Checksum',
        'Bank Statements',
        'Remarks',
      ];
      const entries = loadWiseUsd(year);
      const sorted = sortWiseUsdForView(entries, 'datePL', 'asc');
      const lines = [];
      lines.push(header.map(escapeCsvValue).join(','));
      for (const e of sorted) {
        const receipts = getWiseUsdReceipts(e);
        const disburse = getWiseUsdDisburse(e);
        const checksumVal = e && e.checksum !== null && e.checksum !== undefined && String(e.checksum).trim() !== '' ? e.checksum : '';
        const values = [
          String(e && e.budgetNo ? e.budgetNo : ''),
          String(e && (e.datePL || e.date) ? (e.datePL || e.date) : ''),
          String(e && e.idTrack ? e.idTrack : ''),
          String(e && (e.receivedFromDisbursedTo || e.party) ? (e.receivedFromDisbursedTo || e.party) : ''),
          receipts ? String(receipts) : '',
          disburse ? String(disburse) : '',
          String(e && (e.description || e.reference) ? (e.description || e.reference) : ''),
          String(e && e.issuanceDateBank ? e.issuanceDateBank : ''),
          getWiseUsdVerified(e) ? '1' : '',
          String(checksumVal),
          String(e && e.bankStatements ? e.bankStatements : ''),
          String(e && e.remarks ? e.remarks : ''),
        ];
        lines.push(values.map(escapeCsvValue).join(','));
      }
      const csv = `\uFEFF${lines.join('\r\n')}\r\n`;
      downloadCsvFile(csv, `wise_usd_${year}_${getTodayStamp()}.csv`);
    }

    function downloadWiseUsdCsvTemplate() {
      const header = [
        'Budget #',
        'ACTION DATE',
        '# ID-TRACK',
        'RECEIVED FROM - DISBURSED TO:',
        'RECEIPTS $',
        'DISBURSE $',
        'DESCRIPTION',
        'Issuance Date Bank',
        'Verified',
        'Checksum',
        'Bank Statements',
        'Remarks',
      ];
      const example = ['', getTodayStamp(), '', 'Example Party', '100.00', '', 'Example description', '', '1', '', '', ''];
      const lines = [];
      lines.push(header.map(escapeCsvValue).join(','));
      lines.push(example.map(escapeCsvValue).join(','));
      const csv = `\uFEFF${lines.join('\r\n')}\r\n`;
      downloadCsvFile(csv, `wise_usd_template_${year}_${getTodayStamp()}.csv`);
    }

    function parseCsvText(text) {
      const rows = [];
      const s = String(text ?? '');
      let row = [];
      let field = '';
      let inQuotes = false;

      for (let i = 0; i < s.length; i += 1) {
        const ch = s[i];
        if (inQuotes) {
          if (ch === '"') {
            const next = s[i + 1];
            if (next === '"') {
              field += '"';
              i += 1;
            } else {
              inQuotes = false;
            }
          } else {
            field += ch;
          }
          continue;
        }

        if (ch === '"') {
          inQuotes = true;
          continue;
        }

        if (ch === ',') {
          row.push(field);
          field = '';
          continue;
        }

        if (ch === '\n') {
          row.push(field);
          field = '';
          rows.push(row);
          row = [];
          continue;
        }

        if (ch === '\r') continue;
        field += ch;
      }

      row.push(field);
      rows.push(row);

      while (rows.length > 0) {
        const last = rows[rows.length - 1];
        const isEmpty = last.every((c) => String(c ?? '').trim() === '');
        if (!isEmpty) break;
        rows.pop();
      }

      return rows;
    }

    function normalizeHeaderName(name) {
      return String(name ?? '')
        .replace(/\uFEFF/g, '')
        .replace(/\u00A0/g, ' ')
        .trim()
        .toLowerCase();
    }

    function normalizeCsvDate(raw) {
      const s = String(raw ?? '').trim();
      if (!s) return '';
      if (/^\d{4}-\d{2}-\d{2}$/.test(s)) return s;

      const mdy = s.match(/^\s*(\d{1,2})[\/\-](\d{1,2})[\/\-](\d{4})\s*$/);
      if (mdy) {
        const mm = Number(mdy[1]);
        const dd = Number(mdy[2]);
        const yyyy = Number(mdy[3]);
        if (!Number.isInteger(mm) || !Number.isInteger(dd) || !Number.isInteger(yyyy)) return '';
        if (yyyy < 1000 || yyyy > 9999) return '';
        if (mm < 1 || mm > 12) return '';
        if (dd < 1 || dd > 31) return '';
        const d = new Date(yyyy, mm - 1, dd);
        if (d.getFullYear() !== yyyy || d.getMonth() !== mm - 1 || d.getDate() !== dd) return '';
        return `${yyyy}-${String(mm).padStart(2, '0')}-${String(dd).padStart(2, '0')}`;
      }

      const ms = Date.parse(s);
      if (!Number.isFinite(ms)) return '';
      const d = new Date(ms);
      return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
    }

    function parseNonNegativeAmount(raw) {
      const s = String(raw ?? '').replace(/\u00A0/g, ' ').trim();
      if (!s) return null;
      const cleaned = s.replace(/[^0-9.,\-]/g, '').replace(/,/g, '');
      const n = Number(cleaned);
      if (!Number.isFinite(n) || n < 0) return null;
      return n;
    }

    function parseSignedAmount(raw) {
      const s = String(raw ?? '').replace(/\u00A0/g, ' ').trim();
      if (!s) return null;
      const cleaned = s.replace(/[^0-9.,\-]/g, '').replace(/,/g, '');
      const n = Number(cleaned);
      if (!Number.isFinite(n)) return null;
      return n;
    }

    function findHeaderIndex(headerNames, candidates) {
      const names = Array.isArray(headerNames) ? headerNames : [];
      const cands = (Array.isArray(candidates) ? candidates : []).map(normalizeHeaderName).filter(Boolean);
      if (cands.length === 0) return -1;
      for (const c of cands) {
        const exact = names.indexOf(c);
        if (exact !== -1) return exact;
      }
      for (let i = 0; i < names.length; i += 1) {
        const h = String(names[i] ?? '').trim();
        if (!h) continue;
        if (cands.some((c) => h === c || h.startsWith(`${c} `) || h.startsWith(`${c}(`) || h.startsWith(`${c}—`) || h.startsWith(`${c}-`) || h.startsWith(c))) {
          return i;
        }
      }
      return -1;
    }

    function parseWiseUsdCsvTextToEntries(csvText, options) {
      const opts = options && typeof options === 'object' ? options : {};
      const relaxRequired = !!opts.relaxRequired;

      function parseCsvBooleanish(value) {
        const s = String(value ?? '').trim().toLowerCase();
        if (!s) return false;
        if (s === '1' || s === 'true' || s === 'yes' || s === 'y' || s === 'on' || s === 'checked' || s === 'x') return true;
        if (s === '0' || s === 'false' || s === 'no' || s === 'n' || s === 'off') return false;
        // Legacy Checked-by text (e.g., initials) should count as verified.
        return true;
      }

      const rows = parseCsvText(csvText);
      if (rows.length === 0) {
        return { isEmpty: true, imported: [], errors: [] };
      }

      const header = rows[0].map(normalizeHeaderName);
      const dataRows = rows.slice(1).filter((r) => r.some((c) => String(c ?? '').trim() !== ''));

      const idx = {
        budgetNo: findHeaderIndex(header, ['budget #', 'budget', 'budget no', 'budget number']),
        datePL: findHeaderIndex(header, ['action date', 'date p-l', 'date pl', 'date']),
        idTrack: findHeaderIndex(header, ['# id-track', 'id-track', 'id track', 'track', 'tracking']),
        receivedFromDisbursedTo: findHeaderIndex(header, [
          'received from - disbursed to:',
          'received from - disbursed to',
          'received from',
          'disbursed to',
          'party',
          'payee',
          'remitter',
          'name',
          'merchant',
        ]),
        receipts: findHeaderIndex(header, ['receipts $', 'receipts', 'receipt', 'credit', 'received', 'in']),
        disburse: findHeaderIndex(header, ['disburse $', 'disburse', 'disbursement', 'debit', 'paid', 'payment', 'out', 'sent']),
        description: findHeaderIndex(header, ['description', 'reference', 'details', 'memo', 'note']),
        issuanceDateBank: findHeaderIndex(header, ['issuance date bank', 'issuance date', 'bank issuance date']),
        verified: findHeaderIndex(header, ['verified', 'checked by gtreas', 'checked by', 'gtreas']),
        checksum: findHeaderIndex(header, ['checksum', 'balance']),
        bankStatements: findHeaderIndex(header, ['bank statements', 'bank statement']),
        remarks: findHeaderIndex(header, ['remarks', 'remark']),
        amount: findHeaderIndex(header, ['amount', 'usd', '$', 'value']),
        currency: findHeaderIndex(header, ['currency', 'ccy']),
      };

      const hasHeaders =
        idx.datePL !== -1 &&
        (idx.receivedFromDisbursedTo !== -1 || idx.description !== -1) &&
        (idx.receipts !== -1 || idx.disburse !== -1 || idx.amount !== -1);

      if (!hasHeaders && header.length >= 3) {
        // Allow headerless CSV: DATE P-L, RECEIVED FROM - DISBURSED TO, DESCRIPTION, RECEIPTS, DISBURSE
        dataRows.unshift(rows[0]);
        idx.datePL = 0;
        idx.receivedFromDisbursedTo = 1;
        idx.description = 2;
        idx.receipts = 3;
        idx.disburse = 4;
        idx.amount = 5;
      }

      const nowIso = new Date().toISOString();
      const imported = [];
      const errors = [];

      for (let rowIndex = 0; rowIndex < dataRows.length; rowIndex += 1) {
        const r = dataRows[rowIndex];
        const get = (i) => (i >= 0 ? (r[i] ?? '') : '');

        const rowNo = rowIndex + 2;
        const budgetNo = String(get(idx.budgetNo)).trim();
        const datePL = normalizeCsvDate(get(idx.datePL));
        const idTrack = String(get(idx.idTrack)).trim();
        const receivedFromDisbursedTo = String(get(idx.receivedFromDisbursedTo)).trim();
        const description = String(get(idx.description)).trim();
        const issuanceDateBank = normalizeCsvDate(get(idx.issuanceDateBank));
        const verifiedRaw = String(get(idx.verified)).trim();
        const verified = parseCsvBooleanish(verifiedRaw);
        const bankStatements = String(get(idx.bankStatements)).trim();
        const remarks = String(get(idx.remarks)).trim();

        const hasAnyText =
          !!budgetNo ||
          !!datePL ||
          !!idTrack ||
          !!receivedFromDisbursedTo ||
          !!description ||
          !!issuanceDateBank ||
          !!verifiedRaw ||
          !!bankStatements ||
          !!remarks;

        const checksumRaw = String(get(idx.checksum)).trim();
        const checksumNum = parseSignedAmount(checksumRaw);
        const checksum = checksumNum === null ? checksumRaw : checksumNum;

        const currency = idx.currency !== -1 ? String(get(idx.currency)).trim().toUpperCase() : '';
        if (currency && currency !== 'USD' && currency !== '$') {
          errors.push(`Row ${rowNo}: currency is not USD.`);
          continue;
        }

        const receiptsRaw = String(get(idx.receipts)).trim();
        const disburseRaw = String(get(idx.disburse)).trim();
        let receipts = parseNonNegativeAmount(receiptsRaw);
        let disburse = parseNonNegativeAmount(disburseRaw);

        if (receipts === null && disburse === null) {
          const amount = parseSignedAmount(get(idx.amount));
          if (amount === null) {
            if (!relaxRequired && (receiptsRaw || disburseRaw || String(get(idx.amount)).trim())) {
              errors.push(`Row ${rowNo}: missing amount.`);
            }
          } else if (amount > 0) {
            receipts = amount;
            disburse = null;
          } else if (amount < 0) {
            receipts = null;
            disburse = Math.abs(amount);
          } else {
            receipts = null;
            disburse = null;
            if (!relaxRequired) errors.push(`Row ${rowNo}: amount is 0.`);
          }
        }

        const receiptsHas = Number.isFinite(receipts) && receipts > 0;
        const disburseHas = Number.isFinite(disburse) && disburse > 0;

        // If the row is completely blank (no meaningful text, no amounts, no checksum), skip silently.
        const hasAnyAmount = receiptsHas || disburseHas || (checksumRaw && String(checksumRaw).trim() !== '');
        if (!hasAnyText && !hasAnyAmount) continue;

        if (!relaxRequired) {
          if (!datePL) errors.push(`Row ${rowNo}: invalid Action Date.`);
          if (!receivedFromDisbursedTo) errors.push(`Row ${rowNo}: Received From - Disbursed To is required.`);
          if (!receiptsHas && !disburseHas) errors.push(`Row ${rowNo}: enter a Receipts or Disburse amount.`);
          if (receiptsHas && disburseHas) errors.push(`Row ${rowNo}: enter only one: Receipts or Disburse.`);

          // Description is optional for import.
          if (!datePL || !receivedFromDisbursedTo || (!receiptsHas && !disburseHas) || (receiptsHas && disburseHas)) continue;
        } else {
          if (receiptsHas && disburseHas) {
            errors.push(`Row ${rowNo}: enter only one: Receipts or Disburse.`);
            continue;
          }
        }

        imported.push({
          id: (crypto?.randomUUID ? crypto.randomUUID() : `wu_${Date.now()}_${Math.random().toString(16).slice(2)}`),
          createdAt: nowIso,
          updatedAt: nowIso,
          budgetNo,
          datePL,
          idTrack,
          receivedFromDisbursedTo,
          receipts: receiptsHas ? receipts : null,
          disburse: disburseHas ? disburse : null,
          description,
          issuanceDateBank,
          verified: verified ? 1 : 0,
          checksum,
          bankStatements,
          remarks,
        });
      }

      return { isEmpty: false, imported, errors };
    }

    function importWiseUsdFromCsvText(csvText, fileName) {
      const ok = window.confirm(
        `Importing a CSV will add entries to the wiseUSD list for ${year}. Continue?\n\nFile: ${fileName || 'CSV'}`
      );
      if (!ok) return;

      const existingBefore = loadWiseUsd(year);
      const relaxRequired = !Array.isArray(existingBefore) || existingBefore.length === 0;
      const parsed = parseWiseUsdCsvTextToEntries(csvText, { relaxRequired });
      if (parsed.isEmpty) {
        window.alert('CSV is empty.');
        return;
      }

      const imported = parsed.imported;
      const errors = parsed.errors;

      if (imported.length === 0) {
        window.alert(errors.length ? `No rows were imported:\n\n${errors.slice(0, 15).join('\n')}` : 'No rows were imported.');
        return;
      }

      if (errors.length > 0) {
        const proceed = window.confirm(
          `Some rows could not be processed. Continue with ${imported.length} imported row(s)?\n\n${errors
            .slice(0, 15)
            .join('\n')}${errors.length > 15 ? '\n…' : ''}`
        );
        if (!proceed) return;
      }

      const positiveImported = imported.filter((e) => computeWiseUsdNet(e) > 0);
      const negativeImported = imported.filter((e) => computeWiseUsdNet(e) < 0);

      if (negativeImported.length > 0) {
        ensurePaymentOrdersReconciliationListExistsForYear(year);
        for (const e of negativeImported) {
          const po = buildReconciliationOrderFromWiseUsdEntry(e, year);
          if (po) upsertReconciliationOrderBySource(po, year);
        }
      }

      const existing = existingBefore;
      const merged = [...positiveImported, ...(Array.isArray(existing) ? existing : [])];
      saveWiseUsd(merged, year);
      applyWiseUsdView();

      if (typeof showFlashToken === 'function') {
        showFlashToken(`Imported ${positiveImported.length} wiseUSD row(s). Moved ${negativeImported.length} row(s) to Reconciliation.`);
      }
    }

    async function tryAutoSeedWiseUsdFromCsvFile() {
      if (Number(year) !== 2026) return false;

      const seedFlagKey = `payment_order_wise_usd_seeded_${year}_v1`;
      if (localStorage.getItem(seedFlagKey) === '1') return false;

      const existing = loadWiseUsd(year);
      if (Array.isArray(existing) && existing.length > 0) return false;

      let resp;
      try {
        resp = await fetch('wise_usd_2026_seed.csv', { cache: 'no-store' });
      } catch (e) {
        return false;
      }

      if (!resp || !resp.ok) return false;

      const text = await resp.text();
      const parsed = parseWiseUsdCsvTextToEntries(text, { relaxRequired: true });
      if (parsed.isEmpty || !Array.isArray(parsed.imported) || parsed.imported.length === 0) return false;

      saveWiseUsd(parsed.imported, year);
      localStorage.setItem(seedFlagKey, '1');

      if (typeof showFlashToken === 'function') {
        showFlashToken(`Seeded ${parsed.imported.length} wiseUSD row(s) for ${year}.`);
      }

      return true;
    }

    if (wiseUsdExportCsvLink) {
      wiseUsdExportCsvLink.addEventListener('click', (e) => {
        e.preventDefault();
        exportWiseUsdToCsv();
      });
    }
    if (wiseUsdDownloadTemplateLink) {
      wiseUsdDownloadTemplateLink.addEventListener('click', (e) => {
        e.preventDefault();
        downloadWiseUsdCsvTemplate();
      });
    }
    if (wiseUsdImportCsvLink) {
      const input = document.createElement('input');
      input.type = 'file';
      input.accept = '.csv,text/csv';
      input.style.display = 'none';
      document.body.appendChild(input);

      wiseUsdImportCsvLink.addEventListener('click', (e) => {
        e.preventDefault();
        if (wiseUsdImportCsvLink.getAttribute('aria-disabled') === 'true') {
          alertDisabledAction(wiseUsdImportCsvLink);
          return;
        }
        if (!requireWriteAccess('income_bankeur', 'Income is read only for your account.')) return;
        input.value = '';
        input.click();
      });

      input.addEventListener('change', () => {
        const file = input.files && input.files[0];
        if (!file) return;
        const reader = new FileReader();
        reader.onload = () => {
          importWiseUsdFromCsvText(reader.result, file.name);
        };
        reader.onerror = () => {
          window.alert('Could not read CSV file.');
        };
        reader.readAsText(file);
      });
    }

    if (wiseUsdMenuBtn) {
      const MENU_CLOSE_DELAY_MS = 250;
      let menuCloseTimer = 0;

      function isMenuOpen() {
        return Boolean(wiseUsdMenuPanel && !wiseUsdMenuPanel.hasAttribute('hidden'));
      }

      function closeMenu() {
        if (!wiseUsdMenuPanel || !wiseUsdMenuBtn) return;
        wiseUsdMenuPanel.setAttribute('hidden', '');
        wiseUsdMenuBtn.setAttribute('aria-expanded', 'false');
      }

      function openMenu() {
        if (!wiseUsdMenuPanel || !wiseUsdMenuBtn) return;
        wiseUsdMenuPanel.removeAttribute('hidden');
        wiseUsdMenuBtn.setAttribute('aria-expanded', 'true');
      }

      function toggleMenu() {
        if (isMenuOpen()) closeMenu();
        else openMenu();
      }

      function cancelScheduledClose() {
        if (!menuCloseTimer) return;
        clearTimeout(menuCloseTimer);
        menuCloseTimer = 0;
      }

      function scheduleClose() {
        cancelScheduledClose();
        if (!isMenuOpen()) return;
        menuCloseTimer = window.setTimeout(() => {
          closeMenu();
          menuCloseTimer = 0;
        }, MENU_CLOSE_DELAY_MS);
      }

      wiseUsdMenuBtn.addEventListener('click', () => {
        toggleMenu();
      });

      wiseUsdMenuBtn.addEventListener('mouseenter', cancelScheduledClose);
      wiseUsdMenuBtn.addEventListener('mouseleave', scheduleClose);

      if (wiseUsdMenuPanel) {
        wiseUsdMenuPanel.addEventListener('mouseenter', cancelScheduledClose);
        wiseUsdMenuPanel.addEventListener('mouseleave', scheduleClose);
      }

      document.addEventListener('click', (e) => {
        if (!isMenuOpen()) return;
        const menuRoot = e.target?.closest ? e.target.closest('[data-wise-usd-menu]') : null;
        if (menuRoot) return;
        cancelScheduledClose();
        closeMenu();
      });

      document.addEventListener('keydown', (e) => {
        if (!isMenuOpen()) return;
        if (e.key === 'Escape') {
          cancelScheduledClose();
          closeMenu();
        }
      });
    }

    wiseUsdTbody.addEventListener('click', (e) => {
      const dl = e.target && e.target.closest ? e.target.closest('a[data-action="downloadPdf"][data-order-id]') : null;
      if (dl) {
        e.preventDefault();
        const orderId = String(dl.getAttribute('data-order-id') || '').trim();
        const scope = String(dl.getAttribute('data-order-scope') || '').trim().toLowerCase();
        if (!orderId) return;

        const order = scope === 'reconciliation'
          ? loadReconciliationOrders(year).find((o) => o && String(o.id) === orderId)
          : loadOrders(year).find((o) => o && String(o.id) === orderId);
        if (!order) return;
        if (hasOrderMissingRequiredValues(order)) {
          window.alert('Complete all required fields before downloading a PDF.');
          return;
        }
        generatePaymentOrderPdfFromTemplate({ order });
        return;
      }

      const btn = e.target.closest('button[data-wise-usd-action]');
      if (!btn) return;
      const row = btn.closest('tr[data-wise-usd-id]');
      if (!row) return;
      const id = row.getAttribute('data-wise-usd-id');
      const action = btn.getAttribute('data-wise-usd-action');

      if (action === 'delete') {
        if (btn.getAttribute('aria-disabled') === 'true') {
          alertDisabledAction(btn, 'Requires Delete access for wiseUSD.');
          return;
        }
        if (!requireDeleteAccess('income_wise_usd', 'Delete access is required for wiseUSD.')) return;
        const ok = window.confirm('Delete this wiseUSD entry?');
        if (!ok) return;
        deleteWiseUsdEntryById(id, year);
        applyWiseUsdView();
        return;
      }

      if (action === 'edit') {
        if (!requireIncomeEditAccess('Income is read only for your account.')) return;
        const all = loadWiseUsd(year);
        const entry = all.find((x) => x && x.id === id);
        if (!entry) return;
        openWiseUsdModal(entry, year);
      }
    });

    // Persist Verified checkbox state per wiseUSD entry.
    if (!wiseUsdTbody.dataset.verifiedBound) {
      wiseUsdTbody.dataset.verifiedBound = '1';
      wiseUsdTbody.addEventListener('change', (e) => {
        const input =
          e.target && e.target.matches
            ? e.target.matches('input[type="checkbox"][data-wise-usd-verify]')
              ? e.target
              : null
            : null;
        if (!input) return;

        if (!wiseUsdViewState.canVerify) {
          input.checked = !input.checked;
          return;
        }

        if (!requireIncomeEditAccess('Income is read only for your account.')) {
          input.checked = !input.checked;
          return;
        }

        const id = String(input.getAttribute('data-wise-usd-id') || '').trim();
        if (!id) return;
        const all = loadWiseUsd(year);
        const entry = all.find((x) => x && x.id === id);
        if (!entry) return;

        entry.verified = input.checked ? 1 : 0;
        if ('checkedByGTREAS' in entry) delete entry.checkedByGTREAS;
        entry.updatedAt = new Date().toISOString();
        upsertWiseUsdEntry(entry, year);

        // Keep sort/search values consistent.
        applyWiseUsdView();
      });
    }

    if (wiseUsdModal && !wiseUsdModal.dataset.bound) {
      wiseUsdModal.dataset.bound = '1';
      wiseUsdModal.addEventListener('click', (e) => {
        const closeTarget = e.target.closest('[data-wise-usd-modal-close]');
        if (closeTarget) closeWiseUsdModal();
      });
    }

    if (!document.body.dataset.wiseUsdEscBound) {
      document.body.dataset.wiseUsdEscBound = '1';
      document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && wiseUsdModal && wiseUsdModal.classList.contains('is-open')) {
          closeWiseUsdModal();
        }
      });
    }

    if (wiseUsdSaveBtn && !wiseUsdSaveBtn.dataset.bound) {
      wiseUsdSaveBtn.dataset.bound = '1';
      wiseUsdSaveBtn.addEventListener('click', () => {
        try {
          if (!requireIncomeEditAccess('Income is read only for your account.')) return;
          if (!hasIncomeFullAccess && !currentWiseUsdId) {
            window.alert('Requires Full access for Income to create a new wiseUSD entry.');
            return;
          }
          clearWiseUsdModalErrors();
          const res = validateWiseUsdModalValues();
          if (!res.ok) {
            showWiseUsdModalErrors(res.errors);
            return;
          }

          const nowIso = new Date().toISOString();
          const id =
            currentWiseUsdId ||
            (crypto?.randomUUID ? crypto.randomUUID() : `wu_${Date.now()}_${Math.random().toString(16).slice(2)}`);
          const existing = currentWiseUsdId ? loadWiseUsd(year).find((x) => x && x.id === currentWiseUsdId) : null;

          const entry = {
            id,
            createdAt: existing && existing.createdAt ? existing.createdAt : nowIso,
            updatedAt: nowIso,
            ...res.values,
          };

          const net = computeWiseUsdNet(entry);
          if (net < 0) {
            const po = buildReconciliationOrderFromWiseUsdEntry(entry, year);
            if (po) {
              ensurePaymentOrdersReconciliationListExistsForYear(year);
              upsertReconciliationOrderBySource(po, year);
            }
            if (existing) deleteWiseUsdEntryById(entry.id, year);
          } else {
            removeReconciliationOrderBySource('wiseUSD', entry.id, year);
            upsertWiseUsdEntry(entry, year);
            if (!existing) {
              void fireNotificationEvent('new_wise_usd', {
                date: String(entry.date || ''),
                party: String(entry.receivedFromDisbursedTo || ''),
                amount: String(entry.totalAmountInUsd || entry.usdAmount || ''),
                year: String(year),
                directLink: String(window.location.href || ''),
              });
            }
          }
          closeWiseUsdModal();
          applyWiseUsdView();
        } catch (err) {
          console.error('[WiseUSD Save] Failed', err);
          window.alert(`Unable to save wiseUSD entry. ${err && err.message ? err.message : 'Check console for details.'}`);
        }
      });
    }

    if (!wiseUsdTbody.dataset.storageBound) {
      wiseUsdTbody.dataset.storageBound = '1';
      window.addEventListener('storage', (e) => {
        const key = e && typeof e.key === 'string' ? e.key : '';
        if (!key) return;
        if (key.startsWith('payment_order_wise_usd_')) {
          applyWiseUsdView();
        }
      });
    }

    tryAutoSeedWiseUsdFromCsvFile()
      .then((didSeed) => {
        if (didSeed) applyWiseUsdView();
      })
      .catch(() => {});

    applyWiseUsdView();
  }

  
  // [bundle-strip:menu-remove-budget-editor] removed in page-specific build.

  // [bundle-strip:menu-remove-archive-page] removed in page-specific build.
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
        try {
          openAuthLoginOverlay();
        } catch {
          // Hard fallback: force a reload route that auto-opens login.
          window.location.href = withWpEmbedParams('index.html?showLogin=1');
        }
      });
    }

    // URL-flag fallback for environments where direct overlay open can be blocked
    // by stale UI state. Trigger once, then clean the URL.
    try {
      const params = new URLSearchParams(window.location.search || '');
      if (params.get('showLogin') === '1') {
        openAuthLoginOverlay();
        params.delete('showLogin');
        const nextQs = params.toString();
        const nextUrl = `${window.location.pathname}${nextQs ? `?${nextQs}` : ''}${window.location.hash || ''}`;
        if (window.history && typeof window.history.replaceState === 'function') {
          window.history.replaceState(null, '', nextUrl);
        }
      }
    } catch {
      // ignore
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

  // [bundle-strip:menu-remove-request-form] removed in page-specific build.

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

  
  // [bundle-strip:menu-remove-itemize] removed in page-specific build.

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
