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
  const APP_VERSION = '0.1.1';

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

  applyAppTabTitle();
  applyAppVersion();

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

  // ---- WordPress shared-storage bridge (optional) ----
  // When the app is embedded via the WP plugin, the iframe src includes:
  //   ?restUrl=https://example.com/wp-json/&restNonce=...&wp=1
  // In that mode we:
  // - load shared key/value data from WP
  // - store shared keys in-memory (not in browser storage)
  // - sync writes back to WP via REST
  const WP_CTX_KEY = 'acgl_fms_wp_ctx_v1';
  const FULLPAGE_LAST_SRC_KEY = 'acgl_fms_fullpage_last_src_v1';

  function loadWpCtxFromSession() {
    try {
      const raw = String(sessionStorage.getItem(WP_CTX_KEY) || '').trim();
      if (!raw) return null;
      const parsed = JSON.parse(raw);
      if (!parsed || typeof parsed !== 'object') return null;
      const restUrl = String(parsed.restUrl || '').trim();
      const restNonce = String(parsed.restNonce || '').trim();
      if (!restUrl) return null;
      return { restUrl, restNonce };
    } catch {
      return null;
    }
  }

  function saveWpCtxToSession(restUrl, restNonce) {
    const url = String(restUrl || '').trim();
    if (!url) return;
    try {
      sessionStorage.setItem(WP_CTX_KEY, JSON.stringify({ restUrl: url, restNonce: String(restNonce || '').trim() }));
    } catch {
      // ignore
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
      return qs ? `${base}?${qs}` : base;
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

    // Per-year datasets
    if (key.startsWith('payment_orders_')) return true;
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
    if (typeof window.fetch !== 'function') return;
    let storage;
    try {
      storage = window.localStorage;
    } catch {
      // Some embedded/browser privacy modes throw on storage access.
      return;
    }
    if (!storage) return;

    const nativeGet = storage.getItem.bind(storage);
    const nativeSet = storage.setItem.bind(storage);
    const nativeRemove = storage.removeItem.bind(storage);

    const mem = new Map();
    const pendingUpserts = new Map();
    const pendingDeletes = new Set();
    let flushTimer = 0;
    let flushing = false;

    const kvListUrl = wpJoin('acgl-fms/v1/kv');
    const itemUrl = (key) => wpJoin(`acgl-fms/v1/kv/${encodeURIComponent(String(key || ''))}`);

    // 1) Load all shared keys from WP into memory.
    try {
      const res = await wpFetchJson(kvListUrl, { method: 'GET' });
      if (res.status === 401 || res.status === 403) {
        // Not signed into the app yet (public mode). Continue with an empty in-memory store.
      } else if (!res.ok) {
        // If WP is reachable but the API fails, fall back to local storage.
        return;
      }
      if (res.ok) {
        const payload = await readJsonResponse(res);
        const items = payload && Array.isArray(payload.items) ? payload.items : [];
        for (const it of items) {
          if (!it || typeof it !== 'object') continue;
          const k = String(it.k || '').trim();
          if (!isWpSharedKey(k)) continue;
          const v = it.v === null || it.v === undefined ? null : String(it.v);
          if (v === null) mem.delete(k);
          else mem.set(k, v);
        }
      }
    } catch {
      // Network errors: fall back to local storage.
      return;
    }

    function scheduleFlush() {
      if (flushTimer) return;
      flushTimer = window.setTimeout(async () => {
        flushTimer = 0;
        if (flushing) return;
        flushing = true;
        try {
          // Deletes first.
          for (const key of Array.from(pendingDeletes)) {
            pendingDeletes.delete(key);
            pendingUpserts.delete(key);
            try {
              await wpFetchJson(itemUrl(key), { method: 'DELETE' });
            } catch {
              // ignore
            }
          }

          // Upserts.
          for (const [key, value] of Array.from(pendingUpserts.entries())) {
            pendingUpserts.delete(key);
            try {
              await wpFetchJson(itemUrl(key), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ value: String(value) }),
              });
            } catch {
              // ignore
            }
          }
        } finally {
          flushing = false;
        }
      }, 350);
    }

    async function flushNow() {
      if (flushTimer) {
        window.clearTimeout(flushTimer);
        flushTimer = 0;
      }
      if (flushing) return;
      flushing = true;
      try {
        // Deletes first.
        for (const key of Array.from(pendingDeletes)) {
          pendingDeletes.delete(key);
          pendingUpserts.delete(key);
          try {
            await wpFetchJson(itemUrl(key), { method: 'DELETE' });
          } catch {
            // ignore
          }
        }

        // Upserts.
        for (const [key, value] of Array.from(pendingUpserts.entries())) {
          pendingUpserts.delete(key);
          try {
            await wpFetchJson(itemUrl(key), {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ value: String(value) }),
            });
          } catch {
            // ignore
          }
        }
      } finally {
        flushing = false;
      }
    }

    // Expose a safe way to force persistence before navigation.
    // Used when the UI redirects immediately after writing shared keys.
    window.acglFmsWpFlushNow = flushNow;

    // 2) Override localStorage for shared keys only.
    storage.getItem = (key) => {
      const k = String(key || '');
      if (!isWpSharedKey(k)) return nativeGet(k);
      return mem.has(k) ? mem.get(k) : null;
    };

    storage.setItem = (key, value) => {
      const k = String(key || '');
      if (!isWpSharedKey(k)) {
        nativeSet(k, value);
        return;
      }

      const v = String(value);
      mem.set(k, v);

      // In public (unauthenticated) mode, do not queue shared writes.
      // Otherwise stale client-side writes could flush later after login.
      if (!getWpToken()) return;

      pendingDeletes.delete(k);
      pendingUpserts.set(k, v);
      scheduleFlush();
    };

    storage.removeItem = (key) => {
      const k = String(key || '');
      if (!isWpSharedKey(k)) {
        nativeRemove(k);
        return;
      }

      mem.delete(k);

      // In public (unauthenticated) mode, do not queue shared deletes.
      if (!getWpToken()) return;

      pendingUpserts.delete(k);
      pendingDeletes.add(k);
      scheduleFlush();
    };

    // NOTE: In WP mode, the browser 'storage' event won't reflect shared writes.
    // This app currently uses storage events mainly for cross-tab updates; in WP mode
    // the shared store is authoritative and reload is typically acceptable.
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
  const BUDGET_TEMPLATE_ROWS_KEY = 'payment_order_budget_template_rows_v1';
  const USERS_KEY = 'payment_order_users_v1';
  const BACKLOG_KEY = 'payment_order_backlog_v1';
  const CURRENT_USER_KEY = 'payment_order_current_user_v1';
  const LOGIN_AT_KEY = 'payment_order_login_at_v1';
  const LAST_ACTIVITY_AT_KEY = 'payment_order_last_activity_at_v1';
  const AUTH_AUDIT_KEY = 'payment_order_auth_audit_v1';
  const LAST_PAGE_KEY = 'acgl_fms_last_page_v1';

  const HARD_CODED_ADMIN_USERNAME = 'admin.pass';
  const HARD_CODED_ADMIN_PASSWORD = 'acgl1962ADM';
  const HARD_CODED_ADMIN_SALT = 'acgl_fms_admin_v1';

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
        id: 'user_admin_pass_v1',
        createdAt: nowIso,
        updatedAt: nowIso,
        username: normalizeUsername(HARD_CODED_ADMIN_USERNAME),
        email: '',
        salt: HARD_CODED_ADMIN_SALT,
        passwordHash: buildLegacyPwHash(HARD_CODED_ADMIN_PASSWORD, HARD_CODED_ADMIN_SALT),
        passwordPlain: HARD_CODED_ADMIN_PASSWORD,
        permissions: { budget: 'write', income: 'write', orders: 'write', ledger: 'write', settings: 'write' },
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
    const safe = Array.isArray(users) ? users : [];
    localStorage.setItem(USERS_KEY, JSON.stringify(safe));
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

    // Persist an audit trail of sign-in events (in localStorage) so it is visible
    // on the Settings -> Audit Log page.
    if (u) {
      appendAuthAuditEvent('Login', u);
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

  function performAutoLogout() {
    const prev = normalizeUsername(getCurrentUsername());
    if (!prev) return;

    // Record as an auth audit note, excluding hard-coded admin.
    appendAuthAuditEvent('Auto log out', prev);

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
        performAutoLogout();
      }
    }, 15 * 1000);
  }

  function performLogout() {
    const prev = normalizeUsername(getCurrentUsername());
    if (prev) appendAuthAuditEvent('Logout', prev);
    setCurrentUsername('');
    if (IS_WP_SHARED_MODE) clearWpToken();
  }

  async function persistAuthAuditToWpNow(keepalive = false) {
    if (!IS_WP_SHARED_MODE) return { ok: true, skipped: true };
    try {
      const raw = String(localStorage.getItem(AUTH_AUDIT_KEY) || '').trim();
      const value = raw ? raw : '[]';
      const url = wpJoin(`acgl-fms/v1/kv/${encodeURIComponent(String(AUTH_AUDIT_KEY))}`);
      const res = await wpFetchJson(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ value }),
        keepalive: Boolean(keepalive),
      });
      if (!res.ok) return { ok: false, status: res.status };
      return { ok: true };
    } catch {
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

  function appendAuthAuditEvent(actionRaw, usernameRaw) {
    const action = String(actionRaw || '').trim() || 'Event';
    const user = normalizeUsername(usernameRaw) || '—';
    const at = new Date().toISOString();

    const existing = loadAuthAuditEvents();
    const next = [...existing, { at, module: 'Auth', record: 'Session', user, action, changes: [] }];

    // Keep storage bounded.
    const MAX = 500;
    const trimmed = next.length > MAX ? next.slice(next.length - MAX) : next;
    saveAuthAuditEvents(trimmed);

    // In WP mode, localStorage writes are debounced for performance; ensure auth events
    // are persisted immediately so logout/navigation doesn't drop them.
    if (IS_WP_SHARED_MODE) {
      const shouldKeepalive = action === 'Logout' || action === 'Auto log out';
      void persistAuthAuditToWpNow(shouldKeepalive);
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
    if (IS_WP_SHARED_MODE) {
      const perms = getWpPerms();
      if (perms) {
        return {
          username: normalizeUsername(u),
          permissions: perms,
        };
      }
    }
    return getUserByUsername(u);
  }

  function normalizePermissions(perms) {
    const p = perms && typeof perms === 'object' ? perms : {};

    const normalizeLevel = (value) => {
      if (value === true) return 'write';
      if (value === false || value == null) return 'none';
      const v = String(value).trim().toLowerCase();
      if (v === 'write' || v === 'full' || v === 'fullaccess') return 'write';
      if (v === 'partial' || v === 'limited' || v === 'some') return 'partial';
      if (v === 'read' || v === 'readonly' || v === 'read-only') return 'read';
      if (v === 'none' || v === 'no' || v === 'noaccess') return 'none';
      return 'none';
    };

    return {
      budget: normalizeLevel(p.budget),
      income: normalizeLevel(p.income),
      orders: normalizeLevel(p.orders),
      ledger: normalizeLevel(p.ledger),
      settings: normalizeLevel(p.settings),
    };
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

    // Itemize for an existing order requires Orders permission.
    if (base === 'itemize.html') return 'orders';

    if (base === 'budget.html' || base === 'budget_dashboard.html') return 'budget';
    if (base === 'income.html') return 'income';
    if (base === 'wise_eur.html') return 'ledger';
    if (base === 'wise_usd.html') return 'ledger';
    if (base === 'menu.html' || base === 'reconciliation.html') return 'orders';
    if (base === 'grand_secretary_ledger.html') return 'ledger';
    if (base === 'settings.html') return 'settings';
    return null;
  }

  function isPublicRequestPage(pathname) {
    const base = getBasename(pathname);
    if (base === 'index.html') return true;
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
    const p = getEffectivePermissions(user);
    return p[permKey] !== 'none';
  }

  function canWrite(user, permKey) {
    if (!permKey) return true;
    const p = getEffectivePermissions(user);
    return p[permKey] === 'write';
  }

  function canBudgetEdit(user) {
    const p = getEffectivePermissions(user);
    return p.budget === 'write' || p.budget === 'partial';
  }

  function canIncomeEdit(user) {
    const p = getEffectivePermissions(user);
    return p.income === 'write' || p.income === 'partial';
  }

  function canOrdersViewEdit(user) {
    const p = getEffectivePermissions(user);
    return p.orders === 'write' || p.orders === 'partial';
  }

  function canSettingsEdit(user) {
    const p = getEffectivePermissions(user);
    return p.settings === 'write' || p.settings === 'partial';
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

  function requireWriteAccess(permKey, message) {
    // Public New Request Form flow: allow creating a new request without login.
    // If editing an existing order, keep normal permission checks.
    if (permKey === 'orders' && isPublicRequestPage(window.location.pathname) && !getEditOrderId()) {
      // Anonymous users can submit new requests.
      // Signed-in users must have Full access for Payment Orders to create.
      const maybeUser = getCurrentUser();
      if (!maybeUser) return true;
      if (!canWrite(maybeUser, 'orders')) {
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
    if (!canWrite(user, permKey)) {
      window.alert(message || 'Read only access.');
      return false;
    }
    return true;
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

  function requireSettingsEditAccess(message) {
    // Bootstrap: allow initial setup before any users exist.
    const hasAnyUsers = loadUsers().length > 0;
    if (!hasAnyUsers) return true;

    const user = getCurrentUser();
    if (!user) {
      window.alert('Please sign in.');
      return false;
    }
    if (!canSettingsEdit(user)) {
      window.alert(message || 'Read only access.');
      return false;
    }
    return true;
  }

  function firstAllowedHrefForUser(user, resolvedYear) {
    const year = Number.isInteger(Number(resolvedYear)) ? Number(resolvedYear) : getActiveBudgetYear();
    const order = [
      { key: 'orders', href: `menu.html?year=${encodeURIComponent(String(year))}` },
      { key: 'income', href: `income.html?year=${encodeURIComponent(String(year))}` },
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
    try {
      const raw = localStorage.getItem(ACTIVE_BUDGET_YEAR_KEY);
      const y = Number(raw);
      if (!Number.isInteger(y)) return null;
      if (y < 1900 || y > 3000) return null;
      return y;
    } catch {
      return null;
    }
  }

  function saveActiveBudgetYear(year) {
    const y = Number(year);
    if (!Number.isInteger(y) || y < 1900 || y > 3000) return;
    localStorage.setItem(ACTIVE_BUDGET_YEAR_KEY, String(y));
  }

  function clearActiveBudgetYear() {
    try {
      localStorage.removeItem(ACTIVE_BUDGET_YEAR_KEY);
    } catch {
      // ignore
    }
  }

  function getBudgetTableKeyForYear(year) {
    const y = Number(year);
    if (!Number.isInteger(y)) return null;
    return `payment_order_budget_table_html_${y}_v1`;
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
    const normalized = Array.from(new Set((years || []).map((v) => Number(v)).filter((v) => Number.isInteger(v))))
      .sort((a, b) => b - a);
    localStorage.setItem(BUDGET_YEARS_KEY, JSON.stringify(normalized));
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
    const normalized = Array.isArray(rows) ? rows.map(normalizeBudgetTemplateRow).filter(Boolean) : [];
    try {
      localStorage.setItem(BUDGET_TEMPLATE_ROWS_KEY, JSON.stringify(normalized));
    } catch {
      // ignore
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

  function getNavConfig() {
    const years = migrateLegacyBudgetIfNeeded();
    const navYears = years.length > 0 ? years : [getCurrentBudgetYearFromDate(new Date())];
    const currentUser = getCurrentUser();
    const activeYear = (() => {
      const stored = loadActiveBudgetYear();
      if (stored && navYears.includes(stored)) return stored;
      return null;
    })();
    const resolvedYear = (() => {
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
          { label: 'Dashboard', href: `budget_dashboard.html?year=${encodeURIComponent(String(resolvedYear))}` },
          // Child #2+: Current year link first, then remaining budget years.
          ...[resolvedYear, ...navYears.filter((y) => y !== resolvedYear)].map((year) => ({
            label: String(year),
            href: `budget.html?year=${encodeURIComponent(String(year))}`,
            isActiveBudgetYear: resolvedYear === year || activeYear === year,
          })),
        ],
      },
      {
        key: 'income',
        label: 'Income',
        href: `income.html?year=${encodeURIComponent(String(resolvedYear))}`,
        children: navYears.map((year) => ({
          label: String(year),
          href: `income.html?year=${encodeURIComponent(String(year))}`,
        })),
      },
      {
        key: 'orders',
        label: 'Payment Orders',
        href: `menu.html?year=${encodeURIComponent(String(resolvedYear))}`,
        children: navYears.map((year) => ({
          label: String(year),
          href: `menu.html?year=${encodeURIComponent(String(year))}`,
        })),
      },
      {
        key: 'ledger',
        label: 'Ledger',
        href: `grand_secretary_ledger.html?year=${encodeURIComponent(String(resolvedYear))}`,
        children: navYears.map((year) => ({
          label: String(year),
          href: `grand_secretary_ledger.html?year=${encodeURIComponent(String(year))}`,
        })),
      },
      { key: null, label: 'Archive', href: 'archive.html' },
      { key: 'settings', label: 'Admin Settings', href: 'settings.html' },
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
    return config.filter((it) => hasPermission(currentUser, it.key));
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
            const user = getCurrentUser();
            if (!tryRedirectToRememberedPage(user)) {
              window.location.reload();
            }
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

          const required = requiredPermissionForPage(window.location.pathname);
          if (!hasPermission(user, required)) {
            window.location.href = firstAllowedHrefForUser(user, getActiveBudgetYear());
            return;
          }

          if (!tryRedirectToRememberedPage(user)) {
            window.location.reload();
          }
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
    if (alreadyOpen) return;

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
          const user = getCurrentUser();
          if (!tryRedirectToRememberedPage(user)) {
            window.location.reload();
          }
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
        if (!tryRedirectToRememberedPage(user)) {
          window.location.reload();
        }
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

  // Request form submission token
  const submitToken = document.getElementById('submitToken');
  const cancelEditBtn = document.getElementById('cancelEditBtn');

  // Menu page flash token (one-time message after redirects)
  const flashToken = document.getElementById('flashToken');

  let submitTokenHideTimer = null;
  let flashTokenHideTimer = null;

  // Remember where the user is in this session so a refresh/login can return here.
  rememberLastPageNow();

  const authGateResult = renderAuthGate();
  if (authGateResult && authGateResult.blocked) return;

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

  // Settings page (numbering)
  const numberingForm = document.getElementById('numberingForm');
  const masonicYearInput = document.getElementById('masonicYear');
  const firstNumberInput = document.getElementById('firstNumber');

  // Settings page (Grand Lodge Information)
  const grandLodgeInfoForm = document.getElementById('grandLodgeInfoForm');
  const grandMasterInput = document.getElementById('grandMaster');
  const grandSecretaryInput = document.getElementById('grandSecretary');
  const grandTreasurerInput = document.getElementById('grandTreasurer');
  const officialAddressInput = document.getElementById('officialAddress');
  const operationAddressInput = document.getElementById('operationAddress');
  const grandLodgeSealFileInput = document.getElementById('grandLodgeSealFile');
  const grandSecretarySignatureFileInput = document.getElementById('grandSecretarySignatureFile');

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

  /** @returns {Array<Object>} */
  function loadReconciliationOrders(year) {
    const resolvedYear = Number.isInteger(Number(year)) ? Number(year) : getActiveBudgetYear();
    const storageKey = getPaymentOrdersReconciliationKeyForYear(resolvedYear);
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

  /** @param {Array<Object>} orders */
  function saveReconciliationOrders(orders, year) {
    const resolvedYear = Number.isInteger(Number(year)) ? Number(year) : getActiveBudgetYear();
    const storageKey = getPaymentOrdersReconciliationKeyForYear(resolvedYear);
    if (!storageKey) return;
    localStorage.setItem(storageKey, JSON.stringify(orders));
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
      return Array.isArray(parsed) ? parsed : [];
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
      if (!raw) return { year2: getDefaultMasonicYear2(), nextSeq: 1 };
      const parsed = JSON.parse(raw);
      return {
        year2: normalizeMasonicYear2(parsed && parsed.year2),
        nextSeq: normalizeSequence(parsed && parsed.nextSeq),
      };
    } catch {
      return { year2: getDefaultMasonicYear2(), nextSeq: 1 };
    }
  }

  function saveNumberingSettings(settings) {
    const year2 = normalizeMasonicYear2(settings && settings.year2);
    const nextSeq = normalizeSequence(settings && settings.nextSeq);
    localStorage.setItem(NUMBERING_KEY, JSON.stringify({ year2, nextSeq }));
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

    if (isSameYear2 && normalizeSequence(current.nextSeq) === nextSeq) return false;
    saveNumberingSettings({ year2, nextSeq });
    return true;
  }

  function getNextPaymentOrderNo() {
    const s = loadNumberingSettings();
    return formatPaymentOrderNo(s.year2, s.nextSeq);
  }

  function advancePaymentOrderSequence() {
    const s = loadNumberingSettings();
    const current = normalizeSequence(s.nextSeq);
    const next = current + 1;
    saveNumberingSettings({ year2: s.year2, nextSeq: next });
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

  function maybeAutofillPaymentOrderNo() {
    if (!form) return;

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
      'paymentOrderNo',
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
    return payload.item && typeof payload.item === 'object' ? payload.item : null;
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
      return wpUploadAttachment(targetKey, file, context);
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
    return record;
  }

  async function deleteAttachmentById(id) {
    if (IS_WP_SHARED_MODE) {
      await wpDeleteAttachmentById(id);
      return;
    }
    const db = await openAttachmentsDb();
    const tx = db.transaction(ATTACHMENTS_STORE, 'readwrite');
    const store = tx.objectStore(ATTACHMENTS_STORE);
    await idbRequestToPromise(store.delete(id));
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
          page.drawText(lineText, { x: drawX, y, size, font });
          y -= lineHeight;
        }
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
      { key: 'name', source: 'form', x: 130, y: 585, size: 10 },

      { key: 'address', source: 'form', x: 130, y: 570, size: 9, wrap: true, lineHeight: 11, maxWidth: 470, maxHeight: 70 },
      { key: 'iban', source: 'form', x: 130, y: 540, size: 10 },
      { key: 'bic', source: 'form', x: 130, y: 525, size: 10 },

      { key: 'euro', source: 'form', x: 180, y: 615, size: 10 },
      { key: 'usd', source: 'form', x: 280, y: 615, size: 10 },

      { key: 'budgetNumber', source: 'form', x: 200, y: 226, size: 10 },
      { key: 'specialInstructions', source: 'form', x: 60, y: 435, size: 9, wrap: true, lineHeight: 11, maxWidth: 540, maxHeight: 180 },
      { key: 'purpose', source: 'form', x: 50, y: 210, size: 9, wrap: true, lineHeight: 11, maxWidth: 540, maxHeight: 180 },

      { key: 'grandMaster', source: 'gl', x: 61, y: 765, size: 10 },
      { key: 'grandSecretary', source: 'gl', x: 465, y: 765, size: 10, marker: 'grandSecretary_top' },
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
      if (f.wrap) {
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

    const sealBytes = gl && gl.grandLodgeSealDataUrl ? dataUrlToUint8Array(gl.grandLodgeSealDataUrl) : null;
    const sigBytes = gl && gl.grandSecretarySignatureDataUrl ? dataUrlToUint8Array(gl.grandSecretarySignatureDataUrl) : null;

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
              <button type="button" class="btn btn--ghost" data-attachment-action="view">View</button>
              <button type="button" class="btn btn--ghost" data-attachment-action="download">Download</button>
              <button type="button" class="btn btn--danger" data-attachment-action="delete">Remove</button>
            </td>
          </tr>
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
              <button type="button" class="btn btn--ghost" data-modal-attachment-action="view">View</button>
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
      if (!requireWriteAccess('orders', 'Payment Orders is read only for your account.')) return;

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

  function isMockOrder(order) {
    return !!order && typeof order === 'object' && String(order.id || '').startsWith('mock_');
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
    const incomeKey = getIncomeKeyForYear(targetYear);
    if (incomeKey) {
      const INCOME_MOCK_VERSION_KEY = 'payment_orders_income_mock_version';
      const INCOME_MOCK_VERSION = '1';

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
    const built = {
      id: (crypto?.randomUUID ? crypto.randomUUID() : `po_${Date.now()}_${Math.random().toString(16).slice(2)}`),
      createdAt,
      ...values,
      status: normalizeOrderStatus(values && values.status),
      with: normalizeWith(values && values.with),
    };
    return {
      ...built,
      timeline: [
        {
          at: createdAt,
          with: getOrderWithLabel(built),
          status: getOrderStatusLabel(built),
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
      { key: 'budgetNumber', label: 'Budget Number', fmt: (v) => auditValue(v) },
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
      { key: 'budgetNumber', label: 'Budget Number', fmt: (v) => auditValue(v) },
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
    if (isHardcodedAdminUsername(name)) return '—';
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
        const w = e.with !== undefined ? normalizeWith(e.with) : '—';
        const s = e.status !== undefined ? normalizeOrderStatus(e.status) : '—';
        return `<div class="timelinegraph__event"><span class="timelinegraph__eventTime">${escapeHtml(t)}</span><span class="timelinegraph__eventSep">•</span><span>With: <strong>${escapeHtml(w)}</strong></span><span class="timelinegraph__eventSep">•</span><span>Status: <strong>${escapeHtml(s)}</strong></span></div>`;
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
    const canFullWrite = currentUser ? canWrite(currentUser, 'orders') : false;
    const canViewItems = currentUser ? canOrdersViewEdit(currentUser) : false;
    const writeDisabledAttr = canFullWrite ? '' : ' disabled';
    const writeAriaDisabled = canFullWrite ? 'false' : 'true';
    const writeTooltipAttr = canFullWrite ? '' : ' data-tooltip="Requires Full access for Payment Orders."';

    const itemsDisabledAttr = canViewItems ? '' : ' disabled';
    const itemsAriaDisabled = canViewItems ? 'false' : 'true';
    const itemsTooltipAttr = canViewItems ? '' : ' data-tooltip="Requires Payment Orders access."';

    if (!orders || orders.length === 0) {
      emptyState.hidden = false;
      return;
    }

    emptyState.hidden = true;

    const rowsHtml = orders
      .map((o) => {
        return `
          <tr data-id="${escapeHtml(o.id)}">
            <td class="col-delete">
              <button
                type="button"
                class="btn btn--x"
                data-action="delete"
                aria-label="Delete request"
                title="${canFullWrite ? 'Delete' : 'Requires Full access for Payment Orders.'}"
                aria-disabled="${writeAriaDisabled}"${writeDisabledAttr}${writeTooltipAttr}
              >
                X
              </button>
            </td>
            <td>${escapeHtml(formatPaymentOrderNoForDisplay(o.paymentOrderNo))}</td>
            <td>${escapeHtml(formatDate(o.date))}</td>
            <td>${escapeHtml(o.name)}</td>
            <td class="num">${escapeHtml(formatCurrency(o.euro, 'EUR'))}</td>
            <td class="num">${escapeHtml(formatCurrency(o.usd, 'USD'))}</td>
            <td>${renderOutBudgetNumberHtml(o.budgetNumber, year)}</td>
            <td>${escapeHtml(o.purpose)}</td>
            <td>${escapeHtml(getOrderWithLabel(o))}</td>
            <td>${escapeHtml(getOrderStatusLabel(o))}</td>
            <td class="actions">
              <button type="button" class="btn btn--ghost btn--items" data-action="items" title="${canViewItems ? 'Items' : 'Requires Payment Orders access.'}" aria-disabled="${itemsAriaDisabled}"${itemsDisabledAttr}${itemsTooltipAttr}>Items</button>
              <button type="button" class="btn btn--editBlue" data-action="edit" title="${canFullWrite ? 'Edit' : 'Requires Full access for Payment Orders.'}" aria-disabled="${writeAriaDisabled}"${writeDisabledAttr}${writeTooltipAttr}>Edit</button>
              <button type="button" class="btn btn--viewGrey" data-action="view">View</button>
            </td>
          </tr>
        `.trim();
      })
      .join('');

    tbody.innerHTML = rowsHtml;
  }

  const PAYMENT_ORDERS_COL_TYPES = {
    paymentOrderNo: 'text',
    date: 'date',
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

    // Default sort: newest first (createdAt desc)
    if (!sortKey) {
      return [...orders].sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)));
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
      modalHeaderBudget.innerHTML = `Budget Number: ${budgetHtml || '—'}`;
    }

    const currentStatus = getOrderStatusLabel(orderForView);
    const statusOptions = ORDER_STATUSES.map((s) => {
      const selected = s === currentStatus ? ' selected' : '';
      return `<option value="${escapeHtml(s)}"${selected}>${escapeHtml(s)}</option>`;
    }).join('');

    const currentWith = getOrderWithLabel(orderForView);
    const withOptions = WITH_OPTIONS.map((w) => {
      const selected = w === currentWith ? ' selected' : '';
      return `<option value="${escapeHtml(w)}"${selected}>${escapeHtml(w)}</option>`;
    }).join('');

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
      </dl>
      ${renderTimelineGraph(orderForView)}
    `.trim();

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

    const statusSelect = modalBody.querySelector('#modalStatusSelect');
    if (statusSelect) {
      statusSelect.addEventListener('change', () => {
        const nextStatus = normalizeOrderStatus(statusSelect.value);

        // Guardrail: cannot set Approved/Paid unless a valid Budget Number exists.
        const outCode = extractOutCodeFromBudgetNumberText(orderForView.budgetNumber);
        const isImpact = nextStatus === 'Approved' || nextStatus === 'Paid';
        if (isImpact && !/^\d{4}$/.test(outCode)) {
          window.alert('Budget Number is required before setting Status to Approved or Paid. Edit the order and set Budget Number first.');
          statusSelect.value = normalizeOrderStatus(currentStatus);
          modal.removeAttribute('data-pending-status');
          return;
        }

        statusSelect.value = nextStatus;
        modal.setAttribute('data-pending-status', nextStatus);
      });
    }

    const withSelect = modalBody.querySelector('#modalWithSelect');
    if (withSelect) {
      withSelect.addEventListener('change', () => {
        const nextWith = normalizeWith(withSelect.value);
        withSelect.value = nextWith;
        modal.setAttribute('data-pending-with', nextWith);
      });
    }

    // Access rules:
    // - Orders Partial: read-only everywhere (including Reconciliation) EXCEPT this View modal
    //   where the user may update only With + Status.
    const currentUser = getCurrentUser();
    const canFullWrite = currentUser ? canWrite(currentUser, 'orders') : false;
    const canViewWrite = currentUser ? canOrdersViewEdit(currentUser) : false;

    if (statusSelect) statusSelect.disabled = !canViewWrite;
    if (withSelect) withSelect.disabled = !canViewWrite;

    if (editOrderBtn) {
      editOrderBtn.disabled = !canFullWrite;
      if (!canFullWrite) editOrderBtn.setAttribute('data-tooltip', 'Requires Full access for Payment Orders.');
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
    modal.classList.remove('is-open');
    modal.setAttribute('aria-hidden', 'true');
    modalBody.innerHTML = '';
    const modalHeaderPo = modal.querySelector('#modalHeaderPo');
    if (modalHeaderPo) modalHeaderPo.textContent = '';
    const modalHeaderBudget = modal.querySelector('#modalHeaderBudget');
    if (modalHeaderBudget) modalHeaderBudget.textContent = '';
    const modalHeaderDate = modal.querySelector('#modalHeaderDate');
    if (modalHeaderDate) modalHeaderDate.textContent = '';
    currentViewedOrderId = null;
    modal.removeAttribute('data-order-id');
    modal.removeAttribute('data-pending-with');
    modal.removeAttribute('data-pending-status');
    modal.removeAttribute('data-original-with');
    modal.removeAttribute('data-original-status');
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
    const next = orders.filter((o) => o.id !== id);
    saveOrders(next, year);
    applyPaymentOrdersView();
  }

  function clearAll() {
    const year = getActiveBudgetYear();
    const orders = loadOrders(year);
    if (orders.length === 0) return;
    const ok = window.confirm('Clear all payment orders? This cannot be undone.');
    if (!ok) return;
    saveOrders([], year);
    applyPaymentOrdersView();
  }

  function initPaymentOrdersListPage() {
    if (!tbody) return;
    const year = getActiveBudgetYear();

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

    applyAppTabTitle();
  }

  // ---- Payment Orders Reconciliation (year-scoped) ----

  const reconciliationViewState = {
    globalFilter: '',
  };

  /** @param {Array<Object>} orders */
  function renderReconciliationOrders(orders) {
    if (!reconcileTbody || !reconcileEmptyState) return;
    reconcileTbody.innerHTML = '';

    if (!orders || orders.length === 0) {
      reconcileEmptyState.hidden = false;
      return;
    }

    reconcileEmptyState.hidden = true;

    const year = getActiveBudgetYear();

    const rowsHtml = orders
      .map((o) => {
        return `
          <tr data-id="${escapeHtml(o.id)}">
            <td class="col-delete">
              <button
                type="button"
                class="btn btn--x"
                data-action="delete"
                aria-label="Delete request"
                title="Delete"
              >
                X
              </button>
            </td>
            <td>${escapeHtml(formatPaymentOrderNoForDisplay(o.paymentOrderNo) || '—')}</td>
            <td>${escapeHtml(formatDate(o.date))}</td>
            <td>${escapeHtml(o.name)}</td>
            <td class="num">${escapeHtml(formatCurrency(o.euro, 'EUR'))}</td>
            <td class="num">${escapeHtml(formatCurrency(o.usd, 'USD'))}</td>
            <td>${renderOutBudgetNumberHtml(o.budgetNumber || '', year)}</td>
            <td>${escapeHtml(o.purpose || '')}</td>
            <td>${escapeHtml(getOrderWithLabel(o))}</td>
            <td>${escapeHtml(getOrderStatusLabel(o))}</td>
            <td class="actions">
              <button type="button" class="btn btn--editBlue" data-action="reconcile">Reconcile</button>
            </td>
          </tr>
        `.trim();
      })
      .join('');

    reconcileTbody.innerHTML = rowsHtml;
  }

  function updateReconciliationHeaderIndicators() {
    const globalInput = document.getElementById('reconcileOrdersGlobalSearch');
    if (globalInput) {
      globalInput.classList.toggle('input-active', normalizeTextForSearch(reconciliationViewState.globalFilter) !== '');
    }

    if (reconcileClearSearchBtn) {
      const hasSearch = normalizeTextForSearch(reconciliationViewState.globalFilter) !== '';
      reconcileClearSearchBtn.hidden = !hasSearch;
      reconcileClearSearchBtn.disabled = !hasSearch;
    }
  }

  function updateReconciliationTotals(orders) {
    const euroEl = document.getElementById('reconcileTotalEuro');
    const usdEl = document.getElementById('reconcileTotalUsd');
    if (!euroEl && !usdEl) return;

    let totalEuro = 0;
    let totalUsd = 0;
    for (const o of orders || []) {
      const e = Number(o && o.euro);
      const u = Number(o && o.usd);
      if (Number.isFinite(e)) totalEuro += e;
      if (Number.isFinite(u)) totalUsd += u;
    }

    if (euroEl) euroEl.textContent = formatCurrency(totalEuro, 'EUR');
    if (usdEl) usdEl.textContent = formatCurrency(totalUsd, 'USD');
  }

  function applyReconciliationView() {
    if (!reconcileTbody || !reconcileEmptyState) return;
    const year = getActiveBudgetYear();
    const all = loadReconciliationOrders(year);
    const filtered = filterOrdersForView(all, {}, reconciliationViewState.globalFilter);
    const sorted = sortOrdersForView(filtered, null, 'asc');
    renderReconciliationOrders(sorted);
    updateReconciliationTotals(sorted);
    updateReconciliationHeaderIndicators();
  }

  function deleteReconciliationOrderById(id) {
    const year = getActiveBudgetYear();
    const orders = loadReconciliationOrders(year);
    const next = orders.filter((o) => o.id !== id);
    saveReconciliationOrders(next, year);
    applyReconciliationView();
  }

  function reconcileOrderById(id) {
    const year = getActiveBudgetYear();
    const rec = loadReconciliationOrders(year);
    const idx = rec.findIndex((o) => o && o.id === id);
    if (idx === -1) return false;

    const [order] = rec.splice(idx, 1);
    saveReconciliationOrders(rec, year);

    ensurePaymentOrdersListExistsForYear(year);
    syncNumberingSettingsToBudgetYear(year);

    const nowIso = new Date().toISOString();
    const needsNo = !String(order && order.paymentOrderNo || '').trim();
    const paymentOrderNo = needsNo ? getNextPaymentOrderNo() : String(order.paymentOrderNo).trim();

    const moved = {
      ...order,
      paymentOrderNo,
      updatedAt: nowIso,
    };

    const existing = loadOrders(year);
    saveOrders([moved, ...(Array.isArray(existing) ? existing : [])], year);

    if (needsNo) advancePaymentOrderSequence();
    return true;
  }

  function initReconciliationListPage() {
    if (!reconcileTbody) return;
    const year = getActiveBudgetYear();

    // Ensure the year is present in the URL for consistent nav highlighting.
    const fromUrl = getBudgetYearFromUrl();
    if (!fromUrl && getBasename(window.location.pathname) === 'reconciliation.html') {
      try {
        const url = new URL(window.location.href);
        url.searchParams.set('year', String(year));
        window.history.replaceState(null, '', url.toString());
      } catch {
        // ignore
      }
    }

    const titleEl = document.querySelector('[data-reconciliation-title]');
    if (titleEl) titleEl.textContent = `${year} Reconciliation`;

    const listTitleEl = document.querySelector('[data-reconciliation-list-title]');
    if (listTitleEl) listTitleEl.textContent = `${year} Reconciliation`;

    applyAppTabTitle();

    if (reconcileToPaymentOrdersBtn) {
      reconcileToPaymentOrdersBtn.textContent = `${year} Payment Orders`;
      reconcileToPaymentOrdersBtn.setAttribute('href', `menu.html?year=${encodeURIComponent(String(year))}`);
    }

    const globalInput = document.getElementById('reconcileOrdersGlobalSearch');
    if (globalInput) {
      globalInput.value = reconciliationViewState.globalFilter || '';
      globalInput.addEventListener('input', () => {
        reconciliationViewState.globalFilter = globalInput.value;
        applyReconciliationView();
      });
    }

    if (reconcileClearSearchBtn && globalInput && !reconcileClearSearchBtn.dataset.bound) {
      reconcileClearSearchBtn.dataset.bound = 'true';
      reconcileClearSearchBtn.addEventListener('click', () => {
        globalInput.value = '';
        reconciliationViewState.globalFilter = '';
        applyReconciliationView();
        if (globalInput.focus) globalInput.focus();
      });
    }

    reconcileTbody.addEventListener('click', (e) => {
      const btn = e.target.closest('button[data-action]');
      if (!btn) return;

      const row = btn.closest('tr[data-id]');
      if (!row) return;

      const id = row.getAttribute('data-id');
      const action = btn.getAttribute('data-action');

      if (action === 'delete') {
        if (!requireWriteAccess('orders', 'Payment Orders is read only for your account.')) return;
        const ok = window.confirm('Delete this reconciliation entry?');
        if (!ok) return;
        deleteReconciliationOrderById(id);
        return;
      }

      if (action === 'reconcile') {
        if (!requireWriteAccess('orders', 'Payment Orders is read only for your account.')) return;
        const ok = window.confirm('Reconcile this entry and move it to Payment Orders?');
        if (!ok) return;
        const moved = reconcileOrderById(id);
        if (moved && typeof showFlashToken === 'function') {
          showFlashToken('Reconciled: moved entry to Payment Orders.');
        }
        applyReconciliationView();
      }
    });

    applyReconciliationView();
  }

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
    if (lv === 'write') return 'Full';
    if (lv === 'partial') return 'Partial';
    if (lv === 'read') return 'Read only';
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
    const maxRows = maxUsers * 2; // each user renders as 2 table rows
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
    const canEdit = currentUser ? canWrite(currentUser, 'settings') : false;

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
        const passwordPlain = String(u && typeof u.passwordPlain === 'string' ? u.passwordPlain : '')
          || extractLegacyPasswordPlain(u && u.passwordHash, u && u.salt);
        const p = getEffectivePermissions(u);
        const isEditing = Boolean(usersTableViewState.editingUsername && usersTableViewState.editingUsername === username);
        const isProtected = username === normalizeUsername(HARD_CODED_ADMIN_USERNAME);
        const safeName = escapeHtml(username);
        const safeEmail = escapeHtml(email);
        const disabled = canEdit && !isProtected ? '' : 'disabled';

        const accessChecks = (key, level) => {
          const lv = String(level || 'none');
          const checkedWrite = lv === 'write' ? 'checked' : '';
          const checkedPartial = lv === 'partial' ? 'checked' : '';
          const checkedRead = lv === 'read' ? 'checked' : '';
          return `
            <div class="rolesChecks" role="group" aria-label="${escapeHtml(key)} access">
              <label class="rolesChecks__item"><input type="checkbox" data-perm="${escapeHtml(key)}" data-level="write" ${checkedWrite} ${disabled} /> Full</label>
              <label class="rolesChecks__item"><input type="checkbox" data-perm="${escapeHtml(key)}" data-level="partial" ${checkedPartial} ${disabled} /> Partial</label>
              <label class="rolesChecks__item"><input type="checkbox" data-perm="${escapeHtml(key)}" data-level="read" ${checkedRead} ${disabled} /> Read only</label>
            </div>
          `.trim();
        };

        const accessDisplay = (key, level) => {
          const label = formatAccessLabel(level);
          const safe = escapeHtml(label);
          return `<span class="usersTable__permLabel" aria-label="${escapeHtml(key)} access">${safe}</span>`;
        };

        const safePw = escapeHtml(passwordPlain);
        const passwordControl = isEditing
          ? `<input type="text" class="usersTable__detailsInput" data-new-password autocomplete="new-password" value="${safePw}" aria-label="Password" ${disabled} />`
          : '<span class="usersTable__permLabel">—</span>';

        const emailControl = isEditing
          ? `<input type="email" class="usersTable__detailsInput" data-email autocomplete="email" placeholder="(optional)" value="${safeEmail}" aria-label="Email" ${disabled} />`
          : `<span class="usersTable__permLabel">${email ? escapeHtml(email) : '—'}</span>`;

        const emailDetailsCell = `
          <div class="usersTable__details" aria-label="Email">
            <span class="usersTable__detailsLabel">Email:</span>
            ${emailControl}
          </div>
        `.trim();

        const passwordDetailsCell = `
          <div class="usersTable__details" aria-label="Password">
            <span class="usersTable__detailsLabel">Password:</span>
            ${passwordControl}
          </div>
        `.trim();

        const actionsCell = (() => {
          const editDisabled = disabled ? 'disabled' : '';
          const deleteDisabled = disabled ? 'disabled' : '';
          const protectTitle = isProtected ? ' title="This user is protected."' : '';

          if (!isEditing) {
            return `
              <button type="button" class="btn btn--primary" data-action="edit" ${editDisabled}${protectTitle}>Edit</button>
              <button type="button" class="btn btn--danger" data-action="delete" ${deleteDisabled}${protectTitle}>Delete</button>
            `.trim();
          }

          return `
            <button type="button" class="btn btn--primary" data-action="save" ${editDisabled}${protectTitle}>Save</button>
            <button type="button" class="btn" data-action="cancel" ${editDisabled}${protectTitle}>Cancel</button>
            <button type="button" class="btn btn--danger" data-action="delete" ${deleteDisabled}${protectTitle}>Delete</button>
          `.trim();
        })();

        const actionsWrap = `<div class="usersTable__actions">${actionsCell}</div>`;

        return `
          <tr data-username="${safeName}">
            <td>
              <div class="usersTable__identity">
                <strong>${safeName}</strong>
              </div>
            </td>
            <td>${isEditing ? accessChecks('budget', p.budget) : accessDisplay('budget', p.budget)}</td>
            <td>${isEditing ? accessChecks('income', p.income) : accessDisplay('income', p.income)}</td>
            <td>${isEditing ? accessChecks('orders', p.orders) : accessDisplay('orders', p.orders)}</td>
            <td>${isEditing ? accessChecks('ledger', p.ledger) : accessDisplay('ledger', p.ledger)}</td>
            <td>${isEditing ? accessChecks('settings', p.settings) : accessDisplay('settings', p.settings)}</td>
            <td class="actions">${actionsWrap}</td>
          </tr>
          <tr class="usersTable__detailsRow" data-details-for="${safeName}">
            <td>${emailDetailsCell}</td>
            <td colspan="5">${passwordDetailsCell}</td>
            <td></td>
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

  async function createUser(usernameRaw, passwordRaw, permissions, emailRaw) {
    const username = normalizeUsername(usernameRaw);
    const password = String(passwordRaw || '').trim();
    const email = normalizeEmail(emailRaw);
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

  async function updateUser(usernameRaw, nextPermissions, newPasswordRaw, nextEmailRaw) {
    const username = normalizeUsername(usernameRaw);
    const newPassword = String(newPasswordRaw || '').trim();
    const nextEmail = normalizeEmail(nextEmailRaw);
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
    const updated = { ...current, permissions: nextPerms, email: nextEmail, updatedAt: nowIso };

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
    const safe = Array.isArray(items) ? items : [];
    localStorage.setItem(BACKLOG_KEY, JSON.stringify(safe));
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

  function openSimpleModal(modalEl, focusSelector) {
    if (!modalEl) return;
    modalEl.classList.add('is-open');
    modalEl.setAttribute('aria-hidden', 'false');
    const focusTarget = focusSelector ? modalEl.querySelector(focusSelector) : null;
    if (focusTarget && typeof focusTarget.focus === 'function') focusTarget.focus();
  }

  function closeSimpleModal(modalEl) {
    if (!modalEl) return;
    modalEl.classList.remove('is-open');
    modalEl.setAttribute('aria-hidden', 'true');
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
              <button type="button" class="btn btn--viewGrey" data-backlog-action="comment" ${actionsDisabled ? 'disabled data-tooltip="Read only access."' : ''}>Comment</button>
              <button type="button" class="btn btn--editBlue" data-backlog-action="edit" ${actionsDisabled ? 'disabled data-tooltip="Read only access."' : ''}>Edit</button>
              <button type="button" class="btn" data-backlog-action="complete" ${actionsDisabled ? 'disabled data-tooltip="Read only access."' : ''}>${escapeHtml(completeText)}</button>
              <button type="button" class="btn btn--danger" data-backlog-action="delete" ${actionsDisabled ? 'disabled data-tooltip="Read only access."' : ''}>Delete</button>
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
        if (!isViewAction && !canEdit) return;

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
            if (!requireWriteAccess('settings', 'Settings is read only for your account.')) throw new Error('not_authorized');
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
        } else {
          comments.push({
            id: (crypto?.randomUUID ? crypto.randomUUID() : `c_${Date.now()}_${Math.random().toString(16).slice(2)}`),
            at: now,
            by,
            text,
          });
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
        comments.splice(editIdx, 1);

        const next = items.slice();
        next[idx] = { ...current, comments };
        saveBacklogItems(next);

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

    function isInteractiveTarget(t) {
      if (!t || !t.closest) return false;
      return Boolean(t.closest('input, textarea, select, button, a, label'));
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
        if (isInteractiveTarget(e.target)) {
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

    for (const year of yearsToInclude) {
      const orders = loadOrders(year);
      for (const order of orders || []) {
        if (!order || typeof order !== 'object') continue;
        let timeline = Array.isArray(order.timeline) ? order.timeline : [];
        if (timeline.length === 0) {
          timeline = ensureOrderTimeline(order);
          // Persist a seeded timeline once so the Activity Log is truly recorded.
          // (Avoid fabricating timestamps: only persist if the record already has createdAt.)
          if (order.createdAt) {
            upsertOrder({ ...order, timeline }, year);
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
          if (isHardcodedAdminUsername(user)) continue;
          const action = e.action !== undefined ? String(e.action || '—') : (i === 0 ? 'Created' : 'Edited');
          const isCreated = String(action).trim().toLowerCase() === 'created';
          let changes = Array.isArray(e.changes) ? e.changes : [];
          if (isCreated) changes = [];
          events.push({ ms, at: String(e.at), module: `Payment Orders (${year})`, record, user, action, changes });
        }
      }

      const income = loadIncome(year);
      for (const entry of income || []) {
        if (!entry || typeof entry !== 'object') continue;
        let timeline = Array.isArray(entry.timeline) ? entry.timeline : [];
        if (timeline.length === 0) {
          timeline = ensureIncomeTimeline(entry);
          // Persist a seeded timeline once so the Activity Log is truly recorded.
          // (Avoid fabricating timestamps: only persist if the record already has createdAt.)
          if (entry.createdAt) {
            upsertIncomeEntry({ ...entry, timeline }, year);
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
          if (isHardcodedAdminUsername(user)) continue;
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
        .filter((e) => !isHardcodedAdminUsername(e.user))
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

    const hasAnyUsers = loadUsers().length > 0;
    const currentUser = getCurrentUser();
    const canEdit = !hasAnyUsers || (currentUser ? canWrite(currentUser, 'settings') : false);

    const createUserModal = document.getElementById('createUserModal');
    const openCreateUserBtn = document.getElementById('openCreateUserBtn');
    const usersSearchInput = document.getElementById('usersSearch');
    const usersClearSearchBtn = document.getElementById('usersClearSearchBtn');

    // Settings page: allow each user to reorder cards (persisted via cookie).
    initSettingsCardsDragAndDrop();
    installSettingsCardGearButtons();

    // Settings page: keep card headers fixed; only body content scrolls.
    prepareSettingsCardsStickyHeaders();

    renderUsersTable();

    // Settings page: allow manually resizing User Roles table columns.
    initUsersTableColumnResizer();

    // Backlog (CRUD + comments)
    initBacklogSettingsSection(canEdit);

    // Timeline audit log (Payment Orders + Income)
    renderSettingsAuditLog();

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
          renderSettingsAuditLog();
        }
        if (key === BACKLOG_KEY) {
          renderBacklogList(canEdit);
        }
      });
    }

    function resetCreateUserForm() {
      const errUser = document.getElementById('error-newUsername');
      const errEmail = document.getElementById('error-newEmail');
      const errPass = document.getElementById('error-newPassword');
      if (errUser) errUser.textContent = '';
      if (errEmail) errEmail.textContent = '';
      if (errPass) errPass.textContent = '';

      const newUsername = document.getElementById('newUsername');
      const newEmail = document.getElementById('newEmail');
      const newPassword = document.getElementById('newPassword');
      if (newUsername) newUsername.value = '';
      if (newEmail) newEmail.value = '';
      if (newPassword) newPassword.value = '';

      [
        'permBudgetWrite', 'permBudgetPartial', 'permBudgetRead',
        'permIncomeWrite', 'permIncomePartial', 'permIncomeRead',
        'permOrdersWrite', 'permOrdersPartial', 'permOrdersRead',
        'permLedgerWrite', 'permLedgerPartial', 'permLedgerRead',
        'permSettingsWrite', 'permSettingsPartial', 'permSettingsRead',
        'permAllWrite', 'permAllPartial', 'permAllRead',
      ].forEach((id) => {
        const el = document.getElementById(id);
        if (el) el.checked = false;
      });
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

      const STORAGE_KEY = 'acgl_usersTable_colWidths_v1';

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
        } catch {
          // ignore
        }
      };

      const headerRow = tableEl.tHead && tableEl.tHead.rows && tableEl.tHead.rows[0] ? tableEl.tHead.rows[0] : null;
      if (!headerRow) return;
      const ths = Array.from(headerRow.cells || []);
      if (ths.length < 2) return;

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

      const applyWidths = (nextWidths, { persist } = { persist: false }) => {
        if (isNarrow()) return;
        widths = nextWidths.slice(0, ths.length);
        while (widths.length < ths.length) widths.push(80);

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
      if (stored && stored.length >= ths.length - 1 && !isNarrow()) {
        applyWidths(stored, { persist: false });
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

    let hideCreateUserTooltip = () => {};

    function initCreateUserModalTooltips(modalEl) {
      if (!modalEl || modalEl.dataset.rolesTooltipBound) return;
      modalEl.dataset.rolesTooltipBound = '1';

      const TOOLTIP_SELECTOR = '.rolesGrid__check[data-tooltip]';
      const margin = 12;
      const gap = 10;
      let tooltipEl = null;
      let activeTarget = null;
      let rafId = 0;

      const ensureTooltipEl = () => {
        if (tooltipEl) return tooltipEl;
        tooltipEl = document.createElement('div');
        tooltipEl.className = 'floatingTooltip';
        tooltipEl.setAttribute('role', 'tooltip');
        tooltipEl.style.display = 'none';
        document.body.appendChild(tooltipEl);
        return tooltipEl;
      };

      const clamp = (v, min, max) => Math.max(min, Math.min(max, v));

      const positionTooltipFor = (target) => {
        if (!target) return;
        const text = String(target.getAttribute('data-tooltip') || '').trim();
        if (!text) return;

        const el = ensureTooltipEl();
        el.textContent = text;
        el.style.display = 'block';
        el.style.visibility = 'hidden';
        el.style.left = '0px';
        el.style.top = '0px';

        const targetRect = target.getBoundingClientRect();

        // Measure tooltip with the new content
        const tipRect = el.getBoundingClientRect();
        const maxLeft = window.innerWidth - margin - tipRect.width;
        const left = clamp(targetRect.left, margin, maxLeft);

        const belowTop = targetRect.bottom + gap;
        const aboveTop = targetRect.top - gap - tipRect.height;
        const fitsBelow = belowTop + tipRect.height <= window.innerHeight - margin;
        const fitsAbove = aboveTop >= margin;

        let top = fitsBelow || !fitsAbove ? belowTop : aboveTop;
        top = clamp(top, margin, window.innerHeight - margin - tipRect.height);

        el.style.left = `${Math.round(left)}px`;
        el.style.top = `${Math.round(top)}px`;
        el.style.visibility = 'visible';
      };

      const scheduleReposition = () => {
        if (!activeTarget) return;
        if (rafId) return;
        rafId = window.requestAnimationFrame(() => {
          rafId = 0;
          positionTooltipFor(activeTarget);
        });
      };

      const hide = () => {
        activeTarget = null;
        if (rafId) {
          window.cancelAnimationFrame(rafId);
          rafId = 0;
        }
        if (tooltipEl) {
          tooltipEl.style.display = 'none';
          tooltipEl.textContent = '';
        }
      };

      hideCreateUserTooltip = hide;

      const findTarget = (node) => (node && node.closest ? node.closest(TOOLTIP_SELECTOR) : null);

      modalEl.addEventListener('mouseover', (e) => {
        const t = findTarget(e.target);
        if (!t) return;
        if (activeTarget === t) return;
        activeTarget = t;
        positionTooltipFor(activeTarget);
      });

      modalEl.addEventListener('mouseout', (e) => {
        if (!activeTarget) return;
        const from = findTarget(e.target);
        if (!from || from !== activeTarget) return;
        const to = e.relatedTarget;
        if (to && from.contains && from.contains(to)) return;
        hide();
      });

      modalEl.addEventListener('focusin', (e) => {
        const t = findTarget(e.target);
        if (!t) return;
        activeTarget = t;
        positionTooltipFor(activeTarget);
      });

      modalEl.addEventListener('focusout', (e) => {
        if (!activeTarget) return;
        const from = findTarget(e.target);
        if (!from || from !== activeTarget) return;
        const to = e.relatedTarget;
        if (to && from.contains && from.contains(to)) return;
        hide();
      });

      const bodyEl = modalEl.querySelector ? modalEl.querySelector('.modal__body') : null;
      if (bodyEl && !bodyEl.dataset.rolesTooltipScrollBound) {
        bodyEl.dataset.rolesTooltipScrollBound = '1';
        bodyEl.addEventListener('scroll', scheduleReposition, { passive: true });
      }

      if (!window.__acglRolesTooltipResizeBound) {
        window.__acglRolesTooltipResizeBound = true;
        window.addEventListener('resize', scheduleReposition);
      }
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
      openCreateUserBtn.disabled = hasAnyUsers && !canEdit;
      if (openCreateUserBtn.disabled) {
        openCreateUserBtn.setAttribute('data-tooltip', 'Read-only: your account cannot add users.');
      } else {
        openCreateUserBtn.removeAttribute('data-tooltip');
      }

      if (!openCreateUserBtn.dataset.bound) {
        openCreateUserBtn.dataset.bound = '1';
        openCreateUserBtn.addEventListener('click', () => {
          if (hasAnyUsers && !canEdit) {
            window.alert('This Settings page is read only for your account.');
            return;
          }
          resetCreateUserForm();
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
        renderUsersTable();
      });
    }

    if (usersClearSearchBtn && usersSearchInput && !usersClearSearchBtn.dataset.bound) {
      usersClearSearchBtn.dataset.bound = '1';
      usersClearSearchBtn.addEventListener('click', () => {
        usersSearchInput.value = '';
        usersTableViewState.globalFilter = '';
        usersClearSearchBtn.hidden = true;
        renderUsersTable();
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
      const p = document.getElementById(`perm${moduleKey}Partial`);
      const r = document.getElementById(`perm${moduleKey}Read`);
      if (w) w.checked = lv === 'write';
      if (p) p.checked = lv === 'partial';
      if (r) r.checked = lv === 'read';
    }

    const pairs = [
      ['Budget', 'budget'],
      ['Income', 'income'],
      ['Orders', 'orders'],
      ['Ledger', 'ledger'],
      ['Settings', 'settings'],
    ];

    // Bind mutual exclusivity for each module checkbox group in the create-user form.
    bindExclusiveCheckboxGroup(
      document.getElementById('permBudgetWrite'),
      document.getElementById('permBudgetPartial'),
      document.getElementById('permBudgetRead')
    );
    bindExclusiveCheckboxGroup(
      document.getElementById('permIncomeWrite'),
      document.getElementById('permIncomePartial'),
      document.getElementById('permIncomeRead')
    );
    bindExclusiveCheckboxGroup(
      document.getElementById('permOrdersWrite'),
      document.getElementById('permOrdersPartial'),
      document.getElementById('permOrdersRead')
    );
    bindExclusiveCheckboxGroup(
      document.getElementById('permLedgerWrite'),
      document.getElementById('permLedgerPartial'),
      document.getElementById('permLedgerRead')
    );
    bindExclusiveCheckboxGroup(
      document.getElementById('permSettingsWrite'),
      document.getElementById('permSettingsPartial'),
      document.getElementById('permSettingsRead')
    );

    const allWrite = document.getElementById('permAllWrite');
    const allPartial = document.getElementById('permAllPartial');
    const allRead = document.getElementById('permAllRead');
    if (allWrite && allRead && !allWrite.dataset.bound) {
      allWrite.dataset.bound = 'true';
      allWrite.disabled = hasAnyUsers && !canEdit;
      if (allPartial) allPartial.disabled = hasAnyUsers && !canEdit;
      allRead.disabled = hasAnyUsers && !canEdit;

      bindExclusiveCheckboxGroup(allWrite, allPartial, allRead);

      allWrite.addEventListener('change', () => {
        if (allWrite.checked) {
          setModuleAccess('Budget', 'write');
          setModuleAccess('Income', 'write');
          setModuleAccess('Orders', 'write');
          setModuleAccess('Ledger', 'write');
          setModuleAccess('Settings', 'write');
        } else {
          setModuleAccess('Budget', 'none');
          setModuleAccess('Income', 'none');
          setModuleAccess('Orders', 'none');
          setModuleAccess('Ledger', 'none');
          setModuleAccess('Settings', 'none');
        }
      });
      allRead.addEventListener('change', () => {
        if (allRead.checked) {
          setModuleAccess('Budget', 'read');
          setModuleAccess('Income', 'read');
          setModuleAccess('Orders', 'read');
          setModuleAccess('Ledger', 'read');
          setModuleAccess('Settings', 'read');
        } else {
          setModuleAccess('Budget', 'none');
          setModuleAccess('Income', 'none');
          setModuleAccess('Orders', 'none');
          setModuleAccess('Ledger', 'none');
          setModuleAccess('Settings', 'none');
        }
      });

      if (allPartial) {
        allPartial.addEventListener('change', () => {
          if (allPartial.checked) {
            setModuleAccess('Budget', 'partial');
            setModuleAccess('Income', 'partial');
            setModuleAccess('Orders', 'partial');
            setModuleAccess('Ledger', 'partial');
            setModuleAccess('Settings', 'partial');
          } else {
            setModuleAccess('Budget', 'none');
            setModuleAccess('Income', 'none');
            setModuleAccess('Orders', 'none');
            setModuleAccess('Ledger', 'none');
            setModuleAccess('Settings', 'none');
          }
        });
      }
    }

    if (logoutBtn && !logoutBtn.dataset.bound) {
      logoutBtn.dataset.bound = 'true';
      logoutBtn.addEventListener('click', () => {
        performLogout();
        window.location.reload();
      });
    }

    createUserForm.addEventListener('submit', async (e) => {
      e.preventDefault();

      if (loadUsers().length > 0 && !canEdit) {
        window.alert('This Settings page is read only for your account.');
        return;
      }

      const newUsername = document.getElementById('newUsername');
      const newEmail = document.getElementById('newEmail');
      const newPassword = document.getElementById('newPassword');
      const errUser = document.getElementById('error-newUsername');
      const errEmail = document.getElementById('error-newEmail');
      const errPass = document.getElementById('error-newPassword');
      if (errUser) errUser.textContent = '';
      if (errEmail) errEmail.textContent = '';
      if (errPass) errPass.textContent = '';

      const username = newUsername ? newUsername.value : '';
      const email = newEmail ? newEmail.value : '';
      const password = newPassword ? newPassword.value : '';

      const perms = {
        budget: document.getElementById('permBudgetWrite')?.checked
          ? 'write'
          : document.getElementById('permBudgetPartial')?.checked
            ? 'partial'
            : document.getElementById('permBudgetRead')?.checked
              ? 'read'
              : 'none',
        income: document.getElementById('permIncomeWrite')?.checked
          ? 'write'
          : document.getElementById('permIncomePartial')?.checked
            ? 'partial'
            : document.getElementById('permIncomeRead')?.checked
              ? 'read'
              : 'none',
        orders: document.getElementById('permOrdersWrite')?.checked
          ? 'write'
          : document.getElementById('permOrdersPartial')?.checked
            ? 'partial'
            : document.getElementById('permOrdersRead')?.checked
              ? 'read'
              : 'none',
        ledger: document.getElementById('permLedgerWrite')?.checked
          ? 'write'
          : document.getElementById('permLedgerPartial')?.checked
            ? 'partial'
            : document.getElementById('permLedgerRead')?.checked
              ? 'read'
              : 'none',
        settings: document.getElementById('permSettingsWrite')?.checked
          ? 'write'
          : document.getElementById('permSettingsPartial')?.checked
            ? 'partial'
            : document.getElementById('permSettingsRead')?.checked
              ? 'read'
              : 'none',
      };

      const hadNoUsers = loadUsers().length === 0;
      const res = await createUser(username, password, perms, email);
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

      if (newUsername) newUsername.value = '';
      if (newEmail) newEmail.value = '';
      if (newPassword) newPassword.value = '';
      [
        'permBudgetWrite', 'permBudgetPartial', 'permBudgetRead',
        'permIncomeWrite', 'permIncomePartial', 'permIncomeRead',
        'permOrdersWrite', 'permOrdersPartial', 'permOrdersRead',
        'permLedgerWrite', 'permLedgerPartial', 'permLedgerRead',
        'permSettingsWrite', 'permSettingsPartial', 'permSettingsRead',
        'permAllWrite', 'permAllPartial', 'permAllRead',
      ].forEach((id) => {
        const el = document.getElementById(id);
        if (el) el.checked = false;
      });

      renderUsersTable();

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

      if (!canEdit) {
        window.alert('This Settings page is read only for your account.');
        return;
      }
      const row = btn.closest('tr[data-username]');
      if (!row) return;

      const username = row.getAttribute('data-username');
      const action = btn.getAttribute('data-action');

      if (action === 'edit') {
        if (!username) return;
        usersTableViewState.editingUsername = normalizeUsername(username);
        renderUsersTable();
        return;
      }

      if (action === 'cancel') {
        usersTableViewState.editingUsername = null;
        renderUsersTable();
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
          renderUsersTable();
          return;
        }
        if (usersTableViewState.editingUsername && normalizeUsername(username) === usersTableViewState.editingUsername) {
          usersTableViewState.editingUsername = null;
        }
        renderUsersTable();
        return;
      }

      if (action === 'save') {
        if (!username) return;
        if (usersTableViewState.editingUsername !== normalizeUsername(username)) return;

        const detailsRow = (() => {
          const next = row.nextElementSibling;
          if (!next || !next.matches || !next.matches('tr[data-details-for]')) return null;
          const forName = next.getAttribute('data-details-for');
          if (normalizeUsername(forName) !== normalizeUsername(username)) return null;
          return next;
        })();

        const perms = { budget: 'none', income: 'none', orders: 'none', ledger: 'none', settings: 'none' };
        const inputs = Array.from(row.querySelectorAll('input[type="checkbox"][data-perm][data-level]'));
        for (const key of Object.keys(perms)) {
          const writeBox = inputs.find((el) => el.getAttribute('data-perm') === key && el.getAttribute('data-level') === 'write');
          const partialBox = inputs.find((el) => el.getAttribute('data-perm') === key && el.getAttribute('data-level') === 'partial');
          const readBox = inputs.find((el) => el.getAttribute('data-perm') === key && el.getAttribute('data-level') === 'read');
          perms[key] = writeBox && writeBox.checked ? 'write' : partialBox && partialBox.checked ? 'partial' : readBox && readBox.checked ? 'read' : 'none';
        }

        const pwEl = (detailsRow || row).querySelector('input[data-new-password]');
        // Only treat the password as changed if the admin actually typed in the field.
        // Password managers may autofill; we ignore those values.
        const pwTouched = pwEl && pwEl.dataset && pwEl.dataset.touched === '1';
        const typedPw = pwEl ? String(pwEl.value || '') : '';
        const currentPw = String((getUserByUsername(username) && getUserByUsername(username).passwordPlain) || '');
        const newPw = pwTouched && typedPw.trim() && typedPw !== currentPw ? typedPw : '';

        const emailEl = (detailsRow || row).querySelector('input[type="email"][data-email]');
        const nextEmail = emailEl ? String(emailEl.value || '') : '';

        const res = await updateUser(username, perms, newPw, nextEmail);
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
        renderUsersTable();

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

      const levels = ['write', 'partial', 'read'];
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
    localStorage.setItem(key, JSON.stringify(entries || []));
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
    localStorage.setItem(key, JSON.stringify(entries || []));
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
    const safe = map && typeof map === 'object' ? map : {};
    localStorage.setItem(key, JSON.stringify(safe));
  }

  function buildGsLedgerRowsForYear(year) {
    const verified = loadGsLedgerVerifiedMap(year);
    const rows = [];

    // Income rows
    const incomeEntries = loadIncome(year);
    for (const inc of Array.isArray(incomeEntries) ? incomeEntries : []) {
      if (!inc || !inc.id) continue;
      const ledgerId = `inc:${String(inc.id)}`;
      rows.push({
        ledgerId,
        date: String(inc.date || ''),
        budgetNumber: extractInCodeFromBudgetNumberText(inc.budgetNumber),
        creditorDebtor: String(inc.remitter || ''),
        paymentOrderNo: '',
        euro: inc.euro,
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
      const statusRaw = String(o.status || '').trim().toLowerCase();
      if (statusRaw !== 'approved' && statusRaw !== 'paid') continue;
      const ledgerId = `po:${String(o.id)}`;

      const euroRaw = String(o.euro ?? '').trim();
      const usdRaw = String(o.usd ?? '').trim();
      const euroNum = euroRaw === '' ? Number.NaN : Number(euroRaw);
      const usdNum = usdRaw === '' ? Number.NaN : Number(usdRaw);

      rows.push({
        ledgerId,
        date: String(o.date || ''),
        budgetNumber: extractInCodeFromBudgetNumberText(o.budgetNumber),
        creditorDebtor: String(o.name || ''),
        paymentOrderNo: String(o.paymentOrderNo || ''),
        euro: Number.isFinite(euroNum) ? -Math.abs(euroNum) : null,
        usd: Number.isFinite(usdNum) ? -Math.abs(usdNum) : null,
        verified: Boolean(verified[ledgerId]),
        with: String(o.with || ''),
        status: String(o.status || ''),
        details: String(o.purpose || ''),
      });
    }

    return rows;
  }

  const GS_LEDGER_COL_TYPES = {
    date: 'date',
    budgetNumber: 'text',
    creditorDebtor: 'text',
    paymentOrderNo: 'text',
    euro: 'number',
    usd: 'number',
    verified: 'boolean',
    with: 'text',
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
      case 'creditorDebtor':
        return row.creditorDebtor || '';
      case 'paymentOrderNo':
        return row.paymentOrderNo || '';
      case 'euro':
        return row.euro === null || row.euro === undefined || row.euro === '' ? '' : formatCurrency(row.euro, 'EUR');
      case 'usd':
        return row.usd === null || row.usd === undefined || row.usd === '' ? '' : formatCurrency(row.usd, 'USD');
      case 'verified':
        return row.verified ? 'Yes' : '';
      case 'with':
        return row.with || '';
      case 'status':
        return row.status || '';
      case 'details':
        return row.details || '';
      default:
        return '';
    }
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
        const date = escapeHtml(getGsLedgerDisplayValueForColumn(r, 'date'));
        const budgetCode = getGsLedgerDisplayValueForColumn(r, 'budgetNumber');
        const code = extractInCodeFromBudgetNumberText(budgetCode);
        const outMap = getOutDescMapForYear(year);
        const inMap = getInDescMapForYear(year);
        const desc = (code && outMap ? outMap.get(code) : '') || (code && inMap ? inMap.get(code) : '') || (code ? BUDGET_DESC_BY_CODE.get(code) : '') || inferDescFromBudgetNumberText(budgetCode);
        const budgetNumber = renderBudgetNumberSpanHtml(code || budgetCode, desc);
        const creditorDebtor = escapeHtml(getGsLedgerDisplayValueForColumn(r, 'creditorDebtor'));
        const poNo = escapeHtml(getGsLedgerDisplayValueForColumn(r, 'paymentOrderNo'));
        const euro = escapeHtml(getGsLedgerDisplayValueForColumn(r, 'euro'));
        const usd = escapeHtml(getGsLedgerDisplayValueForColumn(r, 'usd'));
        const withVal = escapeHtml(getGsLedgerDisplayValueForColumn(r, 'with'));
        const status = escapeHtml(getGsLedgerDisplayValueForColumn(r, 'status'));
        const details = escapeHtml(getGsLedgerDisplayValueForColumn(r, 'details'));

        const checked = r.verified ? 'checked' : '';
        const verifyDisabled = canVerify ? '' : 'disabled';
        return `
          <tr data-ledger-id="${ledgerId}">
            <td>${date}</td>
            <td>${budgetNumber}</td>
            <td>${creditorDebtor}</td>
            <td>${poNo}</td>
            <td class="num">${euro}</td>
            <td class="num">${usd}</td>
            <td class="num">
              <input type="checkbox" data-ledger-verify="1" data-ledger-id="${ledgerId}" aria-label="Verified" ${checked} ${verifyDisabled} />
            </td>
            <td>${withVal}</td>
            <td>${status}</td>
            <td>${details}</td>
          </tr>
        `.trim();
      })
      .join('');

    gsLedgerTbody.innerHTML = html;
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
    if (!euroEl && !usdEl) return;

    let totalEuro = 0;
    let totalUsd = 0;
    for (const r of rows || []) {
      const e = Number(r && r.euro);
      const u = Number(r && r.usd);
      if (Number.isFinite(e)) totalEuro += e;
      if (Number.isFinite(u)) totalUsd += u;
    }

    if (euroEl) euroEl.textContent = formatCurrency(totalEuro, 'EUR');
    if (usdEl) usdEl.textContent = formatCurrency(totalUsd, 'USD');
  }

  function initGsLedgerListPage() {
    if (!gsLedgerTbody || !gsLedgerEmptyState) return;
    const year = getActiveBudgetYear();

    const user = getCurrentUser();
    gsLedgerViewState.canVerify = Boolean(user && canWrite(user, 'ledger'));

    const exportCsvLink = document.getElementById('gsLedgerExportCsvLink');
    const gsLedgerWiseEurBtn = document.getElementById('gsLedgerWiseEurBtn');
    const gsLedgerWiseUsdBtn = document.getElementById('gsLedgerWiseUsdBtn');
    const menuBtn = document.getElementById('gsLedgerActionsMenuBtn');
    const menuPanel = document.getElementById('gsLedgerActionsMenu');

    if (gsLedgerWiseEurBtn && !gsLedgerWiseEurBtn.dataset.bound) {
      gsLedgerWiseEurBtn.dataset.bound = '1';
      gsLedgerWiseEurBtn.addEventListener('click', () => {
        window.location.href = `wise_eur.html?year=${encodeURIComponent(String(year))}`;
      });
    }

    if (gsLedgerWiseEurBtn) {
      gsLedgerWiseEurBtn.textContent = `${year} wiseEUR`;
      gsLedgerWiseEurBtn.title = `Open the ${year} wiseEUR grid`;
    }

    if (gsLedgerWiseUsdBtn && !gsLedgerWiseUsdBtn.dataset.bound) {
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
      const header = ['Date', 'Budget Number', 'Creditor/Debtor', 'Payment Order Nr.', 'Euro (€)', 'USD ($)', 'Verified', 'With', 'Status', 'Details'];
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
        if (key.startsWith('payment_orders_') || key.startsWith('payment_order_income_') || key.startsWith('payment_order_gs_ledger_verified_')) {
          applyGsLedgerView();
        }
      });
    }

    applyGsLedgerView();
  }

  /** @returns {Array<Object>} */
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
    const next = all.filter((e) => e && e.id !== id);
    saveIncome(next, y);
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
        const desc = escapeHtml(getIncomeDisplayValueForColumn(e, 'description', year));

        return `
          <tr${rowClass} data-income-id="${id}">
            <td class="col-delete">
              <button
                type="button"
                class="btn btn--x"
                data-income-action="delete"
                aria-label="Delete entry"
                title="Delete"
              >
                X
              </button>
            </td>
            <td>${date}</td>
            <td>${remitter}</td>
            <td>${budget}</td>
            <td class="num">${euro}</td>
            <td>${desc}</td>
            <td class="actions">
              <button type="button" class="btn btn--editBlue" data-income-action="edit">Edit</button>
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
            <input id="incomeEuro" name="incomeEuro" type="number" inputmode="decimal" step="0.01" min="0" required value="${safeEuro}" />
            <div class="error" id="error-incomeEuro" role="alert" aria-live="polite"></div>
          </div>

          <div class="field">
            <label for="incomeRemitter">Remitter<span class="req" aria-hidden="true">*</span></label>
            <input id="incomeRemitter" name="incomeRemitter" type="text" autocomplete="off" required value="${safeRemitter}" />
            <div class="error" id="error-incomeRemitter" role="alert" aria-live="polite"></div>
          </div>

          <div class="field field--span2">
            <label for="incomeBudgetNumber">Budget Number</label>
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
    if (!values.euro) errors.euro = 'This field is required.';
    else if (!Number.isFinite(euroNum) || euroNum < 0) errors.euro = 'Enter a valid amount.';

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
    const incomeLevel = currentUser ? getEffectivePermissions(currentUser).income : 'none';
    const hasIncomeFullAccess = incomeLevel === 'write';

    const incomeNewLink = document.getElementById('incomeNewLink');
    const incomeExportCsvLink = document.getElementById('incomeExportCsvLink');
    const incomeDownloadTemplateLink = document.getElementById('incomeDownloadTemplateLink');
    const incomeImportCsvLink = document.getElementById('incomeImportCsvLink');
    const incomeMenuBtn = document.getElementById('incomeActionsMenuBtn');
    const incomeMenuPanel = document.getElementById('incomeActionsMenu');

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

    // Ensure older/mock/imported Income entries are reflected in the Budget receipts.
    backfillIncomeBudgetReceiptImpactsIfNeeded(year);

    const titleEl = document.querySelector('[data-income-title]');
    if (titleEl) titleEl.textContent = `${year} Income`;
    const listTitleEl = document.querySelector('[data-income-list-title]');
    if (listTitleEl) listTitleEl.textContent = `${year} Income`;
    applyAppTabTitle();

    initIncomeColumnSorting();

    // Partial access for Income = full access except New Income and Import CSV.
    setLinkDisabled(incomeNewLink, !hasIncomeFullAccess);
    if (incomeNewLink && !hasIncomeFullAccess) {
      incomeNewLink.setAttribute(
        'data-tooltip',
        'Requires Full access for Income. Partial access can edit existing income entries, but cannot create New Income entries.'
      );
    }
    setLinkDisabled(incomeImportCsvLink, !hasIncomeFullAccess);
    if (incomeImportCsvLink && !hasIncomeFullAccess) {
      incomeImportCsvLink.setAttribute(
        'data-tooltip',
        'Requires Full access for Income. Partial access can edit existing income entries, but cannot Import CSV.'
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
        if (incomeNewLink.getAttribute('aria-disabled') === 'true') return;
        if (!requireWriteAccess('income', 'Income is read only for your account.')) return;
        openIncomeModal(null, year);
        if (incomeMenuPanel && incomeMenuBtn) {
          incomeMenuPanel.setAttribute('hidden', '');
          incomeMenuBtn.setAttribute('aria-expanded', 'false');
        }
      });
    }

    if (incomeClearAllBtn) {
      incomeClearAllBtn.addEventListener('click', () => {
        if (!requireIncomeEditAccess('Income is read only for your account.')) return;
        const all = loadIncome(year);
        if (all.length === 0) return;
        const ok = window.confirm('Clear all income entries? This cannot be undone.');
        if (!ok) return;

        // Reverse any previously-applied Budget receipts impacts before clearing.
        const byCode = new Map();
        for (const e of all) {
          const imp = e && e.budgetReceiptImpact && typeof e.budgetReceiptImpact === 'object' ? e.budgetReceiptImpact : null;
          const code = imp ? String(imp.inCode || '').trim() : '';
          const euro = imp ? Number(imp.euro) : NaN;
          if (!/^[0-9]{4}$/.test(code)) continue;
          if (!Number.isFinite(euro) || euro === 0) continue;
          byCode.set(code, (byCode.get(code) || 0) + euro);
        }
        const deltas = Array.from(byCode.entries()).map(([inCode, sumEuro]) => ({ inCode, deltaEuro: -sumEuro }));
        if (deltas.length > 0) {
          const budgetRes = applyIncomeBudgetReceiptsDeltas(year, deltas);
          if (!budgetRes || !budgetRes.ok) {
            const code = budgetRes && budgetRes.inCode ? ` (${budgetRes.inCode})` : '';
            window.alert(`Could not update Budget receipts${code}.\n\nIncome was not cleared. Please verify the ${year} Budget exists and contains the matching IN code.`);
            return;
          }
        }

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
      const header = ['Transaction Date', 'Remitter', 'Budget Number', 'Euro', 'Description'];
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
      const header = ['Transaction Date', 'Remitter', 'Budget Number', 'Euro', 'Description'];
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

        // Negative amounts are expenditures: skip Income import and create Payment Orders instead.
        if (euroSigned < 0) {
          const absEuro = Math.abs(euroSigned);
          const itemTitle = description || 'Imported from Income CSV';
          const po = buildPaymentOrder({
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
          continue;
        }

        const euroNum = parseEuroAmount(String(euroSigned));
        if (euroNum === null) {
          errors.push(`Row ${rowNo}: Euro must be 0 or greater.`);
          continue;
        }

        const inc = {
          id: (crypto?.randomUUID ? crypto.randomUUID() : `inc_${Date.now()}_${Math.random().toString(16).slice(2)}`),
          createdAt: nowIso,
          updatedAt: nowIso,
          date,
          remitter,
          budgetNumber,
          euro: euroNum,
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

      // Apply Budget receipts impacts for any newly imported rows that have Budget Numbers.
      if (imported.length > 0) backfillIncomeBudgetReceiptImpactsIfNeeded(year);
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
        if (incomeImportCsvLink.getAttribute('aria-disabled') === 'true') return;
        if (!requireWriteAccess('income', 'Income is read only for your account.')) return;
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
      const btn = e.target.closest('button[data-income-action]');
      if (!btn) return;
      const row = btn.closest('tr[data-income-id]');
      if (!row) return;
      const id = row.getAttribute('data-income-id');
      const action = btn.getAttribute('data-income-action');

      if (action === 'delete') {
        if (!requireIncomeEditAccess('Income is read only for your account.')) return;
        const ok = window.confirm('Delete this income entry?');
        if (!ok) return;

        const all = loadIncome(year);
        const entry = all.find((x) => x && x.id === id);
        const imp = entry && entry.budgetReceiptImpact && typeof entry.budgetReceiptImpact === 'object' ? entry.budgetReceiptImpact : null;
        const code = imp ? String(imp.inCode || '').trim() : '';
        const euro = imp ? Number(imp.euro) : NaN;
        if (/^[0-9]{4}$/.test(code) && Number.isFinite(euro) && euro !== 0) {
          const budgetRes = applyIncomeBudgetReceiptsDeltas(year, [{ inCode: code, deltaEuro: -euro }]);
          if (!budgetRes || !budgetRes.ok) {
            window.alert(`Could not update Budget receipts (${code}).\n\nIncome was not deleted. Please verify the ${year} Budget exists and contains the matching IN code.`);
            return;
          }
        }

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
        if (!requireIncomeEditAccess('Income is read only for your account.')) return;
        if (!hasIncomeFullAccess && !currentIncomeId) {
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

        // If this income entry has a Budget Number (IN code), roll its Euro amount into the
        // matching Budget year's "Receipts Euro" for that IN code.
        const prevImpact = existing && existing.budgetReceiptImpact && typeof existing.budgetReceiptImpact === 'object'
          ? {
            inCode: String(existing.budgetReceiptImpact.inCode || '').trim(),
            euro: Number(existing.budgetReceiptImpact.euro),
          }
          : null;

        const desiredInCode = extractInCodeFromBudgetNumberText(entry.budgetNumber);
        const desiredEuro = Number(entry.euro);
        const desiredImpact = (/^[0-9]{4}$/.test(desiredInCode) && Number.isFinite(desiredEuro) && desiredEuro > 0)
          ? { inCode: desiredInCode, euro: desiredEuro }
          : null;

        const deltas = [];
        if (prevImpact && /^[0-9]{4}$/.test(prevImpact.inCode) && Number.isFinite(prevImpact.euro) && prevImpact.euro !== 0) {
          if (desiredImpact && desiredImpact.inCode === prevImpact.inCode) {
            const delta = desiredImpact.euro - prevImpact.euro;
            if (delta !== 0) deltas.push({ inCode: prevImpact.inCode, deltaEuro: delta });
          } else {
            deltas.push({ inCode: prevImpact.inCode, deltaEuro: -prevImpact.euro });
          }
        }
        if (desiredImpact) {
          if (!prevImpact || desiredImpact.inCode !== prevImpact.inCode) {
            deltas.push({ inCode: desiredImpact.inCode, deltaEuro: desiredImpact.euro });
          }
        }

        if (deltas.length > 0) {
          const budgetRes = applyIncomeBudgetReceiptsDeltas(year, deltas);
          if (!budgetRes || !budgetRes.ok) {
            const code = budgetRes && budgetRes.inCode ? ` (${budgetRes.inCode})` : '';
            window.alert(`Could not update Budget receipts${code}.\n\nIncome was not saved. Please verify the ${year} Budget exists and contains the matching IN code.`);
            return;
          }
        }

        if (desiredImpact) {
          entry.budgetReceiptImpact = {
            at: nowIso,
            year: Number(year),
            inCode: desiredImpact.inCode,
            euro: desiredImpact.euro,
          };
        } else if (prevImpact) {
          delete entry.budgetReceiptImpact;
        }

        upsertIncomeEntry(entry, year);
        applyIncomeView();
        closeIncomeModal();
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
    const activeYear = getActiveBudgetYear();
    const inMap = getInDescMapForYear(activeYear);
    const outMap = getOutDescMapForYear(activeYear);
    const html = (entries || [])
      .map((e) => {
        const id = escapeHtml(e.id);
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
        const description = escapeHtml(getWiseEurDisplayValueForColumn(e, 'description'));
        const issuanceDateBank = escapeHtml(getWiseEurDisplayValueForColumn(e, 'issuanceDateBank'));
        const verifiedChecked = getWiseEurVerified(e) ? 'checked' : '';
        const verifyDisabled = canVerify ? '' : 'disabled';
        const checksum = escapeHtml(getWiseEurDisplayValueForColumn(e, 'checksum'));
        const bankStatements = escapeHtml(getWiseEurDisplayValueForColumn(e, 'bankStatements'));

        return `
          <tr data-wise-eur-id="${id}">
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
              <button type="button" class="btn btn--editBlue" data-wise-eur-action="edit">Edit</button>
              <button type="button" class="btn btn--x" data-wise-eur-action="delete" aria-label="Delete entry" title="Delete">X</button>
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

    const idTrackRaw = entry && entry.idTrack ? String(entry.idTrack).trim() : '';
    const currentIdTrackDisplay = idTrackRaw ? formatPaymentOrderNoForDisplay(idTrackRaw) : '';
    const safeIdTrack = escapeHtml(currentIdTrackDisplay);

    const paymentOrderYear = getActiveBudgetYear();
    ensurePaymentOrdersListExistsForYear(paymentOrderYear);
    const byCanonical = new Map();
    for (const order of loadOrders(paymentOrderYear) || []) {
      const display = formatPaymentOrderNoForDisplay(order && order.paymentOrderNo);
      if (!display) continue;
      const canonical = canonicalizePaymentOrderNo(display);
      if (canonical && !byCanonical.has(canonical)) byCanonical.set(canonical, display);
    }
    if (currentIdTrackDisplay) {
      const canonical = canonicalizePaymentOrderNo(currentIdTrackDisplay);
      if (canonical && !byCanonical.has(canonical)) byCanonical.set(canonical, currentIdTrackDisplay);
    }

    const sortedOrderNoDisplays = Array.from(byCanonical.values()).sort((a, b) =>
      String(a).localeCompare(String(b), undefined, { numeric: true, sensitivity: 'base' })
    );
    const wiseEurIdTrackOptionsHtml = sortedOrderNoDisplays
      .map((display) => {
        const safe = escapeHtml(display);
        const selected = display === currentIdTrackDisplay ? ' selected' : '';
        return `<option value="${safe}"${selected}>${safe}</option>`;
      })
      .join('');
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

          <div class="field">
            <label for="wiseEurIdTrack"># ID-TRACK</label>
            <select id="wiseEurIdTrack" name="wiseEurIdTrack">
              <option value=""${safeIdTrack ? '' : ' selected'}></option>
              ${wiseEurIdTrackOptionsHtml}
            </select>
            <div class="error" id="error-wiseEurIdTrack" role="alert" aria-live="polite"></div>
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
      idTrack: '#error-wiseEurIdTrack',
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
    const idTrackEl = wiseEurModalBody.querySelector('#wiseEurIdTrack');
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
      idTrack: idTrackEl ? String(idTrackEl.value || '').trim() : '',
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
        idTrack: values.idTrack,
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

  function initWiseEurListPage() {
    if (!wiseEurTbody || !wiseEurEmptyState) return;
    const year = getWiseEurYear();

    const currentUser = getCurrentUser();
    const incomeLevel = currentUser ? getEffectivePermissions(currentUser).income : 'none';
    const hasIncomeFullAccess = incomeLevel === 'write';

    // Verified checkbox should be editable for Income Write/Partial.
    wiseEurViewState.canVerify = currentUser ? canIncomeEdit(currentUser) : false;

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
        if (wiseEurNewLink.getAttribute('aria-disabled') === 'true') return;
        if (!requireWriteAccess('income', 'Income is read only for your account.')) return;
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

      const existing = existingBefore;
      const merged = [...imported, ...(Array.isArray(existing) ? existing : [])];
      saveWiseEur(merged, year);
      applyWiseEurView();

      if (typeof showFlashToken === 'function') {
        showFlashToken(`Imported ${imported.length} wiseEUR row(s).`);
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
        if (wiseEurImportCsvLink.getAttribute('aria-disabled') === 'true') return;
        if (!requireWriteAccess('income', 'Income is read only for your account.')) return;
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
      const btn = e.target.closest('button[data-wise-eur-action]');
      if (!btn) return;
      const row = btn.closest('tr[data-wise-eur-id]');
      if (!row) return;
      const id = row.getAttribute('data-wise-eur-id');
      const action = btn.getAttribute('data-wise-eur-action');

      if (action === 'delete') {
        if (!requireIncomeEditAccess('Income is read only for your account.')) return;
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
        };

        upsertWiseEurEntry(entry, year);
        applyWiseEurView();
        closeWiseEurModal();
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
    const activeYear = getActiveBudgetYear();
    const inMap = getInDescMapForYear(activeYear);
    const outMap = getOutDescMapForYear(activeYear);
    const html = (entries || [])
      .map((e) => {
        const id = escapeHtml(e.id);
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
        const description = escapeHtml(getWiseUsdDisplayValueForColumn(e, 'description'));
        const issuanceDateBank = escapeHtml(getWiseUsdDisplayValueForColumn(e, 'issuanceDateBank'));
        const verifiedChecked = getWiseUsdVerified(e) ? 'checked' : '';
        const verifyDisabled = canVerify ? '' : 'disabled';
        const checksum = escapeHtml(getWiseUsdDisplayValueForColumn(e, 'checksum'));
        const bankStatements = escapeHtml(getWiseUsdDisplayValueForColumn(e, 'bankStatements'));

        return `
          <tr data-wise-usd-id="${id}">
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
              <button type="button" class="btn btn--editBlue" data-wise-usd-action="edit">Edit</button>
              <button type="button" class="btn btn--x" data-wise-usd-action="delete" aria-label="Delete entry" title="Delete">X</button>
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

    const idTrackRaw = entry && entry.idTrack ? String(entry.idTrack).trim() : '';
    const currentIdTrackDisplay = idTrackRaw ? formatPaymentOrderNoForDisplay(idTrackRaw) : '';
    const safeIdTrack = escapeHtml(currentIdTrackDisplay);

    const paymentOrderYear = getActiveBudgetYear();
    ensurePaymentOrdersListExistsForYear(paymentOrderYear);
    const byCanonical = new Map();
    for (const order of loadOrders(paymentOrderYear) || []) {
      const display = formatPaymentOrderNoForDisplay(order && order.paymentOrderNo);
      if (!display) continue;
      const canonical = canonicalizePaymentOrderNo(display);
      if (canonical && !byCanonical.has(canonical)) byCanonical.set(canonical, display);
    }
    if (currentIdTrackDisplay) {
      const canonical = canonicalizePaymentOrderNo(currentIdTrackDisplay);
      if (canonical && !byCanonical.has(canonical)) byCanonical.set(canonical, currentIdTrackDisplay);
    }

    const sortedOrderNoDisplays = Array.from(byCanonical.values()).sort((a, b) =>
      String(a).localeCompare(String(b), undefined, { numeric: true, sensitivity: 'base' })
    );
    const wiseUsdIdTrackOptionsHtml = sortedOrderNoDisplays
      .map((display) => {
        const safe = escapeHtml(display);
        const selected = display === currentIdTrackDisplay ? ' selected' : '';
        return `<option value="${safe}"${selected}>${safe}</option>`;
      })
      .join('');
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

          <div class="field">
            <label for="wiseUsdIdTrack"># ID-TRACK</label>
            <select id="wiseUsdIdTrack" name="wiseUsdIdTrack">
              <option value=""${safeIdTrack ? '' : ' selected'}></option>
              ${wiseUsdIdTrackOptionsHtml}
            </select>
            <div class="error" id="error-wiseUsdIdTrack" role="alert" aria-live="polite"></div>
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
      idTrack: '#error-wiseUsdIdTrack',
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
    const idTrackEl = wiseUsdModalBody.querySelector('#wiseUsdIdTrack');
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
      idTrack: idTrackEl ? String(idTrackEl.value || '').trim() : '',
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
        idTrack: values.idTrack,
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
    const hasIncomeFullAccess = incomeLevel === 'write';

    // Verified checkbox should be editable for Income Write/Partial.
    wiseUsdViewState.canVerify = currentUser ? canIncomeEdit(currentUser) : false;

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
        if (wiseUsdNewLink.getAttribute('aria-disabled') === 'true') return;
        if (!requireWriteAccess('income', 'Income is read only for your account.')) return;
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

      const existing = existingBefore;
      const merged = [...imported, ...(Array.isArray(existing) ? existing : [])];
      saveWiseUsd(merged, year);
      applyWiseUsdView();

      if (typeof showFlashToken === 'function') {
        showFlashToken(`Imported ${imported.length} wiseUSD row(s).`);
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
        if (wiseUsdImportCsvLink.getAttribute('aria-disabled') === 'true') return;
        if (!requireWriteAccess('income', 'Income is read only for your account.')) return;
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
      const btn = e.target.closest('button[data-wise-usd-action]');
      if (!btn) return;
      const row = btn.closest('tr[data-wise-usd-id]');
      if (!row) return;
      const id = row.getAttribute('data-wise-usd-id');
      const action = btn.getAttribute('data-wise-usd-action');

      if (action === 'delete') {
        if (!requireIncomeEditAccess('Income is read only for your account.')) return;
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

        upsertWiseUsdEntry(entry, year);
        applyWiseUsdView();
        closeWiseUsdModal();
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

  function initBudgetEditor() {
    const budgetYear = getActiveBudgetYear();
    const budgetKey = getBudgetTableKeyForYear(budgetYear);
    const editLink = document.getElementById('budgetEditLink');
    const dashboardLink = document.getElementById('budgetDashboardLink');
    const deactivateLink = document.getElementById('budgetDeactivateLink');
    const setActiveBtn = document.getElementById('budgetSetActiveBtn');
    const saveBtn = document.getElementById('budgetSaveBtn');
    const cancelBtn = document.getElementById('budgetCancelBtn');
    const newYearLink = document.getElementById('budgetNewYearLink');
    const addLineLink = document.getElementById('budgetAddLineLink');
    const removeLineLink = document.getElementById('budgetRemoveLineLink');
    const deleteBudgetLink = document.getElementById('budgetDeleteLink');
    const exportCsvLink = document.getElementById('budgetExportCsvLink');
    const downloadTemplateLink = document.getElementById('budgetDownloadTemplateLink');
    const importCsvLink = document.getElementById('budgetImportCsvLink');
    const menuBtn = document.getElementById('budgetActionsMenuBtn');
    const menuPanel = document.getElementById('budgetActionsMenu');
    const table = document.querySelector('table.budgetTable');
    if (!editLink || !saveBtn || !table) return;

    const currentUser = getCurrentUser();
    const budgetLevel = currentUser ? getEffectivePermissions(currentUser).budget : 'none';
    const hasBudgetFullAccess = budgetLevel === 'write';

    const tbody = table.querySelector('tbody');
    if (!tbody) return;

    function getBudgetTemplateRowsForSeeding(fallbackTbodyHtml) {
      const existing = loadBudgetTemplateRows();
      if (existing && existing.length) return existing;

      const active = loadActiveBudgetYear();
      if (active) {
        const fromActive = updateBudgetTemplateRowsFromBudgetYear(active);
        if (fromActive && fromActive.length) return fromActive;
      }

      // Last resort: derive from the static HTML template shipped with this page.
      const derived = readBudgetTemplateRowsFromTbodyHtml(fallbackTbodyHtml);
      return derived && derived.length ? derived : [];
    }

    function buildSeedBudgetTbodyHtmlFromTemplateRows(templateRows) {
      const normalized = Array.isArray(templateRows) ? templateRows.map(normalizeBudgetTemplateRow).filter(Boolean) : [];
      if (!normalized.length) return '';

      const section1 = normalized.filter((r) => r.section === 1);
      const section2 = normalized.filter((r) => r.section === 2);

      const seedTbody = document.createElement('tbody');
      for (const r of section1) {
        seedTbody.appendChild(
          buildDataRowFromRecord({
            in: r.in,
            out: r.out,
            description: r.description,
            approvedEuro: '0.00 €',
            receiptsEuro: '0.00 €',
            expendituresEuro: '0.00 €',
            balanceEuro: '0.00 €',
            receiptsUsd: '-',
            expendituresUsd: '-',
            calcReceiptsOp: r.calcReceiptsOp,
            calcExpendituresOp: r.calcExpendituresOp,
          })
        );
      }
      seedTbody.appendChild(buildSpacerRow());
      seedTbody.appendChild(buildTotalRow('Total Anticipated Values'));
      seedTbody.appendChild(buildSpacerRow());
      for (const r of section2) {
        seedTbody.appendChild(
          buildDataRowFromRecord({
            in: r.in,
            out: r.out,
            description: r.description,
            approvedEuro: '0.00 €',
            receiptsEuro: '0.00 €',
            expendituresEuro: '0.00 €',
            balanceEuro: '0.00 €',
            receiptsUsd: '-',
            expendituresUsd: '-',
            calcReceiptsOp: r.calcReceiptsOp,
            calcExpendituresOp: r.calcExpendituresOp,
          })
        );
      }
      seedTbody.appendChild(buildTotalRow('Total Budget, Receipts, Expenditures'));
      seedTbody.appendChild(buildRemainingRow());
      for (const el of buildChecksumSection()) seedTbody.appendChild(el);
      return seedTbody.innerHTML;
    }

    // Page title ("YYYY Budget")
    const titleEl = document.querySelector('[data-budget-title]');
    if (titleEl) titleEl.textContent = `${budgetYear} Budget`;

    const listTitleEl = document.querySelector('[data-budget-list-title]');
    if (listTitleEl) listTitleEl.textContent = `${budgetYear} Budget`;

    const subheadEl = document.querySelector('[data-budget-subhead]');
    if (subheadEl) subheadEl.textContent = `Budget overview table for ${budgetYear}.`;
    applyAppTabTitle();

    // Register this year and seed it using the stored template rows (derived from the Active Budget).
    // Fallback: the static HTML template shipped in this page.
    const templateHtml = tbody.innerHTML;
    const seedRows = getBudgetTemplateRowsForSeeding(templateHtml);
    const seedHtml = buildSeedBudgetTbodyHtmlFromTemplateRows(seedRows) || templateHtml;
    ensureBudgetYearExists(budgetYear, seedHtml);
    initBudgetYearNav();

    function syncActiveBudgetButton() {
      if (!setActiveBtn) return;
      const active = loadActiveBudgetYear();
      const isActive = active === budgetYear;
      setActiveBtn.textContent = isActive ? 'Active Budget' : 'Set Active Budget';
      setActiveBtn.disabled = isActive || !hasBudgetFullAccess;

      if (isActive) {
        setActiveBtn.setAttribute('title', 'This year is the Active Budget');
        setActiveBtn.setAttribute(
          'data-tooltip',
          'This budget year is currently the Active Budget. Use the gear menu → Deactivate Budget to clear the active selection.'
        );
      } else if (!hasBudgetFullAccess) {
        setActiveBtn.setAttribute('title', 'Requires Full access for Budget');
        setActiveBtn.setAttribute(
          'data-tooltip',
          'Requires Full access for Budget. Partial access can edit and save the budget table, but cannot Activate Budget.'
        );
      } else {
        setActiveBtn.setAttribute('title', 'Set this year as the Active Budget');
        setActiveBtn.setAttribute(
          'data-tooltip',
          'Sets this budget year as the Active Budget. The sidebar Budget link will open this year’s dashboard until you deactivate it.'
        );
      }

      // Deactivate link should only be enabled if any active budget is set.
      const canDeactivate = Boolean(active) && hasBudgetFullAccess;
      setLinkDisabled(deactivateLink, !canDeactivate);
      if (deactivateLink) {
        if (!hasBudgetFullAccess) {
          deactivateLink.setAttribute('data-tooltip', 'Requires Full access for Budget. Partial access cannot Deactivate Budget.');
        }
      }
    }

    syncActiveBudgetButton();

    // Cross-tab sync: if another tab changes the active year, keep this page accurate.
    window.addEventListener('storage', (e) => {
      const key = e && typeof e.key === 'string' ? e.key : '';
      if (key === ACTIVE_BUDGET_YEAR_KEY || key === BUDGET_YEARS_KEY) {
        syncActiveBudgetButton();
        initBudgetYearNav();
      }
    });

    if (setActiveBtn) {
      setActiveBtn.addEventListener('click', (e) => {
        e.preventDefault();
        if (!requireWriteAccess('budget', 'Budget is read only for your account.')) return;
        saveActiveBudgetYear(budgetYear);

        // Treat the newly-activated budget's structure as the template.
        readBudgetTemplateRowsFromTbodyEl(tbody);

        // First activation: if no Payment Orders list exists for this year,
        // create it and reset numbering so the first PO number is always 01.
        const ensured = ensurePaymentOrdersListExistsForYear(budgetYear);
        if (ensured && ensured.ok && ensured.created) {
          const year2 = getYear2ForBudgetYear(budgetYear);
          if (year2) saveNumberingSettings({ year2, nextSeq: 1 });
        } else {
          // Otherwise, keep numbering consistent and never go backwards.
          syncNumberingSettingsToBudgetYear(budgetYear);
        }

        // Income: create the year list on first activation (if missing).
        ensureIncomeListExistsForYear(budgetYear);

        // Grand Secretary Ledger: initialize Verified store on first activation (if missing).
        ensureGsLedgerVerifiedStoreExistsForYear(budgetYear);

        syncActiveBudgetButton();
        // Re-render nav so the parent Budget link points at the new active year.
        initBudgetYearNav();
      });
    }

    if (deactivateLink) {
      deactivateLink.addEventListener('click', (e) => {
        e.preventDefault();
        if (deactivateLink.getAttribute('aria-disabled') === 'true') return;
        if (!requireWriteAccess('budget', 'Budget is read only for your account.')) return;
        clearActiveBudgetYear();
        syncActiveBudgetButton();
        initBudgetYearNav();
        closeMenu();
      });
    }

    if (dashboardLink) {
      dashboardLink.addEventListener('click', (e) => {
        e.preventDefault();
        window.location.href = `budget_dashboard.html?year=${encodeURIComponent(String(budgetYear))}`;
      });
    }

    function parseMoney(text) {
      const raw = String(text ?? '').replace(/\u00A0/g, ' ').trim();
      if (!raw || raw === '-' || raw === '—') return 0;

      const isParenNeg = raw.includes('(') && raw.includes(')');
      const cleaned = raw.replace(/[^0-9.,\-]/g, '').replace(/,/g, '');
      const n = Number(cleaned);
      if (!Number.isFinite(n)) return 0;
      return isParenNeg ? -Math.abs(n) : n;
    }

    function parseMoneyOrNull(text) {
      const raw = String(text ?? '').replace(/\u00A0/g, ' ').trim();
      if (!raw || raw === '-' || raw === '—') return null;
      const isParenNeg = raw.includes('(') && raw.includes(')');
      const cleaned = raw.replace(/[^0-9.,\-]/g, '').replace(/,/g, '');
      if (!/[0-9]/.test(cleaned)) return null;
      const n = Number(cleaned);
      if (!Number.isFinite(n)) return null;
      return isParenNeg ? -Math.abs(n) : n;
    }

    function hasUsdValue(text) {
      const raw = String(text ?? '').replace(/\u00A0/g, ' ').trim();
      if (!raw) return false;
      if (raw === '-' || raw === '—') return false;
      return true;
    }

    function normalizeUsdCells() {
      const usdValueCells = tbody.querySelectorAll('td.budgetTable__usd');
      for (const valueCell of usdValueCells) {
        const parentRow = valueCell.closest('tr');
        const isTotalRow = Boolean(parentRow && parentRow.classList.contains('budgetTable__total'));
        const raw = String(valueCell.textContent ?? '').replace(/\u00A0/g, ' ');
        const trimmed = raw.trim();

        // Clear the separate sign cell (we render "$ " inside the value cell)
        const maybeSign = valueCell.previousElementSibling;
        if (maybeSign && maybeSign.classList.contains('budgetTable__usdSign')) {
          maybeSign.textContent = '';
        }

        if (!hasUsdValue(trimmed)) {
          // Keep USD totals explicit and bold.
          if (isTotalRow) valueCell.innerHTML = '<strong>$ 0.00</strong>';
          else valueCell.textContent = '-';
          continue;
        }

        const withoutDollar = trimmed.replace(/^\$\s*/u, '');
        // Exactly one space after $.
        if (isTotalRow) valueCell.innerHTML = `<strong>$ ${withoutDollar}</strong>`;
        else valueCell.textContent = `$ ${withoutDollar}`;
      }
    }

    function applyNegativeNumberClasses() {
      const rows = tbody.querySelectorAll('tr');
      for (const row of rows) {
        const skipDescriptionCol = isEditableDataRow(row);
        const cells = row.querySelectorAll('td');
        for (let i = 0; i < cells.length; i += 1) {
          const cell = cells[i];
          // Skip Description column (3rd column)
          if (skipDescriptionCol && i === 2) {
            cell.classList.remove('is-negative');
            continue;
          }

          const value = parseMoney(cell.textContent);
          if (value < 0) cell.classList.add('is-negative');
          else cell.classList.remove('is-negative');
        }
      }
    }

    function formatEuro(amount) {
      const n = Number(amount);
      const safe = Number.isFinite(n) ? n : 0;
      return `${safe.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 })} €`;
    }

    function formatUsd(amount) {
      const n = Number(amount);
      const safe = Number.isFinite(n) ? n : 0;
      return `$ ${safe.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
    }

    function normalizeEuroCells() {
      const rows = tbody.querySelectorAll('tr');
      for (const row of rows) {
        if (!isEditableDataRow(row)) continue;
        const tds = row.querySelectorAll('td');

        // Money columns: 4-7 (0-based 3..6)
        for (let col = 3; col <= 6; col += 1) {
          const cell = tds[col];
          if (!cell) continue;
          const parsed = parseMoneyOrNull(cell.textContent);
          if (parsed === null) continue;
          cell.textContent = formatEuro(parsed);
        }
      }
    }

    function isEditableDataRow(row) {
      if (!row) return false;
      if (row.classList.contains('budgetTable__spacer')) return false;
      if (row.classList.contains('budgetTable__total')) return false;
      if (row.classList.contains('budgetTable__remaining')) return false;
      if (row.classList.contains('budgetTable__checksum')) return false;
      const tds = row.querySelectorAll('td');
      return tds.length >= 7;
    }

    function sumSection(rows, kind) {
      const totals = {
        approved: 0,
        receipts: 0,
        expenditures: 0,
        balance: 0,
        receiptsUsd: 0,
        expendituresUsd: 0,
      };

      for (const row of rows) {
        if (!isEditableDataRow(row)) continue;
        const tds = row.querySelectorAll('td');
        const approved = parseMoney(tds[3]?.textContent);
        const receipts = parseMoney(tds[4]?.textContent);
        const expenditures = parseMoney(tds[5]?.textContent);
        const desc = tds[2]?.textContent ?? '';
        const ops = getBudgetCalcOpsForRow(kind, row, desc);
        const balance = computeBudgetBalance(approved, receipts, expenditures, ops);

        totals.approved += approved;
        totals.receipts += receipts;
        totals.expenditures += expenditures;
        totals.balance += balance;

        // Keep Balance Euro consistent for each row
        if (tds[6]) tds[6].textContent = formatEuro(balance);

        // USD value columns (sign columns are present but visually collapsed)
        totals.receiptsUsd += parseMoney(tds[8]?.textContent);
        totals.expendituresUsd += parseMoney(tds[10]?.textContent);
      }

      return totals;
    }

    function updateTotalRow(totalRow, totals) {
      if (!totalRow) return;
      const tds = totalRow.querySelectorAll('td');
      if (tds.length < 11) return;

      tds[3].innerHTML = `<strong>${formatEuro(totals.approved)}</strong>`;
      tds[4].innerHTML = `<strong>${formatEuro(totals.receipts)}</strong>`;
      tds[5].innerHTML = `<strong>${formatEuro(totals.expenditures)}</strong>`;
      tds[6].innerHTML = `<strong>${formatEuro(totals.balance)}</strong>`;

      // Keep USD sign cells blank; render "$ " inside the value cells.
      if (tds[7]) tds[7].textContent = '';
      if (tds[9]) tds[9].textContent = '';
      if (tds[8]) tds[8].innerHTML = `<strong>${formatUsd(totals.receiptsUsd)}</strong>`;
      if (tds[10]) tds[10].innerHTML = `<strong>${formatUsd(totals.expendituresUsd)}</strong>`;
    }

    function updateRemainingRow(remainingRow, section1Totals, section2Totals) {
      if (!remainingRow) return;
      const cells = remainingRow.querySelectorAll('td');
      if (cells.length < 7) return;

      // Remaining funds of balance =
      // (Total Budget, Receipts, Expenditures -> Receipts Euro)
      // + (Total Anticipated Values -> Balance Euro)
      // - (Total Budget, Receipts, Expenditures -> Expenditures Euro)
      const remaining = section2Totals.receipts + section1Totals.balance - section2Totals.expenditures;
      // Value should appear under the Balance Euro column.
      const valueCell = cells[6];
      valueCell.innerHTML = `<strong>${formatEuro(remaining)}</strong>`;

      if (remaining < 0) valueCell.classList.add('is-negative');
      else valueCell.classList.remove('is-negative');
    }

    function ensureRemainingRowLayout() {
      const remainingRow = tbody.querySelector('tr.budgetTable__remaining');
      if (!remainingRow) return;

      const cells = Array.from(remainingRow.querySelectorAll('td'));

      // New layout is 11 plain <td> cells (no colspans) to match the 11 visible columns.
      const hasAnyColspan = cells.some((c) => c.hasAttribute('colspan'));
      if (!hasAnyColspan && cells.length === 11) return;

      // Preserve the label text if we can find it.
      const labelText = remainingRow.textContent?.includes('Remaining') ? 'Remaining funds of balance' : 'Remaining funds of balance';

      // Build 11 cells: label in Description (3), value in Balance Euro (7).
      remainingRow.innerHTML = `
        <td></td>
        <td></td>
        <td><strong>${labelText}</strong></td>
        <td></td>
        <td></td>
        <td></td>
        <td class="num"><strong>-</strong></td>
        <td></td>
        <td></td>
        <td></td>
        <td></td>
      `.trim();
    }

    function ensureTotalRowsLayout() {
      const totalRows = tbody.querySelectorAll('tr.budgetTable__total');
      for (const row of totalRows) {
        const cells = Array.from(row.querySelectorAll('td'));
        const hasAnyColspan = cells.some((c) => c.hasAttribute('colspan'));
        if (!hasAnyColspan && cells.length === 11) continue;

        const rowText = row.textContent ?? '';
        const labelText = rowText.includes('Total Budget')
          ? 'Total Budget, Receipts, Expenditures'
          : 'Total Anticipated Values';

        row.innerHTML = `
          <td></td>
          <td></td>
          <td><strong>${labelText}</strong></td>
          <td class="num"><strong>-</strong></td>
          <td class="num"><strong>-</strong></td>
          <td class="num"><strong>-</strong></td>
          <td class="num"><strong>-</strong></td>
          <td class="budgetTable__usdSign"></td>
          <td class="num budgetTable__usd"><strong>$ 0.00</strong></td>
          <td class="budgetTable__usdSign"></td>
          <td class="num budgetTable__usd"><strong>$ 0.00</strong></td>
        `.trim();
      }
    }

    function buildChecksumSpacerRow() {
      const tr = document.createElement('tr');
      tr.className = 'budgetTable__spacer budgetTable__checksumSpacer';
      tr.innerHTML = '<td colspan="11"></td>';
      return tr;
    }

    function buildChecksumRow(kind) {
      const tr = document.createElement('tr');
      tr.className = 'budgetTable__checksum';
      tr.setAttribute('data-checksum-kind', kind);

      const label = kind === 'receipts' ? 'Receipts Checksum' : 'Expenditure Checksum';
      // Value lives under the related column:
      // receipts checksum -> Receipts Euro (col 5 / index 4)
      // expenditure checksum -> Expenditures Euro (col 6 / index 5)
      tr.innerHTML = `
        <td></td>
        <td></td>
        <td><strong>${label}</strong></td>
        <td></td>
        <td class="num">${kind === 'receipts' ? '<strong>-</strong>' : ''}</td>
        <td class="num">${kind === 'expenditures' ? '<strong>-</strong>' : ''}</td>
        <td></td>
        <td></td>
        <td></td>
        <td></td>
        <td></td>
      `.trim();
      return tr;
    }

    function ensureChecksumRowsLayout() {
      const existing = Array.from(tbody.querySelectorAll('tr.budgetTable__checksum'));
      const hasReceipts = existing.some((r) => r.getAttribute('data-checksum-kind') === 'receipts');
      const hasExpenditures = existing.some((r) => r.getAttribute('data-checksum-kind') === 'expenditures');

      const remainingRow = tbody.querySelector('tr.budgetTable__remaining');
      const insertAfter = remainingRow && remainingRow.isConnected ? remainingRow : null;

      // Ensure we have a spacer before the checksum rows.
      let spacer = tbody.querySelector('tr.budgetTable__checksumSpacer');
      if (!spacer) {
        spacer = buildChecksumSpacerRow();
        if (insertAfter) insertAfter.insertAdjacentElement('afterend', spacer);
        else tbody.appendChild(spacer);
      }

      // Add missing checksum rows (keep existing user-saved ones intact).
      if (!hasReceipts) spacer.insertAdjacentElement('afterend', buildChecksumRow('receipts'));

      // Re-find spacer sibling insertion point for expenditures so ordering is stable.
      const rowsAfterSpacer = Array.from(tbody.querySelectorAll('tr.budgetTable__checksum'));
      const receiptsRow = rowsAfterSpacer.find((r) => r.getAttribute('data-checksum-kind') === 'receipts');
      const insertionPoint = receiptsRow && receiptsRow.isConnected ? receiptsRow : spacer;

      if (!hasExpenditures) insertionPoint.insertAdjacentElement('afterend', buildChecksumRow('expenditures'));

      // Normalize layout to 11 cells (no colspans)
      const all = Array.from(tbody.querySelectorAll('tr.budgetTable__checksum'));
      for (const row of all) {
        const tds = row.querySelectorAll('td');
        if (tds.length === 11) continue;
        const kind = row.getAttribute('data-checksum-kind') || 'receipts';
        row.replaceWith(buildChecksumRow(kind));
      }
    }

    function updateChecksumRows(section1Totals, section2Totals) {
      const receiptsChecksum = section1Totals.receipts - section2Totals.receipts;
      const expendituresChecksum = section1Totals.expenditures - section2Totals.expenditures;

      const rows = Array.from(tbody.querySelectorAll('tr.budgetTable__checksum'));
      for (const row of rows) {
        const kind = row.getAttribute('data-checksum-kind');
        const tds = row.querySelectorAll('td');
        if (tds.length < 11) continue;

        if (kind === 'receipts') {
          tds[4].innerHTML = `<strong>${formatEuro(receiptsChecksum)}</strong>`;
          if (receiptsChecksum < 0) tds[4].classList.add('is-negative');
          else tds[4].classList.remove('is-negative');
        }

        if (kind === 'expenditures') {
          tds[5].innerHTML = `<strong>${formatEuro(expendituresChecksum)}</strong>`;
          if (expendituresChecksum < 0) tds[5].classList.add('is-negative');
          else tds[5].classList.remove('is-negative');
        }
      }
    }

    function recalculateBudgetTotals() {
      const rows = Array.from(tbody.querySelectorAll('tr'));
      const totalRows = rows.filter((r) => r.classList.contains('budgetTable__total'));
      if (totalRows.length < 2) return;

      const firstTotalIndex = rows.indexOf(totalRows[0]);
      const secondTotalIndex = rows.indexOf(totalRows[1]);
      if (firstTotalIndex < 0 || secondTotalIndex < 0 || secondTotalIndex <= firstTotalIndex) return;

      const section1Rows = rows.slice(0, firstTotalIndex);
      const section2Rows = rows.slice(firstTotalIndex + 1, secondTotalIndex);

      const s1 = sumSection(section1Rows, 'anticipated');
      const s2 = sumSection(section2Rows, 'budget');

      updateTotalRow(totalRows[0], s1);
      updateTotalRow(totalRows[1], s2);

      const remainingRow = rows.find((r) => r.classList.contains('budgetTable__remaining'));
      if (remainingRow) updateRemainingRow(remainingRow, s1, s2);

      // Checksum section lives at the bottom and compares totals between sections.
      updateChecksumRows(s1, s2);

      normalizeEuroCells();
      normalizeUsdCells();
      applyNegativeNumberClasses();
    }

    const savedHtml = budgetKey ? localStorage.getItem(budgetKey) : null;
    if (savedHtml) tbody.innerHTML = savedHtml;

    // If older saved HTML is present, migrate row layout to current schema.
    ensureRemainingRowLayout();
    ensureTotalRowsLayout();
    ensureChecksumRowsLayout();

    // Ensure money formats look consistent on load.
    normalizeEuroCells();
    normalizeUsdCells();

    // Ensure totals are correct on load (including restored saved state)
    recalculateBudgetTotals();
    applyNegativeNumberClasses();

    let isEditing = false;
    let selectedRow = null;
    let lastClickedSection = 1; // 1 = anticipated (top), 2 = budget (bottom)
    let editStartHtml = null;

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
      if (!menuPanel || !menuBtn) return;
      if (isMenuOpen()) closeMenu();
      else openMenu();
    }

    function setLinkDisabled(linkEl, disabled) {
      if (!linkEl) return;
      linkEl.setAttribute('aria-disabled', disabled ? 'true' : 'false');
      if (disabled) linkEl.setAttribute('tabindex', '-1');
      else linkEl.removeAttribute('tabindex');
    }

    function setMenuItemVisible(el, visible) {
      if (!el) return;
      el.hidden = !visible;
      el.setAttribute('aria-hidden', visible ? 'false' : 'true');
      if (!visible) el.setAttribute('tabindex', '-1');
    }

    function setSelectedRow(nextRow) {
      if (selectedRow && selectedRow.isConnected) {
        selectedRow.classList.remove('budgetRow--selected');
      }

      selectedRow = nextRow && isEditableDataRow(nextRow) ? nextRow : null;
      if (selectedRow) selectedRow.classList.add('budgetRow--selected');

      setLinkDisabled(removeLineLink, !isEditing || !selectedRow);
    }

    function updateLineButtons() {
      // Only show Add/Remove while editing.
      setMenuItemVisible(addLineLink, isEditing);
      setMenuItemVisible(removeLineLink, isEditing);
      setMenuItemVisible(deleteBudgetLink, isEditing);

      setLinkDisabled(addLineLink, !isEditing);
      setLinkDisabled(removeLineLink, !isEditing || !selectedRow);
      setLinkDisabled(deleteBudgetLink, !isEditing || !hasBudgetFullAccess);

      // In the dropdown, Edit should be available only when not editing.
      setLinkDisabled(editLink, isEditing);

      // Import replaces the table, so prevent it during editing.
      setLinkDisabled(importCsvLink, isEditing || !hasBudgetFullAccess);
      if (importCsvLink && !hasBudgetFullAccess) {
        importCsvLink.setAttribute(
          'data-tooltip',
          'Requires Full access for Budget. Partial access can edit and save the budget table, but cannot Import CSV.'
        );
      }

      // Creating a new year budget should be done outside edit mode.
      setLinkDisabled(newYearLink, isEditing || !hasBudgetFullAccess);
      if (newYearLink && !hasBudgetFullAccess) {
        newYearLink.setAttribute(
          'data-tooltip',
          'Requires Full access for Budget. Partial access cannot create a New Budget Year.'
        );
      }

      // Ensure these remain enabled.
      setLinkDisabled(exportCsvLink, false);
      setLinkDisabled(downloadTemplateLink, false);
    }

    // Apply initial enabled/disabled state (including Partial access restrictions).
    updateLineButtons();

    function applyEditingAttributesToRow(row) {
      if (!row || !isEditableDataRow(row)) return;
      const cells = row.querySelectorAll('td');
      for (const cell of cells) {
        if (cell.classList.contains('budgetTable__usdSign')) {
          cell.removeAttribute('contenteditable');
          cell.removeAttribute('spellcheck');
          continue;
        }

        if (isEditing) {
          cell.setAttribute('contenteditable', 'true');
          cell.setAttribute('spellcheck', 'false');
        } else {
          cell.removeAttribute('contenteditable');
          cell.removeAttribute('spellcheck');
        }
      }
    }

    function createEmptyBudgetRow() {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td class="num"></td>
        <td class="num"></td>
        <td></td>
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

    function addLine() {
      if (!isEditing) return;
      const newRow = createEmptyBudgetRow();

      const firstTotal = tbody.querySelector('tr.budgetTable__total');
      const totalRows = tbody.querySelectorAll('tr.budgetTable__total');
      const secondTotal = totalRows.length >= 2 ? totalRows[1] : null;
      if (selectedRow && selectedRow.isConnected) {
        selectedRow.insertAdjacentElement('afterend', newRow);
      } else if (lastClickedSection === 2 && secondTotal) {
        // Insert into the Budget section by default if the user last clicked there.
        secondTotal.insertAdjacentElement('beforebegin', newRow);
      } else if (firstTotal) {
        // Default to Anticipated section.
        firstTotal.insertAdjacentElement('beforebegin', newRow);
      } else {
        tbody.appendChild(newRow);
      }

      applyEditingAttributesToRow(newRow);
      setSelectedRow(newRow);
      recalculateBudgetTotals();
    }

    function removeLine() {
      if (!isEditing) return;
      if (!selectedRow || !selectedRow.isConnected) return;
      if (!isEditableDataRow(selectedRow)) return;

      const rowToRemove = selectedRow;
      setSelectedRow(null);
      rowToRemove.remove();
      recalculateBudgetTotals();
    }

    function setEditing(next) {
      isEditing = Boolean(next);
      table.classList.toggle('budgetTable--editing', isEditing);

      // Only Save remains a button; Edit is a link.
      saveBtn.hidden = !isEditing;
      if (cancelBtn) cancelBtn.hidden = !isEditing;

      if (!isEditing) setSelectedRow(null);

      const rows = tbody.querySelectorAll('tr');
      for (const row of rows) {
        if (!isEditableDataRow(row)) continue;
        const cells = row.querySelectorAll('td');
        for (const cell of cells) {
          if (cell.classList.contains('budgetTable__usdSign')) {
            cell.removeAttribute('contenteditable');
            cell.removeAttribute('spellcheck');
            continue;
          }
          if (isEditing) {
            cell.setAttribute('contenteditable', 'true');
            cell.setAttribute('spellcheck', 'false');
          } else {
            cell.removeAttribute('contenteditable');
            cell.removeAttribute('spellcheck');
          }
        }
      }

      updateLineButtons();
    }

    function saveEdits() {
      // Update computed totals before persisting
      recalculateBudgetTotals();
      applyNegativeNumberClasses();
      normalizeEuroCells();
      normalizeUsdCells();
      const clone = tbody.cloneNode(true);
      clone.querySelectorAll('.budgetRow--selected').forEach((el) => el.classList.remove('budgetRow--selected'));
      clone.querySelectorAll('[contenteditable]').forEach((el) => el.removeAttribute('contenteditable'));
      clone.querySelectorAll('[spellcheck]').forEach((el) => el.removeAttribute('spellcheck'));

      // If this year is the Active Budget (or no active is set yet), treat its structure as the template.
      const active = loadActiveBudgetYear();
      if (!active || active === budgetYear) {
        readBudgetTemplateRowsFromTbodyEl(clone);
      }

      if (budgetKey) localStorage.setItem(budgetKey, clone.innerHTML);
    }

    function promptForBudgetYear(defaultYear) {
      const suggested = Number.isInteger(defaultYear) ? defaultYear : new Date().getFullYear();
      const raw = window.prompt('Enter budget year (4 digits)', String(suggested));
      if (raw === null) return null;
      const y = Number(String(raw).trim());
      if (!Number.isInteger(y) || y < 1900 || y > 3000) {
        window.alert('Please enter a valid 4-digit year (e.g., 2026).');
        return null;
      }
      return y;
    }

    function openBudgetYear(year) {
      window.location.href = `budget.html?year=${encodeURIComponent(String(year))}`;
    }

    function createOrOpenBudgetYear(year) {
      const y = Number(year);
      if (!Number.isInteger(y)) return;
      const key = getBudgetTableKeyForYear(y);
      if (!key) return;

      const years = loadBudgetYears();
      const exists = years.includes(y) || Boolean(localStorage.getItem(key));
      if (exists) {
        openBudgetYear(y);
        return;
      }

      // Seed new year from the template rows (derived from the Active Budget).
      const templateRows = getBudgetTemplateRowsForSeeding(templateHtml);
      const initial = buildSeedBudgetTbodyHtmlFromTemplateRows(templateRows) || templateHtml;
      localStorage.setItem(key, initial);
      saveBudgetYears([y, ...years]);
      openBudgetYear(y);
    }

    function escapeCsvValue(value) {
      const s = String(value ?? '');
      // Normalize whitespace/newlines for CSV
      const normalized = s.replace(/\u00A0/g, ' ').replace(/\r\n|\r|\n/g, ' ').trim();
      const mustQuote = /[",\n\r]/.test(normalized);
      const escaped = normalized.replace(/"/g, '""');
      return mustQuote ? `"${escaped}"` : escaped;
    }

    function getDownloadFileName() {
      const d = new Date();
      const yyyy = d.getFullYear();
      const mm = String(d.getMonth() + 1).padStart(2, '0');
      const dd = String(d.getDate()).padStart(2, '0');
      return `budget_${yyyy}-${mm}-${dd}.csv`;
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

    function exportBudgetToCsv() {
      // Ensure export is consistent with what the UI shows.
      recalculateBudgetTotals();
      normalizeEuroCells();
      normalizeUsdCells();
      applyNegativeNumberClasses();

      const header = [
        'IN',
        'OUT',
        'Description',
        'Amount Approved Euro',
        'Receipts Euro',
        'Expenditures Euro',
        'Balance Euro',
        'Receipts USD',
        'Expenditures USD',
      ];

      const lines = [];
      lines.push(header.map(escapeCsvValue).join(','));

      const rows = Array.from(tbody.querySelectorAll('tr'));
      for (const row of rows) {
        if (row.classList.contains('budgetTable__spacer')) continue;
        const tds = Array.from(row.querySelectorAll('td'));
        if (tds.length < 7) continue;

        // Table is 11 columns; USD columns are split (sign + value). Export the value cells only.
        const values = [
          tds[0]?.textContent ?? '',
          tds[1]?.textContent ?? '',
          tds[2]?.textContent ?? '',
          tds[3]?.textContent ?? '',
          tds[4]?.textContent ?? '',
          tds[5]?.textContent ?? '',
          tds[6]?.textContent ?? '',
          tds[8]?.textContent ?? '',
          tds[10]?.textContent ?? '',
        ];

        lines.push(values.map(escapeCsvValue).join(','));
      }

      // UTF-8 BOM helps Excel parse UTF-8 + € correctly.
      const csv = `\uFEFF${lines.join('\r\n')}\r\n`;
      downloadCsvFile(csv, getDownloadFileName());
    }

    function getTemplateFileName() {
      const d = new Date();
      const yyyy = d.getFullYear();
      const mm = String(d.getMonth() + 1).padStart(2, '0');
      const dd = String(d.getDate()).padStart(2, '0');
      return `budget_template_${yyyy}-${mm}-${dd}.csv`;
    }

    function downloadBudgetCsvTemplate() {
      const header = [
        'Section',
        'IN',
        'OUT',
        'Description',
        'Amount Approved Euro',
        'Calculation',
        'Receipts Euro',
        'Calculation',
        'Expenditures Euro',
        'Calculation',
        'Balance Euro',
        'Receipts USD',
        'Expenditures USD',
      ];

      function opLabel(op) {
        if (op === 'add') return 'add (+)';
        if (op === 'subtract') return 'subtract (-)';
        if (op === 'equals') return 'equals (=)';
        return '';
      }

      const templateRows = getBudgetTemplateRowsForSeeding(templateHtml);

      const dataRows = templateRows.length
        ? templateRows.map((r) => {
            const sectionName = r.section === 1 ? 'Anticipated' : 'Budget';
            const kind = r.section === 2 ? 'budget' : 'anticipated';
            const ops = getBudgetCalcOpsForRow(kind, null, r.description);
            const receiptsOp = r.calcReceiptsOp || ops.receiptsOp;
            const expendituresOp = r.calcExpendituresOp || ops.expendituresOp;

            return [
              sectionName,
              r.in,
              r.out,
              r.description,
              '0.00 €',
              opLabel(receiptsOp),
              '0.00 €',
              opLabel(expendituresOp),
              '0.00 €',
              opLabel('equals'),
              '0.00 €',
              '-',
              '-',
            ];
          })
        : [
            // Minimal fallback if no template exists yet.
            ['Anticipated', '1020', '2020', 'Example anticipated line', '0.00 €', 'subtract (-)', '0.00 €', 'subtract (-)', '0.00 €', 'equals (=)', '0.00 €', '-', '-'],
            ['Budget', '1998', '2998', 'Example budget line', '0.00 €', 'add (+)', '0.00 €', 'subtract (-)', '0.00 €', 'equals (=)', '0.00 €', '-', '-'],
          ];

      const lines = [];
      lines.push(header.map(escapeCsvValue).join(','));
      for (const r of dataRows) lines.push(r.map(escapeCsvValue).join(','));

      const csv = `\uFEFF${lines.join('\r\n')}\r\n`;
      downloadCsvFile(csv, getTemplateFileName());
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
          // Ignore CR; LF handles end-of-line.
          continue;
        }

        field += ch;
      }

      // Flush
      row.push(field);
      rows.push(row);

      // Drop completely empty trailing row
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

    function buildDataRowFromRecord(rec) {
      const inVal = String(rec.in ?? '').trim();
      const outVal = String(rec.out ?? '').trim();
      const desc = String(rec.description ?? '').trim();

      const approvedEuro = String(rec.approvedEuro ?? '').trim() || '0.00 €';
      const receiptsEuro = String(rec.receiptsEuro ?? '').trim() || '0.00 €';
      const expendituresEuro = String(rec.expendituresEuro ?? '').trim() || '0.00 €';
      const balanceEuro = String(rec.balanceEuro ?? '').trim() || '0.00 €';

      const receiptsUsd = String(rec.receiptsUsd ?? '').replace(/\u00A0/g, ' ').trim();
      const expendituresUsd = String(rec.expendituresUsd ?? '').replace(/\u00A0/g, ' ').trim();

      const tr = document.createElement('tr');
      const receiptsOp = normalizeBudgetCalcToken(rec && (rec.calcReceiptsOp ?? rec.calcReceipts));
      const expendituresOp = normalizeBudgetCalcToken(rec && (rec.calcExpendituresOp ?? rec.calcExpenditures));
      if (receiptsOp === 'add' || receiptsOp === 'subtract') tr.dataset.calcReceipts = receiptsOp;
      if (expendituresOp === 'add' || expendituresOp === 'subtract') tr.dataset.calcExpenditures = expendituresOp;
      tr.innerHTML = `
        <td class="num">${escapeHtml(inVal)}</td>
        <td class="num">${escapeHtml(outVal)}</td>
        <td>${escapeHtml(desc)}</td>
        <td class="num budgetTable__euro">${escapeHtml(approvedEuro)}</td>
        <td class="num budgetTable__euro">${escapeHtml(receiptsEuro)}</td>
        <td class="num budgetTable__euro">${escapeHtml(expendituresEuro)}</td>
        <td class="num budgetTable__bal">${escapeHtml(balanceEuro)}</td>
        <td class="budgetTable__usdSign">$</td>
        <td class="num budgetTable__usd">${escapeHtml(receiptsUsd || '-')}</td>
        <td class="budgetTable__usdSign">$</td>
        <td class="num budgetTable__usd">${escapeHtml(expendituresUsd || '-')}</td>
      `.trim();
      return tr;
    }

    function buildSpacerRow() {
      const tr = document.createElement('tr');
      tr.className = 'budgetTable__spacer';
      tr.innerHTML = '<td colspan="11"></td>';
      return tr;
    }

    function buildTotalRow(label) {
      const tr = document.createElement('tr');
      tr.className = 'budgetTable__total';
      tr.innerHTML = `
        <td></td>
        <td></td>
        <td><strong>${escapeHtml(label)}</strong></td>
        <td class="num"><strong>-</strong></td>
        <td class="num"><strong>-</strong></td>
        <td class="num"><strong>-</strong></td>
        <td class="num"><strong>-</strong></td>
        <td class="budgetTable__usdSign"></td>
        <td class="num budgetTable__usd"><strong>$ 0.00</strong></td>
        <td class="budgetTable__usdSign"></td>
        <td class="num budgetTable__usd"><strong>$ 0.00</strong></td>
      `.trim();
      return tr;
    }

    function buildRemainingRow() {
      const tr = document.createElement('tr');
      tr.className = 'budgetTable__remaining';
      tr.innerHTML = `
        <td></td>
        <td></td>
        <td><strong>Remaining funds of balance</strong></td>
        <td></td>
        <td></td>
        <td></td>
        <td class="num"><strong>-</strong></td>
        <td></td>
        <td></td>
        <td></td>
        <td></td>
      `.trim();
      return tr;
    }

    function buildChecksumSection() {
      return [
        buildChecksumSpacerRow(),
        buildChecksumRow('receipts'),
        buildChecksumRow('expenditures'),
      ];
    }

    // Small local helper for safe HTML insertion
    function escapeHtml(str) {
      return String(str ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
    }

    function importBudgetFromCsvText(csvText, fileName) {
      if (isEditing) {
        window.alert('Please click Save (exit Edit mode) before importing a CSV.');
        return;
      }

      const ok = window.confirm(
        `Importing a CSV will update currency values for matching rows and add any missing rows. Continue?\n\nFile: ${fileName || 'CSV'}`
      );
      if (!ok) return;

      function normalizeKeyText(v) {
        return String(v ?? '').replace(/\u00A0/g, ' ').trim();
      }

      function makeLineKey(inVal, outVal, desc) {
        const a = normalizeKeyText(inVal);
        const b = normalizeKeyText(outVal);
        if (a || b) return `${a}::${b}`;
        return `desc::${normalizeKeyText(desc).toLowerCase()}`;
      }

      function getRowSection(tr) {
        const allRows = Array.from(tbody.querySelectorAll('tr'));
        const totals = allRows.filter((r) => r.classList.contains('budgetTable__total'));
        const firstTotalIndex = totals.length >= 1 ? allRows.indexOf(totals[0]) : -1;
        const rowIndex = allRows.indexOf(tr);
        if (firstTotalIndex >= 0 && rowIndex >= 0 && rowIndex < firstTotalIndex) return 1;
        return 2;
      }

      function isEffectivelyEmptyBudget() {
        const rows = Array.from(tbody.querySelectorAll('tr')).filter((r) => isEditableDataRow(r));
        if (rows.length === 0) return true;
        for (const row of rows) {
          const tds = row.querySelectorAll('td');
          const approved = parseMoney(tds[3]?.textContent);
          const receipts = parseMoney(tds[4]?.textContent);
          const expenditures = parseMoney(tds[5]?.textContent);
          const receiptsUsd = parseMoney(tds[8]?.textContent);
          const expendituresUsd = parseMoney(tds[10]?.textContent);
          if (approved !== 0 || receipts !== 0 || expenditures !== 0 || receiptsUsd !== 0 || expendituresUsd !== 0) return false;
        }
        return true;
      }

      const lockTemplateColumns = isEffectivelyEmptyBudget();

      function findMatchingExistingRow(targetSection, rec) {
        const targetKey = makeLineKey(rec.in, rec.out, rec.description);
        if (!targetKey) return null;

        const rows = Array.from(tbody.querySelectorAll('tr'));
        for (const row of rows) {
          if (!isEditableDataRow(row)) continue;
          if (getRowSection(row) !== targetSection) continue;
          const tds = row.querySelectorAll('td');
          const key = makeLineKey(tds[0]?.textContent, tds[1]?.textContent, tds[2]?.textContent);
          if (key === targetKey) return row;
        }
        return null;
      }

      function patchRowFromRecord(row, rec) {
        if (!row || !isEditableDataRow(row)) return;
        const tds = row.querySelectorAll('td');
        if (tds.length < 11) return;

        const recIn = normalizeKeyText(rec.in);
        const recOut = normalizeKeyText(rec.out);
        const recDesc = normalizeKeyText(rec.description);

        // Only update the template columns if the row is blank. For empty budgets,
        // keep IN/OUT/Description as the template and only patch currency values.
        if (!lockTemplateColumns) {
          if (!normalizeKeyText(tds[0]?.textContent) && recIn) tds[0].textContent = recIn;
          if (!normalizeKeyText(tds[1]?.textContent) && recOut) tds[1].textContent = recOut;
          if (!normalizeKeyText(tds[2]?.textContent) && recDesc) tds[2].textContent = recDesc;
        } else {
          if (!normalizeKeyText(tds[2]?.textContent) && recDesc) tds[2].textContent = recDesc;
        }

        if (String(rec.approvedEuro ?? '').trim() !== '' && tds[3]) tds[3].textContent = rec.approvedEuro;
        if (String(rec.receiptsEuro ?? '').trim() !== '' && tds[4]) tds[4].textContent = rec.receiptsEuro;
        if (String(rec.expendituresEuro ?? '').trim() !== '' && tds[5]) tds[5].textContent = rec.expendituresEuro;
        if (String(rec.balanceEuro ?? '').trim() !== '' && tds[6]) tds[6].textContent = rec.balanceEuro;

        const rUsd = normalizeKeyText(rec.receiptsUsd);
        const eUsd = normalizeKeyText(rec.expendituresUsd);
        if (tds[8]) tds[8].textContent = rUsd || '-';
        if (tds[10]) tds[10].textContent = eUsd || '-';

        if (rec.calcReceiptsOp === 'add' || rec.calcReceiptsOp === 'subtract') row.dataset.calcReceipts = rec.calcReceiptsOp;
        if (rec.calcExpendituresOp === 'add' || rec.calcExpendituresOp === 'subtract') row.dataset.calcExpenditures = rec.calcExpendituresOp;
      }

      function insertRowFromRecord(targetSection, rec) {
        const newRow = buildDataRowFromRecord(rec);
        const totals = tbody.querySelectorAll('tr.budgetTable__total');
        const firstTotal = totals.length >= 1 ? totals[0] : null;
        const secondTotal = totals.length >= 2 ? totals[1] : null;

        if (targetSection === 1 && firstTotal) {
          firstTotal.insertAdjacentElement('beforebegin', newRow);
        } else if (targetSection === 2 && secondTotal) {
          secondTotal.insertAdjacentElement('beforebegin', newRow);
        } else {
          tbody.appendChild(newRow);
        }

        return newRow;
      }

      const rows = parseCsvText(csvText);
      if (rows.length === 0) {
        window.alert('CSV is empty.');
        return;
      }

      const header = rows[0].map(normalizeHeaderName);
      const dataRows = rows.slice(1).filter((r) => r.some((c) => String(c ?? '').trim() !== ''));

      const idx = {
        section: header.indexOf('section'),
        date: header.indexOf('date') !== -1 ? header.indexOf('date') : header.indexOf('transaction date'),
        in: header.indexOf('in'),
        out: header.indexOf('out'),
        description: header.indexOf('description'),
        approvedEuro: header.indexOf('amount approved euro'),
        receiptsEuro: header.indexOf('receipts euro'),
        expendituresEuro: header.indexOf('expenditures euro'),
        balanceEuro: header.indexOf('balance euro'),
        receiptsUsd: header.indexOf('receipts usd'),
        expendituresUsd: header.indexOf('expenditures usd'),
      };

      // New template: three "Calculation" columns (operators) after each EUR amount column.
      // Layout: Amount Approved Euro, Calculation, Receipts Euro, Calculation, Expenditures Euro, Calculation, Balance Euro
      const calcIdx = {
        receiptsOp: idx.approvedEuro !== -1 && header[idx.approvedEuro + 1] === 'calculation' ? idx.approvedEuro + 1 : -1,
        expendituresOp: idx.receiptsEuro !== -1 && header[idx.receiptsEuro + 1] === 'calculation' ? idx.receiptsEuro + 1 : -1,
        equals: idx.expendituresEuro !== -1 && header[idx.expendituresEuro + 1] === 'calculation' ? idx.expendituresEuro + 1 : -1,
      };

      const isCalcTemplate =
        idx.section !== -1 &&
        idx.in !== -1 &&
        idx.out !== -1 &&
        idx.description !== -1 &&
        idx.approvedEuro !== -1 &&
        idx.receiptsEuro !== -1 &&
        idx.expendituresEuro !== -1 &&
        idx.balanceEuro !== -1 &&
        idx.receiptsUsd !== -1 &&
        idx.expendituresUsd !== -1 &&
        calcIdx.receiptsOp !== -1 &&
        calcIdx.expendituresOp !== -1 &&
        calcIdx.equals !== -1;

      const hasAnyCalculationColumn = header.includes('calculation');
      if (hasAnyCalculationColumn && !isCalcTemplate) {
        window.alert(
          'Import failed: CSV includes Calculation column(s) but is missing one or more required columns from the Budget template.'
        );
        return;
      }

      const hasSectionColumn = idx.section !== -1;
      const hasTemplateHeaders = idx.in !== -1 && idx.out !== -1 && idx.description !== -1;

      if (!hasTemplateHeaders && header.length >= 3) {
        // Allow importing a file that has no headers by treating the first row as data.
        dataRows.unshift(rows[0]);
      }

      function normalizeCsvDateForImport(raw) {
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
        const yyyy = d.getFullYear();
        const mm = String(d.getMonth() + 1).padStart(2, '0');
        const dd = String(d.getDate()).padStart(2, '0');
        return `${yyyy}-${mm}-${dd}`;
      }

      function inferHeaderlessColumnOffset(row) {
        // If the first column looks like a date (e.g. M/D/YYYY) and the next columns look
        // like IN/OUT codes, treat the file as having a leading Date column we can ignore.
        const r = Array.isArray(row) ? row : [];
        const firstIsDate = normalizeCsvDateForImport(r[0]) !== '';
        const nextLooksLikeCodes = /^\d{4}$/.test(String(r[1] ?? '').trim()) && /^\d{4}$/.test(String(r[2] ?? '').trim());
        return firstIsDate && nextLooksLikeCodes ? 1 : 0;
      }

      const section1 = [];
      const section2 = [];
      let inferredSection = 1; // 1 = anticipated, 2 = budget

      function isTotalsOrRemaining(descText) {
        const d = String(descText ?? '').toLowerCase();
        if (!d) return false;
        return d.includes('total anticipated values')
          || d.includes('total budget')
          || d.includes('remaining funds of balance')
          || d.includes('receipts checksum')
          || d.includes('expenditure checksum');
      }

      for (const r of dataRows) {
        const get = (i) => (i >= 0 ? (r[i] ?? '') : '');

        // Template-aware record reading
        const rawSection = hasSectionColumn ? get(idx.section) : '';
        const offset = (idx.in === -1 && idx.out === -1 && idx.description === -1) ? inferHeaderlessColumnOffset(r) : 0;
        const inVal = idx.in !== -1 ? get(idx.in) : r[0 + offset] ?? '';
        const outVal = idx.out !== -1 ? get(idx.out) : r[1 + offset] ?? '';
        const desc = idx.description !== -1 ? get(idx.description) : r[2 + offset] ?? '';

        // Support round-tripping from exported CSV (it includes the total/remaining rows)
        if (String(desc ?? '').trim().toLowerCase().includes('total anticipated values')) {
          inferredSection = 2;
          continue;
        }
        if (isTotalsOrRemaining(desc)) continue;

        const record = {
          in: inVal,
          out: outVal,
          description: desc,
          approvedEuro: idx.approvedEuro !== -1 ? get(idx.approvedEuro) : (r[3 + offset] ?? ''),
          receiptsEuro: idx.receiptsEuro !== -1 ? get(idx.receiptsEuro) : (r[4 + offset] ?? ''),
          expendituresEuro: idx.expendituresEuro !== -1 ? get(idx.expendituresEuro) : (r[5 + offset] ?? ''),
          balanceEuro: idx.balanceEuro !== -1 ? get(idx.balanceEuro) : (r[6 + offset] ?? ''),
          receiptsUsd: idx.receiptsUsd !== -1 ? get(idx.receiptsUsd) : (r[7 + offset] ?? ''),
          expendituresUsd: idx.expendituresUsd !== -1 ? get(idx.expendituresUsd) : (r[8 + offset] ?? ''),
        };

        // New template behavior: require Calculation columns + required values and compute Balance Euro from them.
        if (isCalcTemplate) {
          const rawReceiptsOp = get(calcIdx.receiptsOp);
          const rawExpendituresOp = get(calcIdx.expendituresOp);
          const rawEquals = get(calcIdx.equals);

          const receiptsOp = normalizeBudgetCalcToken(rawReceiptsOp);
          const expendituresOp = normalizeBudgetCalcToken(rawExpendituresOp);
          const eq = normalizeBudgetCalcToken(rawEquals);

          const requiredValues = [
            rawSection,
            inVal,
            outVal,
            desc,
            record.approvedEuro,
            rawReceiptsOp,
            record.receiptsEuro,
            rawExpendituresOp,
            record.expendituresEuro,
            rawEquals,
            record.balanceEuro,
            record.receiptsUsd,
            record.expendituresUsd,
          ];

          const missing = requiredValues.some((v) => String(v ?? '').trim() === '');
          if (missing) {
            window.alert(
              `Import failed: missing required value (including Calculation columns) for a row.\n\nFile: ${fileName || 'CSV'}`
            );
            return;
          }

          if ((receiptsOp !== 'add' && receiptsOp !== 'subtract') || (expendituresOp !== 'add' && expendituresOp !== 'subtract') || eq !== 'equals') {
            window.alert(
              `Import failed: invalid Calculation value(s).\n` +
              `Expected add (+) or subtract (-) for the first two Calculation columns, and equals (=) for the third.\n\n` +
              `File: ${fileName || 'CSV'}`
            );
            return;
          }

          const approvedN = parseMoney(record.approvedEuro);
          const receiptsN = parseMoney(record.receiptsEuro);
          const expendituresN = parseMoney(record.expendituresEuro);
          const computedBalance = computeBudgetBalance(approvedN, receiptsN, expendituresN, { receiptsOp, expendituresOp });

          record.calcReceiptsOp = receiptsOp;
          record.calcExpendituresOp = expendituresOp;
          record.balanceEuro = formatEuro(computedBalance);
        }

        const sectionName = String(rawSection ?? '').trim().toLowerCase();
        const targetSection = sectionName.startsWith('a') ? 1 : sectionName.startsWith('b') ? 2 : inferredSection;

        if (targetSection === 1) section1.push(record);
        else section2.push(record);
      }

      const imported = [
        ...section1.map((rec) => ({ section: 1, rec })),
        ...section2.map((rec) => ({ section: 2, rec })),
      ];

      for (const item of imported) {
        const targetSection = item.section;
        const rec = item.rec;

        const match = findMatchingExistingRow(targetSection, rec);
        if (match) patchRowFromRecord(match, rec);
        else insertRowFromRecord(targetSection, rec);
      }

      // Normalize and persist using the same pipeline as manual edits.
      ensureRemainingRowLayout();
      ensureTotalRowsLayout();
      ensureChecksumRowsLayout();
      recalculateBudgetTotals();
      normalizeEuroCells();
      normalizeUsdCells();
      applyNegativeNumberClasses();
      saveEdits();
    }

    editLink.addEventListener('click', (e) => {
      e.preventDefault();
      if (!requireBudgetEditAccess('Budget is read only for your account.')) return;
      if (isEditing) return;
      editStartHtml = tbody.innerHTML;
      setEditing(true);
    });

    saveBtn.addEventListener('click', () => {
      if (!requireBudgetEditAccess('Budget is read only for your account.')) return;
      if (!isEditing) return;
      saveEdits();
      setEditing(false);
      editStartHtml = null;
    });

    if (cancelBtn) {
      cancelBtn.addEventListener('click', () => {
        if (!isEditing) return;
        // Restore the table to the state it was in when Edit was clicked.
        setSelectedRow(null);
        setEditing(false);
        if (typeof editStartHtml === 'string') {
          tbody.innerHTML = editStartHtml;
          ensureRemainingRowLayout();
          ensureTotalRowsLayout();
          ensureChecksumRowsLayout();
          normalizeEuroCells();
          normalizeUsdCells();
          recalculateBudgetTotals();
          applyNegativeNumberClasses();
        }
        editStartHtml = null;
      });
    }

    if (addLineLink) {
      addLineLink.addEventListener('click', (e) => {
        e.preventDefault();
        if (addLineLink.getAttribute('aria-disabled') === 'true') return;
        if (!requireBudgetEditAccess('Budget is read only for your account.')) return;
        if (!isEditing) return;
        addLine();
      });
    }
    if (removeLineLink) {
      removeLineLink.addEventListener('click', (e) => {
        e.preventDefault();
        if (removeLineLink.getAttribute('aria-disabled') === 'true') return;
        if (!requireBudgetEditAccess('Budget is read only for your account.')) return;
        if (!isEditing) return;
        removeLine();
      });
    }

    if (exportCsvLink) {
      exportCsvLink.addEventListener('click', (e) => {
        e.preventDefault();
        exportBudgetToCsv();
      });
    }
    if (downloadTemplateLink) {
      downloadTemplateLink.addEventListener('click', (e) => {
        e.preventDefault();
        downloadBudgetCsvTemplate();
      });
    }

    if (importCsvLink) {
      const input = document.createElement('input');
      input.type = 'file';
      input.accept = '.csv,text/csv';
      input.style.display = 'none';
      document.body.appendChild(input);

      importCsvLink.addEventListener('click', (e) => {
        e.preventDefault();
        if (importCsvLink.getAttribute('aria-disabled') === 'true') return;
        if (!requireWriteAccess('budget', 'Budget is read only for your account.')) return;
        if (isEditing) return;
        input.value = '';
        input.click();
      });

      input.addEventListener('change', () => {
        const file = input.files && input.files[0];
        if (!file) return;
        const reader = new FileReader();
        reader.onload = () => {
          importBudgetFromCsvText(reader.result, file.name);
        };
        reader.onerror = () => {
          window.alert('Could not read CSV file.');
        };
        reader.readAsText(file);
      });
    }

    if (newYearLink) {
      newYearLink.addEventListener('click', (e) => {
        e.preventDefault();
        if (newYearLink.getAttribute('aria-disabled') === 'true') return;
        if (!requireWriteAccess('budget', 'Budget is read only for your account.')) return;
        if (isEditing) return;
        const y = promptForBudgetYear(budgetYear + 1);
        if (!y) return;
        createOrOpenBudgetYear(y);
      });
    }

    function deleteCurrentBudgetYear() {
      if (!requireWriteAccess('budget', 'Budget is read only for your account.')) return;
      if (!hasBudgetFullAccess) {
        window.alert('Requires Full access for Budget.');
        return;
      }
      if (!isEditing) return;

      const ok = window.confirm(
        `Delete the ${budgetYear} budget?\n\nThis removes the saved budget table for ${budgetYear} from shared storage.`
      );
      if (!ok) return;

      // Remove the saved budget HTML for this year.
      if (budgetKey) localStorage.removeItem(budgetKey);

      // Remove the year from the years list.
      const years = loadBudgetYears().filter((y) => Number(y) !== Number(budgetYear));
      saveBudgetYears(years);

      // If this was the active budget year, clear the active setting.
      if (loadActiveBudgetYear() === budgetYear) clearActiveBudgetYear();

      // Exit edit mode and navigate away (staying on this page would recreate the year on reload).
      setSelectedRow(null);
      setEditing(false);
      editStartHtml = null;
      closeMenu();

      const fallback = getCurrentBudgetYearFromDate(new Date());
      const nextYear = years.length ? years[0] : fallback;
      window.location.href = `budget.html?year=${encodeURIComponent(String(nextYear))}`;
    }

    if (deleteBudgetLink) {
      deleteBudgetLink.addEventListener('click', (e) => {
        e.preventDefault();
        if (deleteBudgetLink.getAttribute('aria-disabled') === 'true') return;
        deleteCurrentBudgetYear();
      });
    }

    if (menuBtn) {
      const MENU_CLOSE_DELAY_MS = 250;
      let menuCloseTimer = 0;

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

      // Allow time to move from the gear icon to the menu panel.
      menuBtn.addEventListener('mouseenter', cancelScheduledClose);
      menuBtn.addEventListener('mouseleave', scheduleClose);

      if (menuPanel) {
        menuPanel.addEventListener('mouseenter', cancelScheduledClose);
        menuPanel.addEventListener('mouseleave', scheduleClose);
      }

      document.addEventListener('click', (e) => {
        if (!isMenuOpen()) return;
        const menuRoot = e.target?.closest ? e.target.closest('[data-budget-menu]') : null;
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

    // Select a row for removal while editing.
    tbody.addEventListener('click', (e) => {
      if (!isEditing) return;
      const row = e.target?.closest ? e.target.closest('tr') : null;
      if (!row || row.classList.contains('budgetTable__total') || row.classList.contains('budgetTable__remaining')) {
        setSelectedRow(null);
        return;
      }
      if (!isEditableDataRow(row)) {
        setSelectedRow(null);
        return;
      }

       // Track which section the user is interacting with so Add line
       // defaults into the correct section even when nothing is selected.
      const allRows = Array.from(tbody.querySelectorAll('tr'));
      const totals = allRows.filter((r) => r.classList.contains('budgetTable__total'));
      if (totals.length >= 2) {
        const firstTotalIndex = allRows.indexOf(totals[0]);
        const secondTotalIndex = allRows.indexOf(totals[1]);
        const rowIndex = allRows.indexOf(row);
        if (rowIndex > firstTotalIndex && rowIndex < secondTotalIndex) lastClickedSection = 2;
        else if (rowIndex >= 0 && rowIndex < firstTotalIndex) lastClickedSection = 1;
      }

      setSelectedRow(row);
    });

    // While editing, update negative formatting live.
    let rafId = 0;
    tbody.addEventListener('input', () => {
      if (!isEditing) return;
      if (rafId) cancelAnimationFrame(rafId);
      rafId = requestAnimationFrame(() => {
        applyNegativeNumberClasses();
        rafId = 0;
      });
    });

    // On leaving a USD value cell, normalize to "$ " + value.
    tbody.addEventListener('focusout', (e) => {
      if (!isEditing) return;
      const td = e.target?.closest ? e.target.closest('td') : null;
      if (!td) return;
      const isUsd = td.classList.contains('budgetTable__usd');
      const isEuro = td.classList.contains('budgetTable__euro') || td.classList.contains('budgetTable__bal');
      if (!isUsd && !isEuro) return;
      normalizeEuroCells();
      normalizeUsdCells();
      applyNegativeNumberClasses();
    });

    setEditing(false);
  }

  function initBudgetDashboard() {
    const root = document.querySelector('[data-budget-dashboard]');
    if (!root) return;

    const gridAnt = root.querySelector('[data-budget-dashboard-grid-anticipated]') || root.querySelector('[data-budget-dashboard-grid]');
    const gridBud = root.querySelector('[data-budget-dashboard-grid-budget]');
    const emptyAnt = root.querySelector('[data-budget-dashboard-empty-anticipated]') || root.querySelector('[data-budget-dashboard-empty]');
    const emptyBud = root.querySelector('[data-budget-dashboard-empty-budget]');
    if (!gridAnt) return;

    const year = getActiveBudgetYear();
    const titleEl = document.querySelector('[data-budget-dashboard-title]');
    if (titleEl) titleEl.textContent = `${year} Budget Dashboard`;
    const subheadEl = document.querySelector('[data-budget-dashboard-subhead]');
    if (subheadEl) {
      subheadEl.classList.remove('subhead--withSeal');
      subheadEl.textContent = `Charts for ${year}: Expenditures vs Balance (Euro).`;
    }
    applyAppTabTitle();

    const backLink = document.getElementById('budgetDashboardBackLink');
    if (backLink) {
      backLink.href = `budget.html?year=${encodeURIComponent(String(year))}`;
      backLink.textContent = `${year} Budget`;
      backLink.setAttribute('aria-label', `Back to ${year} Budget`);
      backLink.title = `${year} Budget`;
    }

    initBudgetYearNav();

    const searchInput = document.getElementById('budgetDashboardSearch');

    const key = getBudgetTableKeyForYear(year);
    const html = key ? localStorage.getItem(key) : null;
    const tbody = document.createElement('tbody');
    tbody.innerHTML = String(html || '');

    function parseMoney(text) {
      const raw = String(text ?? '').replace(/\u00A0/g, ' ').trim();
      if (!raw || raw === '-' || raw === '—') return 0;
      const isParenNeg = raw.includes('(') && raw.includes(')');
      const cleaned = raw.replace(/[^0-9.,\-]/g, '').replace(/,/g, '');
      const n = Number(cleaned);
      if (!Number.isFinite(n)) return 0;
      return isParenNeg ? -Math.abs(n) : n;
    }

    function formatEuro(n) {
      const num = Number(n);
      const isNeg = num < 0;
      const abs = Math.abs(num);
      const fmt = new Intl.NumberFormat('en-US', {
        minimumFractionDigits: 2,
        maximumFractionDigits: 2,
      }).format(abs);
      return `${isNeg ? '-' : ''}${fmt} €`;
    }

    function pct(value, total) {
      if (!total || total <= 0) return 0;
      return Math.round((value / total) * 100);
    }

    const leaderUpdaters = [];
    let leaderRaf = 0;

    function scheduleLeaderUpdate() {
      if (leaderRaf) cancelAnimationFrame(leaderRaf);
      leaderRaf = requestAnimationFrame(() => {
        for (const fn of leaderUpdaters) fn();
        leaderRaf = 0;
      });
    }

    function createDonutSvg(valueA, valueB) {
      const total = valueA + valueB;
      const radius = 48;
      const stroke = 20;
      const cx = 60;
      const cy = 60;
      const c = 2 * Math.PI * radius;
      const aLen = total > 0 ? (valueA / total) * c : 0;
      const bLen = total > 0 ? (valueB / total) * c : 0;

      const startAngle = -Math.PI / 2;
      const aFrac = total > 0 ? valueA / total : 0;
      const bFrac = total > 0 ? valueB / total : 0;
      const midAngleA = startAngle + (aFrac * 2 * Math.PI) / 2;
      const midAngleB = startAngle + aFrac * 2 * Math.PI + (bFrac * 2 * Math.PI) / 2;

      const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
      svg.setAttribute('viewBox', '0 0 120 120');
      svg.classList.add('budgetDash__donut');

      const track = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
      track.setAttribute('cx', String(cx));
      track.setAttribute('cy', String(cy));
      track.setAttribute('r', String(radius));
      track.setAttribute('fill', 'none');
      track.setAttribute('stroke-width', String(stroke));
      track.classList.add('budgetDash__donutTrack');
      svg.appendChild(track);

      const segA = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
      segA.setAttribute('cx', String(cx));
      segA.setAttribute('cy', String(cy));
      segA.setAttribute('r', String(radius));
      segA.setAttribute('fill', 'none');
      segA.setAttribute('stroke-width', String(stroke));
      segA.setAttribute('stroke-linecap', 'butt');
      segA.setAttribute('stroke-dasharray', `${aLen} ${Math.max(0, c - aLen)}`);
      segA.setAttribute('transform', `rotate(-90 ${cx} ${cy})`);
      segA.classList.add('budgetDash__donutSegA');
      svg.appendChild(segA);

      const segB = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
      segB.setAttribute('cx', String(cx));
      segB.setAttribute('cy', String(cy));
      segB.setAttribute('r', String(radius));
      segB.setAttribute('fill', 'none');
      segB.setAttribute('stroke-width', String(stroke));
      segB.setAttribute('stroke-linecap', 'butt');
      segB.setAttribute('stroke-dasharray', `${bLen} ${Math.max(0, c - bLen)}`);
      segB.setAttribute('stroke-dashoffset', String(-aLen));
      segB.setAttribute('transform', `rotate(-90 ${cx} ${cy})`);
      segB.classList.add('budgetDash__donutSegB');
      svg.appendChild(segB);

      return {
        svg,
        total,
        meta: {
          cx,
          cy,
          radius,
          stroke,
          midAngleA,
          midAngleB,
        },
      };
    }

    function attachLeaderLines(chartRowEl, donutSvgEl, balanceValueEl, expValueEl, meta, showBalanceLine, showExpLine) {
      if (!chartRowEl || !donutSvgEl || !meta) return;
      if (!balanceValueEl || !expValueEl) return;

      const overlay = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
      overlay.classList.add('budgetDash__leaders');
      overlay.setAttribute('aria-hidden', 'true');

      const lineLeft = document.createElementNS('http://www.w3.org/2000/svg', 'path');
      lineLeft.classList.add('budgetDash__leaderLine');
      const lineRight = document.createElementNS('http://www.w3.org/2000/svg', 'path');
      lineRight.classList.add('budgetDash__leaderLine');

      overlay.appendChild(lineLeft);
      overlay.appendChild(lineRight);
      chartRowEl.appendChild(overlay);

      function pointOnArcToClient(angleRad) {
        // Anchor leader lines to the middle of the donut ring (not the outer edge)
        // so the line sits more centered within the chart space.
        const r = meta.radius;
        const x = meta.cx + r * Math.cos(angleRad);
        const y = meta.cy + r * Math.sin(angleRad);
        const rect = donutSvgEl.getBoundingClientRect();
        return {
          x: rect.left + (x / 120) * rect.width,
          y: rect.top + (y / 120) * rect.height,
        };
      }

      function centerOf(el) {
        const r = el.getBoundingClientRect();
        return { x: r.left + r.width / 2, y: r.top + r.height / 2 };
      }

      function donutCenterClient() {
        const rect = donutSvgEl.getBoundingClientRect();
        return {
          x: rect.left + (meta.cx / 120) * rect.width,
          y: rect.top + (meta.cy / 120) * rect.height,
        };
      }

      function endPointNearText(valueEl, donutCenter) {
        const r = valueEl.getBoundingClientRect();
        const gap = 6;
        const y = r.top + r.height / 2;

        // If the value is left of the donut, approach from the right side
        // and stop just AFTER the text. If it's right of the donut, stop
        // just BEFORE the text.
        const isLeftOfDonut = (r.left + r.width / 2) < donutCenter.x;
        const x = isLeftOfDonut ? (r.right + gap) : (r.left - gap);
        return { x, y };
      }

      function update() {
        const rowRect = chartRowEl.getBoundingClientRect();
        const w = Math.max(1, rowRect.width);
        const h = Math.max(1, rowRect.height);
        overlay.setAttribute('viewBox', `0 0 ${w} ${h}`);
        overlay.setAttribute('width', String(w));
        overlay.setAttribute('height', String(h));

        const dCenter = donutCenterClient();

        // Balance metric -> segment A (only when value > 0)
        const arcA = pointOnArcToClient(meta.midAngleA);
        const balTarget = endPointNearText(balanceValueEl, dCenter);

        // Expenditures metric -> segment B (only when value > 0)
        const arcB = pointOnArcToClient(meta.midAngleB);
        const expTarget = endPointNearText(expValueEl, dCenter);

        const a0x = arcA.x - rowRect.left;
        const a0y = arcA.y - rowRect.top;
        const a1x = balTarget.x - rowRect.left;
        const a1y = balTarget.y - rowRect.top;

        const b0x = arcB.x - rowRect.left;
        const b0y = arcB.y - rowRect.top;
        const b1x = expTarget.x - rowRect.left;
        const b1y = expTarget.y - rowRect.top;

        // Two-segment leader: angled then horizontal.
        const midAx = a0x + (a1x - a0x) * 0.6;
        const midBx = b0x + (b1x - b0x) * 0.6;

        if (showBalanceLine) {
          lineLeft.style.display = '';
          lineLeft.setAttribute('d', `M ${a0x} ${a0y} L ${midAx} ${a1y} L ${a1x} ${a1y}`);
        } else {
          lineLeft.style.display = 'none';
          lineLeft.setAttribute('d', '');
        }

        if (showExpLine) {
          lineRight.style.display = '';
          lineRight.setAttribute('d', `M ${b0x} ${b0y} L ${midBx} ${b1y} L ${b1x} ${b1y}`);
        } else {
          lineRight.style.display = 'none';
          lineRight.setAttribute('d', '');
        }
      }

      leaderUpdaters.push(update);
      update();
    }

    gridAnt.innerHTML = '';
    if (gridBud) gridBud.innerHTML = '';

    const allRows = Array.from(tbody.querySelectorAll('tr'));
    const totals = allRows.filter((r) => r.classList.contains('budgetTable__total'));
    const firstTotalIndex = totals.length >= 1 ? allRows.indexOf(totals[0]) : -1;
    const secondTotalIndex = totals.length >= 2 ? allRows.indexOf(totals[1]) : -1;

    /** @type {Array<{outCode:string, desc:string, exp:number, bal:number, section:'anticipated'|'budget'}>} */
    const items = [];
    for (const tr of allRows) {
      if (tr.classList.contains('budgetTable__spacer')) continue;
      if (tr.classList.contains('budgetTable__total')) continue;
      if (tr.classList.contains('budgetTable__remaining')) continue;
      if (tr.classList.contains('budgetTable__checksum')) continue;

      const tds = tr.querySelectorAll('td');
      if (tds.length < 7) continue;

      const outCode = String(tds[1].textContent || '').trim();
      if (!/^\d{4}$/.test(outCode)) continue;

      const desc = String(tds[2].textContent || '').trim();
      const exp = parseMoney(tds[5].textContent);
      const bal = parseMoney(tds[6].textContent);

      const approved = parseMoney(tds[3].textContent);
      const receipts = parseMoney(tds[4].textContent);
      const total = Math.abs(approved) + Math.abs(receipts);
      const hasAny = total !== 0 || exp !== 0 || bal !== 0;
      if (!hasAny) continue;

      const rowIndex = allRows.indexOf(tr);
      /** @type {'anticipated'|'budget'} */
      let section = 'budget';
      if (firstTotalIndex >= 0 && rowIndex >= 0 && rowIndex < firstTotalIndex) {
        section = 'anticipated';
      } else if (firstTotalIndex >= 0 && secondTotalIndex >= 0 && rowIndex > firstTotalIndex && rowIndex < secondTotalIndex) {
        section = 'budget';
      } else if (firstTotalIndex >= 0 && secondTotalIndex < 0 && rowIndex > firstTotalIndex) {
        section = 'budget';
      }

      items.push({ outCode, desc, exp, bal, section });
    }

    const anticipatedItems = items.filter((i) => i.section === 'anticipated');
    const budgetItems = items.filter((i) => i.section === 'budget');

    const anticipatedCount = anticipatedItems.length;
    const budgetCount = budgetItems.length;

    if (emptyAnt) emptyAnt.hidden = anticipatedItems.length > 0;
    if (emptyBud) emptyBud.hidden = budgetItems.length > 0;

    function renderItem(item, targetGrid) {
      const card = document.createElement('article');
      card.className = 'budgetDash__card';
      card.dataset.search = `${item.outCode} ${item.desc || ''}`.trim();

      const h = document.createElement('h3');
      h.className = 'budgetDash__title';
      h.textContent = `${item.outCode} — ${item.desc || ''}`.trim();
      card.appendChild(h);

      const chartRow = document.createElement('div');
      chartRow.className = 'budgetDash__chartRow';

      const expVal = Math.max(0, Number(item.exp) || 0);
      const rawBal = Number(item.bal) || 0;
      const isOverspent = rawBal < 0;
      const balVal = isOverspent ? Math.abs(rawBal) : Math.max(0, rawBal);
      const labelA = isOverspent ? 'Overspent' : 'Balance';
      const labelB = 'Expenditures';

      const { svg, total, meta } = createDonutSvg(balVal, expVal);

      function createMetricBlock(side, valueText, percentText) {
        const el = document.createElement('div');
        el.className = `budgetDash__metric budgetDash__metric--${side}`;
        const valEl = document.createElement('div');
        valEl.className = 'budgetDash__metricVal';
        valEl.textContent = valueText;
        const pctEl = document.createElement('div');
        pctEl.className = 'budgetDash__metricPct';
        pctEl.textContent = percentText;
        el.appendChild(valEl);
        el.appendChild(pctEl);
        return { el, valEl };
      }

      const balanceSide = Math.cos(meta.midAngleA) >= 0 ? 'right' : 'left';
      const expSide = Math.cos(meta.midAngleB) >= 0 ? 'right' : 'left';

      const leftCol = document.createElement('div');
      leftCol.className = 'budgetDash__metricCol';
      const rightCol = document.createElement('div');
      rightCol.className = 'budgetDash__metricCol';

      const balBlock = createMetricBlock(balanceSide === 'left' ? 'left' : 'right', formatEuro(isOverspent ? -balVal : balVal), `${pct(balVal, total)}%`);
      const expBlock = createMetricBlock(expSide === 'left' ? 'left' : 'right', formatEuro(expVal), `${pct(expVal, total)}%`);

      function sortKeyForAngle(angleRad) {
        // Smaller y first (top). In screen coords, y = sin(angle).
        return Math.sin(angleRad);
      }

      // Place each block on the same side as its segment.
      if (balanceSide === 'left') leftCol.appendChild(balBlock.el);
      else rightCol.appendChild(balBlock.el);

      if (expSide === 'left') leftCol.appendChild(expBlock.el);
      else rightCol.appendChild(expBlock.el);

      // If both land on the same side, order them top-to-bottom
      // to reduce leader-line crossings.
      if (balanceSide === expSide) {
        const col = balanceSide === 'left' ? leftCol : rightCol;
        const children = Array.from(col.children);
        const desired = [
          { el: balBlock.el, key: sortKeyForAngle(meta.midAngleA) },
          { el: expBlock.el, key: sortKeyForAngle(meta.midAngleB) },
        ].sort((a, b) => a.key - b.key);
        for (const child of children) col.removeChild(child);
        for (const item2 of desired) col.appendChild(item2.el);
      }

      chartRow.appendChild(leftCol);
      const donutWrap = document.createElement('div');
      donutWrap.className = 'budgetDash__donutWrap';
      donutWrap.appendChild(svg);
      chartRow.appendChild(donutWrap);
      chartRow.appendChild(rightCol);
      card.appendChild(chartRow);

      // Leader lines connect each value to its donut segment.
      if (total > 0) {
        // End lines near the value text without overlapping it.
        const showBal = balVal > 0;
        const showExp = expVal > 0;
        attachLeaderLines(chartRow, svg, balBlock.valEl, expBlock.valEl, meta, showBal, showExp);
      }

      const legend = document.createElement('div');
      legend.className = 'budgetDash__legend';
      legend.innerHTML = `
        <span class="budgetDash__swatch budgetDash__swatch--a" aria-hidden="true"></span>
        <span>${labelA}</span>
        <span class="budgetDash__swatch budgetDash__swatch--b" aria-hidden="true"></span>
        <span>${labelB}</span>
      `.trim();
      card.appendChild(legend);

      if (targetGrid) targetGrid.appendChild(card);
    }

    for (const item of anticipatedItems) {
      renderItem(item, gridAnt);
    }

    // If the split markup is missing, render everything into the single grid.
    const budgetTarget = gridBud || gridAnt;
    for (const item of budgetItems) {
      renderItem(item, budgetTarget);
    }

    window.addEventListener('resize', scheduleLeaderUpdate);
    scheduleLeaderUpdate();

    // When the left navigation opens/closes or nested sections expand/collapse,
    // the available width for cards changes but the window size does not.
    // Recompute leader lines on layout changes.
    if (!root.dataset.leaderLinesBound) {
      root.dataset.leaderLinesBound = '1';

      if (typeof ResizeObserver !== 'undefined') {
        const ro = new ResizeObserver(() => scheduleLeaderUpdate());
        ro.observe(root);
        const main = document.querySelector('.appMain');
        if (main) ro.observe(main);
      }

      if (navToggleBtn) {
        navToggleBtn.addEventListener('click', () => {
          // Run once immediately, and once after any CSS transition.
          scheduleLeaderUpdate();
          requestAnimationFrame(scheduleLeaderUpdate);
        });
      }

      const navTree = document.querySelector('[data-nav-tree]');
      if (navTree) {
        navTree.addEventListener('click', () => {
          requestAnimationFrame(scheduleLeaderUpdate);
        });
      }

      if (appShell) {
        appShell.addEventListener('transitionend', () => {
          scheduleLeaderUpdate();
        });
      }
    }

    function getVisibleCardCount(gridEl) {
      if (!gridEl) return 0;
      const cards = gridEl.querySelectorAll('.budgetDash__card');
      let n = 0;
      for (const c of cards) {
        if (!c.hasAttribute('hidden')) n += 1;
      }
      return n;
    }

    function applyDashboardFilter() {
      if (!searchInput) return;
      const q = String(searchInput.value || '').trim().toLowerCase();

      const cards = root.querySelectorAll('.budgetDash__card');
      for (const card of cards) {
        const hay = String(card.dataset.search || card.textContent || '').toLowerCase();
        const match = !q || hay.includes(q);
        card.hidden = !match;
      }

      // Empty-state behavior:
      // - No search: show empty only when the section has no items.
      // - With search: show empty when no visible items remain.
      if (!q) {
        if (emptyAnt) emptyAnt.hidden = anticipatedCount > 0;
        if (emptyBud) emptyBud.hidden = budgetCount > 0;
      } else {
        if (emptyAnt) emptyAnt.hidden = getVisibleCardCount(gridAnt) > 0;
        if (emptyBud && gridBud) emptyBud.hidden = getVisibleCardCount(gridBud) > 0;
        if (emptyBud && !gridBud && emptyAnt) {
          // Fallback single-grid markup.
          emptyAnt.hidden = getVisibleCardCount(gridAnt) > 0;
        }
      }

      scheduleLeaderUpdate();
    }

    if (searchInput) {
      searchInput.addEventListener('input', applyDashboardFilter);
      searchInput.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
          searchInput.value = '';
          applyDashboardFilter();
        }
      });
    }
  }

  function initArchivePage() {
    const root = document.querySelector('[data-archive]');
    if (!root) return;

    const grid = root.querySelector('[data-archive-grid]');
    const emptyEl = root.querySelector('[data-archive-empty]');
    if (!grid) return;

    const config = getNavConfig();
    const isYearLabel = (label) => /^\d{4}$/.test(String(label || '').trim());

    const areas = (Array.isArray(config) ? config : []).filter((it) => {
      const children = Array.isArray(it && it.children) ? it.children : [];
      return children.some((c) => isYearLabel(c && c.label));
    });

    grid.innerHTML = '';

    for (const area of areas) {
      const card = document.createElement('div');
      card.className = 'archive__card';

      const header = document.createElement('div');
      header.className = 'archive__cardHeader';

      const h = document.createElement('h2');
      h.className = 'archive__title';
      h.textContent = String(area && area.label ? area.label : '').trim() || 'Archive';

      const yearsWrap = document.createElement('div');
      yearsWrap.className = 'archive__years';

      const yearChildren = (Array.isArray(area && area.children) ? area.children : []).filter((c) => isYearLabel(c && c.label));
      for (const child of yearChildren) {
        const a = document.createElement('a');
        a.className = 'actionLink';
        a.href = String(child && child.href ? child.href : '#');
        a.textContent = '';
        a.appendChild(document.createTextNode(String(child && child.label ? child.label : '').trim()));
        if (child && child.isActiveBudgetYear) {
          const badge = document.createElement('span');
          badge.className = 'appNavTree__badge';
          badge.textContent = ' (active)';
          a.appendChild(badge);
        }
        yearsWrap.appendChild(a);
      }

      header.appendChild(h);
      card.appendChild(header);
      card.appendChild(yearsWrap);
      grid.appendChild(card);
    }

    if (emptyEl) emptyEl.hidden = areas.length > 0;
  }

  // ---- Backups (year-scoped snapshots) ----

  const BACKUP_SCHEMA = 'acgl-fms-year-backup';
  const BACKUP_VERSION = 1;
  const BACKUP_MAX_PER_YEAR = 30;
  const BACKUP_AUTO_INTERVAL_MS = 24 * 60 * 60 * 1000;

  function normalizeBackupYear(year) {
    const y = Number(year);
    if (!Number.isInteger(y)) return null;
    if (y < 1900 || y > 3000) return null;
    return y;
  }

  function getBackupIndexKeyForYear(year) {
    const y = normalizeBackupYear(year);
    if (!y) return null;
    return `payment_order_backup_index_${y}_v1`;
  }

  function getBackupLastAutoKeyForYear(year) {
    const y = normalizeBackupYear(year);
    if (!y) return null;
    return `payment_order_backup_last_auto_${y}_v1`;
  }

  function getBackupDataKeyForYearId(year, id) {
    const y = normalizeBackupYear(year);
    if (!y) return null;
    const raw = String(id ?? '').trim();
    if (!raw) return null;
    const safe = raw.replace(/[^A-Za-z0-9_\-]/g, '').slice(0, 40);
    if (!safe) return null;
    return `payment_order_backup_${y}_${safe}_v1`;
  }

  function getBackupScopedKeysForYear(year) {
    const y = normalizeBackupYear(year);
    if (!y) return [];
    const out = [];
    const add = (k) => {
      if (k) out.push(k);
    };

    add(getPaymentOrdersKeyForYear(y));
    add(getPaymentOrdersReconciliationKeyForYear(y));
    add(getIncomeKeyForYear(y));
    add(getBudgetTableKeyForYear(y));
    add(getWiseEurKeyForYear(y));
    add(getWiseUsdKeyForYear(y));
    add(getGsLedgerVerifiedKeyForYear(y));

    return out;
  }

  function loadBackupIndex(year) {
    const key = getBackupIndexKeyForYear(year);
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

  function saveBackupIndex(year, index) {
    const key = getBackupIndexKeyForYear(year);
    if (!key) return;
    localStorage.setItem(key, JSON.stringify(Array.isArray(index) ? index : []));
  }

  function makeBackupIdNow() {
    const d = new Date();
    const pad = (n) => String(n).padStart(2, '0');
    return `${d.getUTCFullYear()}${pad(d.getUTCMonth() + 1)}${pad(d.getUTCDate())}T${pad(d.getUTCHours())}${pad(d.getUTCMinutes())}${pad(d.getUTCSeconds())}Z`;
  }

  function createYearBackup(year, kind) {
    const y = normalizeBackupYear(year);
    if (!y) return { ok: false, error: 'invalid_year' };

    if (IS_WP_SHARED_MODE && !getWpToken()) {
      return { ok: false, error: 'wp_login_required' };
    }

    // Backups are stored under payment_order_backup_* keys, which are treated as
    // Settings-scoped in WordPress shared storage.
    if (IS_WP_SHARED_MODE) {
      const hasAnyUsers = loadUsers().length > 0;
      const u = getCurrentUser();
      if (hasAnyUsers && (!u || !canSettingsEdit(u))) {
        return { ok: false, error: 'forbidden' };
      }
    }

    const id = makeBackupIdNow();
    const createdAt = new Date().toISOString();
    const keys = getBackupScopedKeysForYear(y);
    const values = {};
    for (const k of keys) {
      values[k] = localStorage.getItem(k);
    }

    const payload = {
      schema: BACKUP_SCHEMA,
      version: BACKUP_VERSION,
      year: y,
      id,
      createdAt,
      kind: kind === 'auto' ? 'auto' : 'manual',
      keys: values,
    };

    const dataKey = getBackupDataKeyForYearId(y, id);
    if (!dataKey) return { ok: false, error: 'invalid_id' };

    const text = JSON.stringify(payload);
    localStorage.setItem(dataKey, text);

    const meta = {
      id,
      createdAt,
      kind: payload.kind,
      bytes: text.length,
      keyCount: keys.length,
    };

    const index = loadBackupIndex(y);
    const nextIndex = [meta, ...(Array.isArray(index) ? index : []).filter((m) => m && m.id !== id)].slice(0, BACKUP_MAX_PER_YEAR);
    saveBackupIndex(y, nextIndex);

    // Prune dropped backups.
    try {
      const keep = new Set(nextIndex.map((m) => (m && m.id ? String(m.id) : '')).filter(Boolean));
      for (const m of Array.isArray(index) ? index : []) {
        const mid = m && m.id ? String(m.id) : '';
        if (!mid || keep.has(mid)) continue;
        const dk = getBackupDataKeyForYearId(y, mid);
        if (dk) localStorage.removeItem(dk);
      }
    } catch {
      // ignore
    }

    return { ok: true, year: y, id, meta, payload };
  }

  function loadBackupPayloadFromStorage(year, id) {
    const y = normalizeBackupYear(year);
    if (!y) return null;
    const dataKey = getBackupDataKeyForYearId(y, id);
    if (!dataKey) return null;
    try {
      const raw = localStorage.getItem(dataKey);
      if (!raw) return null;
      const parsed = JSON.parse(raw);
      return parsed && typeof parsed === 'object' ? parsed : null;
    } catch {
      return null;
    }
  }

  function downloadBackupById(year, id) {
    const payload = loadBackupPayloadFromStorage(year, id);
    if (!payload) {
      window.alert('Backup not found.');
      return;
    }
    const y = normalizeBackupYear(payload.year);
    const bid = String(payload.id || id || '');
    const fileName = `acgl-fms-backup-${String(y || year)}-${bid}.json`;
    const text = JSON.stringify(payload, null, 2);
    const blob = new Blob([text], { type: 'application/json;charset=utf-8;' });
    downloadBlob(blob, fileName);
  }

  function restoreYearBackupFromPayload(payloadRaw) {
    const payload = payloadRaw && typeof payloadRaw === 'object' ? payloadRaw : null;
    if (!payload) return { ok: false, error: 'invalid_payload' };
    if (payload.schema !== BACKUP_SCHEMA) return { ok: false, error: 'invalid_schema' };
    if (Number(payload.version) !== BACKUP_VERSION) return { ok: false, error: 'unsupported_version' };

    const y = normalizeBackupYear(payload.year);
    if (!y) return { ok: false, error: 'invalid_year' };

    if (IS_WP_SHARED_MODE && !getWpToken()) {
      return { ok: false, error: 'wp_login_required' };
    }

    const allowed = new Set(getBackupScopedKeysForYear(y));
    const bag = payload.keys && typeof payload.keys === 'object' ? payload.keys : {};

    for (const k of Object.keys(bag)) {
      if (!allowed.has(k)) continue;
      const v = bag[k];
      if (v === null || v === undefined) {
        localStorage.removeItem(k);
      } else {
        localStorage.setItem(k, String(v));
      }
    }

    // Ensure the year is discoverable in the budget year list.
    try {
      const years = loadBudgetYears();
      if (!years.includes(y)) saveBudgetYears([y, ...years]);
    } catch {
      // ignore
    }

    return { ok: true, year: y };
  }

  function formatBackupCreatedAt(iso) {
    const s = String(iso || '').trim();
    if (!s) return 'Unknown date';
    return s.replace('T', ' ').replace('Z', '');
  }

  function maybeAutoBackupActiveYear() {
    const y = normalizeBackupYear(getActiveBudgetYear());
    if (!y) return;

    if (IS_WP_SHARED_MODE && !getWpToken()) return;
    if (IS_WP_SHARED_MODE) {
      const hasAnyUsers = loadUsers().length > 0;
      const u = getCurrentUser();
      if (hasAnyUsers && (!u || !canSettingsEdit(u))) return;
    }

    const lastKey = getBackupLastAutoKeyForYear(y);
    if (!lastKey) return;
    const now = Date.now();
    try {
      const last = Number(localStorage.getItem(lastKey) || '0');
      if (Number.isFinite(last) && last > 0 && now - last < BACKUP_AUTO_INTERVAL_MS) return;
    } catch {
      // ignore
    }

    const keys = getBackupScopedKeysForYear(y);
    const hasAny = keys.some((k) => localStorage.getItem(k) !== null);
    if (!hasAny) return;

    const res = createYearBackup(y, 'auto');
    if (!res.ok) return;
    try {
      localStorage.setItem(lastKey, String(now));
    } catch {
      // ignore
    }
  }

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
      const active = normalizeBackupYear(getActiveBudgetYear());
      if (active) return active;
      const years = loadBudgetYears();
      const y = Array.isArray(years) && years.length > 0 ? normalizeBackupYear(years[0]) : null;
      return y;
    }

    function filterCloudFilesForYear(files, year) {
      const y = normalizeBackupYear(year);
      if (!y) return [];
      const list = Array.isArray(files) ? files : [];
      const prefix = `acgl-fms-backup-${String(y)}-`;
      return list
        .filter((f) => f && typeof f === 'object')
        .filter((f) => String(f.name || '').trim().startsWith(prefix));
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
        gdriveCloudFiles = filterCloudFilesForYear(data.files || [], y);
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

    function renderGdriveCloudCard(year) {
      const y = normalizeBackupYear(year);
      if (!y) return null;

      const card = document.createElement('div');
      card.className = 'archive__card';

      const header = document.createElement('div');
      header.className = 'archive__cardHeader';

      const h = document.createElement('h3');
      h.className = 'archive__title';
      h.textContent = `${String(y)} Cloud (Google)`;
      header.appendChild(h);
      card.appendChild(header);

      if (gdriveCloudStatus) {
        const status = document.createElement('div');
        status.className = 'subhead';
        status.textContent = gdriveCloudStatus;
        card.appendChild(status);
      }

      const list = gdriveCloudYear === y ? gdriveCloudFiles : [];
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
        dl.className = 'btn btn--ghost';
        dl.textContent = 'Download';
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
          const fileName = String((data.file && data.file.name) || '').trim() || `acgl-fms-backup-${String(y)}-${id}.json`;
          const text = JSON.stringify(data.payload, null, 2);
          const blob = new Blob([text], { type: 'application/json;charset=utf-8;' });
          downloadBlob(blob, fileName);
          gdriveCloudStatus = '';
          render();
        });
        buttons.appendChild(dl);

        const rs = document.createElement('button');
        rs.type = 'button';
        rs.className = 'btn btn--danger';
        rs.textContent = 'Restore';
        rs.addEventListener('click', async () => {
          if (!requireSettingsEditAccess('Settings access required to restore backups.')) return;
          if (!getWpToken()) {
            window.alert('Please sign in.');
            return;
          }
          const ok = window.confirm(`Restore ${String(y)} from this cloud backup? This will overwrite ${String(y)} data.`);
          if (!ok) return;

          gdriveCloudStatus = 'Restoring…';
          render();
          const data = await fetchGdriveBackupPayloadById(id);
          if (!data || !data.payload) {
            gdriveCloudStatus = 'Could not restore cloud backup.';
            render();
            return;
          }
          const res = restoreYearBackupFromPayload(data.payload);
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
      const active = normalizeBackupYear(getActiveBudgetYear());
      const out = Array.isArray(years) ? years.slice() : [];
      if (active && !out.includes(active)) out.push(active);
      return out.filter((v) => Number.isInteger(Number(v))).sort((a, b) => b - a);
    }

    function render() {
      const years = getKnownYears();
      const cloudYear = canUseGdrive ? getCloudYearForUi() : null;
      const activeYear = normalizeBackupYear(getActiveBudgetYear());
      grid.innerHTML = '';

      let anyBackups = false;
      for (const y of years) {
        const idx = loadBackupIndex(y);
        if (idx.length > 0) anyBackups = true;

        // Only render a WordPress year card if it has backups, or if it's the active year.
        // (Create actions live in the card header now.)
        const showWpYearCard = idx.length > 0 || (activeYear && y === activeYear);

        if (showWpYearCard) {
        const card = document.createElement('div');
        card.className = 'archive__card';

        const header = document.createElement('div');
        header.className = 'archive__cardHeader';

        const h = document.createElement('h3');
        h.className = 'archive__title';
        h.textContent = `${String(y)} (WordPress)`;
        header.appendChild(h);
        card.appendChild(header);

        for (const meta of idx) {
          if (!meta || !meta.id) continue;
          const row = document.createElement('div');
          row.className = 'backupRow';

          const label = document.createElement('div');
          label.className = 'muted backupRow__label';
          label.textContent = formatBackupCreatedAt(meta.createdAt);
          row.appendChild(label);

          const buttons = document.createElement('div');
          buttons.className = 'backupRow__buttons';

          const dl = document.createElement('button');
          dl.type = 'button';
          dl.className = 'btn btn--ghost';
          dl.textContent = 'Download';
          dl.addEventListener('click', () => {
            downloadBackupById(y, meta.id);
          });
          buttons.appendChild(dl);

          const rs = document.createElement('button');
          rs.type = 'button';
          rs.className = 'btn btn--danger';
          rs.textContent = 'Restore';
          rs.addEventListener('click', () => {
            if (!requireSettingsEditAccess('Settings access required to restore backups.')) return;
            const ok = window.confirm(`Restore ${String(y)} from this backup? This will overwrite ${String(y)} data.`);
            if (!ok) return;
            const payload = loadBackupPayloadFromStorage(y, meta.id);
            if (!payload) {
              window.alert('Backup not found.');
              return;
            }
            const res = restoreYearBackupFromPayload(payload);
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

        grid.appendChild(card);
        }

        if (canUseGdrive && cloudYear && y === cloudYear) {
          const cloudCard = renderGdriveCloudCard(y);
          if (cloudCard) grid.appendChild(cloudCard);
        }
      }

      if (emptyEl) emptyEl.hidden = anyBackups;
    }

    if (createActiveBtn && !createActiveBtn.dataset.bound) {
      createActiveBtn.dataset.bound = '1';
      createActiveBtn.addEventListener('click', () => {
        const y = normalizeBackupYear(getActiveBudgetYear());
        if (!y) {
          window.alert('No active year.');
          return;
        }
        if (IS_WP_SHARED_MODE && !getWpToken()) {
          window.alert('Please sign in.');
          return;
        }
        if (!requireSettingsEditAccess('Settings access required to create backups.')) return;
        const res = createYearBackup(y, 'manual');
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
        if (!requireSettingsEditAccess('Settings access required to restore backups.')) return;
        restoreFileInput.value = '';
        restoreFileInput.click();
      });

      restoreFileInput.addEventListener('change', async () => {
        const file = restoreFileInput.files && restoreFileInput.files[0] ? restoreFileInput.files[0] : null;
        if (!file) return;
        try {
          const text = await file.text();
          const payload = JSON.parse(text);
          const y = normalizeBackupYear(payload && payload.year);
          if (!y) {
            window.alert('Invalid backup file.');
            return;
          }
          const ok = window.confirm(`Restore ${String(y)} from this file? This will overwrite ${String(y)} data.`);
          if (!ok) return;
          const res = restoreYearBackupFromPayload(payload);
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
  seedMockData2025IfDev();

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
  maybeAutoBackupActiveYear();
  initBudgetYearNav();
  initBudgetEditor();
  initBudgetDashboard();
  initBudgetNumberSelect();
  initArchivePage();

  if (grandLodgeInfoForm) {
    const current = loadGrandLodgeInfo();
    if (grandMasterInput) grandMasterInput.value = current.grandMaster;
    if (grandSecretaryInput) grandSecretaryInput.value = current.grandSecretary;
    if (grandTreasurerInput) grandTreasurerInput.value = current.grandTreasurer;
    if (officialAddressInput) officialAddressInput.value = current.officialAddress;
    if (operationAddressInput) operationAddressInput.value = current.operationAddress;

    {
      const hasAnyUsers = loadUsers().length > 0;
      const currentUser = getCurrentUser();
      const canEdit = !hasAnyUsers || (currentUser ? canSettingsEdit(currentUser) : false);
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

      if (!requireSettingsEditAccess('Settings is read only for your account.')) return;

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
      } catch {
        window.alert('Could not read the selected file(s).');
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
    });
  }

  if (numberingForm) {
    const settings = loadNumberingSettings();
    initMasonicYearSelectFromBudgets(settings.year2);
    if (masonicYearInput) masonicYearInput.value = String(Number(settings.year2));
    if (firstNumberInput) firstNumberInput.value = String(settings.nextSeq);

    {
      const hasAnyUsers = loadUsers().length > 0;
      const currentUser = getCurrentUser();
      const canEdit = !hasAnyUsers || (currentUser ? canSettingsEdit(currentUser) : false);
      if (hasAnyUsers && !canEdit) {
        if (masonicYearInput) masonicYearInput.disabled = true;
        if (firstNumberInput) firstNumberInput.disabled = true;
        const submitBtn = numberingForm.querySelector('button[type="submit"]');
        if (submitBtn) submitBtn.disabled = true;
      }
    }

    numberingForm.addEventListener('submit', (e) => {
      e.preventDefault();

      if (!requireSettingsEditAccess('Settings is read only for your account.')) return;

      const yearErr = document.getElementById('error-masonicYear');
      const seqErr = document.getElementById('error-firstNumber');
      if (yearErr) yearErr.textContent = '';
      if (seqErr) seqErr.textContent = '';

      const yearRaw = masonicYearInput ? masonicYearInput.value : '';
      const seqRaw = firstNumberInput ? firstNumberInput.value : '';

      const yearNum = Number(yearRaw);
      if (!Number.isFinite(yearNum) || yearNum < 0 || yearNum > 99) {
        if (yearErr) yearErr.textContent = 'Enter a 2-digit year (0–99).';
        return;
      }

      const seqNum = Number(seqRaw);
      if (!Number.isFinite(seqNum) || seqNum < 1) {
        if (seqErr) seqErr.textContent = 'Enter a number of 1 or more.';
        return;
      }

      const year2 = normalizeMasonicYear2(yearRaw);
      const nextSeq = normalizeSequence(seqRaw);
      saveNumberingSettings({ year2, nextSeq });

      // Normalize field display after saving
      if (masonicYearInput) masonicYearInput.value = String(Number(year2));
      if (firstNumberInput) firstNumberInput.value = String(nextSeq);

      // Close settings after save
      {
        const year = getActiveBudgetYear();
        window.location.href = `menu.html?year=${encodeURIComponent(String(year))}`;
      }
    });
  }

  // Settings page roles management
  initRolesSettingsPage();
  initBackupPage();

  if (form) {
    const base = getBasename(window.location.pathname);
    // Do not rely on the URL path for detection (WP embeds may not end in index.html).
    const isRequestForm = Boolean(form && form.id === 'paymentOrderForm');
    const params = new URLSearchParams(window.location.search);
    const forceNew = params.get('new') === '1';
    const resumeDraft = params.get('resumeDraft') === '1';
    const doLogout = params.get('logout') === '1';

    if (isRequestForm && doLogout) {
      performLogout();
      setEditOrderId(null);
      form.reset();
      clearDraft();
      void clearDraftAttachments();
      window.location.href = withWpEmbedParams('index.html?new=1');
      return;
    }

    const currentUser = getCurrentUser();
    const editId = getEditOrderId();

    // Budget Number behavior:
    // - Only roles with full Payment Orders access may change it.
    // - In edit mode, we still display the existing value (read-only) for clarity.
    const canEditBudgetNumber = Boolean(currentUser && canWrite(currentUser, 'orders'));
    const budgetNumberEl = form.elements.namedItem('budgetNumber');
    if (budgetNumberEl) {
      budgetNumberEl.disabled = !canEditBudgetNumber;
    }

    if (isRequestForm && forceNew) {
      setEditOrderId(null);
      form.reset();
      clearDraft();
      void clearDraftAttachments();
      updateItemsStatus();
      syncCurrencyFieldsFromItems();
    }

    // New Request Form should start blank every time (except auto-filled PO No.).
    // Only restore a draft when:
    // - editing an existing order, or
    // - explicitly resuming from the Itemize draft flow.
    if (isRequestForm && !forceNew && !editId && !resumeDraft) {
      form.reset();
      clearDraft();
      void clearDraftAttachments();
      updateItemsStatus();
      syncCurrencyFieldsFromItems();
    }

    // Restore draft fields when allowed (so Itemize -> back to form doesn't lose work).
    const shouldRestoreDraft = !forceNew && Boolean(editId || resumeDraft);
    const draft = shouldRestoreDraft ? loadDraft() : null;
    if (draft) {
      if (draft.bankDetailsMode) {
        setBankDetailsModeOnForm(String(draft.bankDetailsMode || ''));
      }

      if (draft.usAccountType) {
        setUsAccountTypeOnForm(String(draft.usAccountType || ''));
      }

      applyBankDetailsModeToUi(getBankDetailsModeFromForm());

      const keys = [
        // paymentOrderNo is auto-filled for new requests; only restore for edits.
        ...(editId ? ['paymentOrderNo'] : []),
        'date',
        'name',
        'euro',
        'usd',
        'address',
        'iban',
        'bic',
        'specialInstructions',
        ...(draft.bankDetailsMode ? ['bankDetailsMode'] : []),
        // Always show the existing Budget Number during edits, even if read-only.
        ...(editId || canEditBudgetNumber ? ['budgetNumber'] : []),
        'purpose',
      ];

      const draftMode = String(draft.bankDetailsMode || '').trim() === 'US' ? 'US' : 'INTL';
      for (const key of keys) {
        const el = form.elements.namedItem(key);
        if (!el || draft[key] === undefined) continue;

        if (key === 'iban') {
          if (draftMode === 'US') {
            el.value = String(draft[key] || '');
          } else {
            const ibanUtils = getIbanUtils();
            if (ibanUtils) {
              const res = ibanUtils.validateIban(String(draft[key] || ''));
              el.value = res.normalized ? ibanUtils.formatIban(res.normalized) : '';
            } else {
              el.value = String(draft[key] || '');
            }
          }
          continue;
        }

        if (key === 'bic') {
          if (draftMode === 'US') {
            el.value = String(draft[key] || '');
          } else {
            const bicUtils = getBicUtils();
            if (bicUtils) {
              const res = bicUtils.validateBic(String(draft[key] || ''));
              el.value = res.normalized ? bicUtils.formatBic(res.normalized) : '';
            } else {
              el.value = String(draft[key] || '');
            }
          }
          continue;
        }

        if (key === 'bankDetailsMode') continue;

        el.value = draft[key];
      }
    }

    // Ensure Payment Order No. always follows the configured pattern
    maybeAutofillPaymentOrderNo();

    // Captcha must be solved before submitting
    generateRequestCaptcha();

    // Bank details mode toggle
    {
      const toggle = form.elements.namedItem('bankDetailsToggle');
      if (toggle && !toggle.dataset.boundBankMode) {
        toggle.dataset.boundBankMode = 'true';
        toggle.addEventListener('change', () => {
          applyBankDetailsModeToUi(getBankDetailsModeFromForm());

          // Re-normalize the fields to match the current mode
          const ibanEl = form.elements.namedItem('iban');
          const bicEl = form.elements.namedItem('bic');
          if (ibanEl && ibanEl.dispatchEvent) ibanEl.dispatchEvent(new Event('blur'));
          if (bicEl && bicEl.dispatchEvent) bicEl.dispatchEvent(new Event('blur'));
        });
      }

      // Ensure UI reflects the initial selection
      applyBankDetailsModeToUi(getBankDetailsModeFromForm());
    }

    // US account type (Checking/Savings) - mutually exclusive checkboxes
    {
      const checkingEl = form.elements.namedItem('usAccountTypeChecking');
      const savingsEl = form.elements.namedItem('usAccountTypeSavings');

      const bind = (el) => {
        if (!el || el.dataset.boundUsAccountType) return;
        el.dataset.boundUsAccountType = 'true';
        el.addEventListener('change', () => {
          if (el === checkingEl && checkingEl && checkingEl.checked && savingsEl) savingsEl.checked = false;
          if (el === savingsEl && savingsEl && savingsEl.checked && checkingEl) checkingEl.checked = false;

          const errEl = document.getElementById('error-usAccountType');
          if (errEl && getUsAccountTypeFromForm()) errEl.textContent = '';
          if (checkingEl && checkingEl.classList) checkingEl.classList.remove('input-error');
          if (savingsEl && savingsEl.classList) savingsEl.classList.remove('input-error');

          saveFormToDraft();
        });
      };

      bind(checkingEl);
      bind(savingsEl);
    }

    // IBAN normalization/formatting on blur (keeps validation logic separate in iban.js)
    {
      const ibanEl = form.elements.namedItem('iban');
      const ibanUtils = getIbanUtils();
      if (ibanEl && ibanUtils) {
        // Normalize any pre-filled value (e.g., when editing)
        if (getBankDetailsModeFromForm() !== 'US') {
          const initial = ibanUtils.validateIban(String(ibanEl.value || ''));
          if (initial.normalized) ibanEl.value = ibanUtils.formatIban(initial.normalized);
        }

        if (!ibanEl.dataset.boundIban) {
          ibanEl.dataset.boundIban = 'true';
          ibanEl.addEventListener('blur', () => {
            const mode = getBankDetailsModeFromForm();
            if (mode === 'US') {
              const normalized = normalizeUsBankText(String(ibanEl.value || ''));
              ibanEl.value = normalized;
              const errEl = document.getElementById('error-iban');
              if (errEl) errEl.textContent = '';
              if (ibanEl.classList) ibanEl.classList.remove('input-error');
              return;
            }

            const res = ibanUtils.validateIban(String(ibanEl.value || ''));
            ibanEl.value = res.normalized ? ibanUtils.formatIban(res.normalized) : '';

            const errEl = document.getElementById('error-iban');
            if (errEl) errEl.textContent = res.isValid ? '' : String(res.error || '');
            if (ibanEl.classList) {
              if (res.isValid) ibanEl.classList.remove('input-error');
              else ibanEl.classList.add('input-error');
            }
          });
        }
      }
    }

    // BIC normalization/formatting on blur (keeps validation logic separate in bic.js)
    {
      const bicEl = form.elements.namedItem('bic');
      const bicUtils = getBicUtils();
      if (bicEl && bicUtils) {
        if (getBankDetailsModeFromForm() !== 'US') {
          const initial = bicUtils.validateBic(String(bicEl.value || ''));
          if (initial.normalized) bicEl.value = bicUtils.formatBic(initial.normalized);
        }

        if (!bicEl.dataset.boundBic) {
          bicEl.dataset.boundBic = 'true';
          bicEl.addEventListener('blur', () => {
            const mode = getBankDetailsModeFromForm();
            if (mode === 'US') {
              const normalized = normalizeUsBankText(String(bicEl.value || ''));
              bicEl.value = normalized;
              const errEl = document.getElementById('error-bic');
              if (errEl) errEl.textContent = '';
              if (bicEl.classList) bicEl.classList.remove('input-error');
              return;
            }

            const res = bicUtils.validateBic(String(bicEl.value || ''));
            bicEl.value = res.normalized ? bicUtils.formatBic(res.normalized) : '';

            const errEl = document.getElementById('error-bic');
            if (errEl) errEl.textContent = res.isValid ? '' : String(res.error || '');
            if (bicEl.classList) {
              if (res.isValid) bicEl.classList.remove('input-error');
              else bicEl.classList.add('input-error');
            }
          });
        }
      }
    }

    updateItemsStatus();
    syncCurrencyFieldsFromItems();

    // If we are editing, tweak submit button label
    const submitBtn = form.querySelector('button[type="submit"]');
    if (submitBtn) {
      submitBtn.textContent = getEditOrderId() ? 'Save Changes' : 'Submit';
    }

    // Cancel edit button only appears in edit mode
    if (cancelEditBtn) {
      cancelEditBtn.hidden = !getEditOrderId();
      cancelEditBtn.addEventListener('click', () => {
        clearFieldErrors();
        clearItemsError();
        showSubmitToken('');
        clearDraft();
        void clearDraftAttachments();
        setEditOrderId(null);
        {
          const year = getActiveBudgetYear();
          window.location.href = `menu.html?year=${encodeURIComponent(String(year))}`;
        }
      });
    }

    // Open itemize page when clicking Euro or USD fields
    if (euroField) {
      euroField.addEventListener('click', openItemizeDraft);
      euroField.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          openItemizeDraft();
        }
      });
    }
    if (usdField) {
      usdField.addEventListener('click', openItemizeDraft);
      usdField.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          openItemizeDraft();
        }
      });
    }

    form.addEventListener('submit', async (e) => {
      e.preventDefault();

      const isPublicSubmit = IS_WP_SHARED_MODE && !getWpToken() && !editId;

      // In WP shared mode, allow public (logged-out) submissions via the server endpoint.
      if (!isPublicSubmit) {
        if (!requireWriteAccess('orders', 'Payment Orders is read only for your account.')) return;
      }

      clearFieldErrors();
      clearItemsError();
      showSubmitToken('');

      const result = validateForm();
      if (!result.ok) {
        showErrors(result.errors);
        // Rotate challenge after a failed attempt
        generateRequestCaptcha();
        return;
      }

      const items = loadDraftItems();
      if (items.length < 1) {
        showItemsError('At least one item is required. Click the Euro or USD field to add items.');
        return;
      }

      const totals = sumItems(items);
      const mode = inferCurrencyModeFromItems(items);
      if (mode === 'MIXED') {
        showItemsError('Use only one currency for all items (Euro or USD).');
        return;
      }
      const usingEuro = mode === 'EUR';
      const usingUsd = mode === 'USD';

      const orderValues = {
        ...result.values,
        euro: usingEuro ? totals.euro : null,
        usd: usingUsd ? totals.usd : null,
        items,
      };

      const year = getActiveBudgetYear();

      if (editId) {
        const existing = getOrderById(editId, year);
        if (!existing) {
          showItemsError('Could not find the submission to edit.');
          return;
        }

        // If this user cannot edit Budget Number, preserve the existing value.
        if (!canEditBudgetNumber) {
          orderValues.budgetNumber = String(existing.budgetNumber || '').trim();
        }

        // Do not allow Payment Order No. to change during edits
        orderValues.paymentOrderNo = existing.paymentOrderNo;

        const nowIso = new Date().toISOString();
        const updatedBase = {
          ...existing,
          ...orderValues,
          id: existing.id,
          createdAt: existing.createdAt,
          updatedAt: nowIso,
        };

        const changes = computeOrderAuditChanges(existing, updatedBase);
        const updated = changes.length > 0
          ? {
            ...updatedBase,
            timeline: appendTimelineEvent(existing, {
              at: nowIso,
              with: getOrderWithLabel(updatedBase),
              status: getOrderStatusLabel(updatedBase),
              user: getTimelineUsername(),
              action: 'Edited',
              changes,
            }),
          }
          : updatedBase;

        upsertOrder(updated, year);

        // In WP shared mode, writes are debounced; if we immediately redirect back to
        // the Payment Orders list the debounced flush may be canceled. Force flush now.
        if (IS_WP_SHARED_MODE && typeof window.acglFmsWpFlushNow === 'function') {
          try {
            await window.acglFmsWpFlushNow();
          } catch {
            // ignore
          }
        }

        // Show the same token after Save Changes (displayed on Payment Orders page)
        setFlashToken('Thank you, your update has been saved.');
      } else {
        if (isPublicSubmit) {
          try {
            const payload = await wpPublicSubmitPaymentOrder(year, orderValues, items);
            if (payload && payload.paymentOrderNo) {
              setPaymentOrderNoField(String(payload.paymentOrderNo));
            }

            form.reset();
            clearDraft();
            void clearDraftAttachments();
            setEditOrderId(null);
            updateItemsStatus();
            generateRequestCaptcha();
            if (euroField) euroField.value = '';
            if (usdField) usdField.value = '';
            maybeAutofillPaymentOrderNo();

            showSubmitToken('Thank you, your request has been submitted.');
            return;
          } catch (err) {
            showItemsError(`Could not submit request: ${String(err && err.message ? err.message : err)}`);
            return;
          }
        }

        // Keep numbering aligned to the active budget year before generating.
        syncNumberingSettingsToBudgetYear(year);

        // Enforce next Payment Order No. from settings
        const generatedPo = getNextPaymentOrderNo();
        const generatedCanon = canonicalizePaymentOrderNo(generatedPo);
        const existingPos = loadOrders(year).some((o) => canonicalizePaymentOrderNo(o && o.paymentOrderNo) === generatedCanon);
        if (existingPos) {
          showItemsError('Next Payment Order No. is already used. Update Settings to set the year/starting number.');
          return;
        }

        orderValues.paymentOrderNo = generatedPo;
        const order = buildPaymentOrder(orderValues);
        const orders = loadOrders(year);

        // Save newest first
        orders.unshift(order);
        saveOrders(orders, year);

        // Increment sequence for the next new request
        advancePaymentOrderSequence();
      }

      form.reset();
      clearDraft();
      void clearDraftAttachments();
      setEditOrderId(null);
      updateItemsStatus();

      // New captcha for the next submission
      generateRequestCaptcha();

      // Clear the auto-filled currency fields too
      if (euroField) euroField.value = '';
      if (usdField) usdField.value = '';

      // Prepare the next Payment Order No. after submitting a new request
      maybeAutofillPaymentOrderNo();

      if (!editId) {
        showSubmitToken('Thank you, your request has been submitted.');
      }

      // Return to list after editing
      if (getEditOrderId() === null) {
        // no-op
      }
      if (editId) {
        window.location.href = `menu.html?year=${encodeURIComponent(String(year))}`;
      }

      // Optional: you can navigate to the menu page manually using the header link.
    });

    if (resetBtn) {
      resetBtn.addEventListener('click', () => {
        clearFieldErrors();
        clearItemsError();
        showSubmitToken('');
        form.reset();
        clearDraft();
        void clearDraftAttachments();
        setEditOrderId(null);
        updateItemsStatus();
        syncCurrencyFieldsFromItems();
        const submitBtn = form.querySelector('button[type="submit"]');
        if (submitBtn) submitBtn.textContent = 'Submit';

        maybeAutofillPaymentOrderNo();

        generateRequestCaptcha();
      });
    }
  }

  if (editOrderBtn) {
    editOrderBtn.addEventListener('click', () => {
      if (!requireWriteAccess('orders', 'Payment Orders is read only for your account.')) return;
      const id = currentViewedOrderId || (modal ? modal.getAttribute('data-order-id') : null);
      if (!id) return;
      const year = getActiveBudgetYear();
      const order = getOrderById(id, year);
      if (!order) return;
      beginEditingOrder(order);
      closeModal();
      window.location.href = `index.html?year=${encodeURIComponent(String(year))}`;
    });
  }

  if (saveOrderBtn) {
    saveOrderBtn.addEventListener('click', () => {
      if (!requireOrdersViewEditAccess('Payment Orders is read only for your account.')) return;
      const id = currentViewedOrderId || (modal ? modal.getAttribute('data-order-id') : null);
      const year = getActiveBudgetYear();
      const latest = id ? getOrderById(id, year) : null;

      const withSelect = modalBody ? modalBody.querySelector('#modalWithSelect') : null;
      const statusSelect = modalBody ? modalBody.querySelector('#modalStatusSelect') : null;

      if (latest && withSelect && statusSelect) {
        const nextWith = normalizeWith(withSelect.value);
        const nextStatus = normalizeOrderStatus(statusSelect.value);

        const prevStatus = normalizeOrderStatus(getOrderStatusLabel(latest));

        // Guardrail: cannot change Status to Approved/Paid unless Budget Number is set.
        const changingToImpact = (nextStatus === 'Approved' || nextStatus === 'Paid') && nextStatus !== getOrderStatusLabel(latest);
        if (changingToImpact) {
          const outCode = extractOutCodeFromBudgetNumberText(latest.budgetNumber);
          if (!/^\d{4}$/.test(outCode)) {
            window.alert('Budget Number is required before setting Status to Approved or Paid. Edit the order and set Budget Number first.');
            statusSelect.value = prevStatus;
            modal.removeAttribute('data-pending-status');
            return;
          }
        }

        const changed = nextWith !== getOrderWithLabel(latest) || nextStatus !== getOrderStatusLabel(latest);
        if (changed) {
          const nowIso = new Date().toISOString();
          const draftNext = {
            ...latest,
            with: nextWith,
            status: nextStatus,
            updatedAt: nowIso,
          };
          const changes = computeOrderAuditChanges(latest, draftNext);
          let updated = {
            ...draftNext,
            timeline: appendTimelineEvent(latest, {
              at: nowIso,
              with: nextWith,
              status: nextStatus,
              user: getTimelineUsername(),
              action: 'Edited',
              changes,
            }),
          };

          function isBudgetImpactStatus(status) {
            return status === 'Approved' || status === 'Paid';
          }

          const hasDeduction = Boolean(updated && updated.budgetDeduction && updated.budgetDeduction.at);
          const entersImpact = !isBudgetImpactStatus(prevStatus) && isBudgetImpactStatus(nextStatus);
          const leavesImpact = isBudgetImpactStatus(prevStatus) && !isBudgetImpactStatus(nextStatus);

          // Leaving Approved/Paid: reverse prior deduction (if any).
          if (leavesImpact && hasDeduction) {
            const ded = updated.budgetDeduction;
            const outCode = ded && ded.budgetNumber ? String(ded.budgetNumber).trim() : '';
            const euro = ded && Number.isFinite(Number(ded.euro)) ? Number(ded.euro) : 0;
            const usd = ded && Number.isFinite(Number(ded.usd)) ? Number(ded.usd) : 0;
            const res = applyOrderBudgetExpendituresDelta(outCode, year, -euro, -usd, nowIso);
            if (res && res.ok) {
              const { budgetDeduction, ...rest } = updated;
              updated = rest;
            }
          }

          // Entering Approved/Paid: apply deduction once.
          // Moving Approved -> Paid does NOT reapply because entersImpact is false.
          if (entersImpact && !hasDeduction) {
            const res = applyApprovedOrderBudgetDeduction(updated, year, nowIso);
            if (res && res.ok) {
              updated = {
                ...updated,
                budgetDeduction: {
                  at: res.at,
                  year: Number(year),
                  budgetNumber: String(res.outCode),
                  euro: res.euroApplied,
                  usd: res.usdApplied,
                },
              };
            }
          }

          upsertOrder(updated, year);
          applyPaymentOrdersView();
        }
      }

      // Close the view modal after saving
      closeModal();
    });
  }

  // Note: "Clear All" button removed from UI.

  if (tbody) {
    // Delegate View/Delete buttons
    tbody.addEventListener('click', (e) => {
      const btn = e.target.closest('button[data-action]');
      if (!btn) return;

      const row = btn.closest('tr[data-id]');
      if (!row) return;

      const id = row.getAttribute('data-id');
      const action = btn.getAttribute('data-action');

      const year = getActiveBudgetYear();
      const orders = loadOrders(year);
      const order = orders.find((o) => o.id === id);
      if (!order) return;

      if (action === 'view') {
        openModalWithOrder(order);
      } else if (action === 'items') {
        if (!requireOrdersViewEditAccess('Payment Orders is read only for your account.')) return;
        window.location.href = `itemize.html?orderId=${encodeURIComponent(id)}&year=${encodeURIComponent(String(year))}`;
      } else if (action === 'edit') {
        if (!requireWriteAccess('orders', 'Payment Orders is read only for your account.')) return;
        beginEditingOrder(order);
        window.location.href = `index.html?year=${encodeURIComponent(String(year))}`;
      } else if (action === 'delete') {
        if (!requireWriteAccess('orders', 'Payment Orders is read only for your account.')) return;
        const ok = window.confirm('Delete this request?');
        if (!ok) return;
        deleteOrderById(id);
      }
    });
  }

  if (modal) {
    // Modal close handlers (backdrop, buttons)
    modal.addEventListener('click', (e) => {
      const closeTarget = e.target.closest('[data-modal-close]');
      if (closeTarget) closeModal();
    });
  }

  // Close modal on Escape (only relevant if a modal exists)
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
  }

  if (reconciliationBtn) {
    reconciliationBtn.addEventListener('click', () => {
      const year = getActiveBudgetYear();
      window.location.href = `reconciliation.html?year=${encodeURIComponent(String(year))}`;
    });
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

  // ---- Itemize page logic ----

  function getMilageRate(vehicleTypeRaw) {
    const v = String(vehicleTypeRaw || '').trim().toLowerCase();
    if (v === 'car') return 0.3;
    return 0.2;
  }

  function roundMoney(n) {
    const num = Number(n);
    if (!Number.isFinite(num)) return NaN;
    return Math.round(num * 100) / 100;
  }

  function computeMilageTotal(vehicleTypeRaw, kmRaw) {
    const km = Number(kmRaw);
    if (!Number.isFinite(km) || km < 0) return NaN;
    const total = km * getMilageRate(vehicleTypeRaw);
    return roundMoney(total);
  }

  function clearMilageErrors() {
    const keys = [
      'milageDate',
      'milageVehicleType',
      'milageStart',
      'milageDestination',
      'milageKilometers',
      'milageTotalCost',
      'milageAttachment',
    ];
    for (const k of keys) {
      const errEl = document.getElementById(`error-${k}`);
      if (errEl) errEl.textContent = '';
      const input = document.getElementById(k);
      if (input) input.classList.remove('input-error');
    }
    const viewErr = document.getElementById('milageViewError');
    if (viewErr) viewErr.textContent = '';
  }

  function showMilageErrors(errors) {
    for (const [k, msg] of Object.entries(errors || {})) {
      const errEl = document.getElementById(`error-${k}`);
      if (errEl) errEl.textContent = String(msg || '');
      const input = document.getElementById(k);
      if (input) input.classList.add('input-error');
    }
  }

  function updateMilageTotalCostField() {
    const vehicleEl = document.getElementById('milageVehicleType');
    const kmEl = document.getElementById('milageKilometers');
    const totalEl = document.getElementById('milageTotalCost');
    if (!vehicleEl || !kmEl || !totalEl) return;
    const total = computeMilageTotal(vehicleEl.value, kmEl.value);
    if (!Number.isFinite(total)) {
      totalEl.value = '';
      return;
    }
    totalEl.value = total.toFixed(2);
  }

  function closeMilageModal() {
    const modalEl = document.getElementById('milageModal');
    const formEl = document.getElementById('milageForm');
    const hintEl = document.getElementById('milageAttachmentHint');
    if (formEl) {
      formEl.reset();
      const editIdEl = document.getElementById('milageEditingId');
      const attIdEl = document.getElementById('milageAttachmentId');
      if (editIdEl) editIdEl.value = '';
      if (attIdEl) attIdEl.value = '';
      const fileEl = document.getElementById('milageAttachment');
      if (fileEl) {
        fileEl.value = '';
        fileEl.required = true;
      }
    }
    if (hintEl) hintEl.hidden = true;
    clearMilageErrors();
    closeSimpleModal(modalEl);
  }

  function closeMilageViewModal() {
    const modalEl = document.getElementById('milageViewModal');
    const bodyEl = document.getElementById('milageViewBody');
    if (bodyEl) bodyEl.innerHTML = '';
    if (modalEl) modalEl.removeAttribute('data-item-id');
    clearMilageErrors();
    closeSimpleModal(modalEl);
  }

  function readItemizeTarget() {
    const params = new URLSearchParams(window.location.search);
    const orderId = params.get('orderId');
    const isDraft = params.get('draft') === '1';
    return { orderId, isDraft };
  }

  function currencyModeFromOrderLike(orderLike) {
    if (!orderLike) return null;
    if (orderLike.euro !== null && orderLike.euro !== undefined && orderLike.euro !== '') return 'EUR';
    if (orderLike.usd !== null && orderLike.usd !== undefined && orderLike.usd !== '') return 'USD';
    return null;
  }

  function getOrderById(orderId, year) {
    const orders = loadOrders(year);
    return orders.find((o) => o.id === orderId) || null;
  }

  function upsertOrder(updatedOrder, year) {
    const orders = loadOrders(year);
    const next = orders.map((o) => (o.id === updatedOrder.id ? updatedOrder : o));
    saveOrders(next, year);
  }

  function clearItemErrors() {
    if (!itemForm) return;
    ['itemTitle', 'itemEuro', 'itemUsd'].forEach((k) => {
      const el = document.getElementById(`error-${k}`);
      if (el) el.textContent = '';
    });
    const inputs = itemForm.querySelectorAll('input');
    inputs.forEach((el) => el.classList.remove('input-error'));
  }

  function showItemErrors(errors) {
    if (!itemForm) return;
    for (const [key, msg] of Object.entries(errors)) {
      const errEl = document.getElementById(`error-${key}`);
      if (errEl) errEl.textContent = msg;
      const input = document.getElementById(key);
      if (input) input.classList.add('input-error');
    }
  }

  function validateItemInput(mode) {
    if (!itemForm) return { ok: false, errors: { itemTitle: 'Form not found.' } };

    const title = document.getElementById('itemTitle').value.trim();
    const euroRaw = document.getElementById('itemEuro').value.trim();
    const usdRaw = document.getElementById('itemUsd').value.trim();

    const hasEuro = euroRaw !== '';
    const hasUsd = usdRaw !== '';

    const errors = {};
    if (!title) errors.itemTitle = 'Title is required.';

    // Exactly one currency per item
    if (!hasEuro && !hasUsd) {
      errors.itemEuro = 'Enter Euro or USD.';
      errors.itemUsd = 'Enter Euro or USD.';
    }
    if (hasEuro && hasUsd) {
      errors.itemEuro = 'Enter only one currency.';
      errors.itemUsd = 'Enter only one currency.';
    }

    let euro = null;
    let usd = null;

    if (hasEuro) {
      const n = Number(euroRaw);
      if (!Number.isFinite(n) || n < 0) errors.itemEuro = 'Enter a valid non-negative number.';
      euro = n;
    }
    if (hasUsd) {
      const n = Number(usdRaw);
      if (!Number.isFinite(n) || n < 0) errors.itemUsd = 'Enter a valid non-negative number.';
      usd = n;
    }

    if (mode === 'EUR' && hasUsd) {
      errors.itemUsd = 'This order is Euro-only.';
    }
    if (mode === 'USD' && hasEuro) {
      errors.itemEuro = 'This order is USD-only.';
    }

    if (Object.keys(errors).length > 0) return { ok: false, errors };
    return { ok: true, value: { title, euro, usd } };
  }

  function renderItems(items, options = {}) {
    if (!itemsTbody || !itemsEmptyState || !totalEuroEl || !totalUsdEl) return;

    const readOnly = Boolean(options && options.readOnly);

    itemsTbody.innerHTML = '';
    if (!items || items.length === 0) {
      itemsEmptyState.hidden = false;
    } else {
      itemsEmptyState.hidden = true;
      itemsTbody.innerHTML = items
        .map((it, idx) => {
          const isMilage = Boolean(it && typeof it === 'object' && it.milage && typeof it.milage === 'object');
          return `
            <tr data-item-id="${escapeHtml(it.id)}">
              <td class="num">${idx + 1}</td>
              <td>${escapeHtml(it.title)}</td>
              <td class="num">${escapeHtml(formatCurrency(it.euro, 'EUR'))}</td>
              <td class="num">${escapeHtml(formatCurrency(it.usd, 'USD'))}</td>
              <td class="actions">
                ${isMilage ? '<button type="button" class="btn btn--ghost" data-item-action="viewMilage">View Milage</button>' : ''}
                ${readOnly ? '' : '<button type="button" class="btn btn--ghost" data-item-action="edit">Edit</button>'}
                ${readOnly ? '' : '<button type="button" class="btn btn--danger" data-item-action="delete">Delete</button>'}
              </td>
            </tr>
          `.trim();
        })
        .join('');
    }

    const totals = sumItems(items);
    totalEuroEl.textContent = formatCurrency(totals.euro, 'EUR') || '€ 0.00';
    totalUsdEl.textContent = formatCurrency(totals.usd, 'USD') || '$ 0.00';
  }

  function resetItemEditor() {
    if (!itemForm) return;
    if (editingItemIdEl) editingItemIdEl.value = '';
    document.getElementById('itemTitle').value = '';
    document.getElementById('itemEuro').value = '';
    document.getElementById('itemUsd').value = '';
    if (addOrUpdateItemBtn) addOrUpdateItemBtn.textContent = 'Add Item';
    const modalTitleEl = document.getElementById('itemModalTitle');
    if (modalTitleEl) modalTitleEl.textContent = 'Add Item';
    clearItemErrors();
  }

  function populateItemEditor(item) {
    if (!itemForm) return;
    if (editingItemIdEl) editingItemIdEl.value = item.id;
    document.getElementById('itemTitle').value = item.title || '';
    document.getElementById('itemEuro').value = item.euro === null || item.euro === undefined ? '' : String(item.euro);
    document.getElementById('itemUsd').value = item.usd === null || item.usd === undefined ? '' : String(item.usd);
    if (addOrUpdateItemBtn) addOrUpdateItemBtn.textContent = 'Update Item';
    const modalTitleEl = document.getElementById('itemModalTitle');
    if (modalTitleEl) modalTitleEl.textContent = 'Edit Item';
    clearItemErrors();
  }

  function closeItemModal() {
    if (itemForm) itemForm.reset();
    resetItemEditor();
    clearItemErrors();
    closeSimpleModal(itemModal);
  }

  if (itemForm && itemsTbody) {
    const target = readItemizeTarget();
    const attachmentTargetKey = getAttachmentTargetKey(target);
    let mode = null;
    let items = [];
    let boundOrderId = null;
    const milageModal = document.getElementById('milageModal');
    const milageForm = document.getElementById('milageForm');
    const milageViewModal = document.getElementById('milageViewModal');
    const currentUser = getCurrentUser();
    const canEditExistingOrderItems = Boolean(currentUser && canOrdersViewEdit(currentUser));
    const canViewExistingOrderItems = Boolean(currentUser && canOrdersViewEdit(currentUser));
    const isExistingOrderView = Boolean(!target.isDraft && target.orderId);
    const itemizeReadOnly = Boolean(isExistingOrderView && !canEditExistingOrderItems);

    if (target.isDraft) {
      const draft = loadDraft();
      mode = currencyModeFromOrderLike(draft);
      items = loadDraftItems();
      if (itemizeContext) {
        const label = draft?.paymentOrderNo ? `Draft: ${draft.paymentOrderNo}` : 'Draft payment order';
        itemizeContext.textContent = `${label}. Add line items below.`;
      }
    } else if (target.orderId) {
      if (!canViewExistingOrderItems) {
        window.alert('Read only access.');
        const year = getActiveBudgetYear();
        window.location.href = `menu.html?year=${encodeURIComponent(String(year))}`;
        return;
      }

      const year = getActiveBudgetYear();
      const order = getOrderById(target.orderId, year);
      boundOrderId = target.orderId;
      mode = currencyModeFromOrderLike(order);
      items = Array.isArray(order?.items) ? order.items : [];
      if (itemizeContext) {
        const label = order?.paymentOrderNo ? `Payment Order: ${order.paymentOrderNo}` : 'Payment Order';
        itemizeContext.textContent = itemizeReadOnly ? `${label}. View items below.` : `${label}. Edit items below.`;
      }
    }

    renderItems(items, { readOnly: itemizeReadOnly });
    if (itemizeReadOnly) {
      if (saveItemsBtn) saveItemsBtn.hidden = true;
      if (openItemModalBtn) openItemModalBtn.hidden = true;
      if (addMilageBtn) addMilageBtn.hidden = true;
    } else {
      resetItemEditor();
    }

    function requireItemizeEditAccess(message) {
      // Existing order itemize requires WP sign-in and at least partial access.
      if (isExistingOrderView) return requireOrdersViewEditAccess(message);

      // Draft itemize is part of the public request flow:
      // - anonymous users may draft
      // - signed-in users need at least partial access
      const u = getCurrentUser();
      if (!u) return true;
      if (!canOrdersViewEdit(u)) {
        window.alert(message || 'Read only access.');
        return false;
      }
      return true;
    }

    function openItemModalForAdd() {
      if (!itemModal || !itemForm) return;
      resetItemEditor();
      openSimpleModal(itemModal, '#itemTitle');
    }

    function openItemModalForEdit(item) {
      if (!itemModal || !itemForm) return;
      populateItemEditor(item);
      openSimpleModal(itemModal, '#itemTitle');
    }

    if (itemModal && !itemModal.dataset.bound) {
      itemModal.dataset.bound = '1';
      itemModal.addEventListener('click', (e) => {
        const closeTarget = e.target.closest('[data-modal-close]');
        if (closeTarget) closeItemModal();
      });
    }

    if (openItemModalBtn && !openItemModalBtn.dataset.bound) {
      openItemModalBtn.dataset.bound = '1';
      openItemModalBtn.disabled = itemizeReadOnly;
      if (itemizeReadOnly) openItemModalBtn.setAttribute('data-tooltip', 'Read only access.');
      openItemModalBtn.addEventListener('click', () => {
        if (itemizeReadOnly) return;
        if (!requireItemizeEditAccess('Payment Orders is read only for your account.')) return;
        openItemModalForAdd();
      });
    }

    const attachmentUploadContext = (() => {
      const year = String(getActiveBudgetYear() || '').trim();
      if (target.isDraft) {
        const draft = loadDraft();
        return {
          year,
          paymentOrderNo: String(draft && draft.paymentOrderNo ? draft.paymentOrderNo : '').trim(),
          orderId: '',
        };
      }
      if (target.orderId) {
        const y = getActiveBudgetYear();
        const order = getOrderById(target.orderId, y);
        return {
          year,
          paymentOrderNo: String(order && order.paymentOrderNo ? order.paymentOrderNo : '').trim(),
          orderId: String(target.orderId || '').trim(),
        };
      }
      return { year, paymentOrderNo: '', orderId: '' };
    })();

    function openMilageModalForAdd() {
      if (!milageModal || !milageForm) return;
      clearMilageErrors();
      milageForm.reset();
      const titleEl = document.getElementById('milageModalTitle');
      if (titleEl) titleEl.textContent = 'Add Milage';
      const editIdEl = document.getElementById('milageEditingId');
      const attIdEl = document.getElementById('milageAttachmentId');
      const fileEl = document.getElementById('milageAttachment');
      const hintEl = document.getElementById('milageAttachmentHint');
      if (editIdEl) editIdEl.value = '';
      if (attIdEl) attIdEl.value = '';
      if (fileEl) {
        fileEl.value = '';
        fileEl.required = true;
      }
      if (hintEl) hintEl.hidden = true;

      const dateEl = document.getElementById('milageDate');
      if (dateEl && !String(dateEl.value || '').trim()) {
        dateEl.value = new Date().toISOString().slice(0, 10);
      }

      updateMilageTotalCostField();
      openSimpleModal(milageModal, '#milageDate');
    }

    function openMilageModalForEdit(item) {
      if (!milageModal || !milageForm) return;
      const m = item && item.milage && typeof item.milage === 'object' ? item.milage : null;
      if (!m) return;
      clearMilageErrors();
      milageForm.reset();
      const titleEl = document.getElementById('milageModalTitle');
      if (titleEl) titleEl.textContent = 'Edit Milage';
      const editIdEl = document.getElementById('milageEditingId');
      const attIdEl = document.getElementById('milageAttachmentId');
      const hintEl = document.getElementById('milageAttachmentHint');
      const fileEl = document.getElementById('milageAttachment');
      if (editIdEl) editIdEl.value = String(item.id || '');
      if (attIdEl) attIdEl.value = String(m.attachmentId || '');
      if (fileEl) {
        fileEl.value = '';
        fileEl.required = false;
      }
      if (hintEl) hintEl.hidden = !Boolean(m.attachmentId);

      const dateEl = document.getElementById('milageDate');
      const vehicleEl = document.getElementById('milageVehicleType');
      const startEl = document.getElementById('milageStart');
      const destEl = document.getElementById('milageDestination');
      const kmEl = document.getElementById('milageKilometers');
      if (dateEl) dateEl.value = String(m.date || '').slice(0, 10);
      if (vehicleEl) vehicleEl.value = String(m.vehicleType || '');
      if (startEl) startEl.value = String(m.start || '');
      if (destEl) destEl.value = String(m.destination || '');
      if (kmEl) kmEl.value = m.kilometers === null || m.kilometers === undefined ? '' : String(m.kilometers);
      updateMilageTotalCostField();
      openSimpleModal(milageModal, '#milageDate');
    }

    function formatMilageVehicleLabel(vehicleTypeRaw) {
      const v = String(vehicleTypeRaw || '').trim().toLowerCase();
      if (v === 'car') return 'Car';
      if (v === 'motorcycle') return 'Motorcycle';
      return vehicleTypeRaw ? String(vehicleTypeRaw) : '—';
    }

    function openMilageView(item) {
      if (!milageViewModal) return;
      clearMilageErrors();
      const m = item && item.milage && typeof item.milage === 'object' ? item.milage : null;
      if (!m) return;
      const titleEl = document.getElementById('milageViewModalTitle');
      if (titleEl) titleEl.textContent = String(item.title || 'Milage');
      milageViewModal.setAttribute('data-item-id', String(item.id || ''));
      const bodyEl = document.getElementById('milageViewBody');
      const currency = item && item.euro !== null && item.euro !== undefined ? 'EUR' : 'USD';
      const symbol = currency === 'EUR' ? '€' : '$';
      const rate = getMilageRate(m.vehicleType);
      const total = computeMilageTotal(m.vehicleType, m.kilometers);
      if (bodyEl) {
        const attId = String(m.attachmentId || '').trim();
        bodyEl.innerHTML = `
          <div class="grid">
            <div class="field">
              <div class="subhead">Date</div>
              <div><strong>${escapeHtml(formatDate(m.date))}</strong></div>
            </div>
            <div class="field">
              <div class="subhead">Vehicle Type</div>
              <div><strong>${escapeHtml(formatMilageVehicleLabel(m.vehicleType))}</strong></div>
            </div>
            <div class="field field--span2">
              <div class="subhead">Start (Departure Location)</div>
              <div><strong>${escapeHtml(String(m.start || ''))}</strong></div>
            </div>
            <div class="field field--span2">
              <div class="subhead">Destination</div>
              <div><strong>${escapeHtml(String(m.destination || ''))}</strong></div>
            </div>
            <div class="field">
              <div class="subhead">Kilometers</div>
              <div><strong>${escapeHtml(String(m.kilometers ?? ''))}</strong></div>
            </div>
            <div class="field">
              <div class="subhead">Rate</div>
              <div><strong>${escapeHtml(symbol)} ${escapeHtml(rate.toFixed(2))} / km</strong></div>
            </div>
            <div class="field">
              <div class="subhead">Total</div>
              <div><strong>${escapeHtml(formatCurrency(total, currency) || '')}</strong></div>
            </div>

            <div class="field field--span2">
              <div class="subhead">ADAC Route Planner Attachment</div>
              ${attId
                ? `<div><a href="#" data-milage-attachment-link="1" data-attachment-id="${escapeHtml(attId)}">${escapeHtml(String(m.attachmentName || 'View / download attachment'))}</a></div>`
                : '<div class="muted">—</div>'}
            </div>
          </div>
        `.trim();
      }

      const downloadBtn = document.getElementById('milageDownloadBtn');
      if (downloadBtn) downloadBtn.disabled = !Boolean(m.attachmentId);

      const editBtn = document.getElementById('milageEditBtn');
      const delBtn = document.getElementById('milageDeleteBtn');
      if (editBtn) editBtn.disabled = itemizeReadOnly;
      if (delBtn) delBtn.disabled = itemizeReadOnly;

      openSimpleModal(milageViewModal, '#milageDownloadBtn');
    }

    async function deleteMilageItem(itemId) {
      const current = items.find((it) => it.id === itemId);
      if (!current) return;
      const m = current && current.milage && typeof current.milage === 'object' ? current.milage : null;
      const ok = window.confirm('Delete this milage report?');
      if (!ok) return;
      items = items.filter((it) => it.id !== itemId);
      renderItems(items, { readOnly: itemizeReadOnly });
      resetItemEditor();
      if (m && m.attachmentId) {
        try {
          await deleteAttachmentById(m.attachmentId);
          if (attachmentTargetKey) await refreshAttachments(attachmentTargetKey);
        } catch {
          // ignore
        }
      }
    }

    if (addMilageBtn && !addMilageBtn.dataset.bound) {
      addMilageBtn.dataset.bound = '1';
      addMilageBtn.disabled = itemizeReadOnly;
      if (itemizeReadOnly) addMilageBtn.setAttribute('data-tooltip', 'Read only access.');
      addMilageBtn.addEventListener('click', () => {
        if (itemizeReadOnly) return;
        if (!requireItemizeEditAccess('Payment Orders is read only for your account.')) return;
        openMilageModalForAdd();
      });
    }

    if (milageModal && !milageModal.dataset.bound) {
      milageModal.dataset.bound = '1';
      milageModal.addEventListener('click', (e) => {
        const closeTarget = e.target.closest('[data-modal-close]');
        if (closeTarget) closeMilageModal();
      });
    }

    if (milageViewModal && !milageViewModal.dataset.bound) {
      milageViewModal.dataset.bound = '1';
      milageViewModal.addEventListener('click', (e) => {
        const closeTarget = e.target.closest('[data-modal-close]');
        if (closeTarget) closeMilageViewModal();
      });
    }

    {
      const vehicleEl = document.getElementById('milageVehicleType');
      const kmEl = document.getElementById('milageKilometers');
      if (vehicleEl && !vehicleEl.dataset.bound) {
        vehicleEl.dataset.bound = '1';
        vehicleEl.addEventListener('change', updateMilageTotalCostField);
      }
      if (kmEl && !kmEl.dataset.bound) {
        kmEl.dataset.bound = '1';
        kmEl.addEventListener('input', updateMilageTotalCostField);
      }
    }

    if (milageForm && !milageForm.dataset.bound) {
      milageForm.dataset.bound = '1';
      milageForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        if (itemizeReadOnly) return;
        if (!requireItemizeEditAccess('Payment Orders is read only for your account.')) return;

        clearMilageErrors();

        const editId = String(document.getElementById('milageEditingId')?.value || '').trim();
        const existingItem = editId ? items.find((it) => it.id === editId) : null;
        const existingMilage = existingItem && existingItem.milage && typeof existingItem.milage === 'object' ? existingItem.milage : null;
        const existingAttachmentId = String(document.getElementById('milageAttachmentId')?.value || '').trim();
        const existingAttachmentName = existingMilage && existingMilage.attachmentName ? String(existingMilage.attachmentName) : '';

        const date = String(document.getElementById('milageDate')?.value || '').trim();
        const vehicleType = String(document.getElementById('milageVehicleType')?.value || '').trim();
        const start = String(document.getElementById('milageStart')?.value || '').trim();
        const destination = String(document.getElementById('milageDestination')?.value || '').trim();
        const kmRaw = String(document.getElementById('milageKilometers')?.value || '').trim();
        const km = Number(kmRaw);
        const total = computeMilageTotal(vehicleType, km);

        const errors = {};
        if (!date) errors.milageDate = 'Date is required.';
        if (!vehicleType) errors.milageVehicleType = 'Vehicle type is required.';
        if (!start) errors.milageStart = 'Start is required.';
        if (!destination) errors.milageDestination = 'Destination is required.';
        if (!kmRaw) errors.milageKilometers = 'Kilometers is required.';
        if (!Number.isFinite(km) || km <= 0) errors.milageKilometers = 'Enter a valid number greater than 0.';
        if (!Number.isFinite(total) || total < 0) errors.milageTotalCost = 'Total cost could not be calculated.';

        const fileEl = document.getElementById('milageAttachment');
        const file = fileEl && fileEl.files && fileEl.files[0] ? fileEl.files[0] : null;
        const mustHaveAttachment = !existingAttachmentId;
        if (mustHaveAttachment && !file) errors.milageAttachment = 'Attachment is required.';
        if (!attachmentTargetKey) errors.milageAttachment = 'Attachments are not available for this payment order.';

        if (Object.keys(errors).length > 0) {
          showMilageErrors(errors);
          return;
        }

        let attachmentId = existingAttachmentId;
        let attachmentName = existingAttachmentName;
        if (file && attachmentTargetKey) {
          try {
            const uploaded = await addAttachment(attachmentTargetKey, file, attachmentUploadContext);
            attachmentId = uploaded && uploaded.id ? String(uploaded.id) : '';
            attachmentName = uploaded && uploaded.name ? String(uploaded.name) : (file && file.name ? String(file.name) : '');
            if (existingAttachmentId) {
              try {
                await deleteAttachmentById(existingAttachmentId);
              } catch {
                // ignore
              }
            }
            await refreshAttachments(attachmentTargetKey);
          } catch {
            showMilageErrors({ milageAttachment: 'Failed to upload attachment.' });
            return;
          }
        }

        const currency = mode || (existingItem && existingItem.euro !== null ? 'EUR' : (existingItem && existingItem.usd !== null ? 'USD' : 'EUR'));
        const title = `Milage ${formatDate(date)}`;

        const nextItem = {
          id: editId || (crypto?.randomUUID ? crypto.randomUUID() : `it_${Date.now()}_${Math.random().toString(16).slice(2)}`),
          title,
          euro: currency === 'EUR' ? total : null,
          usd: currency === 'USD' ? total : null,
          milage: {
            date,
            vehicleType,
            start,
            destination,
            kilometers: km,
            rate: getMilageRate(vehicleType),
            attachmentId,
            attachmentName,
          },
        };

        if (editId) {
          items = items.map((it) => (it.id === editId ? nextItem : it));
        } else {
          items = [...items, nextItem];
        }

        if (!mode) mode = currency;

        closeMilageModal();
        renderItems(items, { readOnly: itemizeReadOnly });
      });
    }

    if (milageViewModal && !milageViewModal.dataset.actionsBound) {
      milageViewModal.dataset.actionsBound = '1';
      const downloadBtn = document.getElementById('milageDownloadBtn');
      const editBtn = document.getElementById('milageEditBtn');
      const delBtn = document.getElementById('milageDeleteBtn');

      milageViewModal.addEventListener('click', async (e) => {
        const link = e.target && e.target.closest ? e.target.closest('a[data-milage-attachment-link="1"]') : null;
        if (!link) return;
        e.preventDefault();
        const attId = String(link.getAttribute('data-attachment-id') || '').trim();
        if (!attId) return;
        try {
          const att = await getAttachmentById(attId);
          if (!att) return;
          openAttachmentInNewTab(att);
        } catch {
          const viewErr = document.getElementById('milageViewError');
          if (viewErr) viewErr.textContent = 'Could not open attachment.';
        }
      });

      if (downloadBtn) {
        downloadBtn.addEventListener('click', async () => {
          const id = String(milageViewModal.getAttribute('data-item-id') || '').trim();
          const item = items.find((it) => it.id === id);
          const m = item && item.milage && typeof item.milage === 'object' ? item.milage : null;
          if (!m || !m.attachmentId) return;
          try {
            const att = await getAttachmentById(m.attachmentId);
            if (!att) return;
            downloadAttachment(att);
          } catch {
            const viewErr = document.getElementById('milageViewError');
            if (viewErr) viewErr.textContent = 'Could not download attachment.';
          }
        });
      }

      if (editBtn) {
        editBtn.addEventListener('click', () => {
          if (itemizeReadOnly) return;
          if (!requireItemizeEditAccess('Payment Orders is read only for your account.')) return;
          const id = String(milageViewModal.getAttribute('data-item-id') || '').trim();
          const item = items.find((it) => it.id === id);
          if (!item) return;
          closeMilageViewModal();
          openMilageModalForEdit(item);
        });
      }

      if (delBtn) {
        delBtn.addEventListener('click', async () => {
          if (itemizeReadOnly) return;
          if (!requireItemizeEditAccess('Payment Orders is read only for your account.')) return;
          const id = String(milageViewModal.getAttribute('data-item-id') || '').trim();
          closeMilageViewModal();
          await deleteMilageItem(id);
        });
      }
    }

    // Attachments init (itemize page)
    if (attachmentsDropzone && attachmentsInput && attachmentTargetKey) {
      refreshAttachments(attachmentTargetKey);

      if (!itemizeReadOnly) {
        const openFilePicker = () => attachmentsInput.click();

        attachmentsDropzone.addEventListener('click', openFilePicker);
        attachmentsDropzone.addEventListener('keydown', (e) => {
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            openFilePicker();
          }
        });

        attachmentsDropzone.addEventListener('dragover', (e) => {
          e.preventDefault();
          attachmentsDropzone.classList.add('dropzone--over');
        });
        attachmentsDropzone.addEventListener('dragleave', () => {
          attachmentsDropzone.classList.remove('dropzone--over');
        });
        attachmentsDropzone.addEventListener('drop', (e) => {
          e.preventDefault();
          attachmentsDropzone.classList.remove('dropzone--over');
          handleAddedFiles(attachmentTargetKey, e.dataTransfer?.files, attachmentUploadContext);
        });

        attachmentsInput.addEventListener('change', () => {
          handleAddedFiles(attachmentTargetKey, attachmentsInput.files, attachmentUploadContext);
          attachmentsInput.value = '';
        });
      } else {
        attachmentsInput.disabled = true;
        attachmentsDropzone.setAttribute('aria-disabled', 'true');
      }

      if (attachmentsTbody) {
        attachmentsTbody.addEventListener('click', async (e) => {
          const btn = e.target.closest('button[data-attachment-action]');
          if (!btn) return;
          const row = btn.closest('tr[data-attachment-id]');
          if (!row) return;
          const id = row.getAttribute('data-attachment-id');
          const action = btn.getAttribute('data-attachment-action');

          if (action === 'delete') {
            if (!requireItemizeEditAccess('Payment Orders is read only for your account.')) return;
            const ok = window.confirm('Remove this attachment?');
            if (!ok) return;
            await deleteAttachmentById(id);
            await refreshAttachments(attachmentTargetKey);
            return;
          }

          if (action === 'view') {
            const att = await getAttachmentById(id);
            if (!att) return;
            openAttachmentInNewTab(att);
            return;
          }

          if (action === 'download') {
            const att = await getAttachmentById(id);
            if (!att) return;
            downloadAttachment(att);
          }
        });
      }
    }

    itemForm.addEventListener('submit', (e) => {
      e.preventDefault();
      if (!requireItemizeEditAccess('Payment Orders is read only for your account.')) return;
      clearItemErrors();

      const result = validateItemInput(mode);
      if (!result.ok) {
        showItemErrors(result.errors);
        return;
      }

      const id = editingItemIdEl ? editingItemIdEl.value : '';
      if (id) {
        items = items.map((it) => (it.id === id ? { ...it, ...result.value } : it));
      } else {
        const newItem = {
          id: (crypto?.randomUUID ? crypto.randomUUID() : `it_${Date.now()}_${Math.random().toString(16).slice(2)}`),
          ...result.value,
        };
        items = [...items, newItem];
      }

      // If mode wasn't chosen yet (draft), infer from the first added item
      if (!mode) {
        mode = result.value.euro !== null ? 'EUR' : 'USD';
      }

      renderItems(items, { readOnly: itemizeReadOnly });
      closeItemModal();
    });

    itemsTbody.addEventListener('click', async (e) => {
      const btn = e.target.closest('button[data-item-action]');
      if (!btn) return;
      const row = btn.closest('tr[data-item-id]');
      if (!row) return;

      const itemId = row.getAttribute('data-item-id');
      const action = btn.getAttribute('data-item-action');
      const current = items.find((it) => it.id === itemId);
      if (!current) return;

      if (action === 'viewMilage') {
        openMilageView(current);
        return;
      }

      if (itemizeReadOnly) return;

      if (action === 'edit') {
        if (current && current.milage && typeof current.milage === 'object') {
          openMilageModalForEdit(current);
          return;
        }
        openItemModalForEdit(current);
      } else if (action === 'delete') {
        if (!requireItemizeEditAccess('Payment Orders is read only for your account.')) return;
        if (current && current.milage && typeof current.milage === 'object') {
          await deleteMilageItem(itemId);
          return;
        }
        {
          const ok = window.confirm('Delete this item?');
          if (!ok) return;
          items = items.filter((it) => it.id !== itemId);
          renderItems(items, { readOnly: itemizeReadOnly });
          resetItemEditor();
        }
      }
    });

    if (saveItemsBtn) {
      saveItemsBtn.addEventListener('click', () => {
        if (!requireItemizeEditAccess('Payment Orders is read only for your account.')) return;
        if (items.length < 1) {
          window.alert('Add at least one item before saving.');
          return;
        }

        const totals = sumItems(items);

        if (target.isDraft) {
          const draft = loadDraft() || {};
          const inferredMode = mode || (totals.euro > 0 ? 'EUR' : 'USD');
          if (inferredMode === 'EUR') {
            draft.euro = String(totals.euro);
            draft.usd = '';
          } else {
            draft.usd = String(totals.usd);
            draft.euro = '';
          }
          saveDraft(draft);
          saveDraftItems(items);
          updateItemsStatus();
          {
            const year = getActiveBudgetYear();
            window.location.href = `index.html?resumeDraft=1&year=${encodeURIComponent(String(year))}`;
          }
          return;
        }

        if (boundOrderId) {
          const year = getActiveBudgetYear();
          const order = getOrderById(boundOrderId, year);
          if (!order) {
            window.alert('Could not find the payment order to update.');
            return;
          }
          const orderMode = mode || currencyModeFromOrderLike(order) || (totals.euro > 0 ? 'EUR' : 'USD');
          const updated = {
            ...order,
            items,
            euro: orderMode === 'EUR' ? totals.euro : null,
            usd: orderMode === 'USD' ? totals.usd : null,
          };
          upsertOrder(updated, year);
          window.location.href = `menu.html?year=${encodeURIComponent(String(year))}`;
        }
      });
    }
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
