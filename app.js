/*
  Payment Order Request app (no backend)
  - Validates required fields
  - Persists payment orders in localStorage
  - Renders newest-first table with View/Delete actions
*/

(() => {
  'use strict';

  const STORAGE_KEY = 'payment_orders';
  const PAYMENT_ORDERS_LEGACY_MIGRATED_KEY = 'payment_orders_legacy_migrated_v1';
  const THEME_KEY = 'payment_order_theme';
  const DRAFT_KEY = 'payment_order_draft';
  const DRAFT_ITEMS_KEY = 'payment_order_draft_items';
  const EDIT_ORDER_ID_KEY = 'payment_order_edit_order_id';
  const EDIT_ORDER_YEAR_KEY = 'payment_order_edit_order_year_v1';
  const NUMBERING_KEY = 'payment_order_numbering';
  const FLASH_TOKEN_KEY = 'payment_order_flash_token';
  const BUDGET_TABLE_HTML_KEY = 'payment_order_budget_table_html_v1';
  const BUDGET_YEARS_KEY = 'payment_order_budget_years_v1';
  const ACTIVE_BUDGET_YEAR_KEY = 'payment_order_active_budget_year_v1';
  const USERS_KEY = 'payment_order_users_v1';
  const CURRENT_USER_KEY = 'payment_order_current_user_v1';
  const LOGIN_AT_KEY = 'payment_order_login_at_v1';
  const AUTH_AUDIT_KEY = 'payment_order_auth_audit_v1';

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

  function getCurrentUsername() {
    try {
      return String(sessionStorage.getItem(CURRENT_USER_KEY) || '').trim();
    } catch {
      return '';
    }
  }

  function getCurrentLoginAtIso() {
    try {
      return String(sessionStorage.getItem(LOGIN_AT_KEY) || '').trim();
    } catch {
      return '';
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

  function setCurrentUsername(username) {
    const u = String(username || '').trim();
    try {
      if (!u) {
        sessionStorage.removeItem(CURRENT_USER_KEY);
        sessionStorage.removeItem(LOGIN_AT_KEY);
      } else {
        sessionStorage.setItem(CURRENT_USER_KEY, u);
        // Capture the time of successful sign-in for this session.
        sessionStorage.setItem(LOGIN_AT_KEY, new Date().toISOString());
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
      return new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(d);
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

  function performLogout() {
    const prev = normalizeUsername(getCurrentUsername());
    if (prev) appendAuthAuditEvent('Logout', prev);
    setCurrentUsername('');
  }

  function loadAuthAuditEvents() {
    try {
      const raw = localStorage.getItem(AUTH_AUDIT_KEY);
      const parsed = raw ? JSON.parse(raw) : [];
      const arr = Array.isArray(parsed) ? parsed : [];
      const filtered = arr.filter((e) => !isHardcodedAdminUsername(e && e.user));
      // If we removed any admin records, persist the cleanup.
      if (filtered.length !== arr.length) saveAuthAuditEvents(filtered);
      return filtered;
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
    if (isHardcodedAdminUsername(user)) return;
    const at = new Date().toISOString();

    const existing = loadAuthAuditEvents();
    const next = [...existing, { at, module: 'Auth', record: 'Session', user, action, changes: [] }];

    // Keep storage bounded.
    const MAX = 500;
    const trimmed = next.length > MAX ? next.slice(next.length - MAX) : next;
    saveAuthAuditEvents(trimmed);
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

  function requiredPermissionForPage(pathname) {
    const base = getBasename(pathname);

    // Public pages: always accessible without login.
    if (base === 'index.html' || base === 'itemize.html') return null;

    if (base === 'budget.html' || base === 'budget_dashboard.html') return 'budget';
    if (base === 'income.html') return 'income';
    if (base === 'menu.html' || base === 'reconciliation.html') return 'orders';
    if (base === 'grand_secretary_ledger.html') return 'ledger';
    if (base === 'settings.html') return 'settings';
    return null;
  }

  function isPublicRequestPage(pathname) {
    const base = getBasename(pathname);
    return base === 'index.html' || base === 'itemize.html';
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
      if (hasPermission(user, it.key)) return it.href;
    }
    return 'settings.html';
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
    const currentUser = getCurrentUser();
    const activeYear = (() => {
      const stored = loadActiveBudgetYear();
      if (stored && years.includes(stored)) return stored;
      return null;
    })();
    const resolvedYear = (() => {
      const storedActive = loadActiveBudgetYear();
      if (storedActive && years.includes(storedActive)) return storedActive;
      const candidate = getCurrentBudgetYearFromDate(new Date());
      if (years.includes(candidate)) return candidate;
      return years.length ? years[0] : candidate;
    })();
    const config = [
      { key: null, label: 'New Request Form', href: 'index.html?new=1' },
      {
        key: 'budget',
        label: 'Budget',
        href: `budget_dashboard.html?year=${encodeURIComponent(String(resolvedYear))}`,
        children: years.map((year) => ({
          label: String(year),
          href: `budget.html?year=${encodeURIComponent(String(year))}`,
          isActiveBudgetYear: activeYear === year,
        })),
      },
      {
        key: 'income',
        label: 'Income',
        href: `income.html?year=${encodeURIComponent(String(resolvedYear))}`,
        children: years.map((year) => ({
          label: String(year),
          href: `income.html?year=${encodeURIComponent(String(year))}`,
        })),
      },
      {
        key: 'orders',
        label: 'Payment Orders',
        href: `menu.html?year=${encodeURIComponent(String(resolvedYear))}`,
        children: years.map((year) => ({
          label: String(year),
          href: `menu.html?year=${encodeURIComponent(String(year))}`,
        })),
      },
      {
        key: 'ledger',
        label: 'Ledger',
        href: `grand_secretary_ledger.html?year=${encodeURIComponent(String(resolvedYear))}`,
        children: years.map((year) => ({
          label: String(year),
          href: `grand_secretary_ledger.html?year=${encodeURIComponent(String(year))}`,
        })),
      },
      { key: 'settings', label: 'Settings', href: 'settings.html' },
      { key: null, label: 'Log out', href: 'index.html?logout=1' },
    ];

    // If no user is logged in, keep nav minimal.
    if (!currentUser) {
      return [
        { key: null, label: 'New Request Form', href: 'index.html?new=1' },
      ];
    }

    // Filter nav by role permissions.
    return config.filter((it) => hasPermission(currentUser, it.key));
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
          <h2 class="authGate__title">Sign in</h2>
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
    const users = loadUsers();
    const hasAnyUsers = users.length > 0;
    if (!hasAnyUsers) {
      // If no users exist yet, there is nothing to verify against.
      window.location.href = 'settings.html';
      return;
    }

    const alreadyOpen = document.querySelector('.authGate[data-manual-auth-gate="1"]');
    if (alreadyOpen) return;

    const overlay = document.createElement('div');
    overlay.className = 'authGate';
    overlay.setAttribute('data-manual-auth-gate', '1');
    overlay.innerHTML = `
      <div class="authGate__card card">
        <h2 class="authGate__title">Sign in</h2>
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
        window.location.reload();
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

    for (const mount of mounts) {
      mount.innerHTML = '';

      const list = document.createElement('ul');
      list.className = 'appNavTree__list';

      for (const item of config) {
        const li = document.createElement('li');
        li.className = 'appNavTree__item';

        const children = Array.isArray(item.children) ? item.children : [];
        const isParent = children.length > 0;

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
        for (const child of children) {
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

        const row1 = document.createElement('div');
        row1.className = 'appNavSession__row';
        row1.appendChild(document.createTextNode(`User: ${username}`));

        const row2 = document.createElement('div');
        row2.className = 'appNavSession__row';
        row2.appendChild(document.createTextNode(`Accessed: ${loginAtText}`));

        footer.appendChild(row1);
        footer.appendChild(row2);
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
        const balance = kind === 'anticipated'
          ? (approved - receipts - expenditures)
          : (approved + receipts - expenditures);

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
    // Anticipated: approved - receipts - expenditures
    // Budget: approved + receipts - expenditures
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
      const balance = sectionKind === 'anticipated'
        ? (approved - receipts - nextExp)
        : (approved + receipts - nextExp);
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
  const itemForm = document.getElementById('itemForm');
  const itemsTbody = document.getElementById('itemsTbody');
  const itemsEmptyState = document.getElementById('itemsEmptyState');
  const totalEuroEl = document.getElementById('totalEuro');
  const totalUsdEl = document.getElementById('totalUsd');
  const saveItemsBtn = document.getElementById('saveItemsBtn');
  const editingItemIdEl = document.getElementById('editingItemId');
  const addOrUpdateItemBtn = document.getElementById('addOrUpdateItemBtn');
  const cancelEditItemBtn = document.getElementById('cancelEditItemBtn');
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
    if (!themeToggle) return;
    const isDark = theme === 'dark';
    if (typeof themeToggle.checked === 'boolean') {
      themeToggle.checked = isDark;
      themeToggle.setAttribute('aria-checked', String(isDark));
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
    return num.toFixed(2);
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
    el.value = String(value ?? '');
    el.readOnly = true;
    el.setAttribute('aria-readonly', 'true');
  }

  function maybeAutofillPaymentOrderNo() {
    if (!form) return;

    const editId = getEditOrderId();
    if (editId) {
      const year = getActiveBudgetYear();
      const existing = getOrderById(editId, year);
      if (existing && existing.paymentOrderNo) setPaymentOrderNoField(existing.paymentOrderNo);
      return;
    }

    const draft = loadDraft();
    if (draft && String(draft.paymentOrderNo || '').trim()) {
      setPaymentOrderNoField(draft.paymentOrderNo);
      return;
    }

    setPaymentOrderNoField(getNextPaymentOrderNo());
  }

  function saveFormToDraft() {
    if (!form) return;
    const draft = {
      paymentOrderNo: form.paymentOrderNo?.value?.trim?.() || '',
      date: form.date?.value?.trim?.() || '',
      name: form.name?.value?.trim?.() || '',
      euro: form.euro?.value?.trim?.() || '',
      usd: form.usd?.value?.trim?.() || '',
      address: form.address?.value?.trim?.() || '',
      iban: form.iban?.value?.trim?.() || '',
      bic: form.bic?.value?.trim?.() || '',
      specialInstructions: form.specialInstructions?.value?.trim?.() || '',
      budgetNumber: form.budgetNumber?.value?.trim?.() || '',
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
    const values = {
      paymentOrderNo: form.paymentOrderNo.value.trim(),
      date: form.date.value.trim(),
      name: form.name.value.trim(),
      address: form.address.value.trim(),
      iban: form.iban.value.trim(),
      bic: form.bic.value.trim(),
      specialInstructions: form.specialInstructions.value.trim(),
      budgetNumber: form.budgetNumber.value.trim(),
      purpose: form.purpose.value.trim(),
      captchaAnswer: form.captchaAnswer ? String(form.captchaAnswer.value || '').trim() : '',
    };

    const errors = {};

    // Required checks (all fields except currency; currency is validated as an either/or pair)
    const requiredKeys = [
      'paymentOrderNo',
      'date',
      'name',
      'address',
      'iban',
      'bic',
      'specialInstructions',
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

  // ---- Attachments (IndexedDB) ----

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
    const db = await openAttachmentsDb();
    const tx = db.transaction(ATTACHMENTS_STORE, 'readonly');
    const store = tx.objectStore(ATTACHMENTS_STORE);
    const index = store.index('by_targetKey');
    const attachments = await idbRequestToPromise(index.getAll(targetKey));

    // Sort newest-first
    return (attachments || []).sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)));
  }

  async function addAttachment(targetKey, file) {
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
    const db = await openAttachmentsDb();
    const tx = db.transaction(ATTACHMENTS_STORE, 'readwrite');
    const store = tx.objectStore(ATTACHMENTS_STORE);
    await idbRequestToPromise(store.delete(id));
  }

  async function deleteAttachmentsByTargetKey(targetKey) {
    if (!targetKey) return;
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
    const db = await openAttachmentsDb();
    const tx = db.transaction(ATTACHMENTS_STORE, 'readonly');
    const store = tx.objectStore(ATTACHMENTS_STORE);
    const record = await idbRequestToPromise(store.get(id));
    return record || null;
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
    setTimeout(() => URL.revokeObjectURL(url), 1000);
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
      showAttachmentsError('Could not load attachments in this browser.');
      // eslint-disable-next-line no-console
      console.error(err);
    }
  }

  async function handleAddedFiles(targetKey, fileList) {
    const files = Array.from(fileList || []);
    if (files.length === 0) return;

    showAttachmentsError('');
    for (const file of files) {
      try {
        // eslint-disable-next-line no-await-in-loop
        await addAttachment(targetKey, file);
      } catch (err) {
        // Likely quota or unsupported blob storage.
        showAttachmentsError('Attachment could not be saved (storage limit or browser restriction).');
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
        iban: 'DE00 0000 0000 0000 0000 00',
        bic: 'EXAMPLED1XXX',
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
        iban: 'GB00 0000 0000 0000 0000 00',
        bic: 'SAMPLEGB2L',
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
        iban: 'FR00 0000 0000 0000 0000 0000 000',
        bic: 'DEMOFRPPXXX',
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
      const balance =
        kind === 'anticipated'
          ? l.approved - l.receipts - l.expenditures
          : l.approved + l.receipts - l.expenditures;

      const approvedText = `EUR ${formatEuroValue(l.approved)}`;
      const receiptsText = `${formatEuroValue(l.receipts)} €`;
      const expText = `${formatEuroValue(l.expenditures)} €`;
      const balText = `${formatEuroValue(balance)} €`;

      return `
        <tr>
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
        totals.balance += kind === 'anticipated'
          ? (l.approved - l.receipts - l.expenditures)
          : (l.approved + l.receipts - l.expenditures);
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
      const input = form.elements.namedItem(key);
      if (input && input.classList) input.classList.add('input-error');

      const errorEl = document.getElementById(`error-${key}`);
      if (errorEl) errorEl.textContent = message;
    }

    // Focus first invalid field
    const firstKey = Object.keys(errors)[0];
    const firstEl = form.elements.namedItem(firstKey);
    if (firstEl && firstEl.focus) firstEl.focus();
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

    const currentUser = getCurrentUser();
    const canFullWrite = currentUser ? canWrite(currentUser, 'orders') : false;
    const writeDisabledAttr = canFullWrite ? '' : ' disabled';
    const writeAriaDisabled = canFullWrite ? 'false' : 'true';
    const writeTooltipAttr = canFullWrite ? '' : ' data-tooltip="Requires Full access for Payment Orders."';

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
            <td>${escapeHtml(o.budgetNumber)}</td>
            <td>${escapeHtml(o.purpose)}</td>
            <td>${escapeHtml(getOrderWithLabel(o))}</td>
            <td>${escapeHtml(getOrderStatusLabel(o))}</td>
            <td class="actions">
              <button type="button" class="btn btn--ghost btn--items" data-action="items" title="${canFullWrite ? 'Items' : 'Requires Full access for Payment Orders.'}" aria-disabled="${writeAriaDisabled}"${writeDisabledAttr}${writeTooltipAttr}>Items</button>
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
      const budget = formatBudgetNumberForDisplay(orderForView.budgetNumber);
      modalHeaderBudget.textContent = `Budget Number: ${budget || '—'}`;
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
        <dt>IBAN</dt><dd>${escapeHtml(orderForView.iban)}</dd>
        <dt>BIC</dt><dd>${escapeHtml(orderForView.bic)}</dd>
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

    document.title = `${year} Payment Orders`;
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
            <td>${escapeHtml(o.budgetNumber || '')}</td>
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

    document.title = `${year} Reconciliation`;

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
  };

  function formatAccessLabel(level) {
    const lv = String(level || 'none').toLowerCase();
    if (lv === 'write') return 'Full';
    if (lv === 'partial') return 'Partial';
    if (lv === 'read') return 'Read only';
    return 'None';
  }

  function renderUsersTable() {
    if (!usersTbody || !usersEmptyState) return;
    const users = loadUsers();
    const visibleUsers = (Array.isArray(users) ? users : []).filter((u) => (
      normalizeUsername(u && u.username) !== normalizeUsername(HARD_CODED_ADMIN_USERNAME)
    ));
    const currentUser = getCurrentUser();
    const canEdit = currentUser ? canWrite(currentUser, 'settings') : false;

    usersTbody.innerHTML = '';
    if (!visibleUsers || visibleUsers.length === 0) {
      usersEmptyState.hidden = false;
      return;
    }
    usersEmptyState.hidden = true;

    const rows = visibleUsers
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
            <td class="actions">${actionsCell}</td>
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
  }

  async function createUser(usernameRaw, passwordRaw, permissions, emailRaw) {
    const username = normalizeUsername(usernameRaw);
    const password = String(passwordRaw || '');
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
    return { ok: true, user };
  }

  async function updateUser(usernameRaw, nextPermissions, newPasswordRaw, nextEmailRaw) {
    const username = normalizeUsername(usernameRaw);
    const newPassword = String(newPasswordRaw || '');
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

  function renderSettingsAuditLog() {
    const listEl = document.getElementById('auditLogList');
    const emptyEl = document.getElementById('auditLogEmptyState');
    const metaEl = document.getElementById('auditLogMeta');
    const searchInput = document.getElementById('auditLogSearch');
    const clearBtn = document.getElementById('auditLogClearSearchBtn');
    if (!listEl || !emptyEl) return;

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

    function applyMaxVisibleItems(maxVisible) {
      const items = Array.from(listEl.querySelectorAll('.auditLog__item'));

      listEl.style.overflowY = 'auto';
      if (items.length <= maxVisible) {
        listEl.style.maxHeight = '';
        return;
      }

      // Prefer bounding-rect measurement so layout gaps are counted correctly,
      // and so we don't depend on offsetParent quirks.
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

      // Fallback: sum item heights + computed gap.
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

        const at = logoutAt || loginAt || new Date().toISOString();
        const ms = (logoutMs != null ? logoutMs : (loginMs != null ? loginMs : (toTimeMs(at) ?? 0)));

        return {
          ms,
          at,
          module: 'Auth',
          record: 'Session',
          user,
          action: 'Session',
          changes: [
            { field: 'Login', from: '', to: loginText },
            { field: 'Logout', from: '', to: logoutText },
            { field: 'Total time logged in', from: '', to: durText },
          ],
        };
      };

      for (const e of raw) {
        const actionLower = String(e.action || '').trim().toLowerCase();
        if (actionLower === 'login') {
          openLoginByUser.set(String(e.user || '—'), e);
          continue;
        }
        if (actionLower === 'logout') {
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

    // Enforce: max 10 visible items; scroll to see the rest.
    // Run twice to reduce cases where first paint hasn't finalized heights yet.
    requestAnimationFrame(() => {
      applyMaxVisibleItems(10);
      requestAnimationFrame(() => applyMaxVisibleItems(10));
    });

    // Re-apply cap on resize (layout changes can affect item wrapping/height).
    if (!listEl.dataset.auditCapResizeBound) {
      listEl.dataset.auditCapResizeBound = '1';
      let resizeTimer = 0;
      window.addEventListener('resize', () => {
        if (resizeTimer) window.clearTimeout(resizeTimer);
        resizeTimer = window.setTimeout(() => {
          resizeTimer = 0;
          applyMaxVisibleItems(10);
        }, 120);
      });
    }
  }

  function initRolesSettingsPage() {
    if (!createUserForm || !usersTbody || !usersEmptyState) return;

    const hasAnyUsers = loadUsers().length > 0;
    const currentUser = getCurrentUser();
    const canEdit = !hasAnyUsers || (currentUser ? canWrite(currentUser, 'settings') : false);

    renderUsersTable();

    // Timeline audit log (Payment Orders + Income)
    renderSettingsAuditLog();

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
      });
    }

    // If the current user cannot write Settings (and users already exist), make the
    // create-user form visibly read-only (submit handler also blocks).
    if (hasAnyUsers && !canEdit) {
      const createInputs = Array.from(createUserForm.querySelectorAll('input, select, textarea, button'));
      createInputs.forEach((el) => {
        el.disabled = true;
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
    const html = (rows || [])
      .map((r) => {
        const ledgerId = escapeHtml(r.ledgerId);
        const date = escapeHtml(getGsLedgerDisplayValueForColumn(r, 'date'));
        const budgetNumber = escapeHtml(getGsLedgerDisplayValueForColumn(r, 'budgetNumber'));
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
    const menuBtn = document.getElementById('gsLedgerActionsMenuBtn');
    const menuPanel = document.getElementById('gsLedgerActionsMenu');

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
    document.title = `${year} Ledger`;

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
        const budget = escapeHtml(getIncomeDisplayValueForColumn(e, 'budgetNumber', year));
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
    document.title = `${year} Income`;

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

    // Page title ("YYYY Budget")
    const titleEl = document.querySelector('[data-budget-title]');
    if (titleEl) titleEl.textContent = `${budgetYear} Budget`;

    const listTitleEl = document.querySelector('[data-budget-list-title]');
    if (listTitleEl) listTitleEl.textContent = `${budgetYear} Budget`;

    const subheadEl = document.querySelector('[data-budget-subhead]');
    if (subheadEl) subheadEl.textContent = `Budget overview table for ${budgetYear}.`;
    document.title = `${budgetYear} Budget`;

    // Register this year and seed it with the current template (if missing)
    const templateHtml = tbody.innerHTML;
    ensureBudgetYearExists(budgetYear, templateHtml);
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

    function sumSection(rows) {
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
        totals.approved += parseMoney(tds[3]?.textContent);
        totals.receipts += parseMoney(tds[4]?.textContent);
        totals.expenditures += parseMoney(tds[5]?.textContent);
        totals.balance += parseMoney(tds[6]?.textContent);

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

      const s1 = sumSection(section1Rows);
      const s2 = sumSection(section2Rows);

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

      setLinkDisabled(addLineLink, !isEditing);
      setLinkDisabled(removeLineLink, !isEditing || !selectedRow);

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

      // Seed new year from the currently saved table for this page's year.
      const seedHtml = budgetKey ? localStorage.getItem(budgetKey) : null;
      const initial = seedHtml || templateHtml;
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
        'Receipts Euro',
        'Expenditures Euro',
        'Balance Euro',
        'Receipts USD',
        'Expenditures USD',
      ];

      const exampleRows = [
        // Use values that match the importer's expectations and the UI's formatting.
        ['Anticipated', '1020', '2020', 'Example anticipated line', '0.00 €', '0.00 €', '0.00 €', '0.00 €', '-', '-'],
        ['Budget', '1998', '2998', 'Example budget line', '0.00 €', '0.00 €', '0.00 €', '0.00 €', '-', '-'],
      ];

      const lines = [];
      lines.push(header.map(escapeCsvValue).join(','));
      for (const r of exampleRows) lines.push(r.map(escapeCsvValue).join(','));

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
        `Importing a CSV will add rows to the current budget table. Continue?\n\nFile: ${fileName || 'CSV'}`
      );
      if (!ok) return;

      function readExistingRecordsBySection() {
        const allRows = Array.from(tbody.querySelectorAll('tr'));
        const totals = allRows.filter((r) => r.classList.contains('budgetTable__total'));
        const firstTotalIndex = totals.length >= 1 ? allRows.indexOf(totals[0]) : -1;
        const secondTotalIndex = totals.length >= 2 ? allRows.indexOf(totals[1]) : -1;

        const section1 = [];
        const section2 = [];

        for (const tr of allRows) {
          if (tr.classList.contains('budgetTable__spacer')) continue;
          if (tr.classList.contains('budgetTable__total')) continue;
          if (tr.classList.contains('budgetTable__remaining')) continue;
          if (tr.classList.contains('budgetTable__checksum')) continue;

          const tds = Array.from(tr.querySelectorAll('td'));
          if (tds.length < 7) continue;

          const rowIndex = allRows.indexOf(tr);
          const isSection1 = firstTotalIndex >= 0 && rowIndex >= 0 && rowIndex < firstTotalIndex;
          const isSection2 =
            firstTotalIndex >= 0 &&
            rowIndex >= 0 &&
            rowIndex > firstTotalIndex &&
            (secondTotalIndex < 0 || rowIndex < secondTotalIndex);

          const rec = {
            in: tds[0]?.textContent ?? '',
            out: tds[1]?.textContent ?? '',
            description: tds[2]?.textContent ?? '',
            approvedEuro: tds[3]?.textContent ?? '',
            receiptsEuro: tds[4]?.textContent ?? '',
            expendituresEuro: tds[5]?.textContent ?? '',
            balanceEuro: tds[6]?.textContent ?? '',
            receiptsUsd: tds[8]?.textContent ?? '',
            expendituresUsd: tds[10]?.textContent ?? '',
          };

          if (isSection1) section1.push(rec);
          else if (isSection2) section2.push(rec);
          else section2.push(rec);
        }

        return { section1, section2 };
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

        const sectionName = String(rawSection ?? '').trim().toLowerCase();
        const targetSection = sectionName.startsWith('a') ? 1 : sectionName.startsWith('b') ? 2 : inferredSection;

        if (targetSection === 1) section1.push(record);
        else section2.push(record);
      }

      const existing = readExistingRecordsBySection();
      const mergedSection1 = [...(existing.section1 || []), ...section1];
      const mergedSection2 = [...(existing.section2 || []), ...section2];

      // Rebuild tbody from merged data
      tbody.innerHTML = '';
      for (const rec of mergedSection1) tbody.appendChild(buildDataRowFromRecord(rec));
      tbody.appendChild(buildSpacerRow());
      tbody.appendChild(buildTotalRow('Total Anticipated Values'));
      tbody.appendChild(buildSpacerRow());
      for (const rec of mergedSection2) tbody.appendChild(buildDataRowFromRecord(rec));
      tbody.appendChild(buildTotalRow('Total Budget, Receipts, Expenditures'));
      tbody.appendChild(buildRemainingRow());
      for (const el of buildChecksumSection()) tbody.appendChild(el);

      // Migrate and recalc using the same pipeline as saved HTML.
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
    if (subheadEl) subheadEl.textContent = `Charts for ${year}: Expenditures vs Balance (Euro).`;
    document.title = `${year} Budget Dashboard`;

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
        const r = meta.radius + meta.stroke / 2;
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
      chartRow.appendChild(svg);
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
  initBudgetYearNav();
  initBudgetEditor();
  initBudgetDashboard();
  initBudgetNumberSelect();

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

  if (form) {
    const base = getBasename(window.location.pathname);
    const isRequestForm = base === 'index.html';
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
      window.location.href = 'index.html?new=1';
      return;
    }

    const currentUser = getCurrentUser();
    const canEditBudgetNumber = Boolean(currentUser && canWrite(currentUser, 'orders'));
    const budgetNumberEl = form.elements.namedItem('budgetNumber');
    if (budgetNumberEl) {
      budgetNumberEl.disabled = !canEditBudgetNumber;
      if (!canEditBudgetNumber) budgetNumberEl.value = '';
    }

    if (isRequestForm && forceNew) {
      setEditOrderId(null);
      form.reset();
      clearDraft();
      void clearDraftAttachments();
      updateItemsStatus();
      syncCurrencyFieldsFromItems();
    }

    const editId = getEditOrderId();

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
        ...(canEditBudgetNumber ? ['budgetNumber'] : []),
        'purpose',
      ];
      for (const key of keys) {
        const el = form.elements.namedItem(key);
        if (el && draft[key] !== undefined) el.value = draft[key];
      }
    }

    // Ensure Payment Order No. always follows the configured pattern
    maybeAutofillPaymentOrderNo();

    // Captcha must be solved before submitting
    generateRequestCaptcha();

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

    form.addEventListener('submit', (e) => {
      e.preventDefault();

      if (!requireWriteAccess('orders', 'Payment Orders is read only for your account.')) return;

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

      // Only Payment Orders Full access can set Budget Number on the request form.
      if (!canEditBudgetNumber && result.values) {
        result.values.budgetNumber = '';
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

      const editId = getEditOrderId();
      const year = getActiveBudgetYear();

      if (editId) {
        const existing = getOrderById(editId, year);
        if (!existing) {
          showItemsError('Could not find the submission to edit.');
          return;
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

        // Show the same token after Save Changes (displayed on Payment Orders page)
        setFlashToken('Thank you, your update has been saved.');
      } else {
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

          // If status transitions to Approved, deduct this order from the selected budget line once.
          const alreadyDeducted = Boolean(updated && updated.budgetDeduction && updated.budgetDeduction.at);
          const becomesApproved = prevStatus !== 'Approved' && nextStatus === 'Approved';
          if (becomesApproved && !alreadyDeducted) {
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
    if (e.key === 'Escape' && modal && modal.classList.contains('is-open')) {
      closeModal();
    }
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

  if (reconcileTbody) {
    initReconciliationListPage();
  }

  if (incomeTbody) {
    initIncomeListPage();
  }

  if (gsLedgerTbody) {
    initGsLedgerListPage();
  }

  // ---- Itemize page logic ----

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

  function renderItems(items) {
    if (!itemsTbody || !itemsEmptyState || !totalEuroEl || !totalUsdEl) return;

    itemsTbody.innerHTML = '';
    if (!items || items.length === 0) {
      itemsEmptyState.hidden = false;
    } else {
      itemsEmptyState.hidden = true;
      itemsTbody.innerHTML = items
        .map((it, idx) => {
          return `
            <tr data-item-id="${escapeHtml(it.id)}">
              <td class="num">${idx + 1}</td>
              <td>${escapeHtml(it.title)}</td>
              <td class="num">${escapeHtml(formatCurrency(it.euro, 'EUR'))}</td>
              <td class="num">${escapeHtml(formatCurrency(it.usd, 'USD'))}</td>
              <td class="actions">
                <button type="button" class="btn btn--ghost" data-item-action="edit">Edit</button>
                <button type="button" class="btn btn--danger" data-item-action="delete">Delete</button>
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
    if (cancelEditItemBtn) cancelEditItemBtn.hidden = true;
    clearItemErrors();
  }

  function populateItemEditor(item) {
    if (!itemForm) return;
    if (editingItemIdEl) editingItemIdEl.value = item.id;
    document.getElementById('itemTitle').value = item.title || '';
    document.getElementById('itemEuro').value = item.euro === null || item.euro === undefined ? '' : String(item.euro);
    document.getElementById('itemUsd').value = item.usd === null || item.usd === undefined ? '' : String(item.usd);
    if (addOrUpdateItemBtn) addOrUpdateItemBtn.textContent = 'Update Item';
    if (cancelEditItemBtn) cancelEditItemBtn.hidden = false;
    clearItemErrors();
  }

  if (itemForm && itemsTbody) {
    const target = readItemizeTarget();
    const attachmentTargetKey = getAttachmentTargetKey(target);
    let mode = null;
    let items = [];
    let boundOrderId = null;

    if (target.isDraft) {
      const draft = loadDraft();
      mode = currencyModeFromOrderLike(draft);
      items = loadDraftItems();
      if (itemizeContext) {
        const label = draft?.paymentOrderNo ? `Draft: ${draft.paymentOrderNo}` : 'Draft payment order';
        itemizeContext.textContent = `${label}. Add line items below.`;
      }
    } else if (target.orderId) {
      const year = getActiveBudgetYear();
      const order = getOrderById(target.orderId, year);
      boundOrderId = target.orderId;
      mode = currencyModeFromOrderLike(order);
      items = Array.isArray(order?.items) ? order.items : [];
      if (itemizeContext) {
        const label = order?.paymentOrderNo ? `Payment Order: ${order.paymentOrderNo}` : 'Payment Order';
        itemizeContext.textContent = `${label}. Edit items below.`;
      }
    }

    renderItems(items);
    resetItemEditor();

    // Attachments init (itemize page)
    if (attachmentsDropzone && attachmentsInput && attachmentTargetKey) {
      refreshAttachments(attachmentTargetKey);

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
        handleAddedFiles(attachmentTargetKey, e.dataTransfer?.files);
      });

      attachmentsInput.addEventListener('change', () => {
        handleAddedFiles(attachmentTargetKey, attachmentsInput.files);
        attachmentsInput.value = '';
      });

      if (attachmentsTbody) {
        attachmentsTbody.addEventListener('click', async (e) => {
          const btn = e.target.closest('button[data-attachment-action]');
          if (!btn) return;
          const row = btn.closest('tr[data-attachment-id]');
          if (!row) return;
          const id = row.getAttribute('data-attachment-id');
          const action = btn.getAttribute('data-attachment-action');

          if (action === 'delete') {
            if (!requireWriteAccess('orders', 'Payment Orders is read only for your account.')) return;
            const ok = window.confirm('Remove this attachment?');
            if (!ok) return;
            await deleteAttachmentById(id);
            await refreshAttachments(attachmentTargetKey);
            return;
          }

          if (action === 'view') {
            const att = await getAttachmentById(id);
            if (!att) return;
            openBlobInNewTab(att.blob);
            return;
          }

          if (action === 'download') {
            const att = await getAttachmentById(id);
            if (!att) return;
            downloadBlob(att.blob, att.name);
          }
        });
      }
    }

    itemForm.addEventListener('submit', (e) => {
      e.preventDefault();
      if (!requireWriteAccess('orders', 'Payment Orders is read only for your account.')) return;
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

      renderItems(items);
      resetItemEditor();
    });

    if (cancelEditItemBtn) {
      cancelEditItemBtn.addEventListener('click', resetItemEditor);
    }

    itemsTbody.addEventListener('click', (e) => {
      const btn = e.target.closest('button[data-item-action]');
      if (!btn) return;
      const row = btn.closest('tr[data-item-id]');
      if (!row) return;

      const itemId = row.getAttribute('data-item-id');
      const action = btn.getAttribute('data-item-action');
      const current = items.find((it) => it.id === itemId);
      if (!current) return;

      if (action === 'edit') {
        populateItemEditor(current);
      } else if (action === 'delete') {
        if (!requireWriteAccess('orders', 'Payment Orders is read only for your account.')) return;
        const ok = window.confirm('Delete this item?');
        if (!ok) return;
        items = items.filter((it) => it.id !== itemId);
        renderItems(items);
        resetItemEditor();
      }
    });

    if (saveItemsBtn) {
      saveItemsBtn.addEventListener('click', () => {
        if (!requireWriteAccess('orders', 'Payment Orders is read only for your account.')) return;
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
})();
