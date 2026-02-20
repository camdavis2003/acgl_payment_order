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

  function getPaymentOrdersKeyForYear(year) {
    const y = Number(year);
    if (!Number.isInteger(y)) return null;
    if (y < 1900 || y > 3000) return null;
    return `payment_orders_${y}_v1`;
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
    return [
      { label: 'New Request Form', href: 'index.html' },
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
        key: 'orders',
        label: 'Payment Orders',
        href: `menu.html?year=${encodeURIComponent(String(resolvedYear))}`,
        children: years.map((year) => ({
          label: String(year),
          href: `menu.html?year=${encodeURIComponent(String(year))}`,
        })),
      },
      { label: 'Settings', href: 'settings.html' },
    ];
  }

  function getBasename(pathname) {
    const raw = String(pathname || '').replace(/\\/g, '/');
    const parts = raw.split('/').filter(Boolean);
    return parts.length ? parts[parts.length - 1].toLowerCase() : '';
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

  const modal = document.getElementById('detailsModal');
  const modalBody = document.getElementById('modalBody');
  const editOrderBtn = document.getElementById('editOrderBtn');
  const saveOrderBtn = document.getElementById('saveOrderBtn');

  const themeToggle = document.getElementById('themeToggle');

  // Request form submission token
  const submitToken = document.getElementById('submitToken');
  const cancelEditBtn = document.getElementById('cancelEditBtn');

  // Menu page flash token (one-time message after redirects)
  const flashToken = document.getElementById('flashToken');

  let submitTokenHideTimer = null;
  let flashTokenHideTimer = null;

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

  // Form page helpers
  const itemsStatus = document.getElementById('itemsStatus');
  const itemsErrorEl = document.getElementById('error-items');

  const euroField = document.getElementById('euro');
  const usdField = document.getElementById('usd');

  let currentViewedOrderId = null;

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
      'budgetNumber',
      'purpose',
    ];
    for (const key of requiredKeys) {
      if (!values[key]) errors[key] = 'This field is required.';
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
              <button type="button" class="btn btn--ghost" data-attachment-action="download">Download</button>
              <button type="button" class="btn btn--danger" data-attachment-action="delete">Remove</button>
            </td>
          </tr>
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

      if (existing.length >= 10) return;
      localStorage.setItem(ordersKey, JSON.stringify(next));
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
      },
    ];
  }

  function appendTimelineEvent(order, evt) {
    const timeline = ensureOrderTimeline(order);
    return [...timeline, evt];
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

    if (!orders || orders.length === 0) {
      emptyState.hidden = false;
      return;
    }

    emptyState.hidden = true;

    // Newest first (createdAt desc)
    const sorted = [...orders].sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)));

    const rowsHtml = sorted
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
              <button type="button" class="btn btn--ghost btn--items" data-action="items">Items</button>
              <button type="button" class="btn btn--editBlue" data-action="edit">Edit</button>
              <button type="button" class="btn btn--viewGrey" data-action="view">View</button>
            </td>
          </tr>
        `.trim();
      })
      .join('');

    tbody.innerHTML = rowsHtml;
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
        <dt>Created</dt><dd>${escapeHtml(orderForView.createdAt)}</dd>
      </dl>
      ${renderTimelineGraph(orderForView)}
    `.trim();

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
    renderOrders(next);
  }

  function clearAll() {
    const year = getActiveBudgetYear();
    const orders = loadOrders(year);
    if (orders.length === 0) return;
    const ok = window.confirm('Clear all payment orders? This cannot be undone.');
    if (!ok) return;
    saveOrders([], year);
    renderOrders([]);
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

    const tbody = table.querySelector('tbody');
    if (!tbody) return;

    // Page title ("YYYY Budget")
    const titleEl = document.querySelector('[data-budget-title]');
    if (titleEl) titleEl.textContent = `${budgetYear} Budget`;
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
      setActiveBtn.disabled = isActive;

      if (isActive) {
        setActiveBtn.setAttribute('title', 'This year is the Active Budget');
        setActiveBtn.setAttribute(
          'data-tooltip',
          'This budget year is currently the Active Budget. Use the gear menu → Deactivate Budget to clear the active selection.'
        );
      } else {
        setActiveBtn.setAttribute('title', 'Set this year as the Active Budget');
        setActiveBtn.setAttribute(
          'data-tooltip',
          'Sets this budget year as the Active Budget. The sidebar Budget link will open this year’s dashboard until you deactivate it.'
        );
      }

      // Deactivate link should only be enabled if any active budget is set.
      setLinkDisabled(deactivateLink, !active);
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
        saveActiveBudgetYear(budgetYear);
        syncActiveBudgetButton();
        // Re-render nav so the parent Budget link points at the new active year.
        initBudgetYearNav();
      });
    }

    if (deactivateLink) {
      deactivateLink.addEventListener('click', (e) => {
        e.preventDefault();
        if (deactivateLink.getAttribute('aria-disabled') === 'true') return;
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
      setLinkDisabled(importCsvLink, isEditing);

      // Creating a new year budget should be done outside edit mode.
      setLinkDisabled(newYearLink, isEditing);

      // Ensure these remain enabled.
      setLinkDisabled(exportCsvLink, false);
      setLinkDisabled(downloadTemplateLink, false);
    }

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
        ['Anticipated', '', '', '', '', '', '', '', '', ''],
        ['Budget', '', '', '', '', '', '', '', '', ''],
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

      const ok = window.confirm(`Importing a CSV will replace the current budget table. Continue?\n\nFile: ${fileName || 'CSV'}`);
      if (!ok) return;

      const rows = parseCsvText(csvText);
      if (rows.length === 0) {
        window.alert('CSV is empty.');
        return;
      }

      const header = rows[0].map(normalizeHeaderName);
      const dataRows = rows.slice(1).filter((r) => r.some((c) => String(c ?? '').trim() !== ''));

      const idx = {
        section: header.indexOf('section'),
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
        const inVal = idx.in !== -1 ? get(idx.in) : r[0] ?? '';
        const outVal = idx.out !== -1 ? get(idx.out) : r[1] ?? '';
        const desc = idx.description !== -1 ? get(idx.description) : r[2] ?? '';

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
          approvedEuro: idx.approvedEuro !== -1 ? get(idx.approvedEuro) : (r[3] ?? ''),
          receiptsEuro: idx.receiptsEuro !== -1 ? get(idx.receiptsEuro) : (r[4] ?? ''),
          expendituresEuro: idx.expendituresEuro !== -1 ? get(idx.expendituresEuro) : (r[5] ?? ''),
          balanceEuro: idx.balanceEuro !== -1 ? get(idx.balanceEuro) : (r[6] ?? ''),
          receiptsUsd: idx.receiptsUsd !== -1 ? get(idx.receiptsUsd) : (r[7] ?? ''),
          expendituresUsd: idx.expendituresUsd !== -1 ? get(idx.expendituresUsd) : (r[8] ?? ''),
        };

        const sectionName = String(rawSection ?? '').trim().toLowerCase();
        const targetSection = sectionName.startsWith('a') ? 1 : sectionName.startsWith('b') ? 2 : inferredSection;

        if (targetSection === 1) section1.push(record);
        else section2.push(record);
      }

      // Rebuild tbody from imported data
      tbody.innerHTML = '';
      for (const rec of section1) tbody.appendChild(buildDataRowFromRecord(rec));
      tbody.appendChild(buildSpacerRow());
      tbody.appendChild(buildTotalRow('Total Anticipated Values'));
      tbody.appendChild(buildSpacerRow());
      for (const rec of section2) tbody.appendChild(buildDataRowFromRecord(rec));
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
      if (isEditing) return;
      editStartHtml = tbody.innerHTML;
      setEditing(true);
    });

    saveBtn.addEventListener('click', () => {
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
        if (!isEditing) return;
        addLine();
      });
    }
    if (removeLineLink) {
      removeLineLink.addEventListener('click', (e) => {
        e.preventDefault();
        if (removeLineLink.getAttribute('aria-disabled') === 'true') return;
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

    numberingForm.addEventListener('submit', (e) => {
      e.preventDefault();

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

  if (form) {
    // Restore draft fields (so Itemize -> back to form doesn't lose work)
    const draft = loadDraft();
    if (draft) {
      const keys = [
        'paymentOrderNo',
        'date',
        'name',
        'euro',
        'usd',
        'address',
        'iban',
        'bic',
        'specialInstructions',
        'budgetNumber',
        'purpose',
      ];
      for (const key of keys) {
        const el = form.elements.namedItem(key);
        if (el && draft[key] !== undefined) el.value = draft[key];
      }
    }

    // Ensure Payment Order No. always follows the configured pattern
    maybeAutofillPaymentOrderNo();

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

      clearFieldErrors();
      clearItemsError();
      showSubmitToken('');

      const result = validateForm();
      if (!result.ok) {
        showErrors(result.errors);
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

        const updated = {
          ...existing,
          ...orderValues,
          id: existing.id,
          createdAt: existing.createdAt,
          updatedAt: new Date().toISOString(),
        };
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
      });
    }
  }

  if (editOrderBtn) {
    editOrderBtn.addEventListener('click', () => {
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
      const id = currentViewedOrderId || (modal ? modal.getAttribute('data-order-id') : null);
      const year = getActiveBudgetYear();
      const latest = id ? getOrderById(id, year) : null;

      const withSelect = modalBody ? modalBody.querySelector('#modalWithSelect') : null;
      const statusSelect = modalBody ? modalBody.querySelector('#modalStatusSelect') : null;

      if (latest && withSelect && statusSelect) {
        const nextWith = normalizeWith(withSelect.value);
        const nextStatus = normalizeOrderStatus(statusSelect.value);

        const changed = nextWith !== getOrderWithLabel(latest) || nextStatus !== getOrderStatusLabel(latest);
        if (changed) {
          const nowIso = new Date().toISOString();
          const updated = {
            ...latest,
            with: nextWith,
            status: nextStatus,
            updatedAt: nowIso,
            timeline: appendTimelineEvent(latest, { at: nowIso, with: nextWith, status: nextStatus }),
          };
          upsertOrder(updated, year);
          renderOrders(loadOrders(year));
        }
      }

      // Close the view modal after saving
      closeModal();
    });
  }

  if (clearAllBtn) {
    clearAllBtn.addEventListener('click', clearAll);
  }

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
        beginEditingOrder(order);
        window.location.href = `index.html?year=${encodeURIComponent(String(year))}`;
      } else if (action === 'delete') {
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
    seedMockOrdersIfDev();
    const year = getActiveBudgetYear();
    renderOrders(loadOrders(year));
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
            const ok = window.confirm('Remove this attachment?');
            if (!ok) return;
            await deleteAttachmentById(id);
            await refreshAttachments(attachmentTargetKey);
            return;
          }

          if (action === 'download') {
            const list = await listAttachments(attachmentTargetKey);
            const att = list.find((a) => a.id === id);
            if (!att) return;
            const blob = att.blob;
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = att.name || 'attachment';
            document.body.appendChild(a);
            a.click();
            a.remove();
            setTimeout(() => URL.revokeObjectURL(url), 1000);
          }
        });
      }
    }

    itemForm.addEventListener('submit', (e) => {
      e.preventDefault();
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
        const ok = window.confirm('Delete this item?');
        if (!ok) return;
        items = items.filter((it) => it.id !== itemId);
        renderItems(items);
        resetItemEditor();
      }
    });

    if (saveItemsBtn) {
      saveItemsBtn.addEventListener('click', () => {
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
            window.location.href = `index.html?year=${encodeURIComponent(String(year))}`;
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
