/*
  Shared client-side data store for WP shared mode.
  - Blocking bootstrap preload before first render
  - Blocking page dataset preload before page init
  - In-memory cache with stale windows
  - SWR reads and request deduping
*/

(function () {
  'use strict';

  function defaultGetBasename(pathname) {
    const parts = String(pathname || '/').split('/').filter(Boolean);
    return parts.length ? parts[parts.length - 1] : 'index.html';
  }

  const KNOWN_DATASET_PAGES = [
    'menu.html',
    'reconciliation.html',
    'income.html',
    'wise_eur.html',
    'wise_usd.html',
    'money_transfers.html',
    'money_transfer.html',
    'grand_secretary_ledger.html',
    'budget_dashboard.html',
    'settings.html',
  ];

  function extractKnownDatasetPage(input) {
    const raw = String(input || '').trim().toLowerCase();
    if (!raw) return '';
    for (const page of KNOWN_DATASET_PAGES) {
      if (raw === page) return page;
      if (raw.endsWith(`/${page}`)) return page;
      if (raw.includes(page)) return page;
    }
    return '';
  }

  function safeDecode(value) {
    const raw = String(value || '');
    if (!raw) return '';
    try {
      return decodeURIComponent(raw);
    } catch {
      return raw;
    }
  }

  async function initWpSharedStorageBridge(config) {
    const cfg = config && typeof config === 'object' ? config : {};
    const isWpSharedMode = Boolean(cfg.isWpSharedMode);
    const wpFetchJson = cfg.wpFetchJson;
    const wpJoin = cfg.wpJoin;
    const isWpSharedKey = cfg.isWpSharedKey;
    const getWpToken = cfg.getWpToken;
    const readJsonResponse = cfg.readJsonResponse;
    const getBasename = typeof cfg.getBasename === 'function' ? cfg.getBasename : defaultGetBasename;

    if (!isWpSharedMode) return null;
    if (typeof wpFetchJson !== 'function') return null;
    if (typeof wpJoin !== 'function') return null;
    if (typeof isWpSharedKey !== 'function') return null;
    if (typeof getWpToken !== 'function') return null;
    if (typeof readJsonResponse !== 'function') return null;
    if (typeof window.fetch !== 'function') return null;

    let storage;
    try {
      storage = window.localStorage;
    } catch {
      return null;
    }
    if (!storage) return null;

    const nativeGet = storage.getItem.bind(storage);
    const nativeSet = storage.setItem.bind(storage);
    const nativeRemove = storage.removeItem.bind(storage);

    const mem = new Map();
    const loadedKeys = new Set();
    const keyMeta = new Map();
    const pendingReads = new Map();
    const pendingUpserts = new Map();
    const pendingDeletes = new Set();
    let flushTimer = 0;
    let flushing = false;
    let activeFlushPromise = null;

    const itemUrl = (key) => wpJoin(`acgl-fms/v1/kv/${encodeURIComponent(String(key || ''))}`);

    const DEFAULT_STALE_MS = 45 * 1000;
    const BOOTSTRAP_STALE_MS = 2 * 60 * 1000;
    const BOOTSTRAP_KEYS = [
      'payment_order_users_v1',
      'payment_order_active_budget_year_v1',
      'payment_order_budget_years_v1',
      'payment_order_numbering',
      'payment_order_grand_lodge_info_v1',
      'payment_order_notifications_settings_v1',
      'payment_order_backlog_v1',
    ];

    function debugStoreLog(message, extra) {
      try {
        if (typeof console !== 'undefined' && typeof console.debug === 'function') {
          console.debug(`[ACGL DataStore] ${message}`, extra || '');
        }
      } catch {
        // ignore
      }
    }

    function getKeyStaleMs(keyRaw) {
      const key = String(keyRaw || '');
      if (BOOTSTRAP_KEYS.includes(key)) return BOOTSTRAP_STALE_MS;
      return DEFAULT_STALE_MS;
    }
    function markLoadedKey(key, value) {
      const k = String(key || '').trim();
      if (!k) return;

      if (value === null || value === undefined) {
        mem.delete(k);
        try { nativeRemove(k); } catch { /* ignore */ }
      } else {
        const text = String(value);
        mem.set(k, text);
        try { nativeSet(k, text); } catch { /* ignore */ }
      }

      const meta = { fetchedAtMs: Date.now(), staleMs: getKeyStaleMs(k) };
      loadedKeys.add(k);
      keyMeta.set(k, meta);
      try { nativeSet(`__acgl_ds_meta_${k}`, JSON.stringify(meta)); } catch { /* ignore */ }
    }

    function isKeyStale(key) {
      const k = String(key || '').trim();
      let meta = keyMeta.get(k);
      if (!meta || !Number.isFinite(meta.fetchedAtMs)) {
        try {
          const raw = nativeGet(`__acgl_ds_meta_${k}`);
          if (raw) {
            meta = JSON.parse(raw);
            keyMeta.set(k, meta);
          }
        } catch { /* ignore */ }
      }
      if (!meta || !Number.isFinite(meta.fetchedAtMs)) return true;
      return (Date.now() - meta.fetchedAtMs) > Number(meta.staleMs || DEFAULT_STALE_MS);
    }

    async function fetchSharedKeyFromWp(keyRaw, { force = false, reason = 'read' } = {}) {
      const key = String(keyRaw || '').trim();
      if (!key || !isWpSharedKey(key)) return false;
      if (!getWpToken()) return false;

      if (!force && pendingReads.has(key)) return pendingReads.get(key);
      if (!force && !isKeyStale(key)) {
        if (!loadedKeys.has(key)) {
          const stored = nativeGet(key);
          mem.set(key, stored !== null ? stored : mem.get(key));
          loadedKeys.add(key);
        }
        return true;
      }

      const started = Date.now();
      const request = (async () => {
        const res = await wpFetchJson(itemUrl(key), { method: 'GET' });
        if (res.status === 401 || res.status === 403) return false;
        if (!res.ok) throw new Error(`kv_item_failed_${res.status}`);

        const payload = await readJsonResponse(res);
        const v = payload && Object.prototype.hasOwnProperty.call(payload, 'v')
          ? payload.v
          : null;
        markLoadedKey(key, v === null || v === undefined ? null : String(v));

        const duration = Date.now() - started;
        const slow = duration >= 120;
        debugStoreLog(
          `${slow ? 'slow ' : ''}fetch key=${key} ms=${duration} reason=${reason}`,
          { key, duration, reason, staleMs: getKeyStaleMs(key) }
        );

        return true;
      })();

      pendingReads.set(key, request);
      try {
        return await request;
      } finally {
        pendingReads.delete(key);
      }
    }

    async function preloadKeys(keysRaw, { force = false, reason = 'preload' } = {}) {
      const keys = Array.isArray(keysRaw)
        ? Array.from(new Set(keysRaw.map((k) => String(k || '').trim()).filter((k) => k && isWpSharedKey(k))))
        : [];
      if (keys.length < 1) return;

      await Promise.all(keys.map((key) => fetchSharedKeyFromWp(key, { force, reason })));
    }

    function getPageDatasetKeys(baseRaw, yearRaw) {
      const base = String(baseRaw || '').trim().toLowerCase();
      const year = Number.isInteger(Number(yearRaw)) ? Number(yearRaw) : null;
      if (!year) return [];

      const ordersKey = `payment_orders_${year}_v1`;
      const reconciliationKey = `payment_orders_reconciliation_${year}_v1`;
      const incomeKey = `payment_order_income_${year}_v1`;
      const wiseEurKey = `payment_order_wise_eur_${year}_v1`;
      const wiseUsdKey = `payment_order_wise_usd_${year}_v1`;
      const moneyTransfersKey = `money_transfers_${year}_v1`;
      const gsLedgerVerifiedKey = `payment_order_gs_ledger_verified_${year}_v1`;

      if (base === 'menu.html') {
        return [ordersKey, reconciliationKey];
      }
      if (base === 'reconciliation.html') {
        return [reconciliationKey, ordersKey, wiseEurKey, wiseUsdKey];
      }
      if (base === 'income.html') {
        return [incomeKey, ordersKey, reconciliationKey];
      }
      if (base === 'wise_eur.html') {
        return [wiseEurKey, ordersKey, reconciliationKey];
      }
      if (base === 'wise_usd.html') {
        return [wiseUsdKey, ordersKey, reconciliationKey];
      }
      if (base === 'money_transfers.html' || base === 'money_transfer.html') {
        return [moneyTransfersKey, incomeKey, wiseEurKey, wiseUsdKey, ordersKey, reconciliationKey, gsLedgerVerifiedKey];
      }
      if (base === 'grand_secretary_ledger.html') {
        return [incomeKey, wiseEurKey, wiseUsdKey, ordersKey, reconciliationKey, moneyTransfersKey, gsLedgerVerifiedKey];
      }
      if (base === 'budget_dashboard.html') {
        return [incomeKey, wiseEurKey, wiseUsdKey, ordersKey, reconciliationKey, moneyTransfersKey, gsLedgerVerifiedKey];
      }
      if (base === 'settings.html') {
        return [ordersKey, incomeKey];
      }
      return [];
    }

    function resolveCurrentPageName(options) {
      const direct = extractKnownDatasetPage(options && options.page);
      if (direct) return direct;

      const fromPath = extractKnownDatasetPage(getBasename(window.location.pathname));
      if (fromPath) return fromPath;

      const candidates = [];
      try {
        const href = String(window.location.href || '');
        const u = new URL(href);
        candidates.push(u.pathname, u.search, u.hash, href);
        const params = u.searchParams;
        const keys = ['view', 'app', 'route', 'path', 'page_file', 'pageFile', 'target', 'src', 'next', 'redirect_to'];
        for (const k of keys) candidates.push(params.get(k));
      } catch {
        candidates.push(window.location.pathname, window.location.search, window.location.hash);
      }

      for (const c of candidates) {
        const hit = extractKnownDatasetPage(c);
        if (hit) return hit;
        const decodedHit = extractKnownDatasetPage(safeDecode(c));
        if (decodedHit) return decodedHit;
      }

      return String(options && options.page ? options.page : getBasename(window.location.pathname) || '')
        .trim()
        .toLowerCase();
    }

    async function preloadBootstrapEssentials({ force = false } = {}) {
      await preloadKeys(BOOTSTRAP_KEYS, { force, reason: 'bootstrap' });
    }

    async function preloadCurrentPageDatasets(opts = {}) {
      const options = opts && typeof opts === 'object' ? opts : {};
      const page = resolveCurrentPageName(options);

      let pageYear = Number(options.year);
      if (!Number.isInteger(pageYear)) {
        try {
          const params = new URLSearchParams(window.location.search || '');
          pageYear = Number(params.get('year'));
        } catch {
          pageYear = NaN;
        }
      }

      if (!Number.isInteger(pageYear)) {
        const activeRaw = mem.get('payment_order_active_budget_year_v1') || nativeGet('payment_order_active_budget_year_v1') || '';
        pageYear = Number(String(activeRaw || '').trim());
      }

      if (!Number.isInteger(pageYear)) {
        try {
          const yearsRaw = mem.get('payment_order_budget_years_v1') || nativeGet('payment_order_budget_years_v1') || '[]';
          const years = JSON.parse(String(yearsRaw || '[]'));
          if (Array.isArray(years)) {
            const numericYears = years
              .map((v) => Number(v))
              .filter((v) => Number.isInteger(v));
            if (numericYears.length > 0) pageYear = Math.max(...numericYears);
          }
        } catch {
          // ignore
        }
      }

      // Final fallback keeps year-scoped pages from rendering empty when no
      // active year has been configured yet.
      if (!Number.isInteger(pageYear)) pageYear = new Date().getFullYear();
      const keys = getPageDatasetKeys(page, pageYear);
      if (keys.length < 1) return;
      await preloadKeys(keys, { force: Boolean(options.force), reason: `page:${page}` });
    }

    async function hydrateSharedFromWp(opts = {}) {
      await preloadBootstrapEssentials({ force: Boolean(opts && opts.force) });
      const shouldLoadPage = opts && Object.prototype.hasOwnProperty.call(opts, 'includePage')
        ? Boolean(opts.includePage)
        : true;
      if (shouldLoadPage) await preloadCurrentPageDatasets(opts);
      return true;
    }

    function scheduleFlush() {
      if (flushTimer) return;
      flushTimer = window.setTimeout(async () => {
        flushTimer = 0;
        if (flushing) return;
        flushing = true;
        activeFlushPromise = (async () => {
          try {
            await runFlush();
          } finally {
            flushing = false;
            activeFlushPromise = null;
          }
        })();
        await activeFlushPromise;
      }, 350);
    }

    async function runFlush() {
      for (const key of Array.from(pendingDeletes)) {
        pendingDeletes.delete(key);
        pendingUpserts.delete(key);
        try {
          await wpFetchJson(itemUrl(key), { method: 'DELETE' });
        } catch {
          // ignore
        }
      }

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
    }

    async function flushNow() {
      if (flushTimer) {
        window.clearTimeout(flushTimer);
        flushTimer = 0;
      }

      // If a flush is already running, wait for it to finish, then flush any
      // ops that were queued while it was in-flight (e.g., from a delete
      // handler that fires just as the 350ms timer was draining).
      if (flushing && activeFlushPromise) {
        try { await activeFlushPromise; } catch { /* ignore */ }
      }
      if (flushing) return;

      flushing = true;
      activeFlushPromise = (async () => {
        try {
          await runFlush();
        } finally {
          flushing = false;
          activeFlushPromise = null;
        }
      })();
      await activeFlushPromise;
    }

    storage.getItem = (key) => {
      const k = String(key || '');
      if (!isWpSharedKey(k)) return nativeGet(k);

      const hasMem = mem.has(k);
      if (hasMem && isKeyStale(k)) {
        void fetchSharedKeyFromWp(k, { force: true, reason: 'swr_get_stale' });
      }

      if (!hasMem && !loadedKeys.has(k)) {
        void fetchSharedKeyFromWp(k, { reason: 'swr_get_miss' });
      }

      if (hasMem) return mem.get(k);
      return nativeGet(k);
    };

    storage.setItem = (key, value) => {
      const k = String(key || '');
      if (!isWpSharedKey(k)) {
        nativeSet(k, value);
        return;
      }

      const v = String(value);
      markLoadedKey(k, v);

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
      loadedKeys.add(k);
      keyMeta.set(k, {
        fetchedAtMs: Date.now(),
        staleMs: getKeyStaleMs(k),
      });
      try { nativeRemove(k); } catch { /* ignore */ }

      if (!getWpToken()) return;

      pendingUpserts.delete(k);
      pendingDeletes.add(k);
      scheduleFlush();
    };

    return {
      flushNow,
      hydrateSharedFromWp,
      preloadBootstrapEssentials,
      preloadCurrentPageDatasets,
      preloadKeys,
      fetchSharedKeyFromWp,
    };
  }

  // Fallback helpers keep split bundles resilient when a page-local helper
  // block is stripped during generation.
  if (typeof window.isIsoDateOnly !== 'function') {
    window.isIsoDateOnly = function isIsoDateOnly(value) {
      const s = String(value || '').trim();
      return /^\d{4}-\d{2}-\d{2}$/.test(s);
    };
  }

  if (typeof window.normalizeMoneyTransferId !== 'function') {
    window.normalizeMoneyTransferId = function normalizeMoneyTransferId(value) {
      return String(value || '').trim();
    };
  }

  if (typeof window.normalizeMoneyTransferEntryLedgerIds !== 'function') {
    window.normalizeMoneyTransferEntryLedgerIds = function normalizeMoneyTransferEntryLedgerIds(row) {
      const parseRaw = (value) => {
        if (Array.isArray(value)) return value;
        if (typeof value === 'string') {
          const s = String(value || '').trim();
          if (!s) return [];
          if (s.startsWith('[') && s.endsWith(']')) {
            try {
              const parsed = JSON.parse(s);
              if (Array.isArray(parsed)) return parsed;
            } catch {
              // ignore and try CSV fallback
            }
          }
          return s.split(',').map((x) => String(x || '').trim()).filter(Boolean);
        }
        return [];
      };

      const raw = row && row.entryLedgerIds !== undefined && row.entryLedgerIds !== null
        ? parseRaw(row.entryLedgerIds)
        : parseRaw(row && row.selectedLedgerIds);

      const out = [];
      const seen = new Set();
      for (const v of raw || []) {
        const id = String(v || '').trim();
        if (!id || seen.has(id)) continue;
        seen.add(id);
        out.push(id);
      }
      return out;
    };
  }

  if (typeof window.ensureMoneyTransfersHaveIdsForYear !== 'function') {
    window.ensureMoneyTransfersHaveIdsForYear = function ensureMoneyTransfersHaveIdsForYear(year) {
      const parseYear = () => {
        const explicit = Number(year);
        if (Number.isInteger(explicit)) return explicit;

        try {
          const activeRaw = String(localStorage.getItem('payment_order_active_budget_year_v1') || '').trim();
          const active = Number(activeRaw);
          if (Number.isInteger(active)) return active;
        } catch {
          // ignore
        }

        return new Date().getFullYear();
      };

      const y = parseYear();
      const key = `money_transfers_${y}_v1`;

      let all = [];
      try {
        const raw = localStorage.getItem(key);
        const parsed = raw ? JSON.parse(raw) : [];
        all = Array.isArray(parsed) ? parsed : [];
      } catch {
        all = [];
      }

      if (all.length === 0) return all;

      let changed = false;
      const next = all.map((row, idx) => {
        const safe = row && typeof row === 'object' ? { ...row } : {};
        const id = String(safe.id || '').trim();
        if (!id) {
          safe.id = (crypto && typeof crypto.randomUUID === 'function')
            ? crypto.randomUUID()
            : `mt_${Date.now()}_${idx}_${Math.random().toString(16).slice(2)}`;
          changed = true;
        }
        return safe;
      });

      if (changed) {
        try {
          localStorage.setItem(key, JSON.stringify(next));
        } catch {
          // ignore
        }
      }

      return next;
    };
  }

  if (typeof window.normalizeMoneyTransferDate !== 'function') {
    window.normalizeMoneyTransferDate = function normalizeMoneyTransferDate(row) {
      const s = String((row && (row.mtDate || row.date || row.transferDate)) || '').trim();
      if (window.isIsoDateOnly(s)) return s;

      const legacyEnd = String((row && (row.rangeEnd || row.endDate || row.end)) || '').trim();
      if (window.isIsoDateOnly(legacyEnd)) return legacyEnd;
      const legacyStart = String((row && (row.rangeStart || row.startDate || row.start)) || '').trim();
      return window.isIsoDateOnly(legacyStart) ? legacyStart : '';
    };
  }

  if (typeof window.hasExplicitMoneyTransferSelection !== 'function') {
    window.hasExplicitMoneyTransferSelection = function hasExplicitMoneyTransferSelection(row) {
      if (!row || typeof row !== 'object') return false;
      return Object.prototype.hasOwnProperty.call(row, 'entryLedgerIds')
        || Object.prototype.hasOwnProperty.call(row, 'selectedLedgerIds');
    };
  }

  if (typeof window.isMtEligibleLedgerIncomeRow !== 'function') {
    window.isMtEligibleLedgerIncomeRow = function isMtEligibleLedgerIncomeRow(row) {
      const ledgerId = String(row && row.ledgerId ? row.ledgerId : '').trim();
      if (!ledgerId || ledgerId.startsWith('po:')) return false;
      const d = String(row && row.date ? row.date : '').trim();
      if (!window.isIsoDateOnly(d)) return false;
      const e = Number(row && row.euro);
      const u = Number(row && row.usd);
      return (Number.isFinite(e) && e > 0) || (Number.isFinite(u) && u > 0);
    };
  }

  if (typeof window.getAssignedMoneyTransferLedgerIdsForYear !== 'function') {
    window.getAssignedMoneyTransferLedgerIdsForYear = function getAssignedMoneyTransferLedgerIdsForYear(year, opts = {}) {
      const exclude = window.normalizeMoneyTransferId(opts && opts.excludeTransferId);
      const allTransfers = window.ensureMoneyTransfersHaveIdsForYear(year);
      const out = new Set();

      for (const t of Array.isArray(allTransfers) ? allTransfers : []) {
        const transferId = window.normalizeMoneyTransferId(t && t.id);
        if (exclude && transferId === exclude) continue;
        const explicit = window.normalizeMoneyTransferEntryLedgerIds(t);
        for (const id of explicit) out.add(id);
      }

      return out;
    };
  }

  if (typeof window.getWiseEurReceipts !== 'function') {
    window.getWiseEurReceipts = function getWiseEurReceipts(entry) {
      const n = Number(entry && entry.receipts);
      return Number.isFinite(n) && n > 0 ? n : 0;
    };
  }

  if (typeof window.getWiseEurDisburse !== 'function') {
    window.getWiseEurDisburse = function getWiseEurDisburse(entry) {
      const n = Number(entry && entry.disburse);
      return Number.isFinite(n) && n > 0 ? n : 0;
    };
  }

  if (typeof window.getWiseUsdReceipts !== 'function') {
    window.getWiseUsdReceipts = function getWiseUsdReceipts(entry) {
      const n = Number(entry && entry.receipts);
      return Number.isFinite(n) && n > 0 ? n : 0;
    };
  }

  if (typeof window.getWiseUsdDisburse !== 'function') {
    window.getWiseUsdDisburse = function getWiseUsdDisburse(entry) {
      const n = Number(entry && entry.disburse);
      return Number.isFinite(n) && n > 0 ? n : 0;
    };
  }

  if (typeof window.initIncomeColumnSorting !== 'function') {
    window.initIncomeColumnSorting = function initIncomeColumnSorting() {
      // no-op fallback for split bundles missing the income sort initializer
    };
  }

  if (typeof window.backfillWiseUsdIdTrackFromOrders !== 'function') {
    window.backfillWiseUsdIdTrackFromOrders = function backfillWiseUsdIdTrackFromOrders() {
      return false;
    };
  }

  if (typeof window.backfillWiseUsdBudgetNoFromOrders !== 'function') {
    window.backfillWiseUsdBudgetNoFromOrders = function backfillWiseUsdBudgetNoFromOrders() {
      return false;
    };
  }

  if (typeof window.backfillWiseEurIdTrackFromOrders !== 'function') {
    window.backfillWiseEurIdTrackFromOrders = function backfillWiseEurIdTrackFromOrders() {
      return false;
    };
  }

  if (typeof window.backfillWiseEurBudgetNoFromOrders !== 'function') {
    window.backfillWiseEurBudgetNoFromOrders = function backfillWiseEurBudgetNoFromOrders() {
      return false;
    };
  }

  if (typeof window.spellOutMoneyTransferNo !== 'function') {
    window.spellOutMoneyTransferNo = function spellOutMoneyTransferNo(noRaw) {
      const s = String(noRaw || '').trim();
      if (!s) return 'Money Transfer';
      return s.replace(/^MT\s*/i, 'Money Transfer ');
    };
  }

  if (!window.incomeViewState || typeof window.incomeViewState !== 'object') {
    window.incomeViewState = {
      globalFilter: '',
      sortKey: 'date',
      sortDir: 'desc',
      defaultEmptyText: null,
      canDelete: false,
    };
  }

  if (typeof window.getDerivedBudgetCreatedDateOnlyForYear !== 'function') {
    window.getDerivedBudgetCreatedDateOnlyForYear = function getDerivedBudgetCreatedDateOnlyForYear(year) {
      const y = Number.isInteger(Number(year)) ? Number(year) : new Date().getFullYear();

      // If ledger rows are available on this page, derive the earliest row date.
      try {
        if (typeof window.buildGsLedgerRowsForYear === 'function') {
          const rows = window.buildGsLedgerRowsForYear(y);
          let minDate = '';
          for (const r of Array.isArray(rows) ? rows : []) {
            const d = String(r && r.date ? r.date : '').trim();
            if (!window.isIsoDateOnly(d)) continue;
            if (!minDate || d < minDate) minDate = d;
          }
          if (minDate) return minDate;
        }
      } catch {
        // ignore
      }

      // Safe fallback used across pages when ledger data is unavailable.
      return `${y - 1}-04-01`;
    };
  }

  window.ACGLDataStore = window.ACGLDataStore || {};
  window.ACGLDataStore.initWpSharedStorageBridge = initWpSharedStorageBridge;
})();
