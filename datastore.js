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

    const itemUrl = (key) => wpJoin(`acgl-fms/v1/kv/${encodeURIComponent(String(key || ''))}`);

    const DEFAULT_STALE_MS = 45 * 1000;
    const BOOTSTRAP_KEYS = [
      'payment_order_users_v1',
      'payment_order_active_budget_year_v1',
      'payment_order_budget_years_v1',
      'payment_order_numbering',
      'payment_order_grand_lodge_info_v1',
      'payment_order_notifications_settings_v1',
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
      if (
        key === 'payment_order_users_v1'
        || key === 'payment_order_numbering'
        || key === 'payment_order_grand_lodge_info_v1'
        || key === 'payment_order_budget_years_v1'
        || key === 'payment_order_active_budget_year_v1'
        || key === 'payment_order_notifications_settings_v1'
      ) {
        return 2 * 60 * 1000;
      }
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

      loadedKeys.add(k);
      keyMeta.set(k, {
        fetchedAtMs: Date.now(),
        staleMs: getKeyStaleMs(k),
      });
    }

    function isKeyStale(key) {
      const meta = keyMeta.get(String(key || '').trim());
      if (!meta || !Number.isFinite(meta.fetchedAtMs)) return true;
      return (Date.now() - meta.fetchedAtMs) > Number(meta.staleMs || DEFAULT_STALE_MS);
    }

    async function fetchSharedKeyFromWp(keyRaw, { force = false, reason = 'read' } = {}) {
      const key = String(keyRaw || '').trim();
      if (!key || !isWpSharedKey(key)) return false;
      if (!getWpToken()) return false;

      if (!force && pendingReads.has(key)) return pendingReads.get(key);
      if (!force && loadedKeys.has(key) && !isKeyStale(key)) return true;

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
      if (base === 'money_transfers.html' || base === 'money_transfer.html') {
        return [moneyTransfersKey, incomeKey, wiseEurKey, wiseUsdKey, ordersKey, reconciliationKey, gsLedgerVerifiedKey];
      }
      if (base === 'grand_secretary_ledger.html') {
        return [incomeKey, wiseEurKey, wiseUsdKey, ordersKey, reconciliationKey, moneyTransfersKey, gsLedgerVerifiedKey];
      }
      return [];
    }

    async function preloadBootstrapEssentials({ force = false } = {}) {
      await preloadKeys(BOOTSTRAP_KEYS, { force, reason: 'bootstrap' });
    }

    async function preloadCurrentPageDatasets(opts = {}) {
      const options = opts && typeof opts === 'object' ? opts : {};
      const page = String(options.page || getBasename(window.location.pathname) || '').trim().toLowerCase();

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
        try {
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
      } finally {
        flushing = false;
      }
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

  window.ACGLDataStore = window.ACGLDataStore || {};
  window.ACGLDataStore.initWpSharedStorageBridge = initWpSharedStorageBridge;
})();
