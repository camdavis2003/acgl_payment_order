/*
  Payment Order Request app (no backend)
  - Validates required fields
  - Persists submitted requests in localStorage
  - Renders newest-first table with View/Delete actions
*/

(() => {
  'use strict';

  const STORAGE_KEY = 'payment_orders';
  const THEME_KEY = 'payment_order_theme';
  const DRAFT_KEY = 'payment_order_draft';
  const DRAFT_ITEMS_KEY = 'payment_order_draft_items';
  const EDIT_ORDER_ID_KEY = 'payment_order_edit_order_id';

  const ORDER_STATUSES = ['Submitted', 'Review', 'Returned', 'Rejected', 'Approved', 'Paid'];

  // Elements are page-dependent (form page vs menu/list page)
  const form = document.getElementById('paymentOrderForm');
  const resetBtn = document.getElementById('resetBtn');

  const tbody = document.getElementById('ordersTbody');
  const emptyState = document.getElementById('emptyState');
  const clearAllBtn = document.getElementById('clearAllBtn');

  const modal = document.getElementById('detailsModal');
  const modalBody = document.getElementById('modalBody');
  const editOrderBtn = document.getElementById('editOrderBtn');

  const themeToggle = document.getElementById('themeToggle');

  // Form page helpers
  const itemsStatus = document.getElementById('itemsStatus');
  const itemsErrorEl = document.getElementById('error-items');

  const euroField = document.getElementById('euro');
  const usdField = document.getElementById('usd');

  let currentViewedOrderId = null;

  function getEditOrderId() {
    const id = localStorage.getItem(EDIT_ORDER_ID_KEY);
    return id && typeof id === 'string' ? id : null;
  }

  function setEditOrderId(id) {
    if (!id) {
      localStorage.removeItem(EDIT_ORDER_ID_KEY);
      return;
    }
    localStorage.setItem(EDIT_ORDER_ID_KEY, id);
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

  function setTheme(theme) {
    localStorage.setItem(THEME_KEY, theme);
    applyTheme(theme);
  }

  /** @returns {Array<Object>} */
  function loadOrders() {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (!raw) return [];
      const parsed = JSON.parse(raw);
      return Array.isArray(parsed) ? parsed : [];
    } catch {
      return [];
    }
  }

  /** @param {Array<Object>} orders */
  function saveOrders(orders) {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(orders));
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
    return ORDER_STATUSES.includes(s) ? s : 'Submitted';
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
    window.location.href = 'itemize.html?draft=1';
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

    const inputs = form.querySelectorAll('input, textarea');
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
        budgetNumber: 'BUD-1001',
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
        budgetNumber: 'BUD-1002',
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
        budgetNumber: 'BUD-1003',
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

  function seedMockOrdersIfDev() {
    if (!isDevEnvironment()) return;

    const existing = loadOrders();
    const storedVersion = localStorage.getItem(MOCK_VERSION_KEY);

    // Fresh seed
    if (existing.length === 0) {
      const now = Date.now();
      saveOrders(makeMockOrders(now));
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

    saveOrders(upgraded);
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
    return {
      id: (crypto?.randomUUID ? crypto.randomUUID() : `po_${Date.now()}_${Math.random().toString(16).slice(2)}`),
      createdAt: new Date().toISOString(),
      ...values,
      status: normalizeOrderStatus(values && values.status),
    };
  }

  function getOrderStatusLabel(order) {
    return normalizeOrderStatus(order && order.status);
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
            <td>${escapeHtml(o.paymentOrderNo)}</td>
            <td>${escapeHtml(formatDate(o.date))}</td>
            <td>${escapeHtml(o.name)}</td>
            <td class="num">${escapeHtml(formatCurrency(o.euro, 'EUR'))}</td>
            <td class="num">${escapeHtml(formatCurrency(o.usd, 'USD'))}</td>
            <td>${escapeHtml(o.budgetNumber)}</td>
            <td>${escapeHtml(o.purpose)}</td>
            <td>${escapeHtml(getOrderStatusLabel(o))}</td>
            <td class="actions">
              <button type="button" class="btn btn--ghost" data-action="items">Items</button>
              <button type="button" class="btn btn--ghost" data-action="view">View</button>
            </td>
          </tr>
        `.trim();
      })
      .join('');

    tbody.innerHTML = rowsHtml;
  }

  function openModalWithOrder(order) {
    if (!modal || !modalBody) return;
    currentViewedOrderId = order.id;
    modal.setAttribute('data-order-id', String(order.id));

    const currentStatus = getOrderStatusLabel(order);
    const statusOptions = ORDER_STATUSES.map((s) => {
      const selected = s === currentStatus ? ' selected' : '';
      return `<option value="${escapeHtml(s)}"${selected}>${escapeHtml(s)}</option>`;
    }).join('');

    modalBody.innerHTML = `
      <dl class="kv">
        <dt>Payment Order No.</dt><dd>${escapeHtml(order.paymentOrderNo)}</dd>
        <dt>Date</dt><dd>${escapeHtml(formatDate(order.date))}</dd>
        <dt>Name</dt><dd>${escapeHtml(order.name)}</dd>
        <dt>Euro (€)</dt><dd>${escapeHtml(formatCurrency(order.euro, 'EUR'))}</dd>
        <dt>USD ($)</dt><dd>${escapeHtml(formatCurrency(order.usd, 'USD'))}</dd>
        <dt>Status</dt>
        <dd>
          <select id="modalStatusSelect" aria-label="Status">
            ${statusOptions}
          </select>
        </dd>
        <dt>Address</dt><dd>${escapeHtml(order.address)}</dd>
        <dt>IBAN</dt><dd>${escapeHtml(order.iban)}</dd>
        <dt>BIC</dt><dd>${escapeHtml(order.bic)}</dd>
        <dt>Special Instructions</dt><dd>${escapeHtml(order.specialInstructions)}</dd>
        <dt>Budget Number</dt><dd>${escapeHtml(order.budgetNumber)}</dd>
        <dt>Purpose</dt><dd>${escapeHtml(order.purpose)}</dd>
        <dt>Created</dt><dd>${escapeHtml(order.createdAt)}</dd>
      </dl>
    `.trim();

    const statusSelect = modalBody.querySelector('#modalStatusSelect');
    if (statusSelect) {
      statusSelect.addEventListener('change', () => {
        const boundOrderId = currentViewedOrderId || (modal ? modal.getAttribute('data-order-id') : null);
        if (!boundOrderId) return;
        const latest = getOrderById(boundOrderId);
        if (!latest) return;
        const nextStatus = normalizeOrderStatus(statusSelect.value);
        const updated = { ...latest, status: nextStatus };
        upsertOrder(updated);
        renderOrders(loadOrders());
      });
    }

    modal.classList.add('is-open');
    modal.setAttribute('aria-hidden', 'false');

    // Focus the close button for accessibility
    const closeBtn = modal.querySelector('[data-modal-close]');
    if (closeBtn) closeBtn.focus();
  }

  function closeModal() {
    if (!modal || !modalBody) return;
    modal.classList.remove('is-open');
    modal.setAttribute('aria-hidden', 'true');
    modalBody.innerHTML = '';
    currentViewedOrderId = null;
    modal.removeAttribute('data-order-id');
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
    const orders = loadOrders();
    const next = orders.filter((o) => o.id !== id);
    saveOrders(next);
    renderOrders(next);
  }

  function clearAll() {
    const orders = loadOrders();
    if (orders.length === 0) return;
    const ok = window.confirm('Clear all submitted requests? This cannot be undone.');
    if (!ok) return;
    saveOrders([]);
    renderOrders([]);
  }

  // ---- Event wiring (only when the elements exist on the page) ----

  // Theme toggle works on both pages
  applyTheme(getPreferredTheme());
  if (themeToggle) {
    themeToggle.addEventListener('change', () => {
      const next = themeToggle.checked ? 'dark' : 'light';
      setTheme(next);
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

    updateItemsStatus();
    syncCurrencyFieldsFromItems();

    // If we are editing, tweak submit button label
    const submitBtn = form.querySelector('button[type="submit"]');
    if (submitBtn) {
      submitBtn.textContent = getEditOrderId() ? 'Save Changes' : 'Add to List';
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
      if (editId) {
        const existing = getOrderById(editId);
        if (!existing) {
          showItemsError('Could not find the submission to edit.');
          return;
        }
        const updated = {
          ...existing,
          ...orderValues,
          id: existing.id,
          createdAt: existing.createdAt,
          updatedAt: new Date().toISOString(),
        };
        upsertOrder(updated);
      } else {
        const order = buildPaymentOrder(orderValues);
        const orders = loadOrders();

        // Save newest first
        orders.unshift(order);
        saveOrders(orders);
      }

      form.reset();
      clearDraft();
      void clearDraftAttachments();
      setEditOrderId(null);
      updateItemsStatus();

      // Clear the auto-filled currency fields too
      if (euroField) euroField.value = '';
      if (usdField) usdField.value = '';

      // Return to list after editing
      if (getEditOrderId() === null) {
        // no-op
      }
      if (editId) {
        window.location.href = 'menu.html';
      }

      // Optional: you can navigate to the menu page manually using the header link.
    });

    if (resetBtn) {
      resetBtn.addEventListener('click', () => {
        clearFieldErrors();
        clearItemsError();
        form.reset();
        clearDraft();
        void clearDraftAttachments();
        setEditOrderId(null);
        updateItemsStatus();
        syncCurrencyFieldsFromItems();
        const submitBtn = form.querySelector('button[type="submit"]');
        if (submitBtn) submitBtn.textContent = 'Add to List';
      });
    }
  }

  if (editOrderBtn) {
    editOrderBtn.addEventListener('click', () => {
      const id = currentViewedOrderId || (modal ? modal.getAttribute('data-order-id') : null);
      if (!id) return;
      const order = getOrderById(id);
      if (!order) return;
      beginEditingOrder(order);
      closeModal();
      window.location.href = 'index.html';
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

      const orders = loadOrders();
      const order = orders.find((o) => o.id === id);
      if (!order) return;

      if (action === 'view') {
        openModalWithOrder(order);
      } else if (action === 'items') {
        window.location.href = `itemize.html?orderId=${encodeURIComponent(id)}`;
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
  seedMockOrdersIfDev();
  renderOrders(loadOrders());

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

  function getOrderById(orderId) {
    const orders = loadOrders();
    return orders.find((o) => o.id === orderId) || null;
  }

  function upsertOrder(updatedOrder) {
    const orders = loadOrders();
    const next = orders.map((o) => (o.id === updatedOrder.id ? updatedOrder : o));
    saveOrders(next);
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
      const order = getOrderById(target.orderId);
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
          window.location.href = 'index.html';
          return;
        }

        if (boundOrderId) {
          const order = getOrderById(boundOrderId);
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
          upsertOrder(updated);
          window.location.href = 'menu.html';
        }
      });
    }
  }
})();
