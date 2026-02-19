/*
  Payment Order Request app (no backend)
  - Validates required fields
  - Persists submitted requests in localStorage
  - Renders newest-first table with View/Delete actions
*/

(() => {
  'use strict';

  const STORAGE_KEY = 'payment_orders';

  const form = document.getElementById('paymentOrderForm');
  const resetBtn = document.getElementById('resetBtn');
  const tbody = document.getElementById('ordersTbody');
  const emptyState = document.getElementById('emptyState');
  const clearAllBtn = document.getElementById('clearAllBtn');

  const modal = document.getElementById('detailsModal');
  const modalBody = document.getElementById('modalBody');

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

  function escapeHtml(value) {
    return String(value)
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;')
      .replaceAll("'", '&#39;');
  }

  function formatMoney(n) {
    const num = Number(n);
    if (!Number.isFinite(num)) return '';
    return num.toFixed(2);
  }

  function formatDate(isoDate) {
    // Keep it stable in all browsers/WP embeds: show as YYYY-MM-DD if present.
    return String(isoDate || '').trim();
  }

  function clearFieldErrors() {
    const errorEls = document.querySelectorAll('.error');
    errorEls.forEach((el) => (el.textContent = ''));

    const inputs = form.querySelectorAll('input, textarea');
    inputs.forEach((el) => el.classList.remove('input-error'));
  }

  /**
   * @returns {{ ok: boolean, values?: Object, errors?: Record<string,string> }}
   */
  function validateForm() {
    const values = {
      paymentOrderNo: form.paymentOrderNo.value.trim(),
      date: form.date.value.trim(),
      name: form.name.value.trim(),
      euro: form.euro.value.trim(),
      usd: form.usd.value.trim(),
      address: form.address.value.trim(),
      iban: form.iban.value.trim(),
      bic: form.bic.value.trim(),
      specialInstructions: form.specialInstructions.value.trim(),
      budgetNumber: form.budgetNumber.value.trim(),
      purpose: form.purpose.value.trim(),
    };

    const errors = {};

    // Required checks
    for (const [key, val] of Object.entries(values)) {
      if (!val) errors[key] = 'This field is required.';
    }

    // Numeric checks (must exist, must be a number, and non-negative)
    const euroNum = Number(values.euro);
    if (values.euro && (!Number.isFinite(euroNum) || euroNum < 0)) {
      errors.euro = 'Enter a valid non-negative number.';
    }

    const usdNum = Number(values.usd);
    if (values.usd && (!Number.isFinite(usdNum) || usdNum < 0)) {
      errors.usd = 'Enter a valid non-negative number.';
    }

    if (Object.keys(errors).length > 0) {
      return { ok: false, errors };
    }

    return {
      ok: true,
      values: {
        ...values,
        euro: euroNum,
        usd: usdNum,
      },
    };
  }

  /** @param {Record<string,string>} errors */
  function showErrors(errors) {
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
    };
  }

  /** @param {Array<Object>} orders */
  function renderOrders(orders) {
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
            <td>${escapeHtml(o.paymentOrderNo)}</td>
            <td>${escapeHtml(formatDate(o.date))}</td>
            <td>${escapeHtml(o.name)}</td>
            <td class="num">${escapeHtml(formatMoney(o.euro))}</td>
            <td class="num">${escapeHtml(formatMoney(o.usd))}</td>
            <td>${escapeHtml(o.budgetNumber)}</td>
            <td>${escapeHtml(o.purpose)}</td>
            <td class="actions">
              <button type="button" class="btn btn--ghost" data-action="view">View</button>
              <button type="button" class="btn btn--danger" data-action="delete">Delete</button>
            </td>
          </tr>
        `.trim();
      })
      .join('');

    tbody.innerHTML = rowsHtml;
  }

  function openModalWithOrder(order) {
    modalBody.innerHTML = `
      <dl class="kv">
        <dt>Payment Order No.</dt><dd>${escapeHtml(order.paymentOrderNo)}</dd>
        <dt>Date</dt><dd>${escapeHtml(formatDate(order.date))}</dd>
        <dt>Name</dt><dd>${escapeHtml(order.name)}</dd>
        <dt>Euro</dt><dd>${escapeHtml(formatMoney(order.euro))}</dd>
        <dt>USD</dt><dd>${escapeHtml(formatMoney(order.usd))}</dd>
        <dt>Address</dt><dd>${escapeHtml(order.address)}</dd>
        <dt>IBAN</dt><dd>${escapeHtml(order.iban)}</dd>
        <dt>BIC</dt><dd>${escapeHtml(order.bic)}</dd>
        <dt>Special Instructions</dt><dd>${escapeHtml(order.specialInstructions)}</dd>
        <dt>Budget Number</dt><dd>${escapeHtml(order.budgetNumber)}</dd>
        <dt>Purpose</dt><dd>${escapeHtml(order.purpose)}</dd>
        <dt>Created</dt><dd>${escapeHtml(order.createdAt)}</dd>
      </dl>
    `.trim();

    modal.classList.add('is-open');
    modal.setAttribute('aria-hidden', 'false');

    // Focus the close button for accessibility
    const closeBtn = modal.querySelector('[data-modal-close]');
    if (closeBtn) closeBtn.focus();
  }

  function closeModal() {
    modal.classList.remove('is-open');
    modal.setAttribute('aria-hidden', 'true');
    modalBody.innerHTML = '';
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

  // ---- Event wiring ----

  form.addEventListener('submit', (e) => {
    e.preventDefault();

    clearFieldErrors();

    const result = validateForm();
    if (!result.ok) {
      showErrors(result.errors);
      return;
    }

    const order = buildPaymentOrder(result.values);
    const orders = loadOrders();

    // Save newest first (unshift) while still sorting on render
    orders.unshift(order);
    saveOrders(orders);

    form.reset();
    renderOrders(orders);
  });

  resetBtn.addEventListener('click', () => {
    clearFieldErrors();
    form.reset();
  });

  clearAllBtn.addEventListener('click', clearAll);

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
    } else if (action === 'delete') {
      const ok = window.confirm('Delete this request?');
      if (!ok) return;
      deleteOrderById(id);
    }
  });

  // Modal close handlers (backdrop, buttons)
  modal.addEventListener('click', (e) => {
    const closeTarget = e.target.closest('[data-modal-close]');
    if (closeTarget) closeModal();
  });

  // Close modal on Escape
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && modal.classList.contains('is-open')) {
      closeModal();
    }
  });

  // Initial render
  renderOrders(loadOrders());
})();
