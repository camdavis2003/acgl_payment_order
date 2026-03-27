(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
    return;
  }
  var built = factory();
  root.ACGLTableEnhancer = built.api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  var DEFAULT_SELECTOR = 'table.table:not([data-table-enhance="off"]), table[data-table-enhance="on"]';
  var STORAGE_PREFIX = 'acgl_table_columns_v1';
  var INSTANCE_COUNTER = { value: 0 };
  var instances = new Map();

  var EYE_OPEN_SVG = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="16" height="16" aria-hidden="true" focusable="false"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>';
  var EYE_OFF_SVG = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="16" height="16" aria-hidden="true" focusable="false"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>';

  function normalizeWhitespace(text) {
    return String(text == null ? '' : text).replace(/\s+/g, ' ').trim();
  }

  function slugify(text, fallback) {
    var normalized = normalizeWhitespace(text).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
    if (normalized) return normalized;
    return fallback || 'col';
  }

  function buildStorageKey(prefix, instanceKey) {
    return String(prefix || STORAGE_PREFIX) + ':' + String(instanceKey || 'default');
  }

  function sanitizeOrder(order, columns) {
    var keys = (Array.isArray(columns) ? columns : []).map(function (c) { return c.key; });
    var keySet = new Set(keys);
    var next = [];
    for (var i = 0; i < (Array.isArray(order) ? order : []).length; i += 1) {
      var key = String(order[i] || '');
      if (!key || !keySet.has(key) || next.indexOf(key) !== -1) continue;
      next.push(key);
    }
    for (var j = 0; j < keys.length; j += 1) {
      if (next.indexOf(keys[j]) === -1) next.push(keys[j]);
    }

    // Keep locked columns at their original header positions.
    // Unlocked columns remain user-reorderable.
    var locked = (Array.isArray(columns) ? columns : []).filter(function (col) { return !!(col && col.locked); });
    for (var l = 0; l < locked.length; l += 1) {
      var lockedKey = locked[l].key;
      var originalIndex = keys.indexOf(lockedKey);
      if (originalIndex === -1) continue;

      var currentIndex = next.indexOf(lockedKey);
      if (currentIndex !== -1) next.splice(currentIndex, 1);

      if (originalIndex >= next.length) next.push(lockedKey);
      else next.splice(originalIndex, 0, lockedKey);
    }

    return next;
  }

  function sanitizeHidden(hidden, columns) {
    var hiddenSet = new Set(Array.isArray(hidden) ? hidden.map(function (key) { return String(key || ''); }) : []);
    var eligible = (Array.isArray(columns) ? columns : []).filter(function (col) { return !col.locked; });
    var visibleEligible = eligible.filter(function (col) { return !hiddenSet.has(col.key); });

    if (eligible.length > 0 && visibleEligible.length === 0) {
      hiddenSet.delete(eligible[0].key);
    }

    var out = [];
    for (var i = 0; i < (Array.isArray(columns) ? columns : []).length; i += 1) {
      var col = columns[i];
      if (!col || col.locked) continue;
      if (hiddenSet.has(col.key)) out.push(col.key);
    }
    return out;
  }

  function canUseDom() {
    return typeof window !== 'undefined' && typeof document !== 'undefined';
  }

  function getHeaderRow(table) {
    if (!table || !table.tHead || !table.tHead.rows || table.tHead.rows.length === 0) return null;
    return table.tHead.rows[table.tHead.rows.length - 1];
  }

  function isBudgetTable(table) {
    return !!(table && table.classList && table.classList.contains('budgetTable'));
  }

  function getTableInstanceKey(table, tableIndex) {
    var explicit = table && table.getAttribute ? normalizeWhitespace(table.getAttribute('data-table-instance')) : '';
    if (explicit) return explicit;

    var id = table && table.id ? normalizeWhitespace(table.id) : '';
    if (id) return id;

    var path = '';
    try {
      path = normalizeWhitespace(window.location.pathname || '').toLowerCase();
    } catch (err) {
      path = '';
    }

    var indexPart = String(Number.isInteger(tableIndex) ? tableIndex : INSTANCE_COUNTER.value);
    return (path || 'table-page') + '#table-' + indexPart;
  }

  function getColumnLabel(th, idx) {
    if (!th) return 'Column ' + String(idx + 1);
    var explicit = normalizeWhitespace(th.getAttribute('data-column-label'));
    if (explicit) return explicit;

    var clone = th.cloneNode(true);
    var ignore = clone.querySelectorAll('[data-th-menu-btn], .tableColResizer, button, input, select, textarea, [aria-hidden="true"]');
    for (var i = 0; i < ignore.length; i += 1) {
      ignore[i].remove();
    }

    var label = normalizeWhitespace(clone.textContent || '');
    if (label) return label;

    var aria = normalizeWhitespace(th.getAttribute('aria-label'));
    if (aria) return aria;

    return 'Column ' + String(idx + 1);
  }

  function buildColumns(table, headerCells) {
    var used = new Set();
    var cols = [];

    for (var i = 0; i < headerCells.length; i += 1) {
      var th = headerCells[i];
      var keyRaw = normalizeWhitespace(
        th.getAttribute('data-column-key') ||
        th.getAttribute('data-sort-key') ||
        th.getAttribute('id') ||
        getColumnLabel(th, i)
      );
      var key = slugify(keyRaw, 'col-' + String(i + 1));
      while (used.has(key)) key = key + '-' + String(i + 1);
      used.add(key);

      var lockAttr = normalizeWhitespace(th.getAttribute('data-column-lock')).toLowerCase();
      var label = getColumnLabel(th, i);
      var labelLower = normalizeWhitespace(label).toLowerCase();
      var ariaLower = normalizeWhitespace(th.getAttribute('aria-label')).toLowerCase();

      // Treat delete/action columns as locked across all tables even when
      // those headers do not use col-delete/col-actions classes.
      var isDeleteLike = (
        labelLower === 'delete' ||
        labelLower === 'x' ||
        labelLower === 'delete x' ||
        ariaLower === 'delete'
      );
      var isActionsLike = (labelLower === 'actions' || ariaLower === 'actions');

      var locked =
        lockAttr === '1' ||
        lockAttr === 'true' ||
        th.classList.contains('col-delete') ||
        th.classList.contains('col-actions') ||
        isDeleteLike ||
        isActionsLike;

      cols.push({
        key: key,
        label: label,
        locked: locked,
      });
    }

    return cols;
  }

  function isTrueLike(text) {
    var value = normalizeWhitespace(text).toLowerCase();
    return value === '1' || value === 'true' || value === 'yes' || value === 'on';
  }

  function cookieSafeName(key) {
    return String(key || '').replace(/[^a-zA-Z0-9!#$%&'*+\-.^_`|~]/g, '_');
  }

  function getCookieValue(name) {
    if (!canUseDom()) return null;
    try {
      var safeName = cookieSafeName(name);
      var pattern = new RegExp('(?:^|;\\s*)' + safeName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '=([^;]*)');
      var match = document.cookie.match(pattern);
      return match ? decodeURIComponent(match[1]) : null;
    } catch (err) {
      return null;
    }
  }

  function setCookieValue(name, value) {
    if (!canUseDom()) return;
    try {
      var safeName = cookieSafeName(name);
      var expires = new Date();
      expires.setFullYear(expires.getFullYear() + 1);
      document.cookie = safeName + '=' + encodeURIComponent(value) + '; expires=' + expires.toUTCString() + '; path=/; SameSite=Lax';
    } catch (err) {
      // Ignore cookie access failures.
    }
  }


  function getColumnKeyByLabel(columns, labelText) {
    var target = normalizeWhitespace(labelText).toLowerCase();
    if (!target) return '';
    for (var i = 0; i < (Array.isArray(columns) ? columns : []).length; i += 1) {
      var col = columns[i];
      if (!col) continue;
      var colLabel = normalizeWhitespace(col.label).toLowerCase();
      if (colLabel === target) return String(col.key || '');
    }
    return '';
  }

  function normalizeMoneyTransfersCommentsOrder(instance, order, allowCommentsMoved) {
    if (!instance || !instance.table || instance.table.id !== 'moneyTransfersTable') return order;
    if (allowCommentsMoved) return order;

    var commentsKey = getColumnKeyByLabel(instance.columns, 'comments');
    var actionsKey = getColumnKeyByLabel(instance.columns, 'actions');
    if (!commentsKey || !actionsKey) return order;

    var next = Array.isArray(order) ? order.slice() : [];
    var commentsIndex = next.indexOf(commentsKey);
    var actionsIndex = next.indexOf(actionsKey);
    if (commentsIndex === -1 || actionsIndex === -1) return order;
    if (commentsIndex === actionsIndex - 1) return order;

    next.splice(commentsIndex, 1);
    actionsIndex = next.indexOf(actionsKey);
    if (actionsIndex === -1) return order;
    next.splice(actionsIndex, 0, commentsKey);
    return next;
  }

  function loadState(instance) {
    try {
      var raw = getCookieValue(instance.storageKey);
      if (!raw) {
        return {
          order: sanitizeOrder([], instance.columns),
          hidden: sanitizeHidden([], instance.columns),
          allowCommentsMoved: false,
        };
      }

      var parsed = JSON.parse(raw);
      var allowCommentsMoved = !!(parsed && parsed.allowCommentsMoved);
      var order = sanitizeOrder(parsed && parsed.order, instance.columns);
      order = normalizeMoneyTransfersCommentsOrder(instance, order, allowCommentsMoved);
      return {
        order: order,
        hidden: sanitizeHidden(parsed && parsed.hidden, instance.columns),
        allowCommentsMoved: allowCommentsMoved,
      };
    } catch (err) {
      return {
        order: sanitizeOrder([], instance.columns),
        hidden: sanitizeHidden([], instance.columns),
        allowCommentsMoved: false,
      };
    }
  }

  function saveState(instance) {
    var payload = {
      order: sanitizeOrder(instance.state.order, instance.columns),
      hidden: sanitizeHidden(instance.state.hidden, instance.columns),
      allowCommentsMoved: !!instance.allowCommentsMoved,
    };
    setCookieValue(instance.storageKey, JSON.stringify(payload));
  }

  function rowCells(row) {
    if (!row) return [];
    var cells = [];
    for (var i = 0; i < row.children.length; i += 1) {
      var cell = row.children[i];
      if (!cell) continue;
      if (cell.tagName === 'TD' || cell.tagName === 'TH') cells.push(cell);
    }
    return cells;
  }

  function makeSpanFillerCell(tagName) {
    var filler = document.createElement(tagName === 'TH' ? 'th' : 'td');
    filler.className = 'tableEnhanceSpanFiller';
    filler.setAttribute('aria-hidden', 'true');
    filler.tabIndex = -1;
    return filler;
  }

  function normalizeRowSpans(row, expectedCells) {
    var cells = rowCells(row);
    if (cells.length === expectedCells && !row.querySelector('[colspan], [rowspan]')) return true;

    var hasRowSpan = false;
    for (var i = 0; i < cells.length; i += 1) {
      var rs = Number(cells[i].getAttribute('rowspan') || '1');
      if (Number.isFinite(rs) && rs > 1) {
        hasRowSpan = true;
        break;
      }
    }

    if (hasRowSpan) return false;

    var rebuilt = [];
    for (var j = 0; j < cells.length; j += 1) {
      var cell = cells[j];
      var span = Number(cell.getAttribute('colspan') || '1');
      if (!Number.isFinite(span) || span < 1) span = 1;
      cell.removeAttribute('colspan');
      rebuilt.push(cell);
      for (var copy = 1; copy < span; copy += 1) {
        rebuilt.push(makeSpanFillerCell(cell.tagName));
      }
    }

    while (rebuilt.length < expectedCells) rebuilt.push(makeSpanFillerCell('TD'));
    if (rebuilt.length > expectedCells) rebuilt = rebuilt.slice(0, expectedCells);

    row.replaceChildren.apply(row, rebuilt);
    return true;
  }

  function normalizeBodyAndFooter(instance) {
    var table = instance.table;
    var expected = instance.columns.length;
    var sections = [];

    for (var i = 0; i < table.tBodies.length; i += 1) sections.push(table.tBodies[i]);
    if (table.tFoot) sections.push(table.tFoot);

    for (var secIdx = 0; secIdx < sections.length; secIdx += 1) {
      var section = sections[secIdx];
      if (!section || !section.rows) continue;
      for (var rowIdx = 0; rowIdx < section.rows.length; rowIdx += 1) {
        var ok = normalizeRowSpans(section.rows[rowIdx], expected);
        if (!ok) return false;
      }
    }

    return true;
  }

  function assignCellKeysByIndex(cells, columns) {
    for (var i = 0; i < cells.length && i < columns.length; i += 1) {
      if (!cells[i].dataset.teColKey) cells[i].dataset.teColKey = columns[i].key;
    }
  }

  function setCellVisibilityFromState(instance, cell) {
    if (!cell) return;
    var key = String((cell.dataset && cell.dataset.teColKey) || '');
    if (!key) return;

    var hidden = instance.state.hidden.indexOf(key) !== -1;
    cell.classList.toggle('tableEnhanceCell--hidden', hidden);

    if (cell.tagName === 'TH') {
      if (hidden) {
        if (!cell.dataset.prevTabIndex && cell.hasAttribute('tabindex')) {
          cell.dataset.prevTabIndex = cell.getAttribute('tabindex') || '';
        }
        cell.setAttribute('tabindex', '-1');
      } else if (cell.dataset.prevTabIndex !== undefined) {
        if (cell.dataset.prevTabIndex === '') cell.removeAttribute('tabindex');
        else cell.setAttribute('tabindex', cell.dataset.prevTabIndex);
        delete cell.dataset.prevTabIndex;
      }
    }
  }

  function measureTextWidth(text, font) {
    var s = normalizeWhitespace(text || '');
    if (!s) return 0;
    var canvas = measureTextWidth._canvas;
    if (!canvas) {
      canvas = document.createElement('canvas');
      measureTextWidth._canvas = canvas;
    }
    var ctx = canvas.getContext && canvas.getContext('2d');
    if (!ctx) return 0;
    ctx.font = font || '14px sans-serif';
    return ctx.measureText(s).width;
  }

  function shouldShowHeaderOverflowTooltip(cell, fullLabel) {
    if (!canUseDom() || !cell) return false;
    var computed;
    try {
      computed = window.getComputedStyle(cell);
    } catch (err) {
      return false;
    }
    if (!computed) return false;

    var textOverflow = normalizeWhitespace(computed.textOverflow).toLowerCase();
    if (textOverflow !== 'ellipsis') return false;

    // Targeted fallback: ensure wiseUSD Counterparty header always gets
    // the full-title popup when it is ellipsis-styled.
    if (cell.matches && cell.matches('#wiseUsdTable th.wiseUsdCol--receivedFrom')) {
      return true;
    }

    var overflowX = normalizeWhitespace(computed.overflowX).toLowerCase();
    var overflow = normalizeWhitespace(computed.overflow).toLowerCase();
    var clips = overflowX === 'hidden' || overflowX === 'clip' || overflow === 'hidden' || overflow === 'clip';
    if (!clips) return false;

    if (cell.scrollWidth > cell.clientWidth + 1) return true;

    var label = normalizeWhitespace(fullLabel || '');
    if (!label) label = normalizeWhitespace(cell.textContent || '');
    if (!label) return false;

    var padLeft = Number.parseFloat(computed.paddingLeft || '0');
    var padRight = Number.parseFloat(computed.paddingRight || '0');
    var available = cell.clientWidth - (Number.isFinite(padLeft) ? padLeft : 0) - (Number.isFinite(padRight) ? padRight : 0);

    // Inline adornments in header cells consume text space (drag grip, etc.).
    var occupied = 0;
    if (cell.children && cell.children.length) {
      for (var i = 0; i < cell.children.length; i += 1) {
        var child = cell.children[i];
        if (!child || child.tagName === 'SCRIPT' || child.tagName === 'STYLE') continue;
        var childStyle;
        try {
          childStyle = window.getComputedStyle(child);
        } catch (err) {
          childStyle = null;
        }
        if (!childStyle || childStyle.display === 'none' || childStyle.position === 'absolute') continue;
        occupied += child.getBoundingClientRect().width;
      }
    }

    // Sort arrows are rendered via ::after and do not affect scrollWidth reliably.
    try {
      var after = window.getComputedStyle(cell, '::after');
      var afterContent = normalizeWhitespace((after && after.content) || '');
      if (afterContent && afterContent !== 'none' && afterContent !== 'normal') {
        afterContent = afterContent.replace(/^['\"]|['\"]$/g, '');
        if (afterContent) {
          occupied += measureTextWidth(afterContent, computed.font) + 2;
        }
      }
    } catch (err) {
      // Ignore pseudo-element measurement failures.
    }

    var textWidth = measureTextWidth(label, computed.font);
    var textRoom = available - occupied;
    if (textRoom <= 1) return true;
    return textWidth > textRoom + 0.5;
  }

  function syncSingleHeaderOverflowTooltip(cell, fullLabel) {
    if (!cell || !cell.getAttribute) return;

    var hasManagedTooltip = cell.dataset.teOverflowTooltipManaged === '1';
    var hasForeignTooltip =
      cell.hasAttribute('data-tooltip') ||
      cell.hasAttribute('title') ||
      (cell.hasAttribute('data-po-tooltip') && !hasManagedTooltip);
    if (hasForeignTooltip) return;

    var text = normalizeWhitespace(fullLabel || '');
    if (!text) text = normalizeWhitespace(cell.textContent || '');
    if (!text) return;

    if (shouldShowHeaderOverflowTooltip(cell, text)) {
      cell.setAttribute('data-po-tooltip', text);
      cell.dataset.teOverflowTooltipManaged = '1';
      return;
    }

    if (hasManagedTooltip) {
      cell.removeAttribute('data-po-tooltip');
      delete cell.dataset.teOverflowTooltipManaged;
    }
  }

  function syncHeaderOverflowTooltips(instance) {
    if (!instance || !instance.table) return;
    var headerRow = getHeaderRow(instance.table);
    if (!headerRow) return;

    var cells = rowCells(headerRow);
    for (var i = 0; i < cells.length; i += 1) {
      var th = cells[i];
      if (!(th.tagName === 'TH' || th.tagName === 'TD')) continue;
      syncSingleHeaderOverflowTooltip(th, getColumnLabel(th, i));
    }
  }

  function bindHeaderOverflowTooltip(th, headerIndex) {
    if (!th || !th.dataset || th.dataset.teOverflowTooltipBound === '1') return;

    var syncNow = function () {
      syncSingleHeaderOverflowTooltip(th, getColumnLabel(th, headerIndex));
    };

    th.addEventListener('mouseenter', syncNow);
    th.addEventListener('focusin', syncNow);
    th.dataset.teOverflowTooltipBound = '1';
  }

  function reorderRowCells(instance, row) {
    var cells = rowCells(row);
    if (cells.length !== instance.columns.length) return;
    assignCellKeysByIndex(cells, instance.columns);

    var byKey = {};
    for (var i = 0; i < cells.length; i += 1) {
      byKey[cells[i].dataset.teColKey] = cells[i];
    }

    var next = [];
    for (var j = 0; j < instance.state.order.length; j += 1) {
      var key = instance.state.order[j];
      if (byKey[key]) next.push(byKey[key]);
    }

    if (next.length !== cells.length) return;

    // Only move cells if they are already out of order. Skipping unnecessary
    // appendChild calls prevents the MutationObserver from firing and causing
    // an infinite RAF loop when the order hasn't changed.
    var needsReorder = false;
    for (var n = 0; n < next.length; n += 1) {
      if (cells[n] !== next[n]) { needsReorder = true; break; }
    }

    for (var k = 0; k < next.length; k += 1) {
      if (needsReorder) row.appendChild(next[k]);
      setCellVisibilityFromState(instance, next[k]);
    }
  }

  function redistributeEqualWidths(instance) {
    if (!instance || !instance.table) return;
    if (instance.table.getAttribute('data-equal-columns') !== 'true') return;
    var headerRow = getHeaderRow(instance.table);
    if (!headerRow) return;
    var cells = rowCells(headerRow);
    var visible = cells.filter(function (c) { return !c.classList.contains('tableEnhanceCell--hidden'); });
    var count = visible.length;
    if (count === 0) return;
    var pct = (100 / count).toFixed(4) + '%';
    for (var i = 0; i < cells.length; i += 1) {
      cells[i].style.width = cells[i].classList.contains('tableEnhanceCell--hidden') ? '' : pct;
    }
  }

  function syncTableToState(instance) {
    if (!instance || !instance.table) return;
    if (instance.syncing) return;

    instance.syncing = true;
    try {
      var headerRow = getHeaderRow(instance.table);
      if (!headerRow) return;
      reorderRowCells(instance, headerRow);

      var sections = [];
      for (var i = 0; i < instance.table.tBodies.length; i += 1) sections.push(instance.table.tBodies[i]);
      if (instance.table.tFoot) sections.push(instance.table.tFoot);

      for (var secIdx = 0; secIdx < sections.length; secIdx += 1) {
        var section = sections[secIdx];
        if (!section || !section.rows) continue;
        for (var rowIdx = 0; rowIdx < section.rows.length; rowIdx += 1) {
          reorderRowCells(instance, section.rows[rowIdx]);
        }
      }

      redistributeEqualWidths(instance);
      syncHeaderOverflowTooltips(instance);
      updatePanelUi(instance);
    } finally {
      instance.syncing = false;
    }
  }

  function moveOrderKey(order, fromKey, toKey, placeAfter) {
    var next = order.slice();
    var from = next.indexOf(fromKey);
    var to = next.indexOf(toKey);
    if (from === -1 || to === -1 || from === to) return next;

    next.splice(from, 1);
    var target = next.indexOf(toKey);
    if (target === -1) return next;
    if (placeAfter) target += 1;
    next.splice(target, 0, fromKey);
    return next;
  }

  function closePanel(instance) {
    if (!instance || !instance.controls || !instance.controls.panel || !instance.controls.button) return;
    instance.controls.panel.setAttribute('hidden', '');
    instance.controls.button.setAttribute('aria-expanded', 'false');
    if (instance.controls.overlay) instance.controls.overlay.setAttribute('hidden', '');
  }

  function openPanel(instance) {
    if (!instance || !instance.controls || !instance.controls.panel || !instance.controls.button) return;
    instance.controls.panel.removeAttribute('hidden');
    instance.controls.button.setAttribute('aria-expanded', 'true');
    if (instance.controls.overlay) instance.controls.overlay.removeAttribute('hidden');
    if (instance.controls.closeBtn && instance.controls.closeBtn.focus) {
      instance.controls.closeBtn.focus();
    }
  }

  function updatePanelUi(instance) {
    if (!instance || !instance.controls || !instance.controls.list) return;
    var list = instance.controls.list;

    var itemsByKey = {};
    for (var i = 0; i < list.children.length; i += 1) {
      var item = list.children[i];
      var key = String(item.getAttribute('data-col-key') || '');
      if (key) itemsByKey[key] = item;
    }

    for (var orderIdx = 0; orderIdx < instance.state.order.length; orderIdx += 1) {
      var colKey = instance.state.order[orderIdx];
      if (itemsByKey[colKey]) list.appendChild(itemsByKey[colKey]);
    }

    var eyeBtns = list.querySelectorAll('.tableEnhanceItem__eye[data-col-key]');
    for (var btnIdx = 0; btnIdx < eyeBtns.length; btnIdx += 1) {
      var btn = eyeBtns[btnIdx];
      var key = String(btn.getAttribute('data-col-key') || '');
      var col = instance.columnsByKey[key];
      if (!col) continue;
      var isHidden = instance.state.hidden.indexOf(key) !== -1;
      btn.setAttribute('aria-pressed', String(!isHidden));
      btn.disabled = !!col.locked;
      btn.classList.toggle('tableEnhanceItem__eye--off', isHidden);
    }
  }

  function buildControls(instance) {
    var table = instance.table;
    var host = table.closest('.table-wrap') || table.parentElement;
    if (!host) return null;
    var hidePanelGrip = !!(table && (table.id === 'usersTable' || table.id === 'notificationsTable'));

    // Full-screen backdrop overlay
    var overlay = document.createElement('div');
    overlay.className = 'tableEnhanceOverlay';
    overlay.setAttribute('hidden', '');
    document.body.appendChild(overlay);

    var controls = document.createElement('div');
    controls.className = 'tableEnhanceControls';

    var button = document.createElement('button');
    button.type = 'button';
    button.className = 'btn btn--ghost tableEnhanceColumnsBtn';
    button.textContent = 'Columns';

    var panelId = 'table-columns-panel-' + slugify(instance.instanceKey, 'table');
    button.setAttribute('aria-haspopup', 'dialog');
    button.setAttribute('aria-expanded', 'false');
    button.setAttribute('aria-controls', panelId);

    // Modal panel – appended to body so it sits above everything
    var panel = document.createElement('div');
    panel.className = 'tableEnhancePanel';
    panel.id = panelId;
    panel.setAttribute('role', 'dialog');
    panel.setAttribute('aria-modal', 'true');
    panel.setAttribute('aria-label', 'Manage Columns');
    panel.setAttribute('hidden', '');
    panel.tabIndex = -1;
    document.body.appendChild(panel);

    // Header row: title + close button
    var head = document.createElement('div');
    head.className = 'tableEnhancePanel__head';

    var title = document.createElement('h2');
    title.className = 'tableEnhancePanel__title';
    title.textContent = 'Manage Columns';

    var closeBtn = document.createElement('button');
    closeBtn.type = 'button';
    closeBtn.className = 'tableEnhancePanel__close';
    closeBtn.setAttribute('aria-label', 'Close column settings');
    closeBtn.innerHTML = '&times;';

    head.appendChild(title);
    head.appendChild(closeBtn);
    panel.appendChild(head);

    // Subheader: "Column Visibility" / "Drag to reorder"
    var subhead = document.createElement('div');
    subhead.className = 'tableEnhancePanel__subhead';

    var subLeft = document.createElement('span');
    subLeft.textContent = 'Column Visibility';

    var subRight = document.createElement('span');
    subRight.textContent = 'Drag to reorder';

    subhead.appendChild(subLeft);
    subhead.appendChild(subRight);
    panel.appendChild(subhead);

    // Scrollable column list
    var list = document.createElement('div');
    list.className = 'tableEnhanceList';

    for (var i = 0; i < instance.columns.length; i += 1) {
      var col = instance.columns[i];

      var item = document.createElement('div');
      item.className = 'tableEnhanceItem';
      item.setAttribute('data-col-key', col.key);

      // 6-dot grip handle — only this element is draggable so clicks on
      // the eye button are never swallowed by the browser's drag logic.
      var grip = document.createElement('span');
      grip.className = 'tableEnhanceItem__grip';
      grip.setAttribute('aria-hidden', 'true');
      grip.draggable = !col.locked;
      if (col.locked) grip.classList.add('tableEnhanceItem__grip--disabled');

      // Eye toggle button
      var eyeBtn = document.createElement('button');
      eyeBtn.type = 'button';
      eyeBtn.className = 'tableEnhanceItem__eye';
      eyeBtn.setAttribute('data-col-key', col.key);
      eyeBtn.setAttribute('aria-label', 'Toggle ' + col.label + ' visibility');
      var isColHidden = instance.state.hidden.indexOf(col.key) !== -1;
      eyeBtn.setAttribute('aria-pressed', String(!isColHidden));
      eyeBtn.disabled = !!col.locked;
      eyeBtn.classList.toggle('tableEnhanceItem__eye--off', isColHidden);
      // Both SVG states are embedded once at creation time. updatePanelUi
      // only toggles the --off class — no innerHTML replacement ever happens,
      // so the click event target is never detached mid-bubble.
      eyeBtn.innerHTML =
        '<span class="eye-icon--on" aria-hidden="true">' + EYE_OPEN_SVG + '</span>' +
        '<span class="eye-icon--off" aria-hidden="true">' + EYE_OFF_SVG + '</span>';

      var labelSpan = document.createElement('span');
      labelSpan.className = 'tableEnhanceItem__label';
      labelSpan.textContent = col.label;

      var dot = document.createElement('span');
      dot.className = 'tableEnhanceItem__dot';

      if (!col.locked && !hidePanelGrip) item.appendChild(grip);
      item.appendChild(eyeBtn);
      item.appendChild(labelSpan);
      item.appendChild(dot);
      list.appendChild(item);

      eyeBtn.addEventListener('click', function (event) {
        var target = event.currentTarget;
        if (!target) return;
        var key = String(target.getAttribute('data-col-key') || '');
        if (!key) return;

        var column = instance.columnsByKey[key];
        if (!column || column.locked) return;

        var nextHidden = new Set(instance.state.hidden);
        if (nextHidden.has(key)) nextHidden.delete(key);
        else nextHidden.add(key);

        instance.state.hidden = sanitizeHidden(Array.from(nextHidden), instance.columns);
        saveState(instance);

        // Apply visibility directly via CSS class only — no DOM restructuring,
        // so the MutationObserver never fires and there is no RAF loop.
        // This keeps the panel open and responsive for successive toggles.
        var tbl = instance.table;
        var sections = [tbl.tHead];
        for (var bi = 0; bi < tbl.tBodies.length; bi += 1) sections.push(tbl.tBodies[bi]);
        if (tbl.tFoot) sections.push(tbl.tFoot);
        for (var si = 0; si < sections.length; si += 1) {
          if (!sections[si]) continue;
          for (var ri = 0; ri < sections[si].rows.length; ri += 1) {
            var cells = rowCells(sections[si].rows[ri]);
            for (var ci = 0; ci < cells.length; ci += 1) {
              if (cells[ci].dataset && cells[ci].dataset.teColKey === key) {
                setCellVisibilityFromState(instance, cells[ci]);
              }
            }
          }
        }

        // Update this eye button's visual state directly.
        var isNowHidden = instance.state.hidden.indexOf(key) !== -1;
        target.setAttribute('aria-pressed', String(!isNowHidden));
        target.classList.toggle('tableEnhanceItem__eye--off', isNowHidden);
      });
    }

    panel.appendChild(list);

    // Stop clicks inside the panel from bubbling to document-level handlers.
    // Without this, any app-level "close on outside click" handler that checks
    // e.target.contains() would mis-fire because updatePanelUi moves DOM nodes
    // during the same event bubble.
    panel.addEventListener('click', function (event) {
      event.stopPropagation();
    });

    controls.appendChild(button);

    // Prefer placing the Columns control next to the global search input.
    // Default: immediately to the right of search. Ledger: to the left.
    var placedNearSearch = false;
    var card = table.closest('.card');
    var searchWrap = card ? card.querySelector('.list-actions .list-search') : null;
    if (searchWrap && searchWrap.parentElement) {
      var searchParent = searchWrap.parentElement;
      var searchInput = searchWrap.querySelector('input[id$="GlobalSearch"]');
      var isLedgerSearch = !!(searchInput && searchInput.id === 'gsLedgerGlobalSearch');

      controls.classList.add('tableEnhanceControls--inlineSearch');
      if (isLedgerSearch) {
        controls.classList.add('tableEnhanceControls--ledgerLeft');
        searchParent.insertBefore(controls, searchWrap);
      } else if (searchWrap.nextSibling) {
        searchParent.insertBefore(controls, searchWrap.nextSibling);
      } else {
        searchParent.appendChild(controls);
      }
      placedNearSearch = true;
    }

    if (!placedNearSearch) {
      host.insertBefore(controls, table);
    }

    if (!hidePanelGrip) bindPanelDragAndDrop(instance, list);

    button.addEventListener('click', function () {
      if (panel.hasAttribute('hidden')) openPanel(instance);
      else closePanel(instance);
    });

    closeBtn.addEventListener('click', function () {
      closePanel(instance);
      if (button.focus) button.focus();
    });

    overlay.addEventListener('click', function () {
      closePanel(instance);
      if (button.focus) button.focus();
    });

    document.addEventListener('keydown', function (event) {
      if (event.key !== 'Escape') return;
      if (!panel || panel.hasAttribute('hidden')) return;
      closePanel(instance);
      if (button.focus) button.focus();
    });

    return {
      root: controls,
      button: button,
      panel: panel,
      overlay: overlay,
      closeBtn: closeBtn,
      list: list,
    };
  }

  function bindPanelDragAndDrop(instance, list) {
    var panelDragKey = '';
    var panelDragToKey = '';
    var panelPlaceAfter = false;

    function clearPanelDropMarkers() {
      var items = list.querySelectorAll('.tableEnhanceItem');
      for (var k = 0; k < items.length; k += 1) {
        items[k].classList.remove('tableEnhancePanelDropBefore', 'tableEnhancePanelDropAfter');
      }
    }

    list.addEventListener('dragstart', function (event) {
      // Only allow drags initiated from the grip handle.
      var grip = event.target && event.target.closest ? event.target.closest('.tableEnhanceItem__grip') : null;
      if (!grip || !list.contains(grip)) {
        event.preventDefault();
        return;
      }
      var item = grip.closest('.tableEnhanceItem');
      if (!item) return;
      var key = String(item.getAttribute('data-col-key') || '');
      if (!key) return;
      var col = instance.columnsByKey[key];
      if (!col || col.locked) {
        event.preventDefault();
        return;
      }
      panelDragKey = key;
      if (event.dataTransfer) {
        event.dataTransfer.effectAllowed = 'move';
        try { event.dataTransfer.setData('text/plain', key); } catch (err) {}
      }
      item.classList.add('tableEnhancePanelDragging');
    });

    list.addEventListener('dragover', function (event) {
      var item = event.target && event.target.closest ? event.target.closest('.tableEnhanceItem') : null;
      if (!item || !list.contains(item)) return;
      var key = String(item.getAttribute('data-col-key') || '');
      if (!key) return;
      var col = instance.columnsByKey[key];
      if (!col || col.locked) {
        clearPanelDropMarkers();
        return;
      }
      event.preventDefault();
      clearPanelDropMarkers();
      var rect = item.getBoundingClientRect();
      panelPlaceAfter = event.clientY > rect.top + rect.height / 2;
      item.classList.add(panelPlaceAfter ? 'tableEnhancePanelDropAfter' : 'tableEnhancePanelDropBefore');
      panelDragToKey = key;
    });

    list.addEventListener('dragleave', function (event) {
      var related = event.relatedTarget;
      if (related && list.contains(related)) return;
      clearPanelDropMarkers();
    });

    list.addEventListener('drop', function (event) {
      event.preventDefault();
      var fromKey = panelDragKey;
      var toKey = panelDragToKey;
      clearPanelDropMarkers();
      var dragging = list.querySelector('.tableEnhancePanelDragging');
      if (dragging) dragging.classList.remove('tableEnhancePanelDragging');
      var fromCol = instance.columnsByKey[fromKey];
      var toCol = instance.columnsByKey[toKey];
      if (!fromCol || fromCol.locked || !toCol || toCol.locked) return;
      if (!fromKey || !toKey || fromKey === toKey) return;
      instance.state.order = sanitizeOrder(moveOrderKey(instance.state.order, fromKey, toKey, panelPlaceAfter), instance.columns);

      var commentsKey = getColumnKeyByLabel(instance.columns, 'comments');
      if (commentsKey && (fromKey === commentsKey || toKey === commentsKey)) {
        instance.allowCommentsMoved = true;
      }

      saveState(instance);
      syncTableToState(instance);
    });

    list.addEventListener('dragend', function () {
      panelDragKey = '';
      panelDragToKey = '';
      panelPlaceAfter = false;
      clearPanelDropMarkers();
      var dragging = list.querySelector('.tableEnhancePanelDragging');
      if (dragging) dragging.classList.remove('tableEnhancePanelDragging');
    });
  }

  function clearDropMarkers(headerRow) {
    if (!headerRow) return;
    var ths = headerRow.querySelectorAll('th');
    for (var i = 0; i < ths.length; i += 1) {
      ths[i].classList.remove('tableEnhanceDropBefore');
      ths[i].classList.remove('tableEnhanceDropAfter');
      ths[i].classList.remove('tableEnhanceDragging');
    }
  }

  function bindDragAndDrop(instance) {
    var headerRow = getHeaderRow(instance.table);
    if (!headerRow) return;
    var hideDragGrip = !!(instance.table && (instance.table.id === 'usersTable' || instance.table.id === 'notificationsTable'));

    for (var i = 0; i < headerRow.cells.length; i += 1) {
      var th = headerRow.cells[i];
      if (!(th.tagName === 'TH' || th.tagName === 'TD')) continue;
      if (!th.dataset.teColKey) th.dataset.teColKey = instance.columns[i].key;
      var key = String(th.dataset.teColKey || '');
      var col = instance.columnsByKey[key];
      var isLocked = !!(col && col.locked);
      th.draggable = !isLocked && !hideDragGrip;
      th.classList.add('tableEnhanceHeaderCell');
      bindHeaderOverflowTooltip(th, i);
      if (!isLocked && !hideDragGrip && !th.querySelector('.tableEnhanceDragHandle')) {
        var handle = document.createElement('span');
        handle.className = 'tableEnhanceDragHandle';
        handle.setAttribute('aria-hidden', 'true');
        th.insertBefore(handle, th.firstChild);
      } else if (isLocked || hideDragGrip) {
        var existingHandle = th.querySelector('.tableEnhanceDragHandle');
        if (existingHandle && existingHandle.parentElement) {
          existingHandle.parentElement.removeChild(existingHandle);
        }
      }
      syncSingleHeaderOverflowTooltip(th, getColumnLabel(th, i));
    }

    if (hideDragGrip) return;

    headerRow.addEventListener('dragstart', function (event) {
      var th = event.target && event.target.closest ? event.target.closest('th,td') : null;
      if (!th || !headerRow.contains(th)) return;

      var key = String(th.dataset.teColKey || '');
      if (!key) return;
      var col = instance.columnsByKey[key];
      if (!col || col.locked) {
        event.preventDefault();
        return;
      }

      instance.drag.fromKey = key;
      if (event.dataTransfer) {
        event.dataTransfer.effectAllowed = 'move';
        try {
          event.dataTransfer.setData('text/plain', key);
        } catch (err) {
          // Ignore setData failures.
        }
      }
      th.classList.add('tableEnhanceDragging');
    });

    headerRow.addEventListener('dragover', function (event) {
      var th = event.target && event.target.closest ? event.target.closest('th,td') : null;
      if (!th || !headerRow.contains(th)) return;
      var key = String(th.dataset.teColKey || '');
      if (!key) return;
      var col = instance.columnsByKey[key];
      if (!col || col.locked) {
        clearDropMarkers(headerRow);
        return;
      }

      event.preventDefault();
      clearDropMarkers(headerRow);

      var rect = th.getBoundingClientRect();
      var placeAfter = event.clientX > rect.left + rect.width / 2;
      th.classList.add(placeAfter ? 'tableEnhanceDropAfter' : 'tableEnhanceDropBefore');
      instance.drag.toKey = key;
      instance.drag.placeAfter = placeAfter;
    });

    headerRow.addEventListener('dragleave', function (event) {
      var related = event.relatedTarget;
      if (related && headerRow.contains(related)) return;
      clearDropMarkers(headerRow);
    });

    headerRow.addEventListener('drop', function (event) {
      event.preventDefault();
      var fromKey = String(instance.drag.fromKey || '');

      var target = event.target && event.target.closest ? event.target.closest('th,td') : null;
      var toKey = target ? String(target.dataset.teColKey || '') : String(instance.drag.toKey || '');
      var fromCol = instance.columnsByKey[fromKey];
      var toCol = instance.columnsByKey[toKey];
      if (!fromCol || fromCol.locked || !toCol || toCol.locked) {
        clearDropMarkers(headerRow);
        return;
      }
      if (!fromKey || !toKey || fromKey === toKey) {
        clearDropMarkers(headerRow);
        return;
      }

      var rect = target ? target.getBoundingClientRect() : null;
      var placeAfter = !!instance.drag.placeAfter;
      if (rect && Number.isFinite(rect.left) && Number.isFinite(rect.width)) {
        placeAfter = event.clientX > rect.left + rect.width / 2;
      }

      instance.state.order = sanitizeOrder(moveOrderKey(instance.state.order, fromKey, toKey, placeAfter), instance.columns);

      var commentsKey = getColumnKeyByLabel(instance.columns, 'comments');
      if (commentsKey && (fromKey === commentsKey || toKey === commentsKey)) {
        instance.allowCommentsMoved = true;
      }

      saveState(instance);
      syncTableToState(instance);
      clearDropMarkers(headerRow);
    });

    headerRow.addEventListener('dragend', function () {
      instance.drag.fromKey = '';
      instance.drag.toKey = '';
      instance.drag.placeAfter = false;
      instance.drag.lastDropAt = Date.now();
      clearDropMarkers(headerRow);
    });

    // Suppress accidental sort-click triggers immediately after dropping.
    headerRow.addEventListener('click', function (event) {
      if (!instance.drag.lastDropAt) return;
      if (Date.now() - instance.drag.lastDropAt > 220) return;
      event.preventDefault();
      event.stopPropagation();
    }, true);
  }

  function installObserver(instance) {
    if (typeof MutationObserver === 'undefined') return null;

    var table = instance.table;
    var observer = new MutationObserver(function () {
      if (instance.syncing) return;
      if (instance.observerRaf) cancelAnimationFrame(instance.observerRaf);
      instance.observerRaf = requestAnimationFrame(function () {
        instance.observerRaf = null;
        if (!normalizeBodyAndFooter(instance)) return;
        syncTableToState(instance);
      });
    });

    observer.observe(table, {
      childList: true,
      subtree: true,
    });

    return observer;
  }

  function initTable(table, options) {
    if (!canUseDom() || !table) return null;

    var opts = options && typeof options === 'object' ? options : {};
    if (instances.has(table)) return instances.get(table).publicApi;

    if (normalizeWhitespace(table.getAttribute('data-table-enhance')).toLowerCase() === 'off') return null;
    if (isBudgetTable(table) && !isTrueLike(table.getAttribute('data-table-enhance-force'))) return null;

    var headerRow = getHeaderRow(table);
    if (!headerRow) return null;

    if (headerRow.querySelector('[colspan], [rowspan]')) {
      if (!isTrueLike(table.getAttribute('data-table-enhance-force'))) return null;
    }

    var headerCells = rowCells(headerRow);
    if (headerCells.length < 2) return null;

    var tableIndex = Number.isInteger(opts.tableIndex) ? opts.tableIndex : INSTANCE_COUNTER.value;
    INSTANCE_COUNTER.value += 1;

    var columns = buildColumns(table, headerCells);
    var columnsByKey = {};
    for (var i = 0; i < columns.length; i += 1) columnsByKey[columns[i].key] = columns[i];

    assignCellKeysByIndex(headerCells, columns);

    var instanceKey = getTableInstanceKey(table, tableIndex);
    var storageKey = buildStorageKey(opts.storagePrefix || STORAGE_PREFIX, instanceKey);

    var instance = {
      table: table,
      instanceKey: instanceKey,
      storage: opts.storage || null,
      storageKey: storageKey,
      columns: columns,
      columnsByKey: columnsByKey,
      syncing: false,
      observerRaf: null,
      drag: {
        fromKey: '',
        toKey: '',
        placeAfter: false,
        lastDropAt: 0,
      },
      controls: null,
      observer: null,
      state: {
        order: sanitizeOrder([], columns),
        hidden: sanitizeHidden([], columns),
      },
      publicApi: null,
    };

    if (!normalizeBodyAndFooter(instance)) return null;

    instance.state = loadState(instance);
    instance.allowCommentsMoved = !!instance.state.allowCommentsMoved;
    delete instance.state.allowCommentsMoved;
    instance.controls = buildControls(instance);
    bindDragAndDrop(instance);
    syncTableToState(instance);
    instance.observer = installObserver(instance);

    var publicApi = {
      table: table,
      instanceKey: instance.instanceKey,
      refresh: function () {
        if (!normalizeBodyAndFooter(instance)) return;
        syncTableToState(instance);
      },
      destroy: function () {
        if (instance.observer) instance.observer.disconnect();
        if (instance.observerRaf) cancelAnimationFrame(instance.observerRaf);
        if (instance.controls && instance.controls.root && instance.controls.root.parentElement) {
          instance.controls.root.parentElement.removeChild(instance.controls.root);
        }
        if (instance.controls && instance.controls.panel && instance.controls.panel.parentElement) {
          instance.controls.panel.parentElement.removeChild(instance.controls.panel);
        }
        if (instance.controls && instance.controls.overlay && instance.controls.overlay.parentElement) {
          instance.controls.overlay.parentElement.removeChild(instance.controls.overlay);
        }
        instances.delete(table);
      },
    };

    instance.publicApi = publicApi;
    instances.set(table, instance);
    return publicApi;
  }

  function initAllTables(options) {
    if (!canUseDom()) return [];
    var opts = options && typeof options === 'object' ? options : {};
    var selector = normalizeWhitespace(opts.selector) || DEFAULT_SELECTOR;

    var tables = [];
    try {
      tables = Array.prototype.slice.call(document.querySelectorAll(selector));
    } catch (err) {
      return [];
    }

    var initialized = [];
    for (var i = 0; i < tables.length; i += 1) {
      var api = initTable(tables[i], {
        storagePrefix: opts.storagePrefix,
        storage: opts.storage,
        tableIndex: i,
      });
      if (api) initialized.push(api);
    }

    return initialized;
  }

  function refreshAll() {
    var list = Array.from(instances.values());
    for (var i = 0; i < list.length; i += 1) {
      var inst = list[i];
      if (!inst || !inst.publicApi || typeof inst.publicApi.refresh !== 'function') continue;
      inst.publicApi.refresh();
    }
  }

  var api = {
    version: '1.0.0',
    DEFAULT_SELECTOR: DEFAULT_SELECTOR,
    initTable: initTable,
    initAllTables: initAllTables,
    refreshAll: refreshAll,
  };

  return {
    api: api,
    internals: {
      slugify: slugify,
      sanitizeOrder: sanitizeOrder,
      sanitizeHidden: sanitizeHidden,
      buildStorageKey: buildStorageKey,
      getTableInstanceKey: getTableInstanceKey,
    },
  };
});
