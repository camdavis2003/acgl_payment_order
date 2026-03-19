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
      var locked = lockAttr === '1' || lockAttr === 'true' || th.classList.contains('col-delete') || th.classList.contains('col-actions');

      cols.push({
        key: key,
        label: getColumnLabel(th, i),
        locked: locked,
      });
    }

    return cols;
  }

  function isTrueLike(text) {
    var value = normalizeWhitespace(text).toLowerCase();
    return value === '1' || value === 'true' || value === 'yes' || value === 'on';
  }

  function getLocalStorage(storage) {
    if (storage) return storage;
    if (!canUseDom()) return null;
    try {
      return window.localStorage;
    } catch (err) {
      return null;
    }
  }

  function loadState(instance) {
    var storage = getLocalStorage(instance.storage);
    if (!storage) {
      return {
        order: sanitizeOrder([], instance.columns),
        hidden: sanitizeHidden([], instance.columns),
      };
    }

    try {
      var raw = storage.getItem(instance.storageKey);
      if (!raw) {
        return {
          order: sanitizeOrder([], instance.columns),
          hidden: sanitizeHidden([], instance.columns),
        };
      }

      var parsed = JSON.parse(raw);
      return {
        order: sanitizeOrder(parsed && parsed.order, instance.columns),
        hidden: sanitizeHidden(parsed && parsed.hidden, instance.columns),
      };
    } catch (err) {
      return {
        order: sanitizeOrder([], instance.columns),
        hidden: sanitizeHidden([], instance.columns),
      };
    }
  }

  function saveState(instance) {
    var storage = getLocalStorage(instance.storage);
    if (!storage) return;

    var payload = {
      order: sanitizeOrder(instance.state.order, instance.columns),
      hidden: sanitizeHidden(instance.state.hidden, instance.columns),
    };

    try {
      storage.setItem(instance.storageKey, JSON.stringify(payload));
    } catch (err) {
      // Ignore localStorage quota and private mode failures.
    }
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

    for (var k = 0; k < next.length; k += 1) {
      row.appendChild(next[k]);
      setCellVisibilityFromState(instance, next[k]);
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
  }

  function openPanel(instance) {
    if (!instance || !instance.controls || !instance.controls.panel || !instance.controls.button) return;
    instance.controls.panel.removeAttribute('hidden');
    instance.controls.button.setAttribute('aria-expanded', 'true');
  }

  function updatePanelUi(instance) {
    if (!instance || !instance.controls || !instance.controls.list) return;
    var list = instance.controls.list;

    var labelsByKey = {};
    for (var i = 0; i < list.children.length; i += 1) {
      var label = list.children[i];
      var key = String(label.getAttribute('data-col-key') || '');
      if (key) labelsByKey[key] = label;
    }

    for (var orderIdx = 0; orderIdx < instance.state.order.length; orderIdx += 1) {
      var colKey = instance.state.order[orderIdx];
      if (labelsByKey[colKey]) list.appendChild(labelsByKey[colKey]);
    }

    var checkboxes = list.querySelectorAll('input[type="checkbox"][data-col-key]');
    for (var cbIdx = 0; cbIdx < checkboxes.length; cbIdx += 1) {
      var checkbox = checkboxes[cbIdx];
      var key = String(checkbox.getAttribute('data-col-key') || '');
      var col = instance.columnsByKey[key];
      if (!col) continue;
      var isHidden = instance.state.hidden.indexOf(key) !== -1;
      checkbox.checked = !isHidden;
      checkbox.disabled = !!col.locked;
    }
  }

  function buildControls(instance) {
    var table = instance.table;
    var host = table.closest('.table-wrap') || table.parentElement;
    if (!host) return null;

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

    var panel = document.createElement('div');
    panel.className = 'tableEnhancePanel';
    panel.id = panelId;
    panel.setAttribute('role', 'dialog');
    panel.setAttribute('aria-label', 'Column settings');
    panel.setAttribute('hidden', '');

    var title = document.createElement('p');
    title.className = 'tableEnhancePanel__title';
    title.textContent = 'Show columns';
    panel.appendChild(title);

    var list = document.createElement('div');
    list.className = 'tableEnhanceList';

    for (var i = 0; i < instance.columns.length; i += 1) {
      var col = instance.columns[i];
      var id = 'table-col-' + slugify(instance.instanceKey + '-' + col.key, 'col-' + String(i + 1));

      var label = document.createElement('label');
      label.className = 'tableEnhanceCheck';
      label.setAttribute('data-col-key', col.key);
      label.setAttribute('for', id);

      var input = document.createElement('input');
      input.type = 'checkbox';
      input.id = id;
      input.setAttribute('data-col-key', col.key);
      input.checked = instance.state.hidden.indexOf(col.key) === -1;
      input.disabled = !!col.locked;

      var text = document.createElement('span');
      text.textContent = col.label;

      label.appendChild(input);
      label.appendChild(text);
      list.appendChild(label);

      input.addEventListener('change', function (event) {
        var target = event.currentTarget;
        if (!target) return;
        var key = String(target.getAttribute('data-col-key') || '');
        if (!key) return;

        var column = instance.columnsByKey[key];
        if (!column || column.locked) {
          target.checked = true;
          return;
        }

        var nextHidden = new Set(instance.state.hidden);
        if (target.checked) nextHidden.delete(key);
        else nextHidden.add(key);

        instance.state.hidden = sanitizeHidden(Array.from(nextHidden), instance.columns);
        saveState(instance);
        syncTableToState(instance);
      });
    }

    panel.appendChild(list);

    var hint = document.createElement('p');
    hint.className = 'tableEnhancePanel__hint';
    hint.textContent = 'Tip: drag table headers to reorder columns.';
    panel.appendChild(hint);

    controls.appendChild(button);
    controls.appendChild(panel);

    host.insertBefore(controls, table);

    button.addEventListener('click', function () {
      if (panel.hasAttribute('hidden')) openPanel(instance);
      else closePanel(instance);
    });

    document.addEventListener('click', function (event) {
      if (!panel || panel.hasAttribute('hidden')) return;
      var target = event.target;
      if (!target) return;
      if (controls.contains(target)) return;
      closePanel(instance);
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
      list: list,
    };
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

    for (var i = 0; i < headerRow.cells.length; i += 1) {
      var th = headerRow.cells[i];
      if (!(th.tagName === 'TH' || th.tagName === 'TD')) continue;
      if (!th.dataset.teColKey) th.dataset.teColKey = instance.columns[i].key;
      th.draggable = true;
      th.classList.add('tableEnhanceHeaderCell');
    }

    headerRow.addEventListener('dragstart', function (event) {
      var th = event.target && event.target.closest ? event.target.closest('th,td') : null;
      if (!th || !headerRow.contains(th)) return;

      var key = String(th.dataset.teColKey || '');
      if (!key) return;

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
