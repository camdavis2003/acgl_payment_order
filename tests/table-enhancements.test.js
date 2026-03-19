const test = require('node:test');
const assert = require('node:assert/strict');

const tableEnhancer = require('../table-enhancements.js');

const {
  slugify,
  sanitizeOrder,
  sanitizeHidden,
  buildStorageKey,
} = tableEnhancer.internals;

test('slugify normalizes labels to stable keys', () => {
  assert.equal(slugify('Payment Order Nr.', 'col-1'), 'payment-order-nr');
  assert.equal(slugify('  ', 'col-2'), 'col-2');
});

test('sanitizeOrder keeps valid unique keys and appends missing keys', () => {
  const columns = [{ key: 'date' }, { key: 'amount' }, { key: 'status' }];
  const order = sanitizeOrder(['status', 'date', 'status', 'unknown'], columns);
  assert.deepEqual(order, ['status', 'date', 'amount']);
});

test('sanitizeHidden never hides locked columns and keeps at least one optional column visible', () => {
  const columns = [
    { key: 'delete', locked: true },
    { key: 'name', locked: false },
    { key: 'amount', locked: false },
  ];

  const hiddenAll = sanitizeHidden(['delete', 'name', 'amount'], columns);
  assert.deepEqual(hiddenAll, ['amount']);

  const hiddenOne = sanitizeHidden(['amount'], columns);
  assert.deepEqual(hiddenOne, ['amount']);
});

test('buildStorageKey is namespaced by instance', () => {
  assert.equal(buildStorageKey('acgl_table_columns_v1', 'ordersTable'), 'acgl_table_columns_v1:ordersTable');
});
