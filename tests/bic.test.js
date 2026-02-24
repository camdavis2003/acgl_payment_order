const test = require('node:test');
const assert = require('node:assert/strict');

const { validateBic, formatBic } = require('../bic.js');

test('empty input -> required', () => {
  const res = validateBic('   ');
  assert.equal(res.isValid, false);
  assert.equal(res.error, 'BIC is required');
  assert.equal(res.normalized, '');
});

test('normalizes spaces/hyphens and uppercases', () => {
  const res = validateBic(' deut-deff xxx ');
  assert.equal(res.normalized, 'DEUTDEFFXXX');
  assert.equal(res.isValid, true);
});

test('wrong length', () => {
  const res = validateBic('DEUTDEFFX');
  assert.equal(res.isValid, false);
  assert.equal(res.error, 'BIC must be 8 or 11 characters');
});

test('invalid characters', () => {
  const res = validateBic('DEUTDEFF$XX');
  assert.equal(res.isValid, false);
  assert.equal(res.error, 'BIC contains invalid characters');
});

test('invalid bank code (non-letters in first 4)', () => {
  const res = validateBic('D3UTDEFF');
  assert.equal(res.isValid, false);
  assert.equal(res.error, 'Bank code must be 4 letters');
});

test('invalid country code (non-letters in positions 5–6)', () => {
  const res = validateBic('DEUTD1FF');
  assert.equal(res.isValid, false);
  assert.equal(res.error, 'Country code must be 2 letters');
});

test('valid 8-char DE BIC', () => {
  const res = validateBic('DEUTDEFF');
  assert.equal(res.isValid, true);
  assert.equal(res.normalized, 'DEUTDEFF');
});

test('valid 11-char DE BIC', () => {
  const res = validateBic('DEUTDEFF500');
  assert.equal(res.isValid, true);
  assert.equal(res.normalized, 'DEUTDEFF500');
});

test('formatBic returns uppercase without spaces', () => {
  assert.equal(formatBic(' deut deff '), 'DEUTDEFF');
});
