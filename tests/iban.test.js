const test = require('node:test');
const assert = require('node:assert/strict');

const { validateIban, formatIban } = require('../iban.js');

test('validateIban normalizes spaces/hyphens and uppercases', () => {
  const res = validateIban('  de89 3704-0044 0532 0130 00  ');
  assert.equal(res.normalized, 'DE89370400440532013000');
  assert.equal(res.isValid, true);
});

test('formatIban groups in 4s for display', () => {
  assert.equal(formatIban('DE89370400440532013000'), 'DE89 3704 0044 0532 0130 00');
});

test('rejects invalid country code', () => {
  const res = validateIban('1E89370400440532013000');
  assert.equal(res.isValid, false);
  assert.equal(res.error, 'Invalid country code');
});

test('rejects when not 2 letters + 2 digits at start', () => {
  const res = validateIban('DEAA370400440532013000');
  assert.equal(res.isValid, false);
  assert.equal(res.error, 'IBAN must start with 2 letters followed by 2 digits');
});

test('rejects invalid characters', () => {
  const res = validateIban('DE89$70400440532013000');
  assert.equal(res.isValid, false);
  assert.equal(res.error, 'IBAN contains invalid characters');
});

test('rejects invalid length (too short)', () => {
  const res = validateIban('GB82WEST123456');
  assert.equal(res.isValid, false);
  assert.equal(res.error, 'IBAN length is invalid');
});

test('DE: requires exactly 22 characters and digit-only BBAN', () => {
  {
    const res = validateIban('DE8937040044053201300');
    assert.equal(res.isValid, false);
    assert.equal(res.error, 'German IBAN must be exactly 22 digits after DE');
  }

  {
    // letter in BLZ/account portion
    const res = validateIban('DE89AB0400440532013000');
    assert.equal(res.isValid, false);
    assert.equal(res.error, 'German IBAN must be exactly 22 digits after DE');
  }
});

test('rejects invalid checksum', () => {
  const res = validateIban('DE89370400440532013001');
  assert.equal(res.isValid, false);
  assert.equal(res.error, 'Invalid IBAN checksum');
});

test('accepts a valid non-DE IBAN (GB)', () => {
  const res = validateIban('GB82 WEST 1234 5698 7654 32');
  assert.equal(res.isValid, true);
  assert.equal(res.normalized, 'GB82WEST12345698765432');
});
