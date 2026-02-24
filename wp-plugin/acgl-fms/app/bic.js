(function (root, factory) {
  if (typeof module === 'object' && typeof module.exports === 'object') {
    module.exports = factory();
  } else {
    root.BicUtils = factory();
  }
})(typeof self !== 'undefined' ? self : globalThis, function () {
  'use strict';

  /**
   * Normalize a BIC/SWIFT string:
   * - Trim whitespace
   * - Remove spaces and hyphens
   * - Uppercase
   * @param {string} raw
   */
  function normalizeBic(raw) {
    const trimmed = String(raw ?? '').trim();
    if (!trimmed) return '';
    return trimmed.replace(/[\s-]+/g, '').toUpperCase();
  }

  function isUpperAlpha(ch) {
    const code = ch.charCodeAt(0);
    return code >= 65 && code <= 90; // A-Z
  }

  function isDigit(ch) {
    const code = ch.charCodeAt(0);
    return code >= 48 && code <= 57; // 0-9
  }

  function isAlnumUpper(ch) {
    return isDigit(ch) || isUpperAlpha(ch);
  }

  /**
   * Display formatting for BIC: normalized (uppercase, no spaces/hyphens).
   * @param {string} normalized
   */
  function formatBic(normalized) {
    return normalizeBic(normalized);
  }

  /**
   * Validates a BIC/SWIFT with structured checks (no regex-only validation).
   * @param {string} raw
   * @returns {{ isValid: boolean; normalized: string; error?: string }}
   */
  function validateBic(raw) {
    const normalized = normalizeBic(raw);

    if (!normalized) {
      return { isValid: false, normalized: '', error: 'BIC is required' };
    }

    // Reject any non A-Z0-9 characters
    for (let i = 0; i < normalized.length; i += 1) {
      const ch = normalized[i];
      if (!isAlnumUpper(ch)) {
        return { isValid: false, normalized, error: 'BIC contains invalid characters' };
      }
    }

    // Length must be 8 or 11
    if (!(normalized.length === 8 || normalized.length === 11)) {
      return { isValid: false, normalized, error: 'BIC must be 8 or 11 characters' };
    }

    // 1–4 bank code: letters only
    for (let i = 0; i <= 3; i += 1) {
      if (!isUpperAlpha(normalized[i])) {
        return { isValid: false, normalized, error: 'Bank code must be 4 letters' };
      }
    }

    // 5–6 country code: letters only
    for (let i = 4; i <= 5; i += 1) {
      if (!isUpperAlpha(normalized[i])) {
        return { isValid: false, normalized, error: 'Country code must be 2 letters' };
      }
    }

    // 7–8 location code: alphanumeric
    for (let i = 6; i <= 7; i += 1) {
      if (!isAlnumUpper(normalized[i])) {
        return { isValid: false, normalized, error: 'Location code must be 2 alphanumeric characters' };
      }
    }

    // 9–11 branch code (optional): alphanumeric
    if (normalized.length === 11) {
      for (let i = 8; i <= 10; i += 1) {
        if (!isAlnumUpper(normalized[i])) {
          return { isValid: false, normalized, error: 'Branch code must be 3 alphanumeric characters' };
        }
      }
    }

    return { isValid: true, normalized };
  }

  return {
    validateBic,
    formatBic,
  };
});
