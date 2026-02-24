(function (root, factory) {
  if (typeof module === 'object' && typeof module.exports === 'object') {
    module.exports = factory();
  } else {
    root.IbanUtils = factory();
  }
})(typeof self !== 'undefined' ? self : globalThis, function () {
  'use strict';

  /**
   * Normalize an IBAN string:
   * - Trim whitespace
   * - Remove spaces and hyphens
   * - Uppercase
   * @param {string} raw
   */
  function normalizeIban(raw) {
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
   * Groups a normalized IBAN into chunks of 4 for display.
   * @param {string} normalized
   */
  function formatIban(normalized) {
    const s = normalizeIban(normalized);
    if (!s) return '';
    let out = '';
    for (let i = 0; i < s.length; i += 1) {
      if (i > 0 && i % 4 === 0) out += ' ';
      out += s[i];
    }
    return out;
  }

  function mod97(ibanNormalized) {
    // Assumes input is uppercase A-Z0-9 and length within bounds.
    const s = String(ibanNormalized);
    const rearranged = s.slice(4) + s.slice(0, 4);

    let remainder = 0;
    for (let i = 0; i < rearranged.length; i += 1) {
      const ch = rearranged[i];
      if (isDigit(ch)) {
        remainder = (remainder * 10 + (ch.charCodeAt(0) - 48)) % 97;
        continue;
      }

      // A=10 ... Z=35 (always two digits)
      const val = ch.charCodeAt(0) - 55;
      remainder = (remainder * 100 + val) % 97;
    }

    return remainder;
  }

  /**
   * Validates an IBAN with basic structure checks, DE-specific rules, and MOD97 checksum.
   * @param {string} raw
   * @returns {{ isValid: boolean; normalized: string; error?: string }}
   */
  function validateIban(raw) {
    const normalized = normalizeIban(raw);

    if (!normalized) {
      return { isValid: false, normalized: '', error: 'IBAN is required' };
    }

    // Country code: first 2 letters
    if (normalized.length < 2) {
      return { isValid: false, normalized, error: 'Invalid country code' };
    }
    const c0 = normalized[0];
    const c1 = normalized[1];
    if (!isUpperAlpha(c0) || !isUpperAlpha(c1)) {
      return { isValid: false, normalized, error: 'Invalid country code' };
    }

    // Next 2 chars: digits
    if (normalized.length < 4) {
      return { isValid: false, normalized, error: 'IBAN must start with 2 letters followed by 2 digits' };
    }
    const d0 = normalized[2];
    const d1 = normalized[3];
    if (!isDigit(d0) || !isDigit(d1)) {
      return { isValid: false, normalized, error: 'IBAN must start with 2 letters followed by 2 digits' };
    }

    // Remaining chars: only A-Z0-9 (also ensures no symbols anywhere)
    for (let i = 0; i < normalized.length; i += 1) {
      const ch = normalized[i];
      if (!isAlnumUpper(ch)) {
        return { isValid: false, normalized, error: 'IBAN contains invalid characters' };
      }
    }

    // Length validation
    if (normalized.length < 15 || normalized.length > 34) {
      return { isValid: false, normalized, error: 'IBAN length is invalid' };
    }

    const country = normalized.slice(0, 2);

    // Germany-specific validation
    if (country === 'DE') {
      if (normalized.length !== 22) {
        return { isValid: false, normalized, error: 'German IBAN must be exactly 22 digits after DE' };
      }

      // Characters 5–12: digits (indices 4..11)
      for (let i = 4; i <= 11; i += 1) {
        if (!isDigit(normalized[i])) {
          return { isValid: false, normalized, error: 'German IBAN must be exactly 22 digits after DE' };
        }
      }

      // Characters 13–22: digits (indices 12..21)
      for (let i = 12; i <= 21; i += 1) {
        if (!isDigit(normalized[i])) {
          return { isValid: false, normalized, error: 'German IBAN must be exactly 22 digits after DE' };
        }
      }
    }

    // Checksum validation (ISO 7064 MOD 97-10)
    if (mod97(normalized) !== 1) {
      return { isValid: false, normalized, error: 'Invalid IBAN checksum' };
    }

    return { isValid: true, normalized };
  }

  return {
    validateIban,
    formatIban,
  };
});
