/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/** Optional separator between a fixed IIN prefix and the remaining digit groups (e.g. `6011 5326…`). */
export const groupedDigitSeparatorAfterPrefix = '[ .-]?';

/**
 * Tail segment for payment-card grok value patterns used by the ingest `redact` processor.
 *
 * `[ .-]?(?:[0-9][ .-]?){n}[0-9]` matches exactly `n + 1` digits when separators are absent. After a
 * fixed-width IIN prefix of length `prefixDigits`, a PAN of `totalDigits` therefore needs
 * `n = totalDigits - prefixDigits - 1`.
 */
export const groupedDigitTail = (totalDigits: number, prefixDigits: number): string => {
  const repeatCount = totalDigits - prefixDigits - 1;
  if (repeatCount < 0) {
    throw new Error(
      `groupedDigitTail: totalDigits (${totalDigits}) must exceed prefixDigits (${prefixDigits})`
    );
  }
  return `${groupedDigitSeparatorAfterPrefix}(?:[0-9][ .-]?){${repeatCount}}[0-9]`;
};

/** Variable-length PAN tail after a fixed IIN prefix (inclusive total digit counts). */
export const groupedDigitTailRange = (
  prefixDigits: number,
  minTotalDigits: number,
  maxTotalDigits: number
): string => {
  const minRepeat = minTotalDigits - prefixDigits - 1;
  const maxRepeat = maxTotalDigits - prefixDigits - 1;
  if (minRepeat < 0 || maxRepeat < minRepeat) {
    throw new Error('groupedDigitTailRange: invalid digit bounds for prefix length');
  }
  return `${groupedDigitSeparatorAfterPrefix}(?:[0-9][ .-]?){${minRepeat},${maxRepeat}}[0-9]`;
};
