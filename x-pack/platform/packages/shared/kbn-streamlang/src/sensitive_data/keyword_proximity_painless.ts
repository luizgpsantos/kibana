/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { SensitiveDataCategory } from '../../types/processors';
import type { Detector } from './catalog';
import { getDetectorById, getDefaultKeywordProximity, requiresKeywordProximity } from './catalog';

/** Escape a value for safe embedding in a single-quoted Painless string literal. */
const painlessSingleQuoted = (value: string): string =>
  value.replace(/\\/g, '\\\\').replace(/'/g, "\\'");

/**
 * Per-candidate Painless scripts (hash/partial/tag) must keep regex patterns small to stay under
 * Elasticsearch's `script.painless.regex.limit-factor` char-scan budget. When keyword proximity is
 * configured, use the catalog detector (value pattern only) and enforce keywords via string search.
 */
export const detectorForScriptRegex = (
  detector: Detector,
  config: SensitiveDataCategory
): Detector => {
  if (config.keywords?.length && requiresKeywordProximity(config.id)) {
    const bare = getDetectorById(config.id);
    if (bare) {
      return bare;
    }
  }
  return detector;
};

/**
 * Painless that sets `kwOk` when any configured keyword appears in the lookback window before `gs`.
 * Returns null when keyword proximity is not configured (caller should emit `boolean kwOk = true`).
 */
export const painlessKeywordProximityGuard = (
  config: SensitiveDataCategory,
  textVar: string,
  matchStartVar: string
): string | null => {
  if (!requiresKeywordProximity(config.id) || !config.keywords?.length) {
    return null;
  }
  const proximity = config.keywordProximity ?? getDefaultKeywordProximity(config.id) ?? 30;
  const maxKeywordLen = Math.max(...config.keywords.map((keyword) => keyword.length));
  const lookback = proximity + maxKeywordLen;
  const checks = config.keywords.map(
    (keyword) => `__kwWin.indexOf('${painlessSingleQuoted(keyword.toLowerCase())}') >= 0`
  );
  return [
    `int __kwStart = ${matchStartVar} - ${lookback};`,
    `if (__kwStart < 0) { __kwStart = 0; }`,
    `String __kwWin = ${textVar}.substring(__kwStart, ${matchStartVar}).toLowerCase();`,
    `boolean kwOk = ${checks.join(' || ')};`,
  ].join('\n');
};
