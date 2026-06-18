/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { Detector } from './catalog';
import { confirmCandidateRegex } from './confirm_candidate_regex';

/** Prefix written before the 16-char hex fingerprint in hashed field values. */
export const HASH_FINGERPRINT_PREFIX = 'h:';

/** FNV-1a 64-bit offset basis as a signed Java `long` (Painless rejects `0xcbf29ce484222325L`). */
const FNV_OFFSET_BASIS_PAINLESS = '-3750763034362895579L';

/** FNV-1a 64-bit prime as a decimal Java `long`. */
const FNV_PRIME_PAINLESS = '1099511628211L';

/**
 * Java-regex with exactly one capturing group for per-candidate hash replacement.
 * Uses {@link confirmCandidateRegex} when available; otherwise structural fallbacks for
 * built-in Grok tokens that lack pattern_definitions (email, ipv4). IPv6 uses regex-free scanning.
 */
const STRUCTURAL_HASH_REGEX: Readonly<Record<string, string>> = {
  // Structural redact uses the native grok processor; hash/partial must use a simpler Java regex for
  // per-candidate Painless scripts that stays under `script.painless.regex.limit-factor`. The budget
  // is `factor (6) × sliceLength`, and the dominant cost is the engine re-reading characters via
  // `matcher.find()`: `find()` retries the pattern at every start offset, and a greedy `[class]+`
  // re-scans the whole run at each retry, so a long run of local-part characters costs O(n²) char
  // visits and blows the budget even on a single 128-char chunk. Two changes keep `email` under
  // budget (both verified against real ES, including the adversarial matrix input, with identical
  // matches to the old greedy form on every valid address):
  //   1. A leading negative lookbehind `(?<![local-part chars])` makes `find()` fail in O(1) at every
  //      interior offset of a run, so a match can only *start* at a true run boundary — this is the
  //      same boundary trick the card detectors use with `(?<![0-9])`, and it is what removes the
  //      O(n²) restart cost on the dense adversarial input.
  //   2. A possessive local part (`++`) stops backtracking within the one real match attempt.
  // The domain is left greedy so matching is unchanged — a sentence-ending address (`bob@host.com.`)
  // still backtracks to the correct span. Lowering the chunk size does not help (the abort count
  // tracks the budget 1:1).
  //
  // Not every detector can be fixed this way — when the *input itself* makes every offset a plausible
  // match start (digit-dense card runs, IP-dense network logs), the lookbehind can't fail fast and
  // `find()` restarts keep the ratio at ~6× regardless of quantifiers, so `ipv4`/checksum-card hashing
  // must fall back to a regex-free scan (see painless_ipv6_scan.ts for the model).
  email: '((?<![a-zA-Z0-9._%+-])[a-zA-Z0-9._%+-]++@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,})',
  ipv4: '((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))',
};

export const hashCandidateRegex = (detector: Detector): string => {
  if (detector.id === 'ipv6') {
    throw new Error(
      'hash compile: ipv6 uses regex-free Painless scanning (see painless_ipv6_scan.ts)'
    );
  }
  try {
    return confirmCandidateRegex(detector);
  } catch {
    const fallback = STRUCTURAL_HASH_REGEX[detector.id];
    if (fallback) {
      return fallback;
    }
    throw new Error(
      `hash compile: ${detector.id} has no value-capture pattern for per-candidate hashing`
    );
  }
};

/**
 * Painless statements that assign an FNV-1a 64-bit fingerprint of `fromVar` to `toVar`.
 * Uses only allowlisted Painless primitives (no MessageDigest).
 */
export const painlessAssignFingerprint = (fromVar: string, toVar: string): string =>
  [
    `long __h = ${FNV_OFFSET_BASIS_PAINLESS};`,
    `long __p = ${FNV_PRIME_PAINLESS};`,
    `for (int __i = 0; __i < ${fromVar}.length(); __i++) {`,
    `  __h ^= (long)${fromVar}.charAt(__i);`,
    `  __h *= __p;`,
    `}`,
    `String __hex = '';`,
    `for (int __i = 15; __i >= 0; __i--) {`,
    `  int __n = (int)((__h >>> (__i * 4)) & 15);`,
    `  __hex += "0123456789abcdef".charAt(__n);`,
    `}`,
    `String ${toVar} = '${HASH_FINGERPRINT_PREFIX}' + __hex;`,
  ].join('\n');

/** FNV-1a over `textVar[startVar..endVar)` without allocating a candidate substring. */
export const painlessAssignFingerprintFromRange = (
  textVar: string,
  startVar: string,
  endVar: string,
  toVar: string
): string =>
  [
    `long __h = ${FNV_OFFSET_BASIS_PAINLESS};`,
    `long __p = ${FNV_PRIME_PAINLESS};`,
    `for (int __i = ${startVar}; __i < ${endVar}; __i++) {`,
    `  __h ^= (long)${textVar}.charAt(__i);`,
    `  __h *= __p;`,
    `}`,
    `String __hex = '';`,
    `for (int __i = 15; __i >= 0; __i--) {`,
    `  int __n = (int)((__h >>> (__i * 4)) & 15);`,
    `  __hex += "0123456789abcdef".charAt(__n);`,
    `}`,
    `String ${toVar} = '${HASH_FINGERPRINT_PREFIX}' + __hex;`,
  ].join('\n');
