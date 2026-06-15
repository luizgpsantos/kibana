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
 * built-in Grok tokens that lack pattern_definitions (email, ipv4, ipv6).
 */
const STRUCTURAL_HASH_REGEX: Readonly<Record<string, string>> = {
  email: '([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,})',
  ipv4: '((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))',
  ipv6: '((?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|:(?::[0-9a-fA-F]{1,4}){1,7})',
};

export const hashCandidateRegex = (detector: Detector): string => {
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
