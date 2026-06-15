/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { hashCandidateRegex, HASH_FINGERPRINT_PREFIX } from './hash_fingerprint';
import { getDetectorsByIds } from './catalog';

const FNV_OFFSET_BASIS = 0xcbf29ce484222325n;
const FNV_PRIME = 0x100000001b3n;
const MASK_64 = 0xffffffffffffffffn;

/** TypeScript mirror of the Painless FNV-1a 64-bit loop (test-only reference). */
const fnv1a64Hex = (input: string): string => {
  let hash = FNV_OFFSET_BASIS;
  for (let i = 0; i < input.length; i++) {
    // eslint-disable-next-line no-bitwise -- FNV-1a requires 64-bit xor/and
    hash ^= BigInt(input.charCodeAt(i));
    // eslint-disable-next-line no-bitwise -- FNV-1a requires 64-bit xor/and
    hash = (hash * FNV_PRIME) & MASK_64;
  }
  return hash.toString(16).padStart(16, '0');
};

const formatHashFingerprint = (raw: string): string =>
  `${HASH_FINGERPRINT_PREFIX}${fnv1a64Hex(raw)}`;

describe('hash_fingerprint', () => {
  it('produces deterministic 16-char hex fingerprints', () => {
    const a = fnv1a64Hex('4111111111111111');
    const b = fnv1a64Hex('4111111111111111');
    expect(a).toBe(b);
    expect(a).toMatch(/^[0-9a-f]{16}$/);
  });

  it('produces different fingerprints for different inputs', () => {
    expect(fnv1a64Hex('4111111111111111')).not.toBe(fnv1a64Hex('5500000000000004'));
  });

  it('formats fingerprints with the h: prefix', () => {
    expect(formatHashFingerprint('test@example.com')).toMatch(
      new RegExp(`^${HASH_FINGERPRINT_PREFIX}[0-9a-f]{16}$`)
    );
  });

  it('builds hash regex for email via structural fallback', () => {
    const [email] = getDetectorsByIds(['email']);
    expect(hashCandidateRegex(email)).toContain('@');
  });

  it('builds hash regex for legacy credit-card via value capture', () => {
    const [legacyCard] = getDetectorsByIds(['credit-card']);
    expect(hashCandidateRegex(legacyCard)).toContain('{12,18}');
  });
});
