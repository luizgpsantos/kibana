/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import fs from 'fs';
import path from 'path';
import { createDefaultCategoryConfig } from './catalog';
import { compileFromCategories } from './compile';

const goldenPath = path.join(__dirname, '__fixtures__', 'golden_hash_processors.json');

/**
 * Approved compiler output for hash actions. Catches accidental Painless rewrites
 * (duplicate declarations, invalid literals, etc.) without brittle substring checks.
 *
 * Painless compile + runtime semantics are covered by Scout
 * `processing_sensitive_data.spec.ts` (`processing/_simulate`).
 *
 * To regenerate after an intentional change:
 * REGENERATE_SENSITIVE_DATA_HASH_GOLDEN=1 node scripts/jest \
 *   x-pack/platform/packages/shared/kbn-streamlang/src/sensitive_data/hash_compile_drift.test.ts
 */
describe('sensitive_data hash compile drift check', () => {
  it('hash processor output matches the approved golden fixture', () => {
    const visaHash = compileFromCategories(
      [{ ...createDefaultCategoryConfig('visa'), action: 'hash' }],
      { field: 'message' }
    );
    const creditCardHash = compileFromCategories([{ id: 'credit-card', action: 'hash' }], {
      field: 'message',
    });
    const emailHash = compileFromCategories([{ id: 'email', action: 'hash' }], {
      field: 'message',
    });
    const ipv6Hash = compileFromCategories([{ id: 'ipv6', action: 'hash' }], {
      field: 'message',
    });

    const compiled = {
      visa_hash: visaHash,
      credit_card_hash: creditCardHash,
      email_hash: emailHash,
      ipv6_hash: ipv6Hash,
    };

    if (process.env.REGENERATE_SENSITIVE_DATA_HASH_GOLDEN === '1') {
      fs.writeFileSync(goldenPath, `${JSON.stringify(compiled, null, 2)}\n`);
    }

    const golden = JSON.parse(fs.readFileSync(goldenPath, 'utf8'));
    expect(compiled).toEqual(golden);
  });
});
