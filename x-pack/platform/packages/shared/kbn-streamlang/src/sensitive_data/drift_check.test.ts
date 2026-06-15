/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import fs from 'fs';
import path from 'path';
import { ACTIVE_DETECTOR_IDS, createDefaultCategoryConfig } from './catalog';
import { compileFromCategories } from './compile';

const goldenPath = path.join(__dirname, '__fixtures__', 'golden_combined_redact.json');

/**
 * Compiler-output snapshot for the active set (structural combined redact for keyword-gated
 * payment-card networks, email, iban, and us-ssn).
 *
 * To regenerate after an intentional change: REGENERATE_SENSITIVE_DATA_GOLDEN=1 node scripts/jest \
 *   x-pack/platform/packages/shared/kbn-streamlang/src/sensitive_data/drift_check.test.ts
 */
describe('sensitive_data drift check (active set, structural snapshot)', () => {
  it('compiler output matches the approved golden fixture', () => {
    const { processors } = compileFromCategories(
      ACTIVE_DETECTOR_IDS.map((id) => createDefaultCategoryConfig(id)),
      { field: 'message' }
    );

    if (process.env.REGENERATE_SENSITIVE_DATA_GOLDEN === '1') {
      fs.writeFileSync(goldenPath, `${JSON.stringify({ processors }, null, 2)}\n`);
    }

    const golden = JSON.parse(fs.readFileSync(goldenPath, 'utf8')) as { processors: unknown[] };
    expect(processors).toEqual(golden.processors);
  });
});
