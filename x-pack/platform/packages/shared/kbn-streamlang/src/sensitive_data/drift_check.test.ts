/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import fs from 'fs';
import path from 'path';
import { getActiveDetectors } from './catalog';
import { compileCombinedRedact } from './compile';

const goldenPath = path.join(__dirname, '__fixtures__', 'golden_combined_redact.json');

/**
 * Compiler-output snapshot for the active set (confirmed path: structural combined redact +
 * per-candidate checksum confirmers). Grok inputs and checksum semantics are traced to
 * elastic-redact-pii @ 972ad43; this golden validates our TypeScript compiler output stability,
 * not byte-identical parity with the full canonical engine.
 *
 * To regenerate after an intentional change: REGENERATE_SENSITIVE_DATA_GOLDEN=1 node scripts/jest \
 *   x-pack/platform/packages/shared/kbn-streamlang/src/sensitive_data/drift_check.test.ts
 */
describe('sensitive_data drift check (active set, confirmed snapshot)', () => {
  it('compiler output matches the approved golden fixture', () => {
    const { processors } = compileCombinedRedact(getActiveDetectors(), { field: 'message' });

    if (process.env.REGENERATE_SENSITIVE_DATA_GOLDEN === '1') {
      fs.writeFileSync(goldenPath, `${JSON.stringify({ processors }, null, 2)}\n`);
    }

    const golden = JSON.parse(fs.readFileSync(goldenPath, 'utf8')) as { processors: unknown[] };
    expect(processors).toEqual(golden.processors);
  });
});
