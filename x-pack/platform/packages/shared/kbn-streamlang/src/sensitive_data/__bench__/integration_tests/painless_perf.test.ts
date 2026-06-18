/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/**
 * Opt-in performance gate for `sensitive_data` Painless scans (Spec 03 Part B).
 *
 * This lives under `integration_tests/` so it only runs in the jest_integration lane, never the
 * default unit run: a wall-clock benchmark is noisy and needs a running Elasticsearch. Even within
 * that lane it is skipped unless RUN_PAINLESS_PERF=1. Run it explicitly:
 *
 *   RUN_PAINLESS_PERF=1 TEST_ES_URL=http://localhost:9200 \
 *     node scripts/jest_integration \
 *       --config x-pack/platform/packages/shared/kbn-streamlang/jest.integration.config.js \
 *       x-pack/platform/packages/shared/kbn-streamlang/src/sensitive_data/__bench__/integration_tests/painless_perf.test.ts
 *
 * Provide ES auth via TEST_ES_AUTH (e.g. "elastic:changeme") or a full Basic header in TEST_ES_AUTH_HEADER.
 * The gate is relative (cost vs. a no-op pipeline measured in the same run); update perf_budget.json
 * deliberately, with justification, when an intentional change moves the numbers.
 */

import { writeFileSync, mkdirSync } from 'fs';
import { dirname, resolve } from 'path';
import {
  runBenchmark,
  evaluateBudgets,
  type EsTarget,
  type CaseResult,
  type PerfBudget,
} from '../painless_perf';
import perfBudget from '../perf_budget.json';

const shouldRun = process.env.RUN_PAINLESS_PERF === '1';
const esUrl = process.env.TEST_ES_URL ?? 'http://localhost:9200';

const authHeader = (): string | undefined => {
  if (process.env.TEST_ES_AUTH_HEADER) return process.env.TEST_ES_AUTH_HEADER;
  if (process.env.TEST_ES_AUTH) {
    return `Basic ${Buffer.from(process.env.TEST_ES_AUTH).toString('base64')}`;
  }
  return `Basic ${Buffer.from('elastic:changeme').toString('base64')}`;
};

const maybe = shouldRun ? describe : describe.skip;

maybe('sensitive_data Painless performance gate', () => {
  let results: CaseResult[];

  beforeAll(async () => {
    const target: EsTarget = { url: esUrl, authHeader: authHeader() };
    results = await runBenchmark(target, {
      docsPerRequest: Number(process.env.PAINLESS_PERF_DOCS ?? 200),
      rounds: Number(process.env.PAINLESS_PERF_ROUNDS ?? 5),
    });
    const outPath = resolve(__dirname, '../../../../target/painless_perf/last_run.json');
    mkdirSync(dirname(outPath), { recursive: true });
    writeFileSync(
      outPath,
      JSON.stringify({ es: esUrl, generatedAt: new Date().toISOString(), results }, null, 2)
    );
    // eslint-disable-next-line no-console
    console.table(
      results.map((r) => ({
        case: r.key,
        'realistic p50 (ms)': r.realistic.medianMs.toFixed(4),
        'adversarial p95 (ms)': r.adversarial.p95Ms.toFixed(4),
        'rel. to no-op': r.relativeToNoop.toFixed(2),
      }))
    );
  }, 600_000);

  it('keeps every detector × action within its relative cost budget', () => {
    const breaches = evaluateBudgets(results, perfBudget as PerfBudget);
    expect(
      `${breaches
        .map((b) => `  ${b.key}: ${b.relativeToNoop.toFixed(2)}x > budget ${b.budget}x`)
        .join('\n')}`
    ).toEqual('');
  });
});
