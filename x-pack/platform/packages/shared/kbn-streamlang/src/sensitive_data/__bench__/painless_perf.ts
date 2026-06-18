/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/**
 * Committed, repeatable benchmark for the per-document cost of `sensitive_data` Painless scans
 * (Spec 03). The pure parts (corpus construction, statistics, budget evaluation) live here and are
 * exercised by `painless_perf.test.ts` in the normal unit lane so the harness can't bit-rot. The
 * actual ES execution + relative budget gate is driven by `painless_perf.integration.test.ts`,
 * which is opt-in (see that file) so it never slows the default unit run.
 *
 * The gate is intentionally **relative** (cost vs. a no-op pipeline measured in the same run) rather
 * than an absolute wall-clock number, so it is stable across CI agents of differing speed. The point
 * is to catch 2–10× regressions, not 5% jitter.
 */

import type { SensitiveDataCategory, SensitiveDataCategoryAction } from '../../../types/processors';
import { compileFromCategories } from '../compile';
import { ACTIVE_DETECTOR_IDS } from '../catalog';
import { getSupportedActionsForCategory } from '../action_capabilities';
import {
  requiresKeywordProximity,
  withRecommendedKeywords,
} from '../catalog/category_keyword_catalog';

/** Worst-case backtracking family used to pick adversarial filler (mirrors the Spec 01 matrix). */
export type AdversarialFamily = 'digits' | 'email' | 'ipv4' | 'ipv6' | 'mac';

export interface BenchCorpusSample {
  /** A real, matchable instance of this detector's PII. */
  value: string;
  /** Proximity keyword for keyword-gated detectors (placed immediately before the value). */
  keyword?: string;
  family: AdversarialFamily;
}

/**
 * One realistic, matchable sample per active detector. Kept in sync with the Spec 01 matrix corpus;
 * a coverage test fails if a new `ACTIVE_DETECTOR_IDS` entry is missing here.
 */
export const SAMPLE_VALUE_BY_DETECTOR: Record<string, BenchCorpusSample> = {
  email: { value: 'alice.smith@example.com', family: 'email' },
  visa: { value: '4111 1111 1111 1111', keyword: 'card', family: 'digits' },
  mastercard: { value: '5555 5555 5555 4444', keyword: 'card', family: 'digits' },
  amex: { value: '3782 822463 10005', keyword: 'card', family: 'digits' },
  discover: { value: '6011 1111 1111 1117', keyword: 'card', family: 'digits' },
  diners: { value: '3056 9309 0259 04', keyword: 'card', family: 'digits' },
  jcb: { value: '3530 1113 3330 0000', keyword: 'card', family: 'digits' },
  maestro: { value: '6759 6498 2643 8453', keyword: 'card', family: 'digits' },
  iban: { value: 'DE89 3704 0044 0532 0130 00', keyword: 'iban', family: 'digits' },
  'us-ssn': { value: '123-45-6789', keyword: 'ssn', family: 'digits' },
  ipv4: { value: '192.168.1.100', family: 'ipv4' },
  ipv6: { value: '2001:0db8:85a3:0000:0000:8a2e:0370:7334', family: 'ipv6' },
  'mac-address': { value: '00:1A:2B:3C:4D:5E', family: 'mac' },
};

/** Dense, separator-heavy filler that maximizes regex work for the matched family. */
const ADVERSARIAL_UNIT: Record<AdversarialFamily, string> = {
  digits: '0123 4567-8901.2345 6789-0123.4567 8901-2345.6789 ',
  email: 'aaaa.bbbb+cccc.dddd_eeee-ffff.gggg_hhhh-iiii.jjjj@sub.domain.example ',
  ipv4: '111.222.333.444 10.0.0.1 255.255.255.255 172.16.254.1 ',
  ipv6: 'abcd:1234:5678:9abc:def0:1234:5678:9abc fedc:ba98:7654:3210:0011:2233:4455:6677 ',
  mac: 'aa:bb:cc:dd:ee:ff 00:11:22:33:44:55 a1:b2:c3:d4:e5:f6 ',
};

const ADVERSARIAL_TARGET_BYTES = 4096;

const repeatToBytes = (unit: string, targetBytes: number): string =>
  unit.repeat(Math.ceil(targetBytes / unit.length)).slice(0, targetBytes);

const matchCore = (sample: BenchCorpusSample): string =>
  sample.keyword ? `${sample.keyword} ${sample.value}` : sample.value;

/** Realistic positive: value surrounded by benign prose filler (~1 KB). */
export const buildRealisticInput = (sample: BenchCorpusSample): string => {
  const lead = repeatToBytes('lorem ipsum dolor sit amet consectetur ', 512);
  const tail = repeatToBytes('the quick brown fox jumps over the lazy dog ', 512);
  return `${lead} ${matchCore(sample)} ${tail}`;
};

/** Adversarial: the match surrounded by a pathological, separator-dense run for its family (~8 KB). */
export const buildAdversarialInput = (sample: BenchCorpusSample): string => {
  const filler = repeatToBytes(ADVERSARIAL_UNIT[sample.family], ADVERSARIAL_TARGET_BYTES);
  return `${filler} ${matchCore(sample)} ${filler}`;
};

const buildCategory = (id: string, action: SensitiveDataCategoryAction): SensitiveDataCategory => {
  const base: SensitiveDataCategory =
    action === 'partial' ? { id, action, keepLast: 4 } : { id, action };
  return requiresKeywordProximity(id) ? withRecommendedKeywords(base) : base;
};

export const BENCH_FIELD = 'message';

export interface BenchCase {
  id: string;
  action: SensitiveDataCategoryAction;
  /** Stable key, e.g. `visa:hash`; matches keys in `perf_budget.json`. */
  key: string;
  /** Compiled ingest processors for this single category, with telemetry on. */
  processors: unknown[];
  realisticInput: string;
  adversarialInput: string;
}

/** The full detector × supported-action grid, compiled and paired with realistic + adversarial inputs. */
export const buildBenchCases = (): BenchCase[] => {
  const cases: BenchCase[] = [];
  for (const id of ACTIVE_DETECTOR_IDS) {
    const sample = SAMPLE_VALUE_BY_DETECTOR[id];
    if (!sample) {
      throw new Error(`Missing SAMPLE_VALUE_BY_DETECTOR entry for detector "${id}"`);
    }
    for (const action of getSupportedActionsForCategory(id)) {
      const { processors } = compileFromCategories([buildCategory(id, action)], {
        field: BENCH_FIELD,
        withFlags: true,
      });
      cases.push({
        id,
        action,
        key: `${id}:${action}`,
        processors,
        realisticInput: buildRealisticInput(sample),
        adversarialInput: buildAdversarialInput(sample),
      });
    }
  }
  return cases;
};

/** Linear-interpolated percentile (`p` in 0..100) of an unsorted sample array. */
export const percentile = (samples: number[], p: number): number => {
  if (samples.length === 0) return NaN;
  const sorted = [...samples].sort((a, b) => a - b);
  if (sorted.length === 1) return sorted[0];
  const rank = (p / 100) * (sorted.length - 1);
  const lo = Math.floor(rank);
  const hi = Math.ceil(rank);
  if (lo === hi) return sorted[lo];
  return sorted[lo] + (sorted[hi] - sorted[lo]) * (rank - lo);
};

export interface CorpusTiming {
  medianMs: number;
  p95Ms: number;
}

export const summarize = (perDocMs: number[]): CorpusTiming => ({
  medianMs: percentile(perDocMs, 50),
  p95Ms: percentile(perDocMs, 95),
});

export interface CaseResult {
  key: string;
  realistic: CorpusTiming;
  adversarial: CorpusTiming;
  /** Median adversarial per-doc time divided by the no-op baseline measured in the same run. */
  relativeToNoop: number;
}

export interface PerfBudget {
  note: string;
  limitFactor: number;
  /** Max allowed `relativeToNoop` per `detector:action` key; `_default` applies to the rest. */
  budgets: Record<string, number>;
}

export interface BudgetBreach {
  key: string;
  relativeToNoop: number;
  budget: number;
}

/** Returns every case whose relative cost exceeds its budget (falling back to `_default`). */
export const evaluateBudgets = (results: CaseResult[], budget: PerfBudget): BudgetBreach[] => {
  const fallback = budget.budgets._default;
  const breaches: BudgetBreach[] = [];
  for (const result of results) {
    const limit = budget.budgets[result.key] ?? fallback;
    if (Number.isFinite(limit) && result.relativeToNoop > limit) {
      breaches.push({ key: result.key, relativeToNoop: result.relativeToNoop, budget: limit });
    }
  }
  return breaches;
};

// --- ES execution (used only by the opt-in integration gate; pure logic above is unit-tested) ---

export interface EsTarget {
  url: string;
  authHeader?: string;
}

interface TimingOptions {
  docsPerRequest: number;
  rounds: number;
  warmupRounds: number;
}

const NOOP_PIPELINE = [{ set: { field: 'attributes._bench_noop', value: 1 } }];

/**
 * Posts `docsPerRequest` identical docs to `_ingest/pipeline/_simulate` for `rounds` rounds and
 * returns per-document wall time (ms) for each round. The first `warmupRounds` are discarded so JIT
 * warm-up doesn't skew the numbers.
 */
const timePerDocMs = async (
  target: EsTarget,
  processors: unknown[],
  input: string,
  options: TimingOptions
): Promise<number[]> => {
  const docs = Array.from({ length: options.docsPerRequest }, () => ({
    _index: 'bench',
    _source: { [BENCH_FIELD]: input },
  }));
  const body = JSON.stringify({ pipeline: { processors }, docs });
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (target.authHeader) headers.Authorization = target.authHeader;

  const samples: number[] = [];
  const totalRounds = options.warmupRounds + options.rounds;
  for (let round = 0; round < totalRounds; round++) {
    const started = performance.now();
    const res = await fetch(`${target.url}/_ingest/pipeline/_simulate`, {
      method: 'POST',
      headers,
      body,
    });
    const elapsed = performance.now() - started;
    if (!res.ok) {
      throw new Error(`_simulate failed (${res.status}): ${(await res.text()).slice(0, 300)}`);
    }
    if (round >= options.warmupRounds) {
      samples.push(elapsed / options.docsPerRequest);
    }
  }
  return samples;
};

export interface RunOptions {
  docsPerRequest?: number;
  rounds?: number;
  warmupRounds?: number;
}

/** Runs the full grid against ES, computing relative-to-no-op cost per case. */
export const runBenchmark = async (
  target: EsTarget,
  options: RunOptions = {}
): Promise<CaseResult[]> => {
  const timing: TimingOptions = {
    docsPerRequest: options.docsPerRequest ?? 200,
    rounds: options.rounds ?? 5,
    warmupRounds: options.warmupRounds ?? 2,
  };
  const results: CaseResult[] = [];
  for (const benchCase of buildBenchCases()) {
    const realistic = summarize(
      await timePerDocMs(target, benchCase.processors, benchCase.realisticInput, timing)
    );
    const adversarial = summarize(
      await timePerDocMs(target, benchCase.processors, benchCase.adversarialInput, timing)
    );
    // No-op baseline on the same adversarial doc isolates processor CPU from HTTP/parse/size cost.
    const noop = summarize(
      await timePerDocMs(target, NOOP_PIPELINE, benchCase.adversarialInput, timing)
    );
    results.push({
      key: benchCase.key,
      realistic,
      adversarial,
      relativeToNoop: adversarial.medianMs / noop.medianMs,
    });
  }
  return results;
};
