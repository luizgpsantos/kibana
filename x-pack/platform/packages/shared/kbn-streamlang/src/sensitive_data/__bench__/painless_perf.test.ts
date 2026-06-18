/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import {
  buildBenchCases,
  buildAdversarialInput,
  buildRealisticInput,
  SAMPLE_VALUE_BY_DETECTOR,
  percentile,
  summarize,
  evaluateBudgets,
  type CaseResult,
  type PerfBudget,
} from './painless_perf';
import { MAX_SCAN_CHARS } from '../compile';
import { ACTIVE_DETECTOR_IDS } from '../catalog';
import perfBudget from './perf_budget.json';

describe('painless_perf harness (pure parts)', () => {
  it('has a corpus sample for every active detector', () => {
    const missing = ACTIVE_DETECTOR_IDS.filter((id) => !(id in SAMPLE_VALUE_BY_DETECTOR));
    expect(missing).toEqual([]);
  });

  it('compiles a non-empty case for every detector × supported action', () => {
    const cases = buildBenchCases();
    expect(cases.length).toBeGreaterThanOrEqual(ACTIVE_DETECTOR_IDS.length);
    for (const benchCase of cases) {
      expect(benchCase.processors.length).toBeGreaterThan(0);
      expect(benchCase.key).toBe(`${benchCase.id}:${benchCase.action}`);
    }
  });

  it('keeps the planted match well within the scan cap so the cap never hides it', () => {
    for (const sample of Object.values(SAMPLE_VALUE_BY_DETECTOR)) {
      const adversarial = buildAdversarialInput(sample);
      const realistic = buildRealisticInput(sample);
      // The match core sits in the middle of ~8 KB of filler — far below the 32 KB cap.
      expect(adversarial.indexOf(sample.value)).toBeGreaterThanOrEqual(0);
      expect(adversarial.indexOf(sample.value)).toBeLessThan(MAX_SCAN_CHARS);
      expect(realistic.indexOf(sample.value)).toBeLessThan(MAX_SCAN_CHARS);
    }
  });

  describe('percentile', () => {
    it('interpolates between ranks', () => {
      const samples = [10, 20, 30, 40, 50];
      expect(percentile(samples, 50)).toBe(30);
      expect(percentile(samples, 0)).toBe(10);
      expect(percentile(samples, 100)).toBe(50);
      expect(percentile(samples, 95)).toBeCloseTo(48, 5);
    });

    it('handles single-sample and empty inputs', () => {
      expect(percentile([42], 95)).toBe(42);
      expect(Number.isNaN(percentile([], 50))).toBe(true);
    });

    it('is order-independent', () => {
      expect(percentile([50, 10, 40, 20, 30], 50)).toBe(30);
    });
  });

  it('summarize reports median and p95', () => {
    const summary = summarize([1, 2, 3, 4, 100]);
    expect(summary.medianMs).toBe(3);
    expect(summary.p95Ms).toBeCloseTo(80.8, 5);
  });

  describe('evaluateBudgets', () => {
    const budget: PerfBudget = {
      note: '',
      limitFactor: 6,
      budgets: { 'visa:hash': 5, _default: 8 },
    };
    const result = (key: string, relativeToNoop: number): CaseResult => ({
      key,
      relativeToNoop,
      realistic: { medianMs: 0, p95Ms: 0 },
      adversarial: { medianMs: 0, p95Ms: 0 },
    });

    it('flags cases over their explicit budget', () => {
      const breaches = evaluateBudgets([result('visa:hash', 6)], budget);
      expect(breaches).toEqual([{ key: 'visa:hash', relativeToNoop: 6, budget: 5 }]);
    });

    it('falls back to _default for cases without an explicit budget', () => {
      expect(evaluateBudgets([result('email:partial', 9)], budget)).toHaveLength(1);
      expect(evaluateBudgets([result('email:partial', 7)], budget)).toEqual([]);
    });

    it('passes cases at or under budget', () => {
      expect(evaluateBudgets([result('visa:hash', 5)], budget)).toEqual([]);
    });
  });

  it('ships a budget file with a usable _default', () => {
    expect(typeof (perfBudget as PerfBudget).budgets._default).toBe('number');
    expect((perfBudget as PerfBudget).budgets._default).toBeGreaterThan(0);
  });
});
