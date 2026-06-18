/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { createDefaultCategoryConfig, getDetectorsByIds } from './catalog';
import {
  compileCombinedRedact,
  compileFromCategories,
  confirmCandidateRegex,
  applyKeywordOverride,
  isChecksum,
  captureName,
  maskToken,
} from './compile';

const scriptSource = (p: unknown): string => {
  if (!p || typeof p !== 'object' || !('script' in p)) {
    throw new Error('expected a script processor');
  }
  return (p as { script: { source: string } }).script.source;
};

const visaRedact = createDefaultCategoryConfig('visa');

describe('compileCombinedRedact (active structural set)', () => {
  it('classifies active detectors as structural and legacy credit-card as checksum', () => {
    const [email, visa, legacyCard] = getDetectorsByIds(['email', 'visa', 'credit-card']);
    expect(isChecksum(email)).toBe(false);
    expect(isChecksum(visa)).toBe(false);
    expect(isChecksum(legacyCard)).toBe(true);
    expect(captureName(email)).toBe('EMAIL');
    expect(maskToken(visa)).toBe('<VISA>');
    expect(maskToken(legacyCard)).toBe('<CREDIT_CARD>');
  });

  it('emits ONE combined redact processor for active structural detectors', () => {
    const detectors = getDetectorsByIds(['email', 'visa']);
    const { processors } = compileCombinedRedact(detectors, { field: 'message' });
    expect(processors).toHaveLength(1);
    const first = processors[0];
    if (!first || !('redact' in first) || !first.redact) {
      throw new Error('expected combined redact processor');
    }
    expect(first.redact.field).toBe('message');
    expect(first.redact.patterns?.length).toBeGreaterThanOrEqual(2);
  });

  it('emits a per-candidate checksum confirmer for legacy credit-card', () => {
    const [legacyCard] = getDetectorsByIds(['credit-card']);
    const { processors } = compileCombinedRedact([legacyCard], { field: 'message' });
    expect(processors).toHaveLength(1);
    const first = processors[0];
    if (!first || !('script' in first) || !first.script) {
      throw new Error('expected a confirmer script processor');
    }
    expect(first.script.description).toMatch(/Luhn/i);
    expect(scriptSource(first)).toContain('sum % 10 == 0');
  });

  it('active set compile uses structural redact only (no checksum confirmers)', () => {
    const detectors = getDetectorsByIds(['email', 'visa', 'iban', 'us-ssn']);
    const { processors } = compileCombinedRedact(detectors, { field: 'message' });
    expect(processors).toHaveLength(1);
    expect(processors[0] && 'redact' in processors[0]).toBe(true);
  });

  it('appends the telemetry flag script when withFlags is set', () => {
    const detectors = getDetectorsByIds(['email', 'visa']);
    const { processors } = compileCombinedRedact(detectors, { field: 'message', withFlags: true });
    const flagSource = scriptSource(processors[processors.length - 1]);
    expect(flagSource).toContain("indexOf('<EMAIL>')");
    expect(flagSource).toContain("indexOf('<VISA>')");
  });

  it('structuralOnly restores the legacy single-redact shape', () => {
    const detectors = getDetectorsByIds(['email', 'visa']);
    const { processors } = compileCombinedRedact(detectors, {
      field: 'message',
      structuralOnly: true,
    });
    expect(processors).toHaveLength(1);
    const first = processors[0];
    if (!first || !('redact' in first) || !first.redact) {
      throw new Error('expected combined redact processor');
    }
    expect(first.redact.description).toMatch(/structural-only/i);
  });
});

describe('compileFromCategories', () => {
  it('compiles IPv4 detector to a combined redact processor', () => {
    const { processors } = compileFromCategories([{ id: 'ipv4', action: 'redact' }], {
      field: 'message',
    });
    expect(processors).toHaveLength(1);
    const first = processors[0];
    if (!first || !('redact' in first) || !first.redact) {
      throw new Error('expected combined redact processor');
    }
    expect(first.redact.patterns?.some((p) => p.includes('IPV4'))).toBe(true);
  });

  it('mixed IPv4 and credit-card: structural redact + Luhn confirmer', () => {
    const { processors } = compileFromCategories(
      [
        { id: 'ipv4', action: 'redact' },
        { id: 'credit-card', action: 'redact' },
      ],
      { field: 'message' }
    );
    expect(processors.some((p) => p && 'redact' in p)).toBe(true);
    expect(
      processors.some((p) => p && 'script' in p && p.script?.description?.match(/Luhn/i))
    ).toBe(true);
  });

  it('reports telemetry from hash script when withFlags is set', () => {
    const { processors } = compileFromCategories([{ id: 'credit-card', action: 'hash' }], {
      field: 'message',
      withFlags: true,
    });
    const hashProcessor = processors.find(
      (p) =>
        p &&
        'script' in p &&
        (p as { script: { description?: string } }).script.description?.includes('FNV-1a')
    );
    const source = scriptSource(hashProcessor);
    expect(source).toContain("'credit-card'");
  });

  it('honors partial action on visa with keyword defaults', () => {
    const { processors } = compileFromCategories(
      [{ ...visaRedact, action: 'partial', keepLast: 4 }],
      { field: 'message' }
    );
    expect(processors).toHaveLength(1);
    const source = scriptSource(processors[0]);
    expect(source).toContain('substring(cand.length() - 4');
    expect(source).not.toContain('sum % 10 == 0');
  });

  it('emits tag-only flag script with bounded-window detection for visa', () => {
    const { processors } = compileFromCategories([{ ...visaRedact, action: 'tag' }], {
      field: 'message',
      withFlags: true,
    });
    expect(processors).toHaveLength(1);
    const source = scriptSource(processors[0]);
    expect(source).toContain("cats.add('visa')");
    // Digit-boundary cards use the bounded-window matcher (lookingAt on a short window), not the
    // chunked `find()` matcher — that is what keeps them under the Painless regex limit.
    expect(source).toContain('lookingAt');
    expect(source).not.toContain('__slice');
    expect(source).not.toMatch(/^\s*\{ def tm/m);
  });

  it('emits tag-only flag script with keyword guard without map-literal braces', () => {
    const { processors } = compileFromCategories(
      [{ ...visaRedact, action: 'tag', useRecommendedKeywords: true }],
      { field: 'message', withFlags: true }
    );
    const source = scriptSource(processors[0]!);
    expect(source).toContain('lookingAt');
    expect(source).toContain('kwOk');
    expect(source).not.toContain('{ def tm');
  });

  it('emits regex-free ipv6 hash script instead of a Painless regex matcher', () => {
    const { processors } = compileFromCategories([{ id: 'ipv6', action: 'hash' }], {
      field: 'message',
      withFlags: true,
    });
    const hashProcessor = processors.find(
      (p) => p && 'script' in p && p.script?.description?.includes('Hash')
    );
    const source = scriptSource(hashProcessor);
    // Scans new-match starts up to the input-size cap (Spec 03), not the raw field length.
    expect(source).toContain('for (int i = 0; i < __scanLen; i++)');
    expect(source).toContain('int __scanLen = text.length() < 32768 ? text.length() : 32768');
    expect(source).toContain('StringBuilder out');
    expect(source).not.toContain('.matcher(');
  });

  it('emits chunked email hash script to stay under Painless regex scan limits', () => {
    const { processors } = compileFromCategories([{ id: 'email', action: 'hash' }], {
      field: 'message',
      withFlags: true,
    });
    const hashProcessor = processors.find(
      (p) => p && 'script' in p && p.script?.description?.includes('Hash')
    );
    const source = scriptSource(hashProcessor);
    expect(source).toContain('__slice');
    expect(source).toContain('__off = 0; __off < __scanLen; __off += 64');
  });

  it('caps per-candidate scanning at MAX_SCAN_CHARS and flags truncation when telemetry is on', () => {
    const { processors } = compileFromCategories([{ id: 'email', action: 'hash' }], {
      field: 'message',
      withFlags: true,
    });
    const source = scriptSource(
      processors.find((p) => p && 'script' in p && p.script?.description?.includes('Hash'))
    );
    expect(source).toContain('int __scanLen = text.length() < 32768 ? text.length() : 32768');
    // The un-scanned tail is still copied through unchanged by the existing final append.
    expect(source).toContain('out.append(text, last, text.length())');
    expect(source).toContain(
      "if (text.length() > __scanLen) { ctx['sensitive_data.truncated'] = true; }"
    );
  });

  it('does not emit a truncation flag when telemetry is off', () => {
    const { processors } = compileFromCategories([{ id: 'email', action: 'hash' }], {
      field: 'message',
      withFlags: false,
    });
    const source = scriptSource(
      processors.find((p) => p && 'script' in p && p.script?.description?.includes('Hash'))
    );
    expect(source).toContain('int __scanLen = text.length() < 32768 ? text.length() : 32768');
    expect(source).not.toContain('.truncated');
  });

  it('confirmCandidateRegex expands visa value capture and drops \\K', () => {
    const [visa, legacyCard] = getDetectorsByIds(['visa', 'credit-card']);
    expect(confirmCandidateRegex(visa)).toContain('4[ .-]?(?:[0-9]');
    expect(confirmCandidateRegex(legacyCard)).toContain('{12,18}');
  });

  it('applyKeywordOverride does not duplicate the built-in \\K anchor', () => {
    const [visa] = getDetectorsByIds(['visa']);
    const configured = applyKeywordOverride(visa, {
      id: 'visa',
      action: 'redact',
      keywords: ['card'],
      keywordProximity: 30,
    });
    expect(configured.detection.grokPatterns[0]).not.toContain('\\K\\K');
    expect(configured.detection.grokPatterns[0]).toMatch(/\\K%\{VISA:VISA\}$/);
  });

  it('skips unknown category ids with a warning', () => {
    const { processors, warnings } = compileFromCategories(
      [
        { id: 'not-a-detector', action: 'redact' },
        { id: 'email', action: 'redact' },
      ],
      { field: 'message' }
    );
    expect(warnings[0]).toMatch(/Unknown sensitive-data category "not-a-detector"/);
    expect(processors.some((p) => p && 'redact' in p)).toBe(true);
  });

  it('warns when keyword-gated categories have no keywords configured', () => {
    const { warnings } = compileFromCategories(
      [{ id: 'visa', action: 'redact', useRecommendedKeywords: false }],
      { field: 'message' }
    );
    expect(warnings.some((w) => w.includes('keyword proximity'))).toBe(true);
  });

  it('degrades unsupported tag on email to redact with warning', () => {
    const { processors, warnings } = compileFromCategories([{ id: 'email', action: 'tag' }], {
      field: 'message',
      withFlags: true,
    });
    expect(warnings[0]).toMatch(/action "tag" is not supported/);
    expect(processors.some((p) => p && 'redact' in p)).toBe(true);
  });

  it('uses default mask tokens in the flag script, not per-category overrides', () => {
    const { processors } = compileFromCategories(
      [
        { id: 'email', action: 'redact', maskToken: 'REDACTED' },
        { ...visaRedact, action: 'redact', maskToken: 'REDACTED' },
      ],
      { field: 'message', withFlags: true }
    );
    const flag = processors.find(
      (p) =>
        p &&
        typeof p === 'object' &&
        'script' in p &&
        (p as { script: { description?: string } }).script.description?.startsWith('Record ')
    );
    const flagSource = scriptSource(flag);
    expect(flagSource).toContain("indexOf('<EMAIL>')");
    expect(flagSource).not.toContain('REDACTED');
  });

  it('applies a custom mask token to email after telemetry detection', () => {
    const { processors } = compileFromCategories(
      [{ id: 'email', action: 'redact', maskToken: 'REDACTED' }],
      { field: 'message', withFlags: true }
    );
    expect(processors).toHaveLength(3);
    const rewriteSource = scriptSource(processors[processors.length - 1]);
    expect(rewriteSource).toContain(".replace('<EMAIL>', 'REDACTED')");
  });

  it('structuralOnly skips tag entries and emits a warning', () => {
    const { processors, warnings } = compileFromCategories(
      [
        { id: 'email', action: 'redact' },
        { ...visaRedact, action: 'tag' },
      ],
      { field: 'message', structuralOnly: true }
    );
    expect(processors).toHaveLength(1);
    expect(warnings.some((w) => w.includes('tag') && w.includes('visa'))).toBe(true);
  });

  it('structuralOnly promotes partial entries to full redact and emits a warning', () => {
    const { processors, warnings } = compileFromCategories(
      [{ ...visaRedact, action: 'partial', keepLast: 4 }],
      { field: 'message', structuralOnly: true }
    );
    expect(processors).toHaveLength(1);
    expect(processors[0] && 'redact' in processors[0]).toBe(true);
    expect(warnings.some((w) => w.includes('partial') && w.includes('visa'))).toBe(true);
  });

  it('structuralOnly promotes hash entries to full redact and emits a warning', () => {
    const { processors, warnings } = compileFromCategories(
      [{ id: 'credit-card', action: 'hash' }],
      { field: 'message', structuralOnly: true }
    );
    expect(processors).toHaveLength(1);
    expect(processors[0] && 'redact' in processors[0]).toBe(true);
    expect(warnings.some((w) => w.includes('hash') && w.includes('credit-card'))).toBe(true);
  });

  it('escapes single quotes in a custom maskToken for legacy credit-card confirm script', () => {
    const { processors } = compileFromCategories(
      [{ id: 'credit-card', action: 'redact', maskToken: "don't" }],
      { field: 'message' }
    );
    const source = scriptSource(processors[0]);
    expect(source).toContain("out += 'don\\'t'");
  });
});
