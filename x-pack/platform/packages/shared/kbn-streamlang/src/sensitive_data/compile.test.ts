/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { getDetectorsByIds } from './catalog';
import {
  compileCombinedRedact,
  compileFromCategories,
  confirmCandidateRegex,
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

describe('compileCombinedRedact (confirmed path)', () => {
  it('classifies detectors by checksum validation type', () => {
    const [dob, email, creditCard] = getDetectorsByIds(['date-of-birth', 'email', 'credit-card']);
    expect(isChecksum(dob)).toBe(false);
    expect(isChecksum(email)).toBe(false);
    expect(isChecksum(creditCard)).toBe(true);
    expect(captureName(dob)).toBe('DOB');
    expect(maskToken(email)).toBe('<EMAIL>');
    expect(maskToken(creditCard)).toBe('<CREDIT_CARD>');
  });

  it('emits ONE combined redact processor for structural-only detectors', () => {
    const detectors = getDetectorsByIds(['date-of-birth']);
    const { processors } = compileCombinedRedact(detectors, { field: 'message' });
    expect(processors).toHaveLength(1);
    const first = processors[0];
    if (!first || !('redact' in first) || !first.redact) {
      throw new Error('expected combined redact processor');
    }
    expect(first.redact.field).toBe('message');
    expect(first.redact.ignore_missing).toBe(true);
    expect(first.redact.patterns?.length).toBeGreaterThanOrEqual(1);
  });

  it('emits a per-candidate checksum confirmer for a checksum detector (no redact)', () => {
    const [creditCard] = getDetectorsByIds(['credit-card']);
    const { processors } = compileCombinedRedact([creditCard], { field: 'message' });
    expect(processors).toHaveLength(1);
    const first = processors[0];
    if (!first || !('script' in first) || !first.script) {
      throw new Error('expected a confirmer script processor');
    }
    expect(first.script.description).toMatch(/Luhn/i);
    const source = scriptSource(first);
    // Single-pass matcher over the field, replacing only confirmed candidates with the mask token.
    expect(source).toContain('.matcher(text)');
    expect(source).toContain('sum % 10 == 0');
    expect(source).toContain('multi');
    expect(source).toContain("out += '<CREDIT_CARD>'");
  });

  it('separates structural detectors (combined redact) from checksum confirmers, in order', () => {
    const detectors = getDetectorsByIds([
      'date-of-birth',
      'email',
      'credit-card',
      'iban',
      'us-ssn',
    ]);
    const { processors } = compileCombinedRedact(detectors, { field: 'message' });
    // One combined redact for the 3 structural detectors, then one confirmer per checksum detector.
    expect(processors).toHaveLength(3);
    const [combined, ccConfirm, ibanConfirm] = processors;
    expect(combined && 'redact' in combined).toBe(true);
    expect(ccConfirm && 'script' in ccConfirm).toBe(true);
    expect(scriptSource(ccConfirm)).toContain('sum % 10 == 0');
    expect(scriptSource(ibanConfirm)).toContain('rem == 1');
  });

  it('appends the telemetry flag script when withFlags is set', () => {
    const detectors = getDetectorsByIds(['date-of-birth', 'credit-card']);
    const { processors } = compileCombinedRedact(detectors, { field: 'message', withFlags: true });
    const confirmSource = scriptSource(processors[1]);
    const flagSource = scriptSource(processors[processors.length - 1]);
    expect(confirmSource).toContain("if (!__cats.contains('credit-card'))");
    expect(flagSource).toContain("indexOf('<DOB>')");
    expect(flagSource).not.toContain("cats.add('credit-card')");
    expect(flagSource).toContain('__existing');
  });

  it('writes telemetry flags under a nested namespace using a flat key', () => {
    const detectors = getDetectorsByIds(['date-of-birth', 'credit-card']);
    const { processors } = compileCombinedRedact(detectors, {
      field: 'attributes.body',
      withFlags: true,
      flagNamespace: 'attributes.sensitive_data',
    });
    const source = scriptSource(processors[processors.length - 1]);
    expect(source).toContain("def value = $('attributes.body', null)");
    expect(source).toContain("ctx['attributes.sensitive_data.detected'] = true");
    expect(source).toContain("ctx['attributes.sensitive_data.categories'] = cats");
  });

  it('reads and writes the target field with the flexible access helpers (dotted/flat keys)', () => {
    const [creditCard] = getDetectorsByIds(['credit-card']);
    const { processors } = compileCombinedRedact([creditCard], { field: 'attributes.body' });
    const source = scriptSource(processors[0]);
    expect(source).toContain("def value = $('attributes.body', null)");
    expect(source).toContain("ctx['attributes.body'] = out");
    // No raw ctx.<dotted> access that would break for flat-key/hyphenated fields.
    expect(source).not.toContain('ctx.attributes.body');
  });

  it('structuralOnly restores the legacy single-redact, pattern-only shape', () => {
    const detectors = getDetectorsByIds(['date-of-birth', 'credit-card']);
    const { processors } = compileCombinedRedact(detectors, {
      field: 'message',
      structuralOnly: true,
    });
    expect(processors).toHaveLength(1);
    const first = processors[0];
    if (!first || !('redact' in first) || !first.redact) {
      throw new Error('expected combined redact processor');
    }
    expect(first.redact.pattern_definitions?.CREDIT_CARD).toBeDefined();
    expect(first.redact.description).toMatch(/structural-only/i);
  });

  it('compileFromCategories honors partial action on a checksum detector', () => {
    const { processors } = compileFromCategories(
      [{ id: 'credit-card', action: 'partial', keepLast: 4 }],
      { field: 'message' }
    );
    expect(processors).toHaveLength(1);
    const source = scriptSource(processors[0]);
    expect(source).toContain('substring(cand.length() - 4');
    expect(source).toContain('sum % 10 == 0');
  });

  it('compileFromCategories emits tag-only flag script with regex detection', () => {
    const { processors } = compileFromCategories([{ id: 'credit-card', action: 'tag' }], {
      field: 'message',
      withFlags: true,
    });
    expect(processors).toHaveLength(1);
    const source = scriptSource(processors[0]);
    expect(source).toContain("cats.add('credit-card')");
    expect(source).toContain('.matcher(f)');
  });

  it('confirmCandidateRegex expands the value capture into a single group and drops \\K', () => {
    const [creditCard, usSsn] = getDetectorsByIds(['credit-card', 'us-ssn']);
    expect(confirmCandidateRegex(creditCard)).toContain('{12,18}');
    // us-ssn has a \K keyword prefix; it is dropped so group(1) is the value.
    expect(confirmCandidateRegex(usSsn)).not.toContain('\\K');
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

  it('degrades unsupported tag on email to redact with warning', () => {
    const { processors, warnings } = compileFromCategories([{ id: 'email', action: 'tag' }], {
      field: 'message',
      withFlags: true,
    });
    expect(warnings[0]).toMatch(/action "tag" is not supported/);
    expect(processors.some((p) => p && 'redact' in p)).toBe(true);
    const flagSource = scriptSource(processors[processors.length - 1]);
    expect(flagSource).not.toContain('.matcher(f)');
  });

  it('emits regex-based tag flags for credit-card tag-only', () => {
    const { processors, warnings } = compileFromCategories([{ id: 'credit-card', action: 'tag' }], {
      field: 'message',
      withFlags: true,
    });
    expect(warnings).toHaveLength(0);
    const source = scriptSource(processors[0]);
    expect(source).toContain('.matcher(f)');
    expect(source).toContain("cats.add('credit-card')");
    expect(source).toContain('__existing');
  });

  it('uses default mask tokens in the flag script, not per-category overrides', () => {
    const { processors } = compileFromCategories(
      [
        { id: 'email', action: 'redact', maskToken: 'REDACTED' },
        { id: 'credit-card', action: 'redact', maskToken: 'REDACTED' },
      ],
      { field: 'message', withFlags: true }
    );
    // The custom token is applied by a trailing rewrite; the flag script (telemetry) is identified
    // by its description and must still detect via the DEFAULT token.
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
    expect(flagSource).not.toContain("indexOf('<CREDIT_CARD>')");
  });

  it('self-reports partial transforms and skips them in the final flag script', () => {
    const { processors } = compileFromCategories(
      [{ id: 'credit-card', action: 'partial', keepLast: 4 }],
      { field: 'message', withFlags: true }
    );
    expect(processors).toHaveLength(2);
    const partialSource = scriptSource(processors[0]);
    const flagSource = scriptSource(processors[1]);
    expect(partialSource).toContain("if (!__cats.contains('credit-card'))");
    expect(flagSource).not.toContain('.matcher(f)');
    expect(flagSource).not.toContain("indexOf('<CREDIT_CARD>')");
  });

  it('applies a custom mask token to a structural detector after telemetry detection', () => {
    const { processors } = compileFromCategories(
      [{ id: 'email', action: 'redact', maskToken: 'REDACTED' }],
      { field: 'message', withFlags: true }
    );
    // combined redact -> flag script -> token rewrite (rewrite must run last)
    expect(processors).toHaveLength(3);
    const rewriteSource = scriptSource(processors[processors.length - 1]);
    expect(rewriteSource).toContain(".replace('<EMAIL>', 'REDACTED')");
    // Telemetry still keys off the DEFAULT token, which is present until the rewrite runs.
    const flagSource = scriptSource(processors[processors.length - 2]);
    expect(flagSource).toContain("indexOf('<EMAIL>')");
  });

  it('does not emit a token rewrite when the custom token equals the default', () => {
    const { processors } = compileFromCategories(
      [{ id: 'email', action: 'redact', maskToken: '<EMAIL>' }],
      { field: 'message' }
    );
    expect(processors).toHaveLength(1);
    expect('redact' in (processors[0] as object)).toBe(true);
  });

  it('uses the custom mask token as the partial-redaction prefix', () => {
    const { processors } = compileFromCategories(
      [{ id: 'credit-card', action: 'partial', keepLast: 4, maskToken: '##' }],
      { field: 'message' }
    );
    const source = scriptSource(processors[0]);
    expect(source).toContain("repl = '##' + cand.substring");
  });

  // --- Bug regression: confirmScript must escape single quotes in user-supplied maskToken ---

  it('escapes single quotes in a custom maskToken for the confirm script', () => {
    const { processors } = compileFromCategories(
      [{ id: 'credit-card', action: 'redact', maskToken: "don't" }],
      { field: 'message' }
    );
    const source = scriptSource(processors[0]);
    // Unescaped: out += 'don't'; → Painless syntax error. Escaped: out += 'don\'t';
    expect(source).toContain("out += 'don\\'t'");
    expect(source).not.toContain("out += 'don't'");
  });

  it('escapes backslashes in a custom maskToken for the confirm script', () => {
    const { processors } = compileFromCategories(
      [{ id: 'credit-card', action: 'redact', maskToken: 'C:\\secret' }],
      { field: 'message' }
    );
    const source = scriptSource(processors[0]);
    expect(source).toContain("out += 'C:\\\\secret'");
  });

  it('escapes single quotes in a custom maskToken for the IBAN confirm script', () => {
    const { processors } = compileFromCategories(
      [{ id: 'iban', action: 'redact', maskToken: "it's" }],
      { field: 'message' }
    );
    const source = scriptSource(processors[0]);
    expect(source).toContain("out += 'it\\'s'");
  });

  // --- Bug regression: structuralOnly must respect per-category action ---

  it('structuralOnly skips tag entries and emits a warning', () => {
    const { processors, warnings } = compileFromCategories(
      [
        { id: 'email', action: 'redact' },
        { id: 'credit-card', action: 'tag' },
      ],
      { field: 'message', structuralOnly: true }
    );
    // credit-card tag must be skipped; only email redact passes through
    expect(processors).toHaveLength(1);
    const first = processors[0];
    if (!first || !('redact' in first) || !first.redact) throw new Error('expected redact');
    // credit-card pattern should NOT appear — only email
    expect(first.redact.pattern_definitions?.CREDIT_CARD).toBeUndefined();
    expect(warnings.some((w) => w.includes('tag') && w.includes('credit-card'))).toBe(true);
  });

  it('structuralOnly with only tag entries produces an empty processor list and a warning', () => {
    const { processors, warnings } = compileFromCategories([{ id: 'credit-card', action: 'tag' }], {
      field: 'message',
      structuralOnly: true,
    });
    expect(processors).toHaveLength(0);
    expect(warnings.some((w) => w.includes('tag'))).toBe(true);
  });

  it('structuralOnly promotes partial entries to full redact and emits a warning', () => {
    const { processors, warnings } = compileFromCategories(
      [{ id: 'credit-card', action: 'partial', keepLast: 4 }],
      { field: 'message', structuralOnly: true }
    );
    // Must produce a combined structural redact (not a partial Painless script)
    expect(processors).toHaveLength(1);
    const first = processors[0];
    if (!first || !('redact' in first) || !first.redact) throw new Error('expected redact');
    expect(first.redact.pattern_definitions?.CREDIT_CARD).toBeDefined();
    expect(warnings.some((w) => w.includes('partial') && w.includes('credit-card'))).toBe(true);
  });

  it('structuralOnly with mixed actions: redacts only the redact entries, promotes partial, skips tag', () => {
    const { processors, warnings } = compileFromCategories(
      [
        { id: 'email', action: 'redact' },
        { id: 'credit-card', action: 'partial', keepLast: 4 },
        { id: 'iban', action: 'tag' },
      ],
      { field: 'message', structuralOnly: true }
    );
    // One combined redact covering email + promoted credit-card; iban tag skipped
    expect(processors).toHaveLength(1);
    const first = processors[0];
    if (!first || !('redact' in first) || !first.redact) throw new Error('expected redact');
    expect(first.redact.pattern_definitions?.CREDIT_CARD).toBeDefined();
    expect(first.redact.pattern_definitions?.IBAN).toBeUndefined();
    expect(warnings.some((w) => w.includes('partial'))).toBe(true);
    expect(warnings.some((w) => w.includes('tag'))).toBe(true);
  });
});
