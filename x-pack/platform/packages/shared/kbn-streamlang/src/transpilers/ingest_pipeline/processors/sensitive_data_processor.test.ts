/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { processSensitiveDataProcessor } from './sensitive_data_processor';

describe('processSensitiveDataProcessor', () => {
  it('expands structural categories into a combined redact plus the telemetry flag script', () => {
    const processors = processSensitiveDataProcessor({
      action: 'sensitive_data',
      from: 'attributes.body',
      categories: [{ id: 'date-of-birth', action: 'redact' }],
    });
    const redact = processors.find((p) => p && 'redact' in p);
    expect(redact).toBeDefined();
    if (!redact || !('redact' in redact) || !redact.redact) {
      throw new Error('expected redact processor');
    }
    expect(redact.redact.field).toBe('attributes.body');

    // The saved pipeline always emits the telemetry flag script for dashboards.
    const scripts = processors.filter(
      (p): p is { script: { source: string } } => !!p && 'script' in p
    );
    expect(scripts).toHaveLength(1);
    expect(scripts[0].script.source).toContain("ctx['sensitive_data.detected'] = true");
  });

  it('emits a per-candidate confirmer for checksum categories alongside the flag script', () => {
    const processors = processSensitiveDataProcessor({
      action: 'sensitive_data',
      from: 'message',
      categories: [{ id: 'credit-card', action: 'redact' }],
    });
    const scripts = processors.filter(
      (p): p is { script: { source: string; description?: string } } => !!p && 'script' in p
    );
    // One Luhn confirmer + one flag script; no structural redact for a checksum-only selection.
    expect(scripts).toHaveLength(2);
    expect(processors.some((p) => p && 'redact' in p)).toBe(false);
    expect(scripts.some((s) => /Luhn/i.test(s.script.description ?? ''))).toBe(true);
  });

  it('writes telemetry flags under the provided namespace (OTel attributes.*)', () => {
    const processors = processSensitiveDataProcessor(
      {
        action: 'sensitive_data',
        from: 'attributes.body',
        categories: [{ id: 'date-of-birth', action: 'redact' }],
      },
      { flagNamespace: 'attributes.sensitive_data' }
    );
    const scripts = processors.filter(
      (p): p is { script: { source: string } } => !!p && 'script' in p
    );
    expect(scripts[scripts.length - 1].script.source).toContain(
      "ctx['attributes.sensitive_data.detected'] = true"
    );
  });

  it('honors structural_only by skipping per-candidate confirmers (pattern-only redaction)', () => {
    const processors = processSensitiveDataProcessor({
      action: 'sensitive_data',
      from: 'message',
      categories: [{ id: 'credit-card', action: 'redact' }],
      structural_only: true,
    });
    const redact = processors.find((p) => p && 'redact' in p);
    expect(redact).toBeDefined();
    const scripts = processors.filter(
      (p): p is { script: { source: string; description?: string } } => !!p && 'script' in p
    );
    // Only the telemetry flag script — no Luhn confirmer in structural-only mode.
    expect(scripts).toHaveLength(1);
    expect(scripts[0].script.source).toContain("ctx['sensitive_data.detected'] = true");
  });

  it('propagates processor tag and if to the compiled redact (required for simulation metrics)', () => {
    const processors = processSensitiveDataProcessor({
      action: 'sensitive_data',
      from: 'message',
      categories: [{ id: 'date-of-birth', action: 'redact' }],
      tag: 'sensitive-data-step-1',
      if: 'ctx.message != null',
    });

    const redact = processors.find((p) => p && 'redact' in p);
    expect(redact).toBeDefined();
    if (!redact || !('redact' in redact) || !redact.redact) {
      throw new Error('expected redact processor');
    }
    expect(redact.redact.tag).toBe('sensitive-data-step-1');
    expect(redact.redact.if).toBe('ctx.message != null');
  });

  it('propagates ignore_failure to every compiled processor', () => {
    const processors = processSensitiveDataProcessor({
      action: 'sensitive_data',
      from: 'message',
      categories: [
        { id: 'date-of-birth', action: 'redact' },
        { id: 'credit-card', action: 'redact' },
      ],
      ignore_failure: true,
    });

    for (const p of processors) {
      if (p && 'redact' in p && p.redact) {
        expect(p.redact.ignore_failure).toBe(true);
      }
      if (p && 'script' in p && p.script) {
        expect(p.script.ignore_failure).toBe(true);
      }
    }
  });

  it('propagates tag and if to EVERY processor, including a checksum-only selection', () => {
    // Checksum-only selection: no structural redact, so the condition must reach the confirmer
    // and the flag script or it would silently run on every document.
    const processors = processSensitiveDataProcessor({
      action: 'sensitive_data',
      from: 'message',
      categories: [{ id: 'credit-card', action: 'redact' }],
      tag: 'sensitive-data-step-1',
      if: 'ctx.message != null',
    });

    expect(processors.some((p) => p && 'redact' in p)).toBe(false);
    const scripts = processors.filter(
      (p): p is { script: { source: string; if?: string; tag?: string } } => !!p && 'script' in p
    );
    expect(scripts).toHaveLength(2);
    for (const s of scripts) {
      expect(s.script.if).toBe('ctx.message != null');
      expect(s.script.tag).toBe('sensitive-data-step-1');
    }
  });
});
