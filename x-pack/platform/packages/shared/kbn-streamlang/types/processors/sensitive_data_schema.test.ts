/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import {
  normalizeSensitiveDataCategories,
  sensitiveDataProcessorSchema,
  isSensitiveDataProcessorDefinition,
  type SensitiveDataCategory,
} from '.';

describe('normalizeSensitiveDataCategories', () => {
  it('maps legacy string ids to redact instances', () => {
    expect(normalizeSensitiveDataCategories(['email', 'credit-card'])).toEqual([
      { id: 'email', action: 'redact' },
      { id: 'credit-card', action: 'redact' },
    ]);
  });

  it('maps legacy keyword-gated ids without pre-filled keywords (toggle OFF)', () => {
    expect(normalizeSensitiveDataCategories(['date-of-birth'])).toEqual([
      { id: 'date-of-birth', action: 'redact' },
    ]);
  });

  it('coerces legacy hash action to redact', () => {
    expect(
      normalizeSensitiveDataCategories([
        { id: 'credit-card', action: 'hash' },
      ] as unknown as SensitiveDataCategory[])
    ).toEqual([{ id: 'credit-card', action: 'redact' }]);
  });

  it('parses legacy hash action as redact', () => {
    const parsed = sensitiveDataProcessorSchema.parse({
      action: 'sensitive_data',
      from: 'message',
      categories: [{ id: 'email', action: 'hash' }],
    });
    expect(parsed.categories).toEqual([{ id: 'email', action: 'redact' }]);
  });

  it('passes through configured category objects', () => {
    const configured = [
      { id: 'email', action: 'tag' as const },
      { id: 'credit-card', action: 'partial' as const, keepLast: 4, maskToken: '<PAN>' },
    ];
    expect(normalizeSensitiveDataCategories(configured)).toEqual(configured);
  });
});

describe('sensitiveDataProcessorSchema', () => {
  it('accepts a valid configured selection', () => {
    const parsed = sensitiveDataProcessorSchema.parse({
      action: 'sensitive_data',
      from: 'message',
      categories: [{ id: 'date-of-birth', action: 'redact' }],
    });
    expect(parsed.categories).toEqual([{ id: 'date-of-birth', action: 'redact' }]);
  });

  it('upgrades legacy string[] categories on parse', () => {
    const parsed = sensitiveDataProcessorSchema.parse({
      action: 'sensitive_data',
      from: 'message',
      categories: ['date-of-birth', 'email'],
    });
    expect(parsed.categories).toEqual([
      { id: 'date-of-birth', action: 'redact' },
      { id: 'email', action: 'redact' },
    ]);
  });

  it('accepts per-category settings', () => {
    const parsed = sensitiveDataProcessorSchema.parse({
      action: 'sensitive_data',
      from: 'message',
      categories: [
        {
          id: 'credit-card',
          action: 'partial',
          keepLast: 4,
          maskToken: '<CARD>',
          keywords: ['pan', 'card'],
          keywordProximity: 30,
        },
      ],
    });
    expect(parsed.categories[0]).toMatchObject({
      id: 'credit-card',
      action: 'partial',
      keepLast: 4,
      maskToken: '<CARD>',
      keywords: ['pan', 'card'],
      keywordProximity: 30,
    });
  });

  it('rejects an empty category selection', () => {
    expect(() =>
      sensitiveDataProcessorSchema.parse({
        action: 'sensitive_data',
        from: 'message',
        categories: [],
      })
    ).toThrow();
  });

  it('narrows via the type guard', () => {
    const step = {
      action: 'sensitive_data' as const,
      from: 'message',
      categories: [{ id: 'date-of-birth', action: 'redact' as const }],
    };
    expect(isSensitiveDataProcessorDefinition(step)).toBe(true);
    expect(isSensitiveDataProcessorDefinition({ action: 'grok', from: 'a', patterns: ['x'] })).toBe(
      false
    );
  });
});
