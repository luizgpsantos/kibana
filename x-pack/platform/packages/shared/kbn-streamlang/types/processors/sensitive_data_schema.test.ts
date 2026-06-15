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
import { PAYMENT_CARD_NETWORK_IDS } from '../../src/sensitive_data/catalog/payment_card_keywords';

describe('normalizeSensitiveDataCategories', () => {
  it('maps legacy credit-card to all payment-card networks with keywords', () => {
    const normalized = normalizeSensitiveDataCategories(['email', 'credit-card']);
    expect(normalized[0]).toEqual({ id: 'email', action: 'redact' });
    expect(normalized.slice(1)).toHaveLength(PAYMENT_CARD_NETWORK_IDS.length);
    expect(normalized.slice(1).every((c) => c.useRecommendedKeywords === true)).toBe(true);
  });

  it('drops legacy date-of-birth ids', () => {
    expect(normalizeSensitiveDataCategories(['date-of-birth'])).toEqual([]);
    expect(normalizeSensitiveDataCategories(['date-of-birth', 'email'])).toEqual([
      { id: 'email', action: 'redact' },
    ]);
  });

  it('expands legacy credit-card objects to network instances', () => {
    const expanded = normalizeSensitiveDataCategories([
      { id: 'credit-card', action: 'partial', keepLast: 4, maskToken: '<PAN>' },
    ]);
    expect(expanded).toHaveLength(PAYMENT_CARD_NETWORK_IDS.length);
    expect(expanded[0]).toMatchObject({
      id: 'visa',
      action: 'partial',
      keepLast: 4,
      maskToken: '<PAN>',
      useRecommendedKeywords: true,
    });
  });

  it('coerces legacy hash action to redact when expanding credit-card', () => {
    const expanded = normalizeSensitiveDataCategories([
      { id: 'credit-card', action: 'hash' },
    ] as unknown as SensitiveDataCategory[]);
    expect(expanded.every((c) => c.action === 'redact')).toBe(true);
  });

  it('passes through configured category objects', () => {
    const configured = [{ id: 'email', action: 'tag' as const }];
    expect(normalizeSensitiveDataCategories(configured)).toEqual(configured);
  });

  it('adds recommended keywords to legacy iban configs without keywords', () => {
    const [iban] = normalizeSensitiveDataCategories([{ id: 'iban', action: 'redact' }]);
    expect(iban).toMatchObject({
      id: 'iban',
      useRecommendedKeywords: true,
      keywordProximity: 30,
    });
  });
});

describe('sensitiveDataProcessorSchema', () => {
  it('accepts a valid configured selection', () => {
    const parsed = sensitiveDataProcessorSchema.parse({
      action: 'sensitive_data',
      from: 'message',
      categories: [
        {
          id: 'visa',
          action: 'redact',
          useRecommendedKeywords: true,
          keywords: ['card', 'visa'],
          keywordProximity: 30,
        },
      ],
    });
    expect(parsed.categories[0].id).toBe('visa');
  });

  it('upgrades legacy string[] categories on parse', () => {
    const parsed = sensitiveDataProcessorSchema.parse({
      action: 'sensitive_data',
      from: 'message',
      categories: ['credit-card', 'email'],
    });
    expect(parsed.categories.filter((c) => c.id === 'email')).toEqual([
      { id: 'email', action: 'redact' },
    ]);
    expect(
      parsed.categories.filter((c) =>
        PAYMENT_CARD_NETWORK_IDS.includes(c.id as (typeof PAYMENT_CARD_NETWORK_IDS)[number])
      )
    ).toHaveLength(7);
  });

  it('accepts per-category settings', () => {
    const parsed = sensitiveDataProcessorSchema.parse({
      action: 'sensitive_data',
      from: 'message',
      categories: [
        {
          id: 'visa',
          action: 'partial',
          keepLast: 4,
          maskToken: '<PAN>',
          keywords: ['card'],
          keywordProximity: 30,
        },
      ],
    });
    expect(parsed.categories[0]).toMatchObject({
      id: 'visa',
      action: 'partial',
      keepLast: 4,
    });
  });

  it('isSensitiveDataProcessorDefinition narrows sensitive_data steps', () => {
    expect(
      isSensitiveDataProcessorDefinition({
        action: 'sensitive_data',
        from: 'message',
        categories: [{ id: 'email', action: 'redact' }],
      })
    ).toBe(true);
  });
});
