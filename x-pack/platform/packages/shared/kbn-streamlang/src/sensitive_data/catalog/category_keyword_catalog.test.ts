/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import {
  buildDefaultCategoryConfig,
  createDefaultCategoryConfig,
  disableRecommendedKeywordsSync,
  listCatalogCategories,
  omitKeywordOverrides,
  requiresKeywordProximity,
  withRecommendedKeywords,
  PAYMENT_CARD_NETWORK_IDS,
} from '.';

describe('category keyword catalog', () => {
  it('marks payment cards, iban, and us-ssn as keyword-gated', () => {
    for (const id of [...PAYMENT_CARD_NETWORK_IDS, 'iban', 'us-ssn']) {
      expect(requiresKeywordProximity(id)).toBe(true);
    }
    expect(requiresKeywordProximity('email')).toBe(false);
    expect(requiresKeywordProximity('date-of-birth')).toBe(false);
  });

  it('starts keyword-gated categories with recommended keywords enabled', () => {
    expect(createDefaultCategoryConfig('visa')).toMatchObject({
      id: 'visa',
      action: 'redact',
      useRecommendedKeywords: true,
      keywordProximity: 30,
      keywords: expect.arrayContaining(['card', 'visa']),
    });
    expect(createDefaultCategoryConfig('email')).toEqual({
      id: 'email',
      action: 'redact',
    });
  });

  it('withRecommendedKeywords applies catalog defaults for us-ssn', () => {
    expect(withRecommendedKeywords(buildDefaultCategoryConfig('us-ssn'))).toMatchObject({
      useRecommendedKeywords: true,
      keywords: expect.arrayContaining(['social security', 'ssn']),
      keywordProximity: 30,
    });
  });

  it('disableRecommendedKeywordsSync keeps keywords but stops recommended sync', () => {
    const synced = withRecommendedKeywords(buildDefaultCategoryConfig('iban'));
    expect(disableRecommendedKeywordsSync(synced)).toMatchObject({
      useRecommendedKeywords: false,
      keywords: synced.keywords,
      keywordProximity: 30,
    });
  });

  it('omitKeywordOverrides clears keywords for compile', () => {
    expect(
      omitKeywordOverrides({
        id: 'visa',
        action: 'redact',
        useRecommendedKeywords: true,
        keywords: ['card'],
        keywordProximity: 30,
      })
    ).toEqual({
      id: 'visa',
      action: 'redact',
    });
  });

  it('exposes keyword metadata on listCatalogCategories', () => {
    const byId = new Map(listCatalogCategories().map((c) => [c.id, c]));
    expect(byId.get('email')).toMatchObject({
      requiresKeywordProximity: false,
      recommendedKeywords: [],
    });
    expect(byId.get('visa')).toMatchObject({
      requiresKeywordProximity: true,
      defaultKeywordProximity: 30,
      recommendedKeywords: expect.arrayContaining(['visa', 'card']),
    });
  });
});
