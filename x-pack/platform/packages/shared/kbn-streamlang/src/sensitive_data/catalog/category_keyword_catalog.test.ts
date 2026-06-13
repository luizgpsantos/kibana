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
} from '.';

describe('category keyword catalog', () => {
  it('marks only DOB and US SSN as keyword-gated', () => {
    expect(requiresKeywordProximity('date-of-birth')).toBe(true);
    expect(requiresKeywordProximity('us-ssn')).toBe(true);
    expect(requiresKeywordProximity('email')).toBe(false);
    expect(requiresKeywordProximity('credit-card')).toBe(false);
    expect(requiresKeywordProximity('iban')).toBe(false);
  });

  it('starts new categories without keyword overrides (toggle OFF)', () => {
    expect(createDefaultCategoryConfig('date-of-birth')).toEqual({
      id: 'date-of-birth',
      action: 'redact',
    });
    expect(createDefaultCategoryConfig('email')).toEqual({
      id: 'email',
      action: 'redact',
    });
  });

  it('withRecommendedKeywords applies catalog defaults', () => {
    expect(withRecommendedKeywords(buildDefaultCategoryConfig('us-ssn'))).toMatchObject({
      useRecommendedKeywords: true,
      keywords: expect.arrayContaining(['social security', 'ssn']),
      keywordProximity: 20,
    });
  });

  it('disableRecommendedKeywordsSync keeps keywords but stops recommended sync', () => {
    const synced = withRecommendedKeywords(buildDefaultCategoryConfig('date-of-birth'));
    expect(disableRecommendedKeywordsSync(synced)).toMatchObject({
      useRecommendedKeywords: false,
      keywords: synced.keywords,
      keywordProximity: 15,
    });
  });

  it('omitKeywordOverrides clears keywords for built-in grok', () => {
    expect(
      omitKeywordOverrides({
        id: 'date-of-birth',
        action: 'redact',
        useRecommendedKeywords: true,
        keywords: ['dob'],
        keywordProximity: 15,
      })
    ).toEqual({
      id: 'date-of-birth',
      action: 'redact',
    });
  });

  it('exposes keyword metadata on listCatalogCategories', () => {
    const byId = new Map(listCatalogCategories().map((c) => [c.id, c]));
    expect(byId.get('email')).toMatchObject({
      requiresKeywordProximity: false,
      recommendedKeywords: [],
    });
    expect(byId.get('date-of-birth')).toMatchObject({
      requiresKeywordProximity: true,
      defaultKeywordProximity: 15,
      recommendedKeywords: expect.arrayContaining(['dob']),
    });
  });
});
