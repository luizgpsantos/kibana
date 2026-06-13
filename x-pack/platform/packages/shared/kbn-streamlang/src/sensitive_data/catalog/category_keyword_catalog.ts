/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { SensitiveDataCategory } from '../../../types/processors';

/**
 * Keyword proximity metadata per active catalog detector.
 *
 * Email uses regex-only (no keyword gating needed); credit card and IBAN rely on ingest-time
 * checksum confirmation (Luhn/mod-97) rather than keyword gates. US SSN requires keyword
 * proximity to avoid false positives. Date of birth is keyword-gated (Elastic-catalog-only).
 */
export interface CategoryKeywordCatalogEntry {
  readonly requiresKeywordProximity: boolean;
  readonly recommendedKeywords: readonly string[];
  readonly defaultKeywordProximity: number;
}

const CATEGORY_KEYWORD_CATALOG: Readonly<Record<string, CategoryKeywordCatalogEntry>> = {
  'date-of-birth': {
    requiresKeywordProximity: true,
    recommendedKeywords: ['date of birth', 'd.o.b.', 'dob', 'birth date', 'born', 'born on'],
    defaultKeywordProximity: 15,
  },
  'us-ssn': {
    requiresKeywordProximity: true,
    recommendedKeywords: ['social security', 'ssn', 'ssns', 'ss#', 'soc sec', 'tax id'],
    defaultKeywordProximity: 20,
  },
};

export const requiresKeywordProximity = (categoryId: string): boolean =>
  CATEGORY_KEYWORD_CATALOG[categoryId]?.requiresKeywordProximity ?? false;

export const getCategoryKeywordCatalog = (
  categoryId: string
): CategoryKeywordCatalogEntry | undefined => CATEGORY_KEYWORD_CATALOG[categoryId];

export const getRecommendedKeywords = (categoryId: string): readonly string[] =>
  CATEGORY_KEYWORD_CATALOG[categoryId]?.recommendedKeywords ?? [];

export const getDefaultKeywordProximity = (categoryId: string): number | undefined =>
  CATEGORY_KEYWORD_CATALOG[categoryId]?.defaultKeywordProximity;

/** Toggle ON: persist catalog recommended tokens (overrides built-in grok prefix at compile). */
export const withRecommendedKeywords = (config: SensitiveDataCategory): SensitiveDataCategory => {
  const catalog = CATEGORY_KEYWORD_CATALOG[config.id];
  if (!catalog?.requiresKeywordProximity) {
    return config;
  }
  return {
    ...config,
    useRecommendedKeywords: true,
    keywords: [...catalog.recommendedKeywords],
    keywordProximity: catalog.defaultKeywordProximity,
  };
};

/** Toggle OFF: stop syncing catalog defaults; keep current keywords/proximity for manual edits. */
export const disableRecommendedKeywordsSync = (
  config: SensitiveDataCategory
): SensitiveDataCategory => ({
  ...config,
  useRecommendedKeywords: false,
});

/** Remove keyword overrides so compile uses the detector built-in `\K` prefix. */
export const omitKeywordOverrides = (config: SensitiveDataCategory): SensitiveDataCategory => {
  const { keywords, keywordProximity, useRecommendedKeywords, ...rest } = config;
  return rest;
};

/** @deprecated Use omitKeywordOverrides — spread-merge in forms failed to delete keyword fields. */
export const withoutKeywordOverrides = omitKeywordOverrides;

/** Default instance when adding from the library — keyword toggle starts OFF. */
export const buildDefaultCategoryConfig = (id: string): SensitiveDataCategory => ({
  id,
  action: 'redact',
});
