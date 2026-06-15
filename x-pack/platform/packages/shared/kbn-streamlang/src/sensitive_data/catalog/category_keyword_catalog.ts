/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { SensitiveDataCategory } from '../../../types/processors';
import {
  PAYMENT_CARD_KEYWORD_PROXIMITY,
  PAYMENT_CARD_NETWORK_IDS,
  paymentCardKeywords,
} from './payment_card_keywords';

/**
 * Keyword proximity metadata per catalog detector.
 *
 * Payment-card networks, IBAN, and US SSN require keyword proximity by default. Email is
 * pattern-only.
 */
export interface CategoryKeywordCatalogEntry {
  readonly requiresKeywordProximity: boolean;
  readonly recommendedKeywords: readonly string[];
  readonly defaultKeywordProximity: number;
}

const IBAN_KEYWORDS = [
  'account code',
  'account number',
  'accountno#',
  'accountnumber#',
  'bank account',
  'bank acct',
  'bban',
  'checking account',
  'checking acct',
  'chequing account',
  'chequing acct',
  'customer account id',
  'deposit account',
  'deposit acct',
  'iban',
  'savings account',
  'savings acct',
  'sepa',
] as const;

const PAYMENT_CARD_KEYWORD_ENTRIES: Readonly<Record<string, CategoryKeywordCatalogEntry>> =
  Object.fromEntries(
    PAYMENT_CARD_NETWORK_IDS.map((id) => {
      const networkTokens: Record<string, readonly string[]> = {
        visa: paymentCardKeywords('electron', 'visa'),
        mastercard: paymentCardKeywords('mastercard', 'mc'),
        amex: paymentCardKeywords('american express', 'amex'),
        discover: paymentCardKeywords('discover'),
        diners: paymentCardKeywords('diners club', 'mastercard', 'mc'),
        jcb: paymentCardKeywords('jcb'),
        maestro: paymentCardKeywords('mastercard', 'mc'),
      };
      return [
        id,
        {
          requiresKeywordProximity: true,
          recommendedKeywords: networkTokens[id] ?? paymentCardKeywords(),
          defaultKeywordProximity: PAYMENT_CARD_KEYWORD_PROXIMITY,
        },
      ];
    })
  );

const CATEGORY_KEYWORD_CATALOG: Readonly<Record<string, CategoryKeywordCatalogEntry>> = {
  ...PAYMENT_CARD_KEYWORD_ENTRIES,
  iban: {
    requiresKeywordProximity: true,
    recommendedKeywords: IBAN_KEYWORDS,
    defaultKeywordProximity: PAYMENT_CARD_KEYWORD_PROXIMITY,
  },
  'us-ssn': {
    requiresKeywordProximity: true,
    recommendedKeywords: ['social security', 'ssn'],
    defaultKeywordProximity: PAYMENT_CARD_KEYWORD_PROXIMITY,
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

/** Default instance when adding from the library — keyword-gated categories include recommended keywords. */
export const buildDefaultCategoryConfig = (id: string): SensitiveDataCategory => {
  const base: SensitiveDataCategory = { id, action: 'redact' };
  if (requiresKeywordProximity(id)) {
    return withRecommendedKeywords(base);
  }
  return base;
};
