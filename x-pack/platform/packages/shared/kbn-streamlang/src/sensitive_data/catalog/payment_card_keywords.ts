/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/** Shared proximity keywords for payment-card network detectors (library default). */
export const SHARED_PAYMENT_CARD_KEYWORDS = [
  'account number',
  'card',
  'cc #',
  'ccn',
  'credit',
  'dankort',
  'debit',
  'pan',
  'pcn',
  'union pay',
] as const;

export const paymentCardKeywords = (...networkTokens: readonly string[]): readonly string[] => [
  ...SHARED_PAYMENT_CARD_KEYWORDS,
  ...networkTokens,
];

/** Active payment-card network detector ids (replaces legacy `credit-card` in the active set). */
export const PAYMENT_CARD_NETWORK_IDS = [
  'visa',
  'mastercard',
  'amex',
  'discover',
  'diners',
  'jcb',
  'maestro',
] as const;

export type PaymentCardNetworkId = (typeof PAYMENT_CARD_NETWORK_IDS)[number];

/** Default keyword proximity for payment-card rules (characters before the match). */
export const PAYMENT_CARD_KEYWORD_PROXIMITY = 30;
