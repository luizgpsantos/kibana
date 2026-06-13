/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/**
 * Vendored from elastic-redact-pii/catalog/detectors/credit-card.json @ 972ad43 — local knowledge
 * base, not a Kibana build/test dependency. Keep in sync manually.
 *
 * Plan 6 confirms candidates at ingest with a per-candidate Luhn checksum (see compile.ts
 * `confirmScript`). The precision guard is kept in plain language for end users — no Luhn jargon.
 */
export const creditCardDetector = {
  id: 'credit-card',
  displayName: 'Credit card number',
  description:
    'Payment card numbers (PAN), 13-19 digits, optionally separated by spaces, dashes, or dots. Confirmed with the Luhn checksum so random digit strings are not redacted.',
  categories: ['PCI DSS'],
  detection: {
    grokPatterns: ['%{CREDIT_CARD:CREDIT_CARD}'],
    grokPatternDefinitions: {
      CREDIT_CARD: '(?<![0-9])(?:[0-9][ .-]?){12,18}[0-9](?![0-9])',
    },
    validation: {
      type: 'luhn',
      appliesToField: 'CREDIT_CARD',
    },
  },
  recommendedAction: 'remove',
  defaultPrecisionGuards: ['Redact credit card numbers'],
  anticipatoryAffinity: ['iban'],
};
