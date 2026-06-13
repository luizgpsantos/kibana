/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/**
 * Vendored from elastic-redact-pii/catalog/detectors/iban.json @ 972ad43 — local knowledge base,
 * not a Kibana build/test dependency. Keep in sync manually.
 *
 * Confirmed at ingest via a per-candidate mod-97 (ISO 7064) check; the precision guard is kept in
 * plain language for end users (no checksum jargon in the UI).
 */
export const ibanDetector = {
  id: 'iban',
  displayName: 'IBAN (bank account number)',
  description:
    'International Bank Account Numbers: a 2-letter country code, 2 check digits, then up to 30 alphanumeric characters. Confirmed with the ISO 7064 mod-97 checksum so random alphanumeric strings are not redacted.',
  categories: ['PII', 'Financial'],
  detection: {
    grokPatterns: ['%{IBAN:IBAN}'],
    grokPatternDefinitions: {
      IBAN: '(?<![A-Za-z0-9])(?:[A-Za-z]{2}[0-9]{2}[A-Za-z0-9]{11,30}|[A-Za-z]{2}[0-9]{2}(?: [A-Za-z0-9]{4})+(?: [A-Za-z0-9]{1,3})?)(?![A-Za-z0-9])',
    },
    validation: {
      type: 'mod97',
      appliesToField: 'IBAN',
    },
  },
  recommendedAction: 'remove',
  defaultPrecisionGuards: ['Redact IBANs (bank account numbers)'],
  anticipatoryAffinity: ['credit-card'],
};
