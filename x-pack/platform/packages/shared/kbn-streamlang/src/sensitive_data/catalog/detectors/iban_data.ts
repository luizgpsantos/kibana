/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

export const ibanDetector = {
  id: 'iban',
  displayName: 'IBAN (bank account number)',
  description:
    'International Bank Account Numbers: a 2-letter country code, 2 check digits, then up to 30 alphanumeric characters. Requires a nearby banking keyword within 30 characters.',
  categories: ['PII', 'Financial'],
  detection: {
    grokPatterns: ['\\K%{IBAN:IBAN}'],
    grokPatternDefinitions: {
      IBAN: '(?<![A-Za-z0-9])(?:[A-Za-z]{2}[0-9]{2}[A-Za-z0-9]{11,30}|[A-Za-z]{2}[0-9]{2}(?: [A-Za-z0-9]{4})+(?: [A-Za-z0-9]{1,3})?)(?![A-Za-z0-9])',
    },
    validation: {
      type: 'none',
    },
  },
  recommendedAction: 'remove',
  defaultPrecisionGuards: ['Only redact IBANs labeled nearby'],
  anticipatoryAffinity: ['visa', 'mastercard'],
};
