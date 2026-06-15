/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { groupedDigitTailRange } from '../payment_card_pattern';

export const visaDetector = {
  id: 'visa',
  displayName: 'Visa card number',
  description:
    'Visa payment card numbers (13, 16, or 19 digits). Requires a nearby payment-card keyword within 30 characters.',
  categories: ['PCI DSS'],
  detection: {
    grokPatterns: ['\\K%{VISA:VISA}'],
    grokPatternDefinitions: {
      VISA: `(?<![0-9])4${groupedDigitTailRange(1, 13, 19)}(?![0-9])`,
    },
    validation: {
      type: 'none',
    },
  },
  recommendedAction: 'remove',
  defaultPrecisionGuards: ['Only redact Visa numbers labeled nearby'],
  anticipatoryAffinity: ['mastercard', 'amex', 'iban'],
};
