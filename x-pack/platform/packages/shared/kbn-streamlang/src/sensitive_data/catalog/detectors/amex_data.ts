/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { groupedDigitTail } from '../payment_card_pattern';

export const amexDetector = {
  id: 'amex',
  displayName: 'American Express card number',
  description:
    'American Express payment card numbers (15 digits). Requires a nearby payment-card keyword within 30 characters.',
  categories: ['PCI DSS'],
  detection: {
    grokPatterns: ['\\K%{AMEX:AMEX}'],
    grokPatternDefinitions: {
      AMEX: `(?<![0-9])3[47]${groupedDigitTail(15, 2)}(?![0-9])`,
    },
    validation: {
      type: 'none',
    },
  },
  recommendedAction: 'remove',
  defaultPrecisionGuards: ['Only redact American Express numbers labeled nearby'],
  anticipatoryAffinity: ['visa', 'mastercard'],
};
