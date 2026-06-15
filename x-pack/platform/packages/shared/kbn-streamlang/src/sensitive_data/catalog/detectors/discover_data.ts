/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { groupedDigitTail } from '../payment_card_pattern';

export const discoverDetector = {
  id: 'discover',
  displayName: 'Discover card number',
  description:
    'Discover payment card numbers (16 digits). Requires a nearby payment-card keyword within 30 characters.',
  categories: ['PCI DSS'],
  detection: {
    grokPatterns: ['\\K%{DISCOVER:DISCOVER}'],
    grokPatternDefinitions: {
      DISCOVER: `(?<![0-9])(?:6011${groupedDigitTail(16, 4)}|65${groupedDigitTail(
        16,
        2
      )}|64[4-9]${groupedDigitTail(16, 3)})(?![0-9])`,
    },
    validation: {
      type: 'none',
    },
  },
  recommendedAction: 'remove',
  defaultPrecisionGuards: ['Only redact Discover numbers labeled nearby'],
  anticipatoryAffinity: ['visa', 'mastercard'],
};
