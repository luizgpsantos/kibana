/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { groupedDigitTail } from '../payment_card_pattern';

export const dinersDetector = {
  id: 'diners',
  displayName: 'Diners Club card number',
  description:
    'Diners Club payment card numbers (14 digits). Requires a nearby payment-card keyword within 30 characters.',
  categories: ['PCI DSS'],
  detection: {
    grokPatterns: ['\\K%{DINERS:DINERS}'],
    grokPatternDefinitions: {
      DINERS: `(?<![0-9])(?:3(?:0[0-5]|[68][0-9])${groupedDigitTail(
        14,
        3
      )}|3[0689]${groupedDigitTail(14, 2)})(?![0-9])`,
    },
    validation: {
      type: 'none',
    },
  },
  recommendedAction: 'remove',
  defaultPrecisionGuards: ['Only redact Diners Club numbers labeled nearby'],
  anticipatoryAffinity: ['visa', 'mastercard'],
};
