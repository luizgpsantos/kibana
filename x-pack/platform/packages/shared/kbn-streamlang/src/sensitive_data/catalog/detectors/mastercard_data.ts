/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { groupedDigitTail } from '../payment_card_pattern';

export const mastercardDetector = {
  id: 'mastercard',
  displayName: 'Mastercard number',
  description:
    'Mastercard payment card numbers (16 digits). Requires a nearby payment-card keyword within 30 characters.',
  categories: ['PCI DSS'],
  detection: {
    grokPatterns: ['\\K%{MASTERCARD:MASTERCARD}'],
    grokPatternDefinitions: {
      MASTERCARD: `(?<![0-9])(?:5[1-5]${groupedDigitTail(
        16,
        2
      )}|(?:222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)${groupedDigitTail(
        16,
        4
      )})(?![0-9])`,
    },
    validation: {
      type: 'none',
    },
  },
  recommendedAction: 'remove',
  defaultPrecisionGuards: ['Only redact Mastercard numbers labeled nearby'],
  anticipatoryAffinity: ['visa', 'amex'],
};
