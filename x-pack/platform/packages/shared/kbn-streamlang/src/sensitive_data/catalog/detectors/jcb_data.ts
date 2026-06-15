/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { groupedDigitTail } from '../payment_card_pattern';

export const jcbDetector = {
  id: 'jcb',
  displayName: 'JCB card number',
  description:
    'JCB payment card numbers (16 digits). Requires a nearby payment-card keyword within 30 characters.',
  categories: ['PCI DSS'],
  detection: {
    grokPatterns: ['\\K%{JCB:JCB}'],
    grokPatternDefinitions: {
      JCB: `(?<![0-9])35(?:2[89]|[3-8][0-9])${groupedDigitTail(16, 4)}(?![0-9])`,
    },
    validation: {
      type: 'none',
    },
  },
  recommendedAction: 'remove',
  defaultPrecisionGuards: ['Only redact JCB numbers labeled nearby'],
  anticipatoryAffinity: ['visa', 'mastercard'],
};
