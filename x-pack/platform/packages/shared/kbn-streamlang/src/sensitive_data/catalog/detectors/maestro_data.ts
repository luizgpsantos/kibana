/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { groupedDigitTailRange } from '../payment_card_pattern';

export const maestroDetector = {
  id: 'maestro',
  displayName: 'Maestro card number',
  description:
    'Maestro payment card numbers (12–19 digits). Requires a nearby payment-card keyword within 30 characters.',
  categories: ['PCI DSS'],
  detection: {
    grokPatterns: ['\\K%{MAESTRO:MAESTRO}'],
    grokPatternDefinitions: {
      MAESTRO: `(?<![0-9])(?:6304|6759|676[123])${groupedDigitTailRange(4, 12, 19)}(?![0-9])`,
    },
    validation: {
      type: 'none',
    },
  },
  recommendedAction: 'remove',
  defaultPrecisionGuards: ['Only redact Maestro numbers labeled nearby'],
  anticipatoryAffinity: ['visa', 'mastercard'],
};
