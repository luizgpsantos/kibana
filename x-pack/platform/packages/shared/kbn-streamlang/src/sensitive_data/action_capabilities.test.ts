/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { detectorHasValueCapture, getSupportedActionsForCategory } from './action_capabilities';
import { getDetectorsByIds } from './catalog';

describe('action capabilities', () => {
  it('limits email and network detectors to full redact (no value capture for tag/partial)', () => {
    const [email, ipv4] = getDetectorsByIds(['email', 'ipv4']);
    expect(detectorHasValueCapture(email)).toBe(false);
    expect(detectorHasValueCapture(ipv4)).toBe(false);
    expect(getSupportedActionsForCategory('email')).toEqual(['redact']);
    expect(getSupportedActionsForCategory('ipv4')).toEqual(['redact']);
    expect(getSupportedActionsForCategory('mac-address')).toEqual(['redact', 'partial', 'tag']);
  });

  it('allows all actions for keyword-gated detectors with value capture', () => {
    expect(getSupportedActionsForCategory('visa')).toEqual(['redact', 'partial', 'tag']);
    expect(getSupportedActionsForCategory('us-ssn')).toEqual(['redact', 'partial', 'tag']);
    expect(getSupportedActionsForCategory('credit-card')).toEqual(['redact', 'partial', 'tag']);
  });
});
