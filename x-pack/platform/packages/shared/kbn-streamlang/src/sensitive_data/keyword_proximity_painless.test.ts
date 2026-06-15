/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { createDefaultCategoryConfig, getDetectorsByIds } from './catalog';
import { confirmCandidateRegex } from './confirm_candidate_regex';
import {
  detectorForScriptRegex,
  painlessKeywordProximityGuard,
} from './keyword_proximity_painless';

describe('keyword_proximity_painless', () => {
  it('uses the catalog detector without keyword prefix for script regex', () => {
    const [visa] = getDetectorsByIds(['visa']);
    const configured = createDefaultCategoryConfig('visa');
    const scriptDetector = detectorForScriptRegex(visa, configured);
    const withKeywords = confirmCandidateRegex(scriptDetector);
    expect(withKeywords).not.toMatch(/account number\|card/);
    expect(withKeywords.length).toBeLessThan(720);
  });

  it('emits a string lookback guard for recommended payment-card keywords', () => {
    const guard = painlessKeywordProximityGuard(createDefaultCategoryConfig('visa'), 'text', 'gs');
    expect(guard).toContain('boolean kwOk =');
    expect(guard).toContain('__kwWin.indexOf');
    expect(guard).not.toContain('Math.max');
  });
});
