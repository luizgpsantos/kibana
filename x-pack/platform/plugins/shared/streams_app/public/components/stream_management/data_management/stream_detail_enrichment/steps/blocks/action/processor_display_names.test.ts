/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { getProcessorDisplayName } from './processor_display_names';

describe('getProcessorDisplayName', () => {
  it('returns the type-selector label for sensitive_data', () => {
    expect(getProcessorDisplayName('sensitive_data')).toBe('Sensitive Data');
  });

  it('returns the type-selector label for grok', () => {
    expect(getProcessorDisplayName('grok')).toBe('Grok');
  });

  it('humanizes unknown processor ids', () => {
    expect(getProcessorDisplayName('custom_thing')).toBe('Custom Thing');
  });

  it('includes manual pipeline on non-wired streams', () => {
    expect(getProcessorDisplayName('manual_ingest_pipeline', false)).toBe(
      'Manual pipeline configuration'
    );
    expect(getProcessorDisplayName('manual_ingest_pipeline', true)).toBe('Manual Ingest Pipeline');
  });
});
