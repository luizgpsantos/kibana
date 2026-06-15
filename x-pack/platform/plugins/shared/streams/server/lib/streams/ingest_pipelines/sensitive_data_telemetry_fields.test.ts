/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { Streams } from '@kbn/streams-schema';
import {
  applySensitiveDataTelemetryFields,
  getSensitiveDataTelemetryFieldPaths,
  processingHasSensitiveDataTelemetry,
} from './sensitive_data_telemetry_fields';

describe('sensitive_data telemetry fields', () => {
  const classicWithSensitiveData = (): Streams.ClassicStream.Definition => ({
    type: 'classic',
    name: 'logs-test-default',
    description: '',
    updated_at: new Date().toISOString(),
    ingest: {
      lifecycle: { inherit: {} },
      failure_store: { inherit: {} },
      settings: {},
      processing: {
        updated_at: new Date().toISOString(),
        steps: [
          {
            action: 'sensitive_data',
            from: 'message',
            categories: [{ id: 'visa', action: 'hash' }],
          },
        ],
      },
      classic: { field_overrides: {} },
    },
  });

  it('detects active sensitive_data processors', () => {
    const definition = classicWithSensitiveData();
    expect(processingHasSensitiveDataTelemetry(definition.ingest.processing)).toBe(true);
    expect(
      processingHasSensitiveDataTelemetry({
        ...definition.ingest.processing,
        steps: [],
      })
    ).toBe(false);
  });

  it('merges telemetry field overrides for classic streams', () => {
    const definition = classicWithSensitiveData();
    const merged = applySensitiveDataTelemetryFields(definition);
    const paths = getSensitiveDataTelemetryFieldPaths(definition);

    expect(merged.ingest.classic.field_overrides?.[paths.detected]).toEqual({ type: 'boolean' });
    expect(merged.ingest.classic.field_overrides?.[paths.categories]).toEqual({ type: 'keyword' });
  });

  it('uses attributes.sensitive_data for OTel wired streams', () => {
    const definition: Streams.WiredStream.Definition = {
      type: 'wired',
      name: 'logs.otel.nginx',
      description: '',
      updated_at: new Date().toISOString(),
      ingest: {
        lifecycle: { inherit: {} },
        failure_store: { inherit: {} },
        settings: {},
        processing: {
          updated_at: new Date().toISOString(),
          steps: [
            {
              action: 'sensitive_data',
              from: 'attributes.body',
              categories: [{ id: 'email', action: 'redact' }],
            },
          ],
        },
        wired: { fields: {}, routing: [] },
      },
    };

    const merged = applySensitiveDataTelemetryFields(definition);
    expect(merged.ingest.wired.fields['attributes.sensitive_data.detected']).toEqual({
      type: 'boolean',
    });
    expect(merged.ingest.wired.fields['attributes.sensitive_data.categories']).toEqual({
      type: 'keyword',
    });
  });

  it('does not overwrite existing field overrides', () => {
    const definition = classicWithSensitiveData();
    definition.ingest.classic.field_overrides = {
      'sensitive_data.detected': { type: 'boolean', description: 'custom' },
    };

    const merged = applySensitiveDataTelemetryFields(definition);
    expect(merged.ingest.classic.field_overrides?.['sensitive_data.detected']).toEqual({
      type: 'boolean',
      description: 'custom',
    });
    expect(merged.ingest.classic.field_overrides?.['sensitive_data.categories']).toEqual({
      type: 'keyword',
    });
  });
});
