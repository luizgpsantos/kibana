/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { DEFAULT_FLAG_NAMESPACE, flattenSteps } from '@kbn/streamlang';
import type { ClassicFieldDefinitionConfig, FieldDefinitionConfig } from '@kbn/streams-schema';
import { Streams } from '@kbn/streams-schema';
import { isEqual } from 'lodash';
import { getSensitiveDataFlagNamespace } from './sensitive_data_flag_namespace';

const TELEMETRY_DETECTED_FIELD: ClassicFieldDefinitionConfig = { type: 'boolean' };
const TELEMETRY_CATEGORIES_FIELD: ClassicFieldDefinitionConfig = { type: 'keyword' };

export const getSensitiveDataTelemetryFieldPaths = (
  definition: Streams.all.Definition
): { detected: string; categories: string } => {
  const namespace = getSensitiveDataFlagNamespace(definition) ?? DEFAULT_FLAG_NAMESPACE;
  return {
    detected: `${namespace}.detected`,
    categories: `${namespace}.categories`,
  };
};

export const processingHasSensitiveDataTelemetry = (
  processing: Streams.ingest.all.Definition['ingest']['processing']
): boolean =>
  flattenSteps(processing.steps).some(
    (step) => step.action === 'sensitive_data' && (step.categories?.length ?? 0) > 0
  );

const mergeTelemetryFields = <T extends FieldDefinitionConfig>(
  target: Record<string, T> | undefined,
  paths: { detected: string; categories: string }
): Record<string, T> => {
  const merged = { ...(target ?? {}) };
  if (!merged[paths.detected]) {
    merged[paths.detected] = TELEMETRY_DETECTED_FIELD as T;
  }
  if (!merged[paths.categories]) {
    merged[paths.categories] = TELEMETRY_CATEGORIES_FIELD as T;
  }
  return merged;
};

/**
 * Ensures `sensitive_data` telemetry fields are declared in the stream schema whenever a
 * `sensitive_data` processor is configured, so mappings and the schema editor expose
 * `*.detected` and `*.categories` without waiting for simulation or live data.
 */
export const applySensitiveDataTelemetryFields = <T extends Streams.all.Definition>(
  definition: T
): T => {
  if (!Streams.ingest.all.Definition.is(definition)) {
    return definition;
  }

  if (!processingHasSensitiveDataTelemetry(definition.ingest.processing)) {
    return definition;
  }

  const paths = getSensitiveDataTelemetryFieldPaths(definition);

  if (Streams.ClassicStream.Definition.is(definition)) {
    const fieldOverrides = definition.ingest.classic.field_overrides;
    const merged = mergeTelemetryFields(fieldOverrides, paths);
    if (isEqual(merged, fieldOverrides ?? {})) {
      return definition;
    }
    return {
      ...definition,
      ingest: {
        ...definition.ingest,
        classic: {
          ...definition.ingest.classic,
          field_overrides: merged,
        },
      },
    };
  }

  if (Streams.WiredStream.Definition.is(definition)) {
    const fields = definition.ingest.wired.fields;
    const merged = mergeTelemetryFields(fields, paths);
    if (isEqual(merged, fields ?? {})) {
      return definition;
    }
    return {
      ...definition,
      ingest: {
        ...definition.ingest,
        wired: {
          ...definition.ingest.wired,
          fields: merged,
        },
      },
    };
  }

  return definition;
};
