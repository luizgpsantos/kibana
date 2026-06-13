/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { IngestProcessorContainer } from '@elastic/elasticsearch/lib/api/types';
import type { SensitiveDataProcessor } from '../../../../types/processors';
import { compileFromCategories } from '../../../sensitive_data/compile';

/** Ingest transpile output — `where` is already renamed to `if`; `customIdentifier` may be `tag`. */
export type SensitiveDataIngestProcessor = SensitiveDataProcessor & {
  tag?: string;
  if?: string;
};

/**
 * Attach the step's `tag`, compiled `if` (`where`) condition, and `description` to a generated
 * processor. A `sensitive_data` step expands to several processors (a structural `redact`, one
 * `confirmScript` per checksum detector, and the telemetry flag script). The condition must reach
 * every one of them — a checksum-only selection has no `redact`, so attaching only to `redact`
 * would silently drop the `where` and run the confirmers/flag script on all documents.
 */
const attachStepMetadata = (
  container: IngestProcessorContainer | undefined,
  processor: SensitiveDataIngestProcessor
): IngestProcessorContainer | undefined => {
  if (!container) {
    return container;
  }

  const { tag, if: ifCondition, description, ignore_failure } = processor;
  const metadata = {
    ...(tag !== undefined && { tag }),
    ...(ifCondition !== undefined && { if: ifCondition }),
    ...(description !== undefined && { description }),
    ...(ignore_failure !== undefined && { ignore_failure }),
  };

  if ('redact' in container && container.redact) {
    return { redact: { ...container.redact, ...metadata } };
  }
  if ('script' in container && container.script) {
    return { script: { ...container.script, ...metadata } };
  }
  return container;
};

export interface SensitiveDataProcessorOptions {
  /**
   * Dotted namespace for the telemetry flags. Streams pass `attributes.sensitive_data` for the OTel
   * convention; defaults to the ECS-style top-level `sensitive_data` custom field set.
   */
  flagNamespace?: string;
}

export const processSensitiveDataProcessor = (
  processor: SensitiveDataIngestProcessor,
  { flagNamespace }: SensitiveDataProcessorOptions = {}
): IngestProcessorContainer[] => {
  // Always emit the telemetry flag script: redacted documents get `<namespace>.detected` and
  // `<namespace>.categories`, so users can build dashboards from what the processor masks.
  // `structural_only` opts out of per-candidate checksum confirmation (pattern-only redaction).
  const { processors, warnings } = compileFromCategories(processor.categories, {
    field: processor.from,
    withFlags: true,
    flagNamespace,
    structuralOnly: processor.structural_only ?? false,
  });
  const compileNote = warnings.length ? warnings.join(' ') : undefined;
  const processorWithMetadata: SensitiveDataIngestProcessor = {
    ...processor,
    ...(compileNote && {
      description: [processor.description, compileNote].filter(Boolean).join(' | '),
    }),
  };
  return processors
    .map((p) => attachStepMetadata(p, processorWithMetadata))
    .filter((p): p is IngestProcessorContainer => p !== undefined);
};
