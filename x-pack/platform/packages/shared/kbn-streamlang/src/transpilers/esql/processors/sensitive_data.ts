/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { ESQLAstCommand } from '@elastic/esql/types';
import type { RedactProcessor, SensitiveDataProcessor } from '../../../../types/processors';
import { getDetectorById } from '../../../sensitive_data/catalog';
import { applyKeywordOverride } from '../../../sensitive_data/compile';
import { convertRedactProcessorToESQL } from './redact';

/**
 * ES|QL is a STRUCTURAL-ONLY degradation of sensitive_data: per-candidate checksum
 * confirmation (Luhn/mod-97 Painless) and hash fingerprints have no ES|QL equivalent.
 * Partial redact and custom mask tokens are ingest-only. Tag-only categories are skipped.
 * ES|QL emits a combined structural redact over redact/partial/hash category patterns
 * (hash previews as redact; ingest applies FNV-1a fingerprints).
 */
export const convertSensitiveDataProcessorToESQL = (
  processor: SensitiveDataProcessor
): ESQLAstCommand[] => {
  const patterns: string[] = [];
  const patternDefinitions: Record<string, string> = {};
  for (const category of processor.categories) {
    if (category.action === 'tag') {
      continue;
    }
    const detector = getDetectorById(category.id);
    if (!detector) {
      continue;
    }
    const configured = applyKeywordOverride(detector, category);
    for (const p of configured.detection.grokPatterns) {
      patterns.push(p);
    }
    Object.assign(patternDefinitions, configured.detection.grokPatternDefinitions || {});
  }

  if (patterns.length === 0) {
    return [];
  }

  const redact: RedactProcessor = {
    action: 'redact',
    from: processor.from,
    patterns,
    pattern_definitions: patternDefinitions,
    ignore_missing: true,
  };
  return convertRedactProcessorToESQL(redact);
};
