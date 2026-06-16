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
import { sensitiveDataEsqlPreviewWarnings } from '../../../sensitive_data/esql_preview_notes';
import { convertRedactProcessorToESQL } from './redact';

export interface SensitiveDataEsqlTranspilationResult {
  commands: ESQLAstCommand[];
  warnings: string[];
}

/**
 * ES|QL is a best-effort preview of sensitive_data: per-candidate Painless scripts (partial, hash,
 * checksum confirmation, keyword proximity) have no ES|QL equivalent. Tag-only categories emit no
 * field changes. Partial and hash categories degrade to structural full redact with warnings.
 */
export const convertSensitiveDataProcessorToESQL = (
  processor: SensitiveDataProcessor
): SensitiveDataEsqlTranspilationResult => {
  const warnings = sensitiveDataEsqlPreviewWarnings(processor.categories);
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
    return { commands: [], warnings };
  }

  const redact: RedactProcessor = {
    action: 'redact',
    from: processor.from,
    patterns,
    pattern_definitions: patternDefinitions,
    ignore_missing: true,
  };

  return {
    commands: convertRedactProcessorToESQL(redact),
    warnings,
  };
};
