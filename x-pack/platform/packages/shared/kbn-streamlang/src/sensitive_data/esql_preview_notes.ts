/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { SensitiveDataCategory } from '../../types/processors';
import { getDetectorById } from './catalog';
import { isChecksum } from './compile';

/** Structured preview fidelity notes for sensitive_data ES|QL transpilation and UI callouts. */
export type SensitiveDataEsqlPreviewNote =
  | { kind: 'tag'; categoryId: string }
  | { kind: 'partial'; categoryId: string; keepLast: number }
  | { kind: 'hash'; categoryId: string }
  | { kind: 'structural_only'; categoryId: string };

const displayNameFor = (categoryId: string): string =>
  getDetectorById(categoryId)?.displayName ?? categoryId;

/** Collect preview notes for configured categories (tag, partial, hash, legacy checksum redact). */
export const collectSensitiveDataEsqlPreviewNotes = (
  categories: SensitiveDataCategory[]
): SensitiveDataEsqlPreviewNote[] => {
  const notes: SensitiveDataEsqlPreviewNote[] = [];

  for (const category of categories) {
    const detector = getDetectorById(category.id);
    if (!detector) {
      continue;
    }

    if (category.action === 'tag') {
      notes.push({ kind: 'tag', categoryId: category.id });
      continue;
    }

    if (category.action === 'partial') {
      notes.push({
        kind: 'partial',
        categoryId: category.id,
        keepLast: category.keepLast ?? 4,
      });
      continue;
    }

    if (category.action === 'hash') {
      notes.push({ kind: 'hash', categoryId: category.id });
      continue;
    }

    if (category.action === 'redact' && isChecksum(detector)) {
      notes.push({ kind: 'structural_only', categoryId: category.id });
    }
  }

  return notes;
};

/** Plain-text warning strings for ES|QL transpiler output and unit tests. */
export const formatSensitiveDataEsqlPreviewNote = (note: SensitiveDataEsqlPreviewNote): string => {
  const name = displayNameFor(note.categoryId);
  switch (note.kind) {
    case 'tag':
      return `Category "${name}" is tag-only — ES|QL preview does not modify field values (ingest writes telemetry flags).`;
    case 'partial':
      return `Category "${name}" uses partial redact — ES|QL preview shows full redact; ingest keeps the last ${note.keepLast} characters.`;
    case 'hash':
      return `Category "${name}" uses hash — ES|QL preview shows full redact; ingest replaces matches with h: fingerprints.`;
    case 'structural_only':
      return `Category "${name}" uses checksum confirmation at ingest — ES|QL preview matches structurally only and may redact more candidates.`;
  }
};

export const sensitiveDataEsqlPreviewWarnings = (categories: SensitiveDataCategory[]): string[] =>
  collectSensitiveDataEsqlPreviewNotes(categories).map(formatSensitiveDataEsqlPreviewNote);
