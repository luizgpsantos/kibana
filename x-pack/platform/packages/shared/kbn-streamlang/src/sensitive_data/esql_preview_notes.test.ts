/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { createDefaultCategoryConfig } from './catalog';
import {
  collectSensitiveDataEsqlPreviewNotes,
  formatSensitiveDataEsqlPreviewNote,
  sensitiveDataEsqlPreviewWarnings,
} from './esql_preview_notes';

describe('esql_preview_notes', () => {
  it('collects tag, partial, and hash notes', () => {
    const notes = collectSensitiveDataEsqlPreviewNotes([
      { ...createDefaultCategoryConfig('email'), action: 'tag' },
      { ...createDefaultCategoryConfig('visa'), action: 'partial', keepLast: 4 },
      { id: 'ipv4', action: 'hash' },
    ]);
    expect(notes.map((n) => n.kind)).toEqual(['tag', 'partial', 'hash']);
  });

  it('formats tag-only warnings for ES|QL transpiler output', () => {
    const [note] = collectSensitiveDataEsqlPreviewNotes([
      { ...createDefaultCategoryConfig('visa'), action: 'tag' },
    ]);
    expect(formatSensitiveDataEsqlPreviewNote(note)).toMatch(/tag-only/);
  });

  it('returns empty warnings for all-redact structural categories', () => {
    expect(sensitiveDataEsqlPreviewWarnings([{ id: 'email', action: 'redact' }])).toEqual([]);
  });
});
