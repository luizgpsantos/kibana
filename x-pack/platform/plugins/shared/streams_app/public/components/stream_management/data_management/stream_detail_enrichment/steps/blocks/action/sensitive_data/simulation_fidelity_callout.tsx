/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React, { useMemo } from 'react';
import { EuiCallOut, EuiSpacer, EuiText } from '@elastic/eui';
import { i18n } from '@kbn/i18n';
import {
  collectSensitiveDataEsqlPreviewNotes,
  getDetectorById,
  type SensitiveDataCategory,
} from '@kbn/streamlang';

const previewNoteMessage = (
  note: ReturnType<typeof collectSensitiveDataEsqlPreviewNotes>[number]
): string => {
  const displayName = getDetectorById(note.categoryId)?.displayName ?? note.categoryId;
  switch (note.kind) {
    case 'tag':
      return i18n.translate('xpack.streams.sensitiveData.previewNote.tag', {
        defaultMessage:
          '{category} is tag-only — field values are unchanged in ES|QL views; ingest writes telemetry flags.',
        values: { category: displayName },
      });
    case 'partial':
      return i18n.translate('xpack.streams.sensitiveData.previewNote.partial', {
        defaultMessage:
          '{category} uses partial redact — ES|QL views show full redact; ingest keeps the last {keepLast, number} characters.',
        values: { category: displayName, keepLast: note.keepLast },
      });
    case 'hash':
      return i18n.translate('xpack.streams.sensitiveData.previewNote.hash', {
        defaultMessage:
          '{category} uses hash — ES|QL views show full redact; ingest replaces matches with h: fingerprints.',
        values: { category: displayName },
      });
    case 'structural_only':
      return i18n.translate('xpack.streams.sensitiveData.previewNote.structuralOnly', {
        defaultMessage:
          '{category} applies extra ingest validation — ES|QL views match structurally only and may redact more candidates.',
        values: { category: displayName },
      });
  }
};

interface SimulationFidelityCalloutProps {
  categories: SensitiveDataCategory[];
}

export const SimulationFidelityCallout = ({ categories }: SimulationFidelityCalloutProps) => {
  const notes = useMemo(() => collectSensitiveDataEsqlPreviewNotes(categories), [categories]);

  if (notes.length === 0) {
    return null;
  }

  return (
    <>
      <EuiCallOut
        size="s"
        color="warning"
        title={i18n.translate('xpack.streams.sensitiveData.previewNote.title', {
          defaultMessage: 'ES|QL preview differs from ingest',
        })}
      >
        <EuiText size="s" component="div">
          <ul>
            {notes.map((note) => (
              <li key={`${note.kind}-${note.categoryId}`}>{previewNoteMessage(note)}</li>
            ))}
          </ul>
          <p>
            {i18n.translate('xpack.streams.sensitiveData.previewNote.ingestHint', {
              defaultMessage:
                'The data preview tab uses ingest simulation and reflects partial, hash, and tag actions accurately.',
            })}
          </p>
        </EuiText>
      </EuiCallOut>
      <EuiSpacer size="m" />
    </>
  );
};
