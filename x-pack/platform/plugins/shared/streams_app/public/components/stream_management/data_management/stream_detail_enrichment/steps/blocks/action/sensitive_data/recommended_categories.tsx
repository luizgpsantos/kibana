/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React, { useMemo } from 'react';
import { useFormContext } from 'react-hook-form';
import { EuiBadge, EuiBadgeGroup, EuiButtonEmpty, EuiSpacer, EuiText } from '@elastic/eui';
import { i18n } from '@kbn/i18n';
import {
  ACTIVE_DETECTOR_IDS,
  createDefaultCategoryConfig,
  listCatalogCategories,
  type SensitiveDataCategory,
} from '@kbn/streamlang';
import type { SensitiveDataFormState } from '../../../../types';
import { selectPreviewRecords } from '../../../../state_management/simulation_state_machine/selectors';
import { useSimulatorSelector } from '../../../../state_management/stream_enrichment_state_machine';

const LIKELY_PATTERNS: Array<{ id: string; test: (text: string) => boolean }> = [
  {
    id: 'email',
    test: (text) => /[^\s@]+@[^\s@]+\.[^\s@]+/.test(text),
  },
  {
    id: 'credit-card',
    test: (text) => /(?:\d[ .-]?){12,18}\d/.test(text),
  },
  {
    id: 'iban',
    test: (text) => /[A-Z]{2}\d{2}[A-Z0-9]{11,30}/i.test(text),
  },
  {
    id: 'us-ssn',
    test: (text) => /(?:ssn|social security)/i.test(text) && /\d{3}[- ]?\d{2}[- ]?\d{4}/.test(text),
  },
];

const detectLikelyCategoryIds = (
  samples: Array<Record<string, unknown>>,
  field: string
): string[] => {
  const text = samples
    .map((doc) => doc[field])
    .filter((v): v is string => typeof v === 'string' && v.length > 0)
    .join('\n');
  if (!text) {
    return [];
  }
  return LIKELY_PATTERNS.filter((p) => p.test(text)).map((p) => p.id);
};

interface RecommendedCategoriesProps {
  configuredIds: Set<string>;
  onAddCategories: (categories: SensitiveDataCategory[]) => void;
}

export const RecommendedCategories = ({
  configuredIds,
  onAddCategories,
}: RecommendedCategoriesProps) => {
  const previewRecords = useSimulatorSelector((snapshot) => selectPreviewRecords(snapshot.context));
  const { watch } = useFormContext<SensitiveDataFormState>();
  const fromField = watch('from') ?? 'message';

  const likelyIds = useMemo(() => {
    const detected = detectLikelyCategoryIds(previewRecords, fromField);
    return detected.filter(
      (id) => (ACTIVE_DETECTOR_IDS as readonly string[]).includes(id) && !configuredIds.has(id)
    );
  }, [previewRecords, configuredIds, fromField]);

  const labels = useMemo(() => {
    const byId = new Map(listCatalogCategories().map((c) => [c.id, c.displayName]));
    return likelyIds.map((id) => ({ id, displayName: byId.get(id) ?? id }));
  }, [likelyIds]);

  if (labels.length === 0) {
    return null;
  }

  const handleAddAll = () => {
    onAddCategories(likelyIds.map((id) => createDefaultCategoryConfig(id)));
  };

  return (
    <>
      <EuiText size="s">
        <h4>
          {i18n.translate('xpack.streams.sensitiveData.recommended.title', {
            defaultMessage: 'Recommended for this source',
          })}
        </h4>
      </EuiText>
      <EuiText size="xs" color="subdued">
        {i18n.translate('xpack.streams.sensitiveData.recommended.subtitle', {
          defaultMessage:
            'Likely sensitive data types found in your preview sample. Add them with one click.',
        })}
      </EuiText>
      <EuiSpacer size="s" />
      <EuiBadgeGroup>
        {labels.map(({ id, displayName }) => (
          <EuiBadge key={id} color="hollow">
            {displayName}
          </EuiBadge>
        ))}
      </EuiBadgeGroup>
      <EuiSpacer size="s" />
      <EuiButtonEmpty
        size="s"
        onClick={handleAddAll}
        data-test-subj="sensitiveData-add-recommended"
      >
        {i18n.translate('xpack.streams.sensitiveData.recommended.addAll', {
          defaultMessage: 'Add recommended categories',
        })}
      </EuiButtonEmpty>
    </>
  );
};
