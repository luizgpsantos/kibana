/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React, { useMemo, useState } from 'react';
import { EuiSpacer } from '@elastic/eui';
import { i18n } from '@kbn/i18n';
import type { SensitiveDataCategory } from '@kbn/streamlang';
import { isDraftStream, Streams } from '@kbn/streams-schema';
import { ProcessorFieldSelector } from '../processor_field_selector';
import { CategoryLibraryFlyout } from './category_library_flyout';
import { ConfiguredCategories } from './configured_categories';
import { RecommendedCategories } from './recommended_categories';
import { SensitiveDataLicenseCallout } from './license_callout';
import { SimulationFidelityCallout } from './simulation_fidelity_callout';
import { useNormalizedCategoriesField } from './use_normalized_categories';
import { useSensitiveDataLicense } from './use_sensitive_data_license';
import { useStreamEnrichmentSelector } from '../../../state_management/stream_enrichment_state_machine';

const FROM_FIELD_HELP_TEXT = i18n.translate('xpack.streams.sensitiveData.fromFieldHelpText', {
  defaultMessage:
    'This processor runs on every document. Full redact is the cheapest action (native). Hash, partial, and tag scan for each match and cost more on large or high-volume fields, so target a specific field. Only the first 32 KB of a field is scanned; the rest passes through unchanged.',
});

export const SensitiveDataProcessorForm = () => {
  const { categoriesController, categories } = useNormalizedCategoriesField();

  const configuredIds = useMemo(() => new Set(categories.map((c) => c.id)), [categories]);

  const [isLibraryOpen, setIsLibraryOpen] = useState(false);

  const { hasRequiredLicense, isLoading: isLicenseLoading } = useSensitiveDataLicense();

  const showEsqlPreviewNote = useStreamEnrichmentSelector((snapshot) => {
    const stream = snapshot.context.definition.stream;
    return Streams.WiredStream.Definition.is(stream) && isDraftStream(stream);
  });

  const addCategories = (toAdd: SensitiveDataCategory[]) => {
    const existing = new Set(categories.map((c) => c.id));
    const merged = [...categories, ...toAdd.filter((c) => !existing.has(c.id))];
    categoriesController.field.onChange(merged);
  };

  return (
    <>
      <ProcessorFieldSelector fieldKey="from" helpText={FROM_FIELD_HELP_TEXT} />
      <EuiSpacer size="m" />

      {!isLicenseLoading && !hasRequiredLicense && <SensitiveDataLicenseCallout />}

      <SimulationFidelityCallout
        categories={categories}
        showEsqlPreviewNote={showEsqlPreviewNote}
      />

      <ConfiguredCategories onAddCategories={() => setIsLibraryOpen(true)} />
      <EuiSpacer size="m" />
      <RecommendedCategories configuredIds={configuredIds} onAddCategories={addCategories} />

      <CategoryLibraryFlyout
        isOpen={isLibraryOpen}
        onClose={() => setIsLibraryOpen(false)}
        configuredIds={configuredIds}
        onAdd={addCategories}
      />
    </>
  );
};
