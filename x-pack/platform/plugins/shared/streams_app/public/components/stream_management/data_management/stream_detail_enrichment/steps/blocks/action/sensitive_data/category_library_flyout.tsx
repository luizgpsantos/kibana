/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React, { useMemo, useState } from 'react';
import {
  EuiButton,
  EuiButtonEmpty,
  EuiFilterButton,
  EuiFieldSearch,
  EuiFilterGroup,
  EuiFlyout,
  EuiFlyoutBody,
  EuiFlyoutFooter,
  EuiFlyoutHeader,
  EuiSelectable,
  EuiSpacer,
  EuiText,
  EuiTitle,
  type EuiSelectableOption,
} from '@elastic/eui';
import { i18n } from '@kbn/i18n';
import {
  createDefaultCategoryConfig,
  listLibraryCategories,
  type LibraryCategoryGroup,
  type SensitiveDataCategory,
} from '@kbn/streamlang';

interface CategoryLibraryFlyoutProps {
  isOpen: boolean;
  onClose: () => void;
  configuredIds: Set<string>;
  onAdd: (categories: SensitiveDataCategory[]) => void;
}

type FilterGroup = LibraryCategoryGroup | 'all';

const GROUP_LABELS: Record<LibraryCategoryGroup, string> = {
  pii: i18n.translate('xpack.streams.sensitiveData.library.filterPii', {
    defaultMessage: 'PII',
  }),
  payment_banking: i18n.translate('xpack.streams.sensitiveData.library.filterPayment', {
    defaultMessage: 'Payment & banking',
  }),
  network_device: i18n.translate('xpack.streams.sensitiveData.library.filterNetwork', {
    defaultMessage: 'Network & device',
  }),
  secrets_credentials: i18n.translate('xpack.streams.sensitiveData.library.filterSecrets', {
    defaultMessage: 'Secrets & credentials',
  }),
};

export const CategoryLibraryFlyout = ({
  isOpen,
  onClose,
  configuredIds,
  onAdd,
}: CategoryLibraryFlyoutProps) => {
  const [searchValue, setSearchValue] = useState('');
  const [groupFilter, setGroupFilter] = useState<FilterGroup>('all');
  const [selected, setSelected] = useState<Record<string, boolean>>({});

  const library = useMemo(() => listLibraryCategories(), []);

  const filterGroups = useMemo((): FilterGroup[] => {
    const groups = new Set(library.map((entry) => entry.group));
    const ordered: LibraryCategoryGroup[] = [
      'pii',
      'payment_banking',
      'network_device',
      'secrets_credentials',
    ];
    return ['all', ...ordered.filter((group) => groups.has(group))];
  }, [library]);

  const filtered = useMemo(() => {
    const q = searchValue.trim().toLowerCase();
    return library.filter((entry) => {
      if (configuredIds.has(entry.id)) {
        return false;
      }
      if (groupFilter !== 'all' && entry.group !== groupFilter) {
        return false;
      }
      if (!q) {
        return true;
      }
      return (
        entry.displayName.toLowerCase().includes(q) ||
        entry.id.toLowerCase().includes(q) ||
        (entry.description?.toLowerCase().includes(q) ?? false)
      );
    });
  }, [library, searchValue, groupFilter, configuredIds]);

  const options = useMemo<EuiSelectableOption[]>(
    () =>
      filtered.map((entry) => ({
        label: entry.displayName,
        key: entry.id,
        checked: selected[entry.id] ? ('on' as const) : undefined,
        'data-test-subj': `sensitiveData-library-${entry.id}`,
      })),
    [filtered, selected]
  );

  if (!isOpen) {
    return null;
  }

  const handleAdd = () => {
    const toAdd = filtered
      .filter((entry) => selected[entry.id])
      .map((entry) => createDefaultCategoryConfig(entry.id));
    if (toAdd.length) {
      onAdd(toAdd);
    }
    setSelected({});
    setSearchValue('');
    onClose();
  };

  const flyoutTitleId = 'sensitiveDataCategoryLibraryTitle';

  return (
    <EuiFlyout
      onClose={onClose}
      size="m"
      aria-labelledby={flyoutTitleId}
      data-test-subj="sensitiveData-category-library-flyout"
    >
      <EuiFlyoutHeader hasBorder>
        <EuiTitle size="s">
          <h3 id={flyoutTitleId}>
            {i18n.translate('xpack.streams.sensitiveData.library.title', {
              defaultMessage: 'Add sensitive data categories',
            })}
          </h3>
        </EuiTitle>
        <EuiSpacer size="s" />
        <EuiText size="s" color="subdued">
          {i18n.translate('xpack.streams.sensitiveData.library.subtitle', {
            defaultMessage: 'Search the category library and add the types you want to scan for.',
          })}
        </EuiText>
      </EuiFlyoutHeader>
      <EuiFlyoutBody>
        <EuiFilterGroup>
          {filterGroups.map((group) => (
            <EuiFilterButton
              key={group}
              hasActiveFilters={groupFilter === group}
              onClick={() => setGroupFilter(group)}
            >
              {group === 'all'
                ? i18n.translate('xpack.streams.sensitiveData.library.filterAll', {
                    defaultMessage: 'All',
                  })
                : GROUP_LABELS[group]}
            </EuiFilterButton>
          ))}
        </EuiFilterGroup>
        <EuiSpacer size="m" />
        <EuiFieldSearch
          placeholder={i18n.translate('xpack.streams.sensitiveData.library.searchPlaceholder', {
            defaultMessage: 'Search categories',
          })}
          value={searchValue}
          onChange={(e) => setSearchValue(e.target.value)}
          data-test-subj="sensitiveData-library-search"
        />
        <EuiSpacer size="s" />
        <EuiSelectable
          options={options}
          onChange={(newOptions) => {
            const next: Record<string, boolean> = {};
            for (const opt of newOptions) {
              if (opt.checked === 'on' && opt.key) {
                next[opt.key] = true;
              }
            }
            setSelected(next);
          }}
        >
          {(list) => list}
        </EuiSelectable>
      </EuiFlyoutBody>
      <EuiFlyoutFooter>
        <EuiButtonEmpty onClick={onClose}>
          {i18n.translate('xpack.streams.sensitiveData.library.cancel', {
            defaultMessage: 'Cancel',
          })}
        </EuiButtonEmpty>
        <EuiButton fill onClick={handleAdd} data-test-subj="sensitiveData-library-add">
          {i18n.translate('xpack.streams.sensitiveData.library.addSelected', {
            defaultMessage: 'Add selected',
          })}
        </EuiButton>
      </EuiFlyoutFooter>
    </EuiFlyout>
  );
};
