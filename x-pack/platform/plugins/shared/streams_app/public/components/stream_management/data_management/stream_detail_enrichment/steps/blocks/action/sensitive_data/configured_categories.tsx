/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React, { useEffect, useRef, useState } from 'react';
import {
  EuiAccordion,
  EuiButton,
  EuiButtonEmpty,
  EuiButtonIcon,
  EuiComboBox,
  EuiFieldNumber,
  EuiFieldText,
  EuiFormRow,
  EuiPanel,
  EuiSelect,
  EuiSpacer,
  EuiSwitch,
  EuiText,
} from '@elastic/eui';
import { i18n } from '@kbn/i18n';
import {
  disableRecommendedKeywordsSync,
  getCategoryMaskToken,
  getDefaultKeywordProximity,
  getSupportedActionsForCategory,
  listCatalogCategories,
  omitKeywordOverrides,
  requiresKeywordProximity,
  type SensitiveDataCategory,
  type SensitiveDataCategoryAction,
  withRecommendedKeywords,
} from '@kbn/streamlang';
import { useNormalizedCategoriesField } from './use_normalized_categories';

const ACTION_OPTIONS: Array<{ value: SensitiveDataCategoryAction; text: string }> = [
  {
    value: 'redact',
    text: i18n.translate('xpack.streams.sensitiveData.action.redact', {
      defaultMessage: 'Full redact',
    }),
  },
  {
    value: 'hash',
    text: i18n.translate('xpack.streams.sensitiveData.action.hash', {
      defaultMessage: 'Hash (fingerprint)',
    }),
  },
  {
    value: 'partial',
    text: i18n.translate('xpack.streams.sensitiveData.action.partial', {
      defaultMessage: 'Partial redact',
    }),
  },
  {
    value: 'tag',
    text: i18n.translate('xpack.streams.sensitiveData.action.tag', {
      defaultMessage: 'Tag only (no redaction)',
    }),
  },
];

const labelById = (): Map<string, string> => {
  const map = new Map<string, string>();
  for (const meta of listCatalogCategories()) {
    map.set(meta.id, meta.displayName);
  }
  return map;
};

const DISPLAY_NAMES = labelById();

const actionOptionsForCategory = (
  categoryId: string
): Array<{ value: SensitiveDataCategoryAction; text: string }> => {
  const supported = new Set(getSupportedActionsForCategory(categoryId));
  return ACTION_OPTIONS.filter((option) => supported.has(option.value));
};

const actionSummary = (category: SensitiveDataCategory): string => {
  const actionLabel =
    ACTION_OPTIONS.find((o) => o.value === category.action)?.text ?? category.action;
  const parts = [actionLabel];
  if (category.keywords?.length) {
    parts.push(
      i18n.translate('xpack.streams.sensitiveData.summary.keywords', {
        defaultMessage: '{count, plural, one {# keyword} other {# keywords}}',
        values: { count: category.keywords.length },
      })
    );
  }
  if (category.maskToken) {
    parts.push(category.maskToken);
  }
  return parts.join(' · ');
};

interface ConfiguredCategoriesProps {
  onAddCategories: () => void;
}

export const ConfiguredCategories = ({ onAddCategories }: ConfiguredCategoriesProps) => {
  const { categoriesController, categories } = useNormalizedCategoriesField();

  // Keep the first category expanded by default and auto-expand any newly added category, so the
  // configured list never appears as a wall of collapsed rows. Each row stays independently toggleable.
  const [openIds, setOpenIds] = useState<Set<string>>(
    () => new Set(categories.length > 0 ? [categories[0].id] : [])
  );
  const previousIdsRef = useRef<string[]>(categories.map((c) => c.id));
  const idsKey = categories.map((c) => c.id).join('|');

  useEffect(() => {
    const currentIds = idsKey ? idsKey.split('|') : [];
    const addedIds = currentIds.filter((id) => !previousIdsRef.current.includes(id));
    if (addedIds.length > 0) {
      setOpenIds((prev) => {
        const next = new Set(prev);
        addedIds.forEach((id) => next.add(id));
        return next;
      });
    }
    previousIdsRef.current = currentIds;
  }, [idsKey]);

  const setOpen = (id: string, isOpen: boolean) => {
    setOpenIds((prev) => {
      const next = new Set(prev);
      if (isOpen) {
        next.add(id);
      } else {
        next.delete(id);
      }
      return next;
    });
  };

  const replaceAt = (index: number, category: SensitiveDataCategory) => {
    categoriesController.field.onChange(
      categories.map((item, i) => (i === index ? category : item))
    );
  };

  const patchAt = (index: number, patch: Partial<SensitiveDataCategory>) => {
    const current = categories[index];
    if (!current) {
      return;
    }
    replaceAt(index, { ...current, ...patch });
  };

  const removeAt = (index: number) => {
    categoriesController.field.onChange(categories.filter((_, i) => i !== index));
  };

  if (categories.length === 0) {
    return (
      <>
        <EuiText size="s">
          <h4>
            {i18n.translate('xpack.streams.sensitiveData.configured.title', {
              defaultMessage: 'Configured categories',
            })}
          </h4>
        </EuiText>
        <EuiSpacer size="s" />
        <EuiText size="xs" color="subdued" data-test-subj="sensitiveData-empty-state">
          {i18n.translate('xpack.streams.sensitiveData.configured.empty', {
            defaultMessage:
              'No categories selected. Add categories from the library to scan and redact sensitive data.',
          })}
        </EuiText>
        <EuiSpacer size="m" />
        <EuiButton fill onClick={onAddCategories} data-test-subj="sensitiveData-add-categories">
          {i18n.translate('xpack.streams.sensitiveData.configured.add', {
            defaultMessage: 'Add categories',
          })}
        </EuiButton>
      </>
    );
  }

  return (
    <>
      <EuiText size="s">
        <h4>
          {i18n.translate('xpack.streams.sensitiveData.configured.title', {
            defaultMessage: 'Configured categories',
          })}
        </h4>
      </EuiText>
      <EuiText size="xs" color="subdued">
        {i18n.translate('xpack.streams.sensitiveData.configured.subtitle', {
          defaultMessage:
            'Opt-in: only the categories you add are scanned. Expand a row to change action, keywords, or mask token.',
        })}
      </EuiText>
      <EuiSpacer size="s" />
      {categories.map((category, index) => {
        const displayName = DISPLAY_NAMES.get(category.id) ?? category.id;
        const defaultMask =
          category.action === 'partial' ? '****' : getCategoryMaskToken(category.id) ?? '';
        const keywordGated = requiresKeywordProximity(category.id);
        const syncRecommendedKeywords = category.useRecommendedKeywords === true;
        const hasCustomKeywords = (category.keywords?.length ?? 0) > 0;
        const defaultProximity = getDefaultKeywordProximity(category.id);
        const actionOptions = actionOptionsForCategory(category.id);
        const selectedAction = actionOptions.some((o) => o.value === category.action)
          ? category.action
          : 'redact';
        return (
          <React.Fragment key={category.id}>
            <EuiPanel hasBorder paddingSize="m">
              <EuiAccordion
                id={`sensitiveData-configured-${category.id}`}
                forceState={openIds.has(category.id) ? 'open' : 'closed'}
                onToggle={(isOpen) => setOpen(category.id, isOpen)}
                buttonContent={
                  <div>
                    <EuiText size="s">
                      <strong>{displayName}</strong>
                    </EuiText>
                    <EuiText size="xs" color="subdued" className="eui-textTruncate">
                      {actionSummary(category)}
                    </EuiText>
                  </div>
                }
                extraAction={
                  <EuiButtonIcon
                    iconType="trash"
                    color="danger"
                    aria-label={i18n.translate('xpack.streams.sensitiveData.configured.remove', {
                      defaultMessage: 'Remove category',
                    })}
                    onClick={() => removeAt(index)}
                    data-test-subj={`sensitiveData-remove-${category.id}`}
                  />
                }
              >
                <EuiSpacer size="m" />
                {actionOptions.length > 1 && (
                  <EuiFormRow
                    label={i18n.translate('xpack.streams.sensitiveData.settings.action', {
                      defaultMessage: 'Action',
                    })}
                  >
                    <EuiSelect
                      options={actionOptions}
                      value={selectedAction}
                      onChange={(e) =>
                        patchAt(index, { action: e.target.value as SensitiveDataCategoryAction })
                      }
                      data-test-subj={`sensitiveData-action-${category.id}`}
                    />
                  </EuiFormRow>
                )}
                {category.action === 'hash' && (
                  <EuiText size="xs" color="subdued">
                    {i18n.translate('xpack.streams.sensitiveData.settings.hashHelp', {
                      defaultMessage:
                        'Replaces matched values with a consistent FNV-1a 64-bit fingerprint (h:…). Useful for counting unique values and correlating events without seeing raw data. ES|QL preview shows redaction where ingest will hash.',
                    })}
                  </EuiText>
                )}
                {(category.action === 'redact' || category.action === 'partial') && (
                  <EuiFormRow
                    label={i18n.translate('xpack.streams.sensitiveData.settings.maskToken', {
                      defaultMessage: 'Mask / replacement token',
                    })}
                  >
                    <EuiFieldText
                      value={category.maskToken ?? ''}
                      placeholder={defaultMask}
                      onChange={(e) => patchAt(index, { maskToken: e.target.value || undefined })}
                    />
                  </EuiFormRow>
                )}
                {category.action === 'partial' && (
                  <EuiFormRow
                    label={i18n.translate('xpack.streams.sensitiveData.settings.keepLast', {
                      defaultMessage: 'Keep last N characters',
                    })}
                  >
                    <EuiFieldNumber
                      value={category.keepLast ?? 4}
                      min={0}
                      onChange={(e) =>
                        patchAt(index, {
                          keepLast: e.target.value ? Number(e.target.value) : undefined,
                        })
                      }
                    />
                  </EuiFormRow>
                )}
                {keywordGated && (
                  <>
                    <EuiFormRow>
                      <EuiSwitch
                        label={i18n.translate(
                          'xpack.streams.sensitiveData.settings.useRecommended',
                          {
                            defaultMessage: 'Use recommended keywords',
                          }
                        )}
                        checked={syncRecommendedKeywords}
                        onChange={(e) => {
                          replaceAt(
                            index,
                            e.target.checked
                              ? withRecommendedKeywords(category)
                              : disableRecommendedKeywordsSync(category)
                          );
                        }}
                        data-test-subj={`sensitiveData-use-recommended-${category.id}`}
                      />
                    </EuiFormRow>
                    <EuiText size="xs" color="subdued">
                      {syncRecommendedKeywords
                        ? i18n.translate('xpack.streams.sensitiveData.settings.recommendedOnHelp', {
                            defaultMessage:
                              'Catalog recommended keywords are applied. You can edit them below or turn off to stop syncing defaults.',
                          })
                        : hasCustomKeywords
                        ? i18n.translate(
                            'xpack.streams.sensitiveData.settings.customKeywordsHelp',
                            {
                              defaultMessage:
                                'Custom proximity keywords apply at runtime. Clear all keywords to use built-in catalog matching.',
                            }
                          )
                        : i18n.translate('xpack.streams.sensitiveData.settings.builtinKeywords', {
                            defaultMessage:
                              'Built-in catalog keywords apply at runtime. Add your own below or turn on recommended keywords.',
                          })}
                    </EuiText>
                    <EuiFormRow
                      label={i18n.translate('xpack.streams.sensitiveData.settings.keywords', {
                        defaultMessage: 'Proximity keywords',
                      })}
                      helpText={i18n.translate(
                        'xpack.streams.sensitiveData.settings.keywordsHelp',
                        {
                          defaultMessage:
                            'Redact only when one of these words appears near the match (optional).',
                        }
                      )}
                    >
                      <EuiComboBox
                        selectedOptions={(category.keywords ?? []).map((k) => ({ label: k }))}
                        onCreateOption={(searchValue) => {
                          const trimmed = searchValue.trim();
                          if (!trimmed) {
                            return;
                          }
                          replaceAt(index, {
                            ...disableRecommendedKeywordsSync(category),
                            keywords: [...(category.keywords ?? []), trimmed],
                            keywordProximity:
                              category.keywordProximity ?? defaultProximity ?? undefined,
                          });
                        }}
                        onChange={(opts) => {
                          const keywords = opts
                            .map((o) => o.label)
                            .filter((l): l is string => Boolean(l));
                          replaceAt(
                            index,
                            keywords.length > 0
                              ? {
                                  ...disableRecommendedKeywordsSync(category),
                                  keywords,
                                  keywordProximity:
                                    category.keywordProximity ?? defaultProximity ?? undefined,
                                }
                              : omitKeywordOverrides(disableRecommendedKeywordsSync(category))
                          );
                        }}
                        data-test-subj={`sensitiveData-keywords-${category.id}`}
                      />
                    </EuiFormRow>
                    <EuiFormRow
                      label={i18n.translate(
                        'xpack.streams.sensitiveData.settings.keywordProximity',
                        {
                          defaultMessage: 'Keyword proximity (characters)',
                        }
                      )}
                    >
                      <EuiFieldNumber
                        value={category.keywordProximity ?? ''}
                        min={0}
                        placeholder={defaultProximity?.toString() ?? '15'}
                        onChange={(e) =>
                          patchAt(index, {
                            useRecommendedKeywords: false,
                            keywordProximity: e.target.value ? Number(e.target.value) : undefined,
                          })
                        }
                        data-test-subj={`sensitiveData-keyword-proximity-${category.id}`}
                      />
                    </EuiFormRow>
                  </>
                )}
              </EuiAccordion>
            </EuiPanel>
            <EuiSpacer size="s" />
          </React.Fragment>
        );
      })}
      <EuiButtonEmpty
        iconType="plusInCircle"
        onClick={onAddCategories}
        data-test-subj="sensitiveData-add-more-categories"
      >
        {i18n.translate('xpack.streams.sensitiveData.configured.addMore', {
          defaultMessage: 'Add categories',
        })}
      </EuiButtonEmpty>
    </>
  );
};
