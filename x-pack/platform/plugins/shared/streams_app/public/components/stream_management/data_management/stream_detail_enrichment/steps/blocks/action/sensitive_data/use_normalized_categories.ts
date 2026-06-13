/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { useEffect, useMemo } from 'react';
import { useController } from 'react-hook-form';
import { normalizeSensitiveDataCategories, type SensitiveDataCategory } from '@kbn/streamlang';

/** React Hook Form may still hold legacy `categories: string[]` until load/save runs schema preprocess. */
export const useNormalizedCategoriesField = () => {
  const categoriesController = useController<{ categories: SensitiveDataCategory[] }, 'categories'>(
    {
      name: 'categories',
    }
  );

  const { value: rawValue, onChange } = categoriesController.field;

  const categories = useMemo(
    () =>
      normalizeSensitiveDataCategories(
        (Array.isArray(rawValue) ? rawValue : []) as string[] | SensitiveDataCategory[]
      ),
    [rawValue]
  );

  useEffect(() => {
    if (!Array.isArray(rawValue) || rawValue.length === 0 || typeof rawValue[0] !== 'string') {
      return;
    }
    onChange(normalizeSensitiveDataCategories(rawValue as unknown as string[]));
  }, [rawValue, onChange]);

  return { categoriesController, categories };
};
