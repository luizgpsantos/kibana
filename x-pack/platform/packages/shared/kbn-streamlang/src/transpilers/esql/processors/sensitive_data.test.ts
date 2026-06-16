/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { createDefaultCategoryConfig } from '../../../sensitive_data/catalog';
import { convertSensitiveDataProcessorToESQL } from './sensitive_data';

const commandSources = (result: ReturnType<typeof convertSensitiveDataProcessorToESQL>): string =>
  JSON.stringify(result.commands);

describe('convertSensitiveDataProcessorToESQL', () => {
  it('emits structural redact EVAL commands for the selected categories', () => {
    const result = convertSensitiveDataProcessorToESQL({
      action: 'sensitive_data',
      from: 'message',
      categories: [{ id: 'email', action: 'redact' }],
    });
    expect(result.commands.length).toBeGreaterThanOrEqual(1);
    expect(result.commands[0].name).toBe('eval');
    expect(result.warnings).toEqual([]);
  });

  it('emits redact EVAL commands for an all-redact selection', () => {
    const result = convertSensitiveDataProcessorToESQL({
      action: 'sensitive_data',
      from: 'message',
      categories: [{ id: 'email', action: 'redact' }, createDefaultCategoryConfig('visa')],
    });
    expect(result.commands.length).toBeGreaterThanOrEqual(2);
    const serialized = commandSources(result);
    expect(serialized).toContain('EMAIL');
    expect(serialized).toContain('VISA');
    expect(result.warnings).toEqual([]);
  });

  it('emits redact EVAL commands for hash categories with a hash preview warning', () => {
    const result = convertSensitiveDataProcessorToESQL({
      action: 'sensitive_data',
      from: 'message',
      categories: [{ id: 'email', action: 'hash' }],
    });
    expect(result.commands.length).toBeGreaterThanOrEqual(1);
    expect(result.commands[0].name).toBe('eval');
    expect(result.warnings.some((w) => w.includes('hash') && w.includes('Email'))).toBe(true);
  });

  it('tag action returns empty clauses with a warning', () => {
    const result = convertSensitiveDataProcessorToESQL({
      action: 'sensitive_data',
      from: 'message',
      categories: [{ ...createDefaultCategoryConfig('visa'), action: 'tag' }],
    });
    expect(result.commands).toEqual([]);
    expect(result.warnings.some((w) => w.includes('tag-only'))).toBe(true);
  });

  it('partial action returns a clause and a partial preview warning', () => {
    const result = convertSensitiveDataProcessorToESQL({
      action: 'sensitive_data',
      from: 'message',
      categories: [{ ...createDefaultCategoryConfig('visa'), action: 'partial', keepLast: 4 }],
    });
    expect(result.commands.length).toBeGreaterThanOrEqual(1);
    expect(result.warnings.some((w) => w.includes('partial redact') && w.includes('4'))).toBe(true);
  });

  it('mixed redact + tag: redact clause emitted, tag warning present', () => {
    const result = convertSensitiveDataProcessorToESQL({
      action: 'sensitive_data',
      from: 'message',
      categories: [
        { ...createDefaultCategoryConfig('visa'), action: 'tag' },
        { id: 'email', action: 'redact' },
      ],
    });
    expect(result.commands.length).toBeGreaterThanOrEqual(1);
    const serialized = commandSources(result);
    expect(serialized).toContain('EMAIL');
    expect(serialized).not.toContain('VISA');
    expect(result.warnings.some((w) => w.includes('tag-only'))).toBe(true);
  });

  it('returns no ES|QL commands when every category is tag-only or unknown', () => {
    const result = convertSensitiveDataProcessorToESQL({
      action: 'sensitive_data',
      from: 'message',
      categories: [
        { id: 'not-a-detector', action: 'redact' },
        { ...createDefaultCategoryConfig('visa'), action: 'tag' },
      ],
    });
    expect(result.commands).toEqual([]);
    expect(result.warnings.some((w) => w.includes('tag-only'))).toBe(true);
  });
});
