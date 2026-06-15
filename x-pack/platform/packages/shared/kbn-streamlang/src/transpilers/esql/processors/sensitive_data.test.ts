/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { createDefaultCategoryConfig } from '../../../sensitive_data/catalog';
import { convertSensitiveDataProcessorToESQL } from './sensitive_data';

const commandSources = (commands: ReturnType<typeof convertSensitiveDataProcessorToESQL>): string =>
  JSON.stringify(commands);

describe('convertSensitiveDataProcessorToESQL', () => {
  it('emits structural redact EVAL commands for the selected categories', () => {
    const commands = convertSensitiveDataProcessorToESQL({
      action: 'sensitive_data',
      from: 'message',
      categories: [{ id: 'email', action: 'redact' }],
    });
    expect(commands.length).toBeGreaterThanOrEqual(1);
    expect(commands[0].name).toBe('eval');
  });

  it('emits redact EVAL commands for an all-redact selection', () => {
    const commands = convertSensitiveDataProcessorToESQL({
      action: 'sensitive_data',
      from: 'message',
      categories: [{ id: 'email', action: 'redact' }, createDefaultCategoryConfig('visa')],
    });
    expect(commands.length).toBeGreaterThanOrEqual(2);
    const serialized = commandSources(commands);
    expect(serialized).toContain('EMAIL');
    expect(serialized).toContain('VISA');
  });

  it('returns no ES|QL commands for tag-only categories', () => {
    const commands = convertSensitiveDataProcessorToESQL({
      action: 'sensitive_data',
      from: 'message',
      categories: [{ ...createDefaultCategoryConfig('visa'), action: 'tag' }],
    });
    expect(commands).toEqual([]);
  });

  it('omits tag-only categories from a mixed tag and redact selection', () => {
    const commands = convertSensitiveDataProcessorToESQL({
      action: 'sensitive_data',
      from: 'message',
      categories: [
        { ...createDefaultCategoryConfig('visa'), action: 'tag' },
        { id: 'email', action: 'redact' },
      ],
    });
    expect(commands.length).toBeGreaterThanOrEqual(1);
    const serialized = commandSources(commands);
    expect(serialized).toContain('EMAIL');
    expect(serialized).not.toContain('VISA');
  });

  it('returns no ES|QL commands when every category is tag-only or unknown', () => {
    const commands = convertSensitiveDataProcessorToESQL({
      action: 'sensitive_data',
      from: 'message',
      categories: [
        { id: 'not-a-detector', action: 'redact' },
        { ...createDefaultCategoryConfig('visa'), action: 'tag' },
      ],
    });
    expect(commands).toEqual([]);
  });
});
