/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React from 'react';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { FormProvider, useForm } from 'react-hook-form';
import type { SimulationActorSnapshot } from '../../../../state_management/stream_enrichment_state_machine';
import type { SensitiveDataFormState } from '../../../../types';
import { SensitiveDataProcessorForm } from '.';

jest.mock('./use_sensitive_data_license', () => ({
  useSensitiveDataLicense: jest.fn(() => ({
    isLoading: false,
    hasRequiredLicense: true,
  })),
}));

jest.mock('../processor_field_selector', () => ({
  ProcessorFieldSelector: () => <div data-test-subj="processor-field-selector" />,
}));

jest.mock('../../../../state_management/stream_enrichment_state_machine', () => ({
  useSimulatorSelector: jest.fn((selector) =>
    selector({
      context: {
        samples: [],
        previewDocsFilter: undefined,
        simulation: undefined,
        selectedConditionId: undefined,
        streamName: 'test-stream',
      },
    })
  ),
}));

const { useSensitiveDataLicense } = jest.requireMock('./use_sensitive_data_license');
const { useSimulatorSelector } = jest.requireMock(
  '../../../../state_management/stream_enrichment_state_machine'
);

const FormWrapper = ({ defaultValues }: { defaultValues: SensitiveDataFormState }) => {
  const methods = useForm<SensitiveDataFormState>({ defaultValues });
  return (
    <FormProvider {...methods}>
      <SensitiveDataProcessorForm />
    </FormProvider>
  );
};

describe('SensitiveDataProcessorForm (proposal panel)', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    useSensitiveDataLicense.mockReturnValue({
      isLoading: false,
      hasRequiredLicense: true,
    });
  });

  it('renders opt-in empty state by default', () => {
    render(
      <FormWrapper
        defaultValues={{
          action: 'sensitive_data',
          from: 'message',
          categories: [],
        }}
      />
    );

    expect(screen.getByText('Configured categories')).toBeInTheDocument();
    expect(screen.getByTestId('sensitiveData-empty-state')).toBeInTheDocument();
    expect(screen.getByTestId('sensitiveData-add-categories')).toBeInTheDocument();
    expect(screen.queryByText('Sensitive data categories')).not.toBeInTheDocument();
  });

  it('shows action selector when email supports multiple actions', async () => {
    const user = userEvent.setup();
    render(
      <FormWrapper
        defaultValues={{
          action: 'sensitive_data',
          from: 'message',
          categories: [{ id: 'email', action: 'redact' }],
        }}
      />
    );

    await user.click(screen.getByText('Email address'));
    const actionSelect = screen.getByTestId('sensitiveData-action-email');
    expect(actionSelect).toBeInTheDocument();
    expect(actionSelect).toHaveValue('redact');
  });

  it('does not show proximity keyword fields for email', async () => {
    const user = userEvent.setup();
    render(
      <FormWrapper
        defaultValues={{
          action: 'sensitive_data',
          from: 'message',
          categories: [{ id: 'email', action: 'redact' }],
        }}
      />
    );

    await user.click(screen.getByText('Email address'));
    expect(screen.queryByText('Use recommended keywords')).not.toBeInTheDocument();
    expect(screen.queryByText('Proximity keywords')).not.toBeInTheDocument();
  });

  it('fills recommended keywords on toggle off and back on while keeping values', async () => {
    const user = userEvent.setup();
    render(
      <FormWrapper
        defaultValues={{
          action: 'sensitive_data',
          from: 'message',
          categories: [{ id: 'us-ssn', action: 'redact' }],
        }}
      />
    );

    await user.click(screen.getByText('US Social Security Number'));
    const toggle = screen.getByTestId('sensitiveData-use-recommended-us-ssn');
    expect(toggle).toBeChecked();
    expect(screen.getByText('social security')).toBeInTheDocument();

    await user.click(toggle);
    expect(toggle).not.toBeChecked();
    expect(screen.getByText('social security')).toBeInTheDocument();

    await user.click(toggle);
    expect(toggle).toBeChecked();
  });

  it('shows manual proximity keywords when saved without recommended toggle', async () => {
    const user = userEvent.setup();
    render(
      <FormWrapper
        defaultValues={{
          action: 'sensitive_data',
          from: 'message',
          categories: [
            {
              id: 'us-ssn',
              action: 'redact',
              keywords: ['employee ssn'],
              keywordProximity: 12,
            },
          ],
        }}
      />
    );

    await user.click(screen.getByText('US Social Security Number'));
    expect(screen.getByTestId('sensitiveData-use-recommended-us-ssn')).not.toBeChecked();
    expect(screen.getByText('employee ssn')).toBeInTheDocument();
    expect(screen.getByTestId('sensitiveData-keywords-us-ssn')).toBeInTheDocument();
  });

  it('renders configured category rows when legacy string[] categories are loaded', () => {
    render(
      <FormWrapper
        defaultValues={
          {
            action: 'sensitive_data',
            from: 'message',
            // Legacy persisted shape: category id strings normalized on load.
            categories: ['email', 'credit-card'],
          } as unknown as SensitiveDataFormState
        }
      />
    );

    expect(screen.getByText('Email address')).toBeInTheDocument();
    expect(screen.getByText('Visa card number')).toBeInTheDocument();
  });

  it('renders configured category rows when categories are set', () => {
    render(
      <FormWrapper
        defaultValues={{
          action: 'sensitive_data',
          from: 'message',
          categories: [
            { id: 'email', action: 'redact' },
            { id: 'visa', action: 'redact' },
          ],
        }}
      />
    );

    expect(screen.getByText('Email address')).toBeInTheDocument();
    expect(screen.getByText('Visa card number')).toBeInTheDocument();
  });

  it('opens the category library flyout from Add categories', async () => {
    const user = userEvent.setup();
    render(
      <FormWrapper
        defaultValues={{
          action: 'sensitive_data',
          from: 'message',
          categories: [],
        }}
      />
    );

    await user.click(screen.getByTestId('sensitiveData-add-categories'));
    expect(screen.getByTestId('sensitiveData-category-library-flyout')).toBeInTheDocument();
  });

  it('shows recommended categories when preview samples contain detectable email', () => {
    useSimulatorSelector.mockImplementation(
      (selector: (snapshot: SimulationActorSnapshot) => unknown) =>
        selector({
          context: {
            samples: [{ document: { message: 'contact us at user@example.com' } }],
            previewDocsFilter: undefined,
            simulation: undefined,
            selectedConditionId: undefined,
            streamName: 'test-stream',
          },
        } as unknown as SimulationActorSnapshot)
    );

    render(
      <FormWrapper
        defaultValues={{
          action: 'sensitive_data',
          from: 'message',
          categories: [],
        }}
      />
    );

    expect(screen.getByText('Recommended for this source')).toBeInTheDocument();
    expect(screen.getByTestId('sensitiveData-add-recommended')).toBeInTheDocument();
  });

  it('shows license callout when license is insufficient', () => {
    useSensitiveDataLicense.mockReturnValue({
      isLoading: false,
      hasRequiredLicense: false,
    });

    render(
      <FormWrapper
        defaultValues={{
          action: 'sensitive_data',
          from: 'message',
          categories: [],
        }}
      />
    );

    expect(
      screen.getByText('Sensitive data redaction requires a Platinum or Enterprise license')
    ).toBeInTheDocument();
  });
});
