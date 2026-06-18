/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React from 'react';
import { render, screen } from '@testing-library/react';
import { SimulationFidelityCallout } from './simulation_fidelity_callout';

const hashCategory = [{ id: 'ipv4', action: 'hash' as const }];

describe('SimulationFidelityCallout', () => {
  it('renders the ES|QL preview warning for draft wired streams', () => {
    render(
      <SimulationFidelityCallout categories={hashCategory} showEsqlPreviewNote={true} />
    );

    expect(screen.getByText('ES|QL preview differs from ingest')).toBeInTheDocument();
  });

  it('does not render for classic streams even when categories need preview notes', () => {
    render(
      <SimulationFidelityCallout categories={hashCategory} showEsqlPreviewNote={false} />
    );

    expect(screen.queryByText('ES|QL preview differs from ingest')).not.toBeInTheDocument();
  });

  it('does not render when categories only use full redact', () => {
    render(
      <SimulationFidelityCallout
        categories={[{ id: 'email', action: 'redact' }]}
        showEsqlPreviewNote={true}
      />
    );

    expect(screen.queryByText('ES|QL preview differs from ingest')).not.toBeInTheDocument();
  });
});
