/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { Streams } from '@kbn/streams-schema';
import { DraftStream } from './draft_stream';
import type { WiredStream } from './wired_stream';
import { streamFromDefinition } from '../stream_active_record/stream_from_definition';
import type { StateDependencies } from '../types';
import type { State } from '../state';
import type { ElasticsearchAction } from '../execution_plan/types';

interface DraftStreamTestable {
  doDetermineCreateActions(desiredState: State): Promise<ElasticsearchAction[]>;
  doDetermineUpdateActions(
    desiredState: State,
    startingState: State,
    startingStateStream: WiredStream
  ): Promise<ElasticsearchAction[]>;
}

describe('DraftStream', () => {
  const createMockDependencies = (): StateDependencies =>
    ({
      logger: { debug: jest.fn(), info: jest.fn(), warn: jest.fn(), error: jest.fn() },
      isServerless: false,
      isWiredStreamViewsEnabled: true,
      isDev: false,
    } as unknown as StateDependencies);

  const createMockState = (
    streams: Map<string, { definition: Streams.all.Definition }> = new Map()
  ): State =>
    ({
      get: (name: string) => streams.get(name),
      has: (name: string) => streams.has(name),
      all: () => Array.from(streams.values()),
    } as unknown as State);

  const createParentDefinition = (): Streams.WiredStream.Definition => ({
    type: 'wired',
    name: 'logs',
    description: '',
    updated_at: new Date().toISOString(),
    ingest: {
      lifecycle: { dsl: {} },
      processing: { steps: [], updated_at: new Date().toISOString() },
      settings: {},
      wired: {
        fields: {},
        routing: [{ destination: 'logs.child', where: { always: {} }, status: 'enabled' }],
      },
      failure_store: { inherit: {} },
    },
  });

  // A draft wired stream that carries a checksum sensitive_data step in its processing. If a draft
  // ever reached pipeline persistence, this step would compile a Painless regex script at
  // `PUT _ingest/pipeline` time and fail on a regex-disabled cluster.
  const createDraftDefinitionWithChecksumStep = (): Streams.WiredStream.Definition => ({
    type: 'wired',
    name: 'logs.child',
    description: '',
    updated_at: new Date().toISOString(),
    ingest: {
      lifecycle: { inherit: {} },
      processing: {
        steps: [
          {
            action: 'sensitive_data',
            from: 'body.text',
            categories: [{ id: 'credit-card', action: 'redact' }],
          },
        ],
        updated_at: new Date().toISOString(),
      },
      settings: {},
      wired: {
        fields: {},
        routing: [],
        draft: true,
      },
      failure_store: { inherit: {} },
    },
  });

  it('streamFromDefinition routes a draft wired definition to DraftStream (not WiredStream)', () => {
    const record = streamFromDefinition(
      createDraftDefinitionWithChecksumStep(),
      createMockDependencies()
    );

    expect(record).toBeInstanceOf(DraftStream);
  });

  it('does not emit a processing upsert_ingest_pipeline on create, even with a checksum step', async () => {
    const draft = new DraftStream(
      createDraftDefinitionWithChecksumStep(),
      createMockDependencies()
    );
    const desiredState = createMockState(
      new Map([
        ['logs', { definition: createParentDefinition() }],
        ['logs.child', { definition: createDraftDefinitionWithChecksumStep() }],
      ])
    );

    const actions = await (draft as unknown as DraftStreamTestable).doDetermineCreateActions(
      desiredState
    );

    expect(actions.some((action) => action.type === 'upsert_ingest_pipeline')).toBe(false);
    // Drafts only write the `.streams` document and an ES|QL view.
    expect(actions.map((action) => action.type).sort()).toEqual([
      'upsert_dot_streams_document',
      'upsert_esql_view',
    ]);
  });

  it('does not emit a processing upsert_ingest_pipeline on update while still a draft', async () => {
    const draftDefinition = createDraftDefinitionWithChecksumStep();
    const draft = new DraftStream(draftDefinition, createMockDependencies());
    const startingStateStream = new DraftStream(draftDefinition, createMockDependencies());
    const desiredState = createMockState(
      new Map([
        ['logs', { definition: createParentDefinition() }],
        ['logs.child', { definition: draftDefinition }],
      ])
    );
    const startingState = createMockState(
      new Map([
        ['logs', { definition: createParentDefinition() }],
        ['logs.child', { definition: draftDefinition }],
      ])
    );

    const actions = await (draft as unknown as DraftStreamTestable).doDetermineUpdateActions(
      desiredState,
      startingState,
      startingStateStream
    );

    expect(actions.some((action) => action.type === 'upsert_ingest_pipeline')).toBe(false);
  });
});
