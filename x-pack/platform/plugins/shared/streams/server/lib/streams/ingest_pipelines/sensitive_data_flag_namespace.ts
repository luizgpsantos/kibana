/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { Streams } from '@kbn/streams-schema';
import { isOtelStream } from '@kbn/streams-schema';

/**
 * Namespace the sensitive_data processor writes its telemetry flags to (`<ns>.detected`,
 * `<ns>.categories`). OTel streams keep custom fields under `attributes.*`; ECS/classic streams use
 * the default top-level `sensitive_data` custom field set (returned as `undefined` so the
 * transpiler falls back to its default). Shared between the saved ingest pipeline and the
 * `_simulate` preview so the live preview matches what gets persisted.
 */
export const getSensitiveDataFlagNamespace = (
  definition: Streams.all.Definition
): string | undefined => (isOtelStream(definition) ? 'attributes.sensitive_data' : undefined);
