/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { BasicPrettyPrinter, Builder } from '@elastic/esql';
import type { ESQLAstCommand } from '@elastic/esql/types';
import { conditionToESQLAst } from './condition_to_esql';

import type { ESQLTranspilationOptions } from '.';
import type {
  AppendProcessor,
  ConvertProcessor,
  DateProcessor,
  DissectProcessor,
  DropDocumentProcessor,
  GrokProcessor,
  MathProcessor,
  RedactProcessor,
  RemoveByPrefixProcessor,
  RemoveProcessor,
  RenameProcessor,
  ReplaceProcessor,
  SetProcessor,
  UppercaseProcessor,
  LowercaseProcessor,
  TrimProcessor,
  JoinProcessor,
  SplitProcessor,
  SortProcessor,
  ConcatProcessor,
  NetworkDirectionProcessor,
  JsonExtractProcessor,
  EnrichProcessor,
  UserAgentProcessor,
  UriPartsProcessor,
  RegisteredDomainProcessor,
  SensitiveDataProcessor,
} from '../../../types/processors';
import { type StreamlangProcessorDefinition } from '../../../types/processors';
import {
  getStreamlangResolverForProcessor,
  type StreamlangResolver,
  type StreamlangResolverOptions,
} from '../../../types/resolvers';
import { convertAppendProcessorToESQL } from './processors/append';
import { convertConvertProcessorToESQL } from './processors/convert';
import { convertDateProcessorToESQL } from './processors/date';
import { convertDissectProcessorToESQL } from './processors/dissect';
import { convertDropDocumentProcessorToESQL } from './processors/drop_document';
import { convertGrokProcessorToESQL } from './processors/grok';
import { convertJoinProcessorToESQL } from './processors/join';
import { convertMathProcessorToESQL } from './processors/math';
import { convertRedactProcessorToESQL } from './processors/redact';
import { convertRemoveProcessorToESQL } from './processors/remove';
import { convertRemoveByPrefixProcessorToESQL } from './processors/remove_by_prefix';
import { convertRenameProcessorToESQL } from './processors/rename';
import { convertReplaceProcessorToESQL } from './processors/replace';
import { convertSetProcessorToESQL } from './processors/set';
import { convertSortProcessorToESQL } from './processors/sort';
import { convertSplitProcessorToESQL } from './processors/split';
import { createTransformStringESQL } from './transform_string';
import { convertConcatProcessorToESQL } from './processors/concat';
import { convertNetworkDirectionProcessorToESQL } from './processors/network_direction';
import { convertJsonExtractProcessorToESQL } from './processors/json_extract';
import { convertEnrichProcessorToESQL } from './processors/enrich';
import { convertUserAgentProcessorToESQL } from './processors/user_agent';
import { convertUriPartsProcessorToESQL } from './processors/uri_parts';
import { convertRegisteredDomainProcessorToESQL } from './processors/registered_domain';
import { convertSensitiveDataProcessorToESQL } from './processors/sensitive_data';

interface ProcessorToESQLResult {
  commands: ESQLAstCommand[] | null;
  warnings: string[];
}

async function convertProcessorToESQL(
  processor: StreamlangProcessorDefinition,
  resolver?: StreamlangResolver
): Promise<ProcessorToESQLResult> {
  switch (processor.action) {
    case 'rename':
      return { commands: convertRenameProcessorToESQL(processor as RenameProcessor), warnings: [] };

    case 'set':
      return { commands: convertSetProcessorToESQL(processor as SetProcessor), warnings: [] };

    case 'append':
      return { commands: convertAppendProcessorToESQL(processor as AppendProcessor), warnings: [] };

    case 'convert':
      return {
        commands: convertConvertProcessorToESQL(processor as ConvertProcessor),
        warnings: [],
      };

    case 'date':
      return { commands: convertDateProcessorToESQL(processor as DateProcessor), warnings: [] };

    case 'dissect':
      return {
        commands: convertDissectProcessorToESQL(processor as DissectProcessor),
        warnings: [],
      };

    case 'grok':
      return { commands: convertGrokProcessorToESQL(processor as GrokProcessor), warnings: [] };

    case 'uri_parts':
      return {
        commands: convertUriPartsProcessorToESQL(processor as UriPartsProcessor),
        warnings: [],
      };

    case 'math':
      return { commands: convertMathProcessorToESQL(processor as MathProcessor), warnings: [] };

    case 'remove_by_prefix':
      return {
        commands: convertRemoveByPrefixProcessorToESQL(processor as RemoveByPrefixProcessor),
        warnings: [],
      };

    case 'remove':
      return { commands: convertRemoveProcessorToESQL(processor as RemoveProcessor), warnings: [] };

    case 'drop_document':
      return {
        commands: convertDropDocumentProcessorToESQL(processor as DropDocumentProcessor),
        warnings: [],
      };

    case 'replace':
      return {
        commands: convertReplaceProcessorToESQL(processor as ReplaceProcessor),
        warnings: [],
      };

    case 'redact':
      return { commands: convertRedactProcessorToESQL(processor as RedactProcessor), warnings: [] };

    case 'sensitive_data': {
      const { commands, warnings } = convertSensitiveDataProcessorToESQL(
        processor as SensitiveDataProcessor
      );
      return { commands, warnings };
    }

    case 'uppercase': {
      const convertUppercaseProcessorToESQL = createTransformStringESQL('TO_UPPER');
      return {
        commands: convertUppercaseProcessorToESQL(processor as UppercaseProcessor),
        warnings: [],
      };
    }

    case 'lowercase': {
      const convertLowercaseProcessorToESQL = createTransformStringESQL('TO_LOWER');
      return {
        commands: convertLowercaseProcessorToESQL(processor as LowercaseProcessor),
        warnings: [],
      };
    }

    case 'trim': {
      const convertTrimProcessorToESQL = createTransformStringESQL('TRIM');
      return {
        commands: convertTrimProcessorToESQL(processor as TrimProcessor),
        warnings: [],
      };
    }

    case 'join':
      return { commands: convertJoinProcessorToESQL(processor as JoinProcessor), warnings: [] };

    case 'split':
      return { commands: convertSplitProcessorToESQL(processor as SplitProcessor), warnings: [] };

    case 'sort':
      return { commands: convertSortProcessorToESQL(processor as SortProcessor), warnings: [] };

    case 'concat':
      return { commands: convertConcatProcessorToESQL(processor as ConcatProcessor), warnings: [] };

    case 'network_direction':
      return {
        commands: convertNetworkDirectionProcessorToESQL(processor as NetworkDirectionProcessor),
        warnings: [],
      };

    case 'json_extract':
      return {
        commands: convertJsonExtractProcessorToESQL(processor as JsonExtractProcessor),
        warnings: [],
      };

    case 'enrich':
      if (!resolver) {
        throw new Error('Enrich policy resolver is required for enrich processor.');
      }
      return {
        commands: await convertEnrichProcessorToESQL(processor as EnrichProcessor, resolver),
        warnings: [],
      };

    case 'user_agent':
      return {
        commands: convertUserAgentProcessorToESQL(processor as UserAgentProcessor),
        warnings: [],
      };

    case 'registered_domain':
      return {
        commands: convertRegisteredDomainProcessorToESQL(processor as RegisteredDomainProcessor),
        warnings: [],
      };

    case 'manual_ingest_pipeline':
      return {
        commands: [
          Builder.command({
            name: 'eval',
            args: [
              Builder.expression.literal.string(
                'WARNING: Manual ingest pipeline not supported in ES|QL'
              ),
            ],
          }),
        ],
        warnings: [],
      };

    default:
      return { commands: null, warnings: [] };
  }
}

export interface StreamlangToESQLCommandsResult {
  query: string;
  warnings: string[];
}

export async function convertStreamlangDSLToESQLCommands(
  actionSteps: StreamlangProcessorDefinition[],
  transpilationOptions: ESQLTranspilationOptions,
  resolverOptions?: StreamlangResolverOptions
): Promise<StreamlangToESQLCommandsResult> {
  const resolved = await Promise.all(
    actionSteps.map((processor) =>
      convertProcessorToESQL(
        processor,
        getStreamlangResolverForProcessor(processor, resolverOptions)
      )
    )
  );

  const esqlAstCommands = resolved.flatMap(({ commands }) => (commands === null ? [] : commands));

  const warnings = resolved.flatMap(({ warnings: processorWarnings }) => processorWarnings);

  const query = BasicPrettyPrinter.multiline(Builder.expression.query(esqlAstCommands), {
    pipeTab: transpilationOptions.pipeTab,
  });

  return { query, warnings };
}

/**
 * Converts a condition to ES|QL string format using the existing AST approach
 * @example: { field: "age", range: { gte: 18, lt: 65 } } -> "age >= 18 AND age < 65"
 */
export function convertConditionToESQL(
  condition: Parameters<typeof conditionToESQLAst>[0]
): string {
  const ast = conditionToESQLAst(condition);
  return BasicPrettyPrinter.print(ast);
}
