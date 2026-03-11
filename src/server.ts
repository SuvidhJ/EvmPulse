// ============================================================
// REST API server (Fastify)
// ============================================================

import Fastify, { FastifyInstance } from 'fastify';
import cors from '@fastify/cors';
import { getChainConfig, CHAINS } from './chains';
import { analyze } from './analyzer';
import { AnalysisFlags, Instruction } from './types';
import dotenv from 'dotenv';

dotenv.config();

/**
 * Build and configure the Fastify application with all routes.
 * Exported for testability (fastify.inject in tests).
 */
export async function buildApp(options: { logger?: boolean } = {}): Promise<FastifyInstance> {
  const app = Fastify({ logger: options.logger ?? true });
  await app.register(cors, { origin: true });

  // --- Simple in-memory rate limiter ---
  const rateLimitMap = new Map<string, { count: number; resetTime: number }>();
  const RATE_LIMIT_WINDOW = 60_000; // 1 minute
  const RATE_LIMIT_MAX = 30; // max requests per window

  app.addHook('onRequest', async (request, reply) => {
    const ip = request.ip;
    const now = Date.now();
    const entry = rateLimitMap.get(ip);

    if (!entry || now > entry.resetTime) {
      rateLimitMap.set(ip, { count: 1, resetTime: now + RATE_LIMIT_WINDOW });
      return;
    }

    entry.count++;
    if (entry.count > RATE_LIMIT_MAX) {
      reply.header('Retry-After', '60');
      return reply.status(429).send({ error: 'Too many requests. Try again later.' });
    }
  });

  // Health check
  app.get('/health', async () => {
    return {
      status: 'ok',
      supportedChains: Object.keys(CHAINS),
      timestamp: new Date().toISOString(),
    };
  });

  // Main analysis endpoint
  app.post<{
    Body: {
      address: string;
      chain?: string;
      rpc?: string;
      analyses?: string[];
    };
  }>('/analyze', {
    schema: {
      body: {
        type: 'object',
        required: ['address'],
        properties: {
          address: { type: 'string' },
          chain: { type: 'string' },
          rpc: { type: 'string' },
          analyses: {
            type: 'array',
            items: { type: 'string' },
          },
        },
      },
    },
    handler: async (request, reply) => {
      const { address, chain = 'ethereum', rpc, analyses } = request.body;

      // Validate address format
      if (!/^0x[a-fA-F0-9]{40}$/.test(address)) {
        return reply
          .status(400)
          .send({ error: 'Invalid Ethereum address format' });
      }

      // Validate RPC URL if provided — block SSRF to private/internal networks
      if (rpc !== undefined) {
        try {
          const parsed = new URL(rpc);
          if (!['http:', 'https:', 'wss:', 'ws:'].includes(parsed.protocol)) {
            return reply
              .status(400)
              .send({ error: 'RPC URL must use http, https, ws, or wss protocol' });
          }
          // Block private/internal hostnames to prevent SSRF
          const hostname = parsed.hostname.toLowerCase();
          const blockedPatterns = [
            /^localhost$/,
            /^127\.\d+\.\d+\.\d+$/,
            /^10\.\d+\.\d+\.\d+$/,
            /^172\.(1[6-9]|2\d|3[01])\.\d+\.\d+$/,
            /^192\.168\.\d+\.\d+$/,
            /^169\.254\.\d+\.\d+$/,   // link-local
            /^0\.0\.0\.0$/,
            /^\[?::1\]?$/,            // IPv6 loopback
            /^\[?fe80:/i,             // IPv6 link-local
            /^\[?fc00:/i,             // IPv6 unique local
            /^\[?fd/i,                // IPv6 unique local
          ];
          if (blockedPatterns.some(p => p.test(hostname))) {
            return reply
              .status(400)
              .send({ error: 'RPC URL must not point to private/internal networks' });
          }
        } catch {
          return reply
            .status(400)
            .send({ error: 'Invalid RPC URL format' });
        }
      }

      try {
        const chainConfig = getChainConfig(chain, rpc);

        const allAnalyses =
          !analyses || analyses.length === 0
            ? ['disasm', 'selectors', 'cfg', 'security']
            : analyses;

        const flags: AnalysisFlags = {
          disasm: allAnalyses.includes('disasm'),
          selectors: allAnalyses.includes('selectors'),
          cfg: allAnalyses.includes('cfg'),
          security: allAnalyses.includes('security'),
        };

        const report = await analyze(address, chainConfig, flags);

        // Clean up the report for JSON response
        // Remove raw instruction data that would make the response huge
        const responseReport: Record<string, unknown> = { ...report };
        if (responseReport.disassembly) {
          responseReport.disassembly = {
            instructionCount: report.disassembly!.instructions.length,
            codeBytes: report.disassembly!.codeBytes,
            dataBytes: report.disassembly!.dataBytes,
            metadata: report.disassembly!.metadata,
            // Include first and last 20 instructions for preview
            firstInstructions: report.disassembly!.instructions
              .slice(0, 20)
              .map(instrToJson),
            lastInstructions: report.disassembly!.instructions
              .slice(-10)
              .map(instrToJson),
          };
        }

        if (responseReport.cfg) {
          responseReport.cfg = {
            totalBlocks: report.cfg!.totalBlocks,
            totalEdges: report.cfg!.totalEdges,
            terminalBlocks: report.cfg!.terminalBlocks,
            jumpResolution: report.cfg!.jumpResolution,
            // Include block summaries, not full instructions
            blocks: report.cfg!.blocks.map((b) => ({
              id: b.id,
              startOffset: '0x' + b.startOffset.toString(16),
              endOffset: '0x' + b.endOffset.toString(16),
              instructionCount: b.instructions.length,
              terminator: b.terminator,
            })),
            edges: report.cfg!.edges,
            adjacencyList: report.cfg!.adjacencyList,
            dot: report.cfg!.dot,
          };
        }

        return reply.send(responseReport);
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : 'Unknown analysis error';
        return reply.status(500).send({
          error: message,
        });
      }
    },
  });

  // Disassembly-only endpoint for quick use
  app.get<{
    Params: { address: string };
    Querystring: { chain?: string };
  }>('/disasm/:address', async (request, reply) => {
    const { address } = request.params;
    const chain = request.query.chain || 'ethereum';

    if (!/^0x[a-fA-F0-9]{40}$/.test(address)) {
      return reply
        .status(400)
        .send({ error: 'Invalid Ethereum address format' });
    }

    try {
      const chainConfig = getChainConfig(chain);
      const report = await analyze(address, chainConfig, {
        disasm: true,
        selectors: true,
        cfg: false,
        security: false,
      });

      return reply.send({
        address,
        chain,
        bytecodeSize: report.bytecodeSize,
        metadata: report.metadata,
        selectors: report.selectors,
        instructions: report.disassembly?.instructions.map(instrToJson),
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      return reply.status(500).send({ error: message });
    }
  });

  return app;
}

function instrToJson(instr: Instruction) {
  return {
    offset: '0x' + instr.offset.toString(16).padStart(4, '0'),
    opcode: '0x' + instr.opcodeByte.toString(16).padStart(2, '0'),
    mnemonic: instr.mnemonic,
    operand: instr.operandHex || undefined,
  };
}

async function start() {
  const app = await buildApp();

  const port = parseInt(process.env.PORT || '3000');
  const host = process.env.HOST || '0.0.0.0';

  // Graceful shutdown
  const shutdown = async () => {
    await app.close();
    process.exit(0);
  };
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);

  await app.listen({ port, host });
  console.log(`\n  EVM Analyzer API running on http://${host}:${port}`);
  console.log(`  Health: GET /health`);
  console.log(`  Analyze: POST /analyze`);
  console.log(`  Quick disasm: GET /disasm/:address\n`);
}

if (require.main === module) {
  start().catch((err) => {
    console.error('Failed to start server:', err);
    process.exit(1);
  });
}