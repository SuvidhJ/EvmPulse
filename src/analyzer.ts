// ============================================================
// Main analysis pipeline orchestrator
// Ties all stages together: fetch → disassemble → selectors →
// CFG → security
// ============================================================

import { ChainConfig, AnalysisFlags, AnalysisReport } from './types';
import { fetchBytecode } from './fetcher';
import { disassemble, classifyCodeData } from './disassembler';
import {
  extractSelectors,
  resolveSelectors,
  inferParameters,
} from './selectors';
import { buildCFG } from './cfg';
import { runSecurityAnalysis } from './security';
import { detectERC165 } from './erc165';

export async function analyze(
  address: string,
  chain: ChainConfig,
  flags: AnalysisFlags
): Promise<AnalysisReport> {
  // Normalize address
  const addr = address.toLowerCase();

  // Stage 1: Fetch bytecode
  const { bytecode, hex } = await fetchBytecode(addr, chain);

  // Stage 2: Disassemble
  const disassemblyResult = disassemble(bytecode);
  const { instructions, metadata } = disassemblyResult;

  const report: AnalysisReport = {
    address: addr,
    chain: chain.name,
    bytecodeSize: bytecode.length,
    isContract: true,
    metadata,
    timestamp: new Date().toISOString(),
  };

  if (flags.disasm) {
    report.disassembly = disassemblyResult;
  }

  // Stage 3: Extract & resolve selectors
  const selectorResult = extractSelectors(instructions);

  if (flags.selectors) {
    // Resolve via APIs
    await resolveSelectors(selectorResult.functions);

    // Infer parameter types for functions with known handler offsets
    for (const func of selectorResult.functions) {
      if (func.handlerOffset !== null) {
        func.parameterHints = inferParameters(
          instructions,
          func.handlerOffset
        );
      }
    }

    report.selectors = selectorResult;
  }

  // Stage 4: Build CFG
  const cfgResult = buildCFG(instructions);

  // Classify code vs data bytes using CFG reachability
  classifyCodeData(disassemblyResult, cfgResult.blocks, cfgResult.adjacencyList);

  if (flags.cfg) {
    report.cfg = cfgResult;
  }

  // Stage 5: Security analysis
  if (flags.security) {
    report.security = await runSecurityAnalysis(
      instructions,
      bytecode,
      cfgResult.blocks,
      cfgResult.edges,
      selectorResult.functions,
      addr,
      chain
    );

    // Update isPayable field on each function selector based on security analysis
    if (report.security.payable && report.selectors) {
      const payableSet = new Set(report.security.payable.payableFunctions);
      const nonPayableSet = new Set(report.security.payable.nonPayableFunctions);
      for (const func of report.selectors.functions) {
        if (payableSet.has(func.selector)) {
          func.isPayable = true;
        } else if (nonPayableSet.has(func.selector)) {
          func.isPayable = false;
        }
      }
    }
  }

  // Stage 6: ERC-165 interface detection (via eth_call)
  // Only run when security analysis is enabled — avoids unnecessary RPC calls
  // when user only wants disassembly or CFG
  if (flags.security) {
    try {
      report.erc165 = await detectERC165(addr, chain);
    } catch {
      // ERC-165 detection is best-effort; don't fail the whole analysis
    }
  }

  return report;
}