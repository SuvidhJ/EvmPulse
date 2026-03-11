// ============================================================
// Security pattern detection orchestrator
//
// Runs all 6 security heuristic detectors in parallel where possible.
// Each detector analyzes the bytecode for a specific vulnerability pattern.
// ============================================================

import { Instruction, BasicBlock, CFGEdge, SecurityReport, FunctionSelector, ChainConfig } from '../types';
import { detectProxy } from './proxy';
import { detectSelfdestruct } from './selfdestruct';
import { detectUncheckedCalls } from './unchecked-calls';
import { detectAccessControl } from './access-control';
import { detectReentrancyGuard } from './reentrancy';
import { detectPayable } from './payable';

export async function runSecurityAnalysis(
  instructions: Instruction[],
  bytecode: Uint8Array,
  blocks: BasicBlock[],
  edges: CFGEdge[],
  selectors: FunctionSelector[],
  address: string,
  chain: ChainConfig
): Promise<SecurityReport> {
  // Start async proxy detection (needs RPC calls for storage slot reads)
  const proxyPromise = detectProxy(instructions, bytecode, address, chain);

  // Run pure bytecode detectors while proxy detection is in flight
  const selfdestruct = detectSelfdestruct(instructions, blocks, edges);
  const uncheckedCalls = detectUncheckedCalls(instructions, blocks);
  const accessControl = detectAccessControl(instructions, blocks);
  const reentrancyGuard = detectReentrancyGuard(instructions, blocks);
  const payable = detectPayable(instructions, blocks, selectors);

  // Await the async result
  const proxy = await proxyPromise;

  return {
    proxy,
    selfdestruct,
    uncheckedCalls,
    accessControl,
    reentrancyGuard,
    payable,
  };
}