// ============================================================
// Linear sweep disassembler for EVM bytecode
//
// EVM bytecode is a flat byte array executed by the Ethereum Virtual
// Machine. This module performs a linear sweep — reading bytes from
// offset 0 onwards, decoding each opcode and its operands.
//
// Linear sweep is simpler than recursive descent but may misinterpret
// data embedded in code sections. We mitigate this by stripping the
// CBOR metadata appended by solc before disassembling.
// ============================================================

import { Instruction, DisassemblyResult, BasicBlock } from './types';
import { getOpcodeInfo } from './opcodes';
import { separateMetadata } from './metadata';
import { bytesToHex, toHex, bfs } from './utils';

/**
 * Disassemble raw EVM bytecode into a list of instructions.
 */
export function disassemble(rawBytecode: Uint8Array): DisassemblyResult {
  const { executableCode, metadata } = separateMetadata(rawBytecode);
  const instructions: Instruction[] = [];

  let offset = 0;
  while (offset < executableCode.length) {
    const opcodeByte = executableCode[offset];
    const info = getOpcodeInfo(opcodeByte);

    let operand: Uint8Array | null = null;
    let operandHex: string | null = null;

    if (info.operandSize > 0) {
      const end = Math.min(offset + 1 + info.operandSize, executableCode.length);
      operand = executableCode.slice(offset + 1, end);
      operandHex = bytesToHex(operand);
    }

    instructions.push({
      offset,
      opcodeByte,
      mnemonic: info.mnemonic,
      operand,
      operandHex,
      info,
    });

    offset += 1 + info.operandSize;
  }

  return {
    instructions,
    codeBytes: executableCode.length,
    dataBytes: rawBytecode.length - executableCode.length,
    unreachableBytes: 0,
    metadata,
    rawBytecodeHex: bytesToHex(rawBytecode),
  };
}

/**
 * Classify code vs data bytes using CFG reachability analysis.
 * Bytes belonging to basic blocks not reachable from block 0
 * (the entry point) are considered embedded data, not code.
 * Updates the disassembly result in place.
 */
export function classifyCodeData(
  result: DisassemblyResult,
  blocks: BasicBlock[],
  adjacencyList: Record<number, number[]>
): void {
  if (blocks.length === 0) return;

  // Convert Record to Map for bfs()
  const adjMap = new Map<number, number[]>();
  for (const [key, val] of Object.entries(adjacencyList)) {
    adjMap.set(Number(key), val);
  }

  // BFS from block 0 to find all reachable blocks
  const reachable = bfs(adjMap, 0);

  let unreachable = 0;
  for (const block of blocks) {
    if (!reachable.has(block.id)) {
      // Count bytes in unreachable blocks
      for (const instr of block.instructions) {
        unreachable += 1 + (instr.operand ? instr.operand.length : 0);
      }
    }
  }

  result.unreachableBytes = unreachable;
}

/**
 * Format disassembly as human-readable annotated text
 */
export function formatDisassembly(
  result: DisassemblyResult,
  selectorMap?: Map<string, string[]>
): string {
  const lines: string[] = [];

  lines.push(`; Bytecode size: ${result.codeBytes + result.dataBytes} bytes`);
  lines.push(`; Executable code: ${result.codeBytes} bytes`);
  lines.push(`; Metadata: ${result.dataBytes} bytes`);
  if (result.unreachableBytes > 0) {
    lines.push(`; Unreachable (data) bytes: ${result.unreachableBytes} bytes`);
  }

  if (result.metadata.detected) {
    if (result.metadata.solcVersion) {
      lines.push(`; Solidity compiler: v${result.metadata.solcVersion}`);
    }
    if (result.metadata.ipfsHash) {
      lines.push(`; IPFS hash: ${result.metadata.ipfsHash}`);
    }
    if (result.metadata.bzzr0Hash) {
      lines.push(`; Swarm (bzzr0): ${result.metadata.bzzr0Hash}`);
    }
    if (result.metadata.bzzr1Hash) {
      lines.push(`; Swarm (bzzr1): ${result.metadata.bzzr1Hash}`);
    }
  }
  lines.push('');

  for (const instr of result.instructions) {
    const offsetStr = toHex(instr.offset);

    // Build raw bytes column
    let rawBytes = instr.opcodeByte.toString(16).padStart(2, '0');
    if (instr.operand) {
      rawBytes += ' ' + bytesToHex(instr.operand, false);
    }

    // Build line
    let line = `${offsetStr}: ${rawBytes.padEnd(22)} ${instr.mnemonic.padEnd(14)}`;
    if (instr.operandHex) {
      line += ` ${instr.operandHex}`;
    }

    // Annotate known selectors
    if (
      selectorMap &&
      instr.mnemonic === 'PUSH4' &&
      instr.operandHex
    ) {
      const sigs = selectorMap.get(instr.operandHex.toLowerCase());
      if (sigs && sigs.length > 0) {
        line += `    // ${sigs[0]}`;
      }
    }

    // Mark JUMPDEST
    if (instr.mnemonic === 'JUMPDEST') {
      line += `    // <--- jump target`;
    }

    lines.push(line);
  }

  return lines.join('\n');
}