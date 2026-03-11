// ============================================================
// Function selector extraction from EVM dispatch table
// and resolution via 4byte.directory / OpenChain APIs
// ============================================================

import { Instruction, FunctionSelector, SelectorResult } from './types';
import { delay, operandToNumber } from './utils';

interface DispatchEntry {
  selector: string;
  handlerOffset: number | null;
}

/**
 * Extract function selectors from the bytecode dispatch table.
 * Handles both linear scan (PUSH4 + EQ + PUSH + JUMPI) and
 * binary search (PUSH4 + GT/LT + PUSH + JUMPI) dispatch patterns.
 */
export function extractSelectors(instructions: Instruction[]): SelectorResult {
  const entries: DispatchEntry[] = [];
  const selectorSet = new Set<string>();

  // Find the dispatch region boundary.
  // Heuristic: dispatch table is in the first portion of the code,
  // typically before the first significant JUMPDEST handler.
  // We look for PUSH4 + EQ/LT/GT patterns.

  // Collect all JUMPDEST offsets for reference
  const jumpdestOffsets = new Set<number>();
  for (const instr of instructions) {
    if (instr.mnemonic === 'JUMPDEST') {
      jumpdestOffsets.add(instr.offset);
    }
  }

  // Find all handler offsets to determine dispatch boundary
  const handlerOffsets: number[] = [];

  for (let i = 0; i < instructions.length; i++) {
    const instr = instructions[i];

    // Look for PUSH4 which could be a selector
    if (instr.mnemonic === 'PUSH4' && instr.operandHex) {
      const selectorHex = instr.operandHex.toLowerCase();

      // Look ahead for EQ + JUMPI (linear scan pattern)
      // or LT/GT + JUMPI (binary search pattern)
      let foundPattern = false;
      let handlerOffset: number | null = null;
      // Look ahead a few instructions for EQ (linear pattern) or GT/LT (binary search pattern)
      for (let j = i + 1; j < Math.min(i + 6, instructions.length); j++) {
        const ahead = instructions[j];

        if (ahead.mnemonic === 'EQ') {
          // Linear dispatch: selector EQ true → PUSH <handler offset> → JUMPI
          for (let k = j + 1; k < Math.min(j + 4, instructions.length); k++) {
            if (instructions[k].mnemonic === 'JUMPI') {
              // Walk backwards from JUMPI to find the PUSH that gives us the handler offset
              for (let m = k - 1; m > j; m--) {
                if (instructions[m].mnemonic.startsWith('PUSH') && instructions[m].operand) {
                  const targetBytes = instructions[m].operand!;
                  let target = 0;
                  for (let b = 0; b < targetBytes.length; b++) {
                    target = (target << 8) | targetBytes[b];
                  }
                  handlerOffset = target;
                  break;
                }
              }
              foundPattern = true;
              break;
            }
          }
          break;
        }

        if (ahead.mnemonic === 'GT' || ahead.mnemonic === 'LT') {
          // Binary search: the PUSH4 is a pivot used for comparison, but it's still a valid selector
          foundPattern = true;
          // We can't resolve the handler from here — it's deeper in the binary search tree
          handlerOffset = null;
          break;
        }
      }

      if (foundPattern && !selectorSet.has(selectorHex)) {
        selectorSet.add(selectorHex);
        entries.push({ selector: selectorHex, handlerOffset });
        if (handlerOffset !== null) {
          handlerOffsets.push(handlerOffset);
        }
      } else if (foundPattern && selectorSet.has(selectorHex) && handlerOffset !== null) {
        // Binary search dispatch: the selector was first seen as a GT/LT pivot
        // (with null handler), and now we found its EQ entry with the real handler.
        const existing = entries.find(e => e.selector === selectorHex);
        if (existing && existing.handlerOffset === null) {
          existing.handlerOffset = handlerOffset;
          handlerOffsets.push(handlerOffset);
        }
      }
    }
  }

  // The dispatch region ends where the first handler begins
  // (i.e., the lowest handler offset marks the boundary between dispatch table and function bodies)
  const dispatchEnd =
    handlerOffsets.length > 0 ? Math.min(...handlerOffsets) : 0;

  // Detect fallback — look for the dispatch's default case
  // (usually a JUMP/JUMPI to a REVERT or a receive/fallback function)
  let fallbackOffset: number | null = null;
  for (let i = 0; i < instructions.length; i++) {
    const instr = instructions[i];
    if (instr.offset >= dispatchEnd && dispatchEnd > 0) break;

    // After last selector comparison, a JUMP or PUSH+JUMP to fallback
    if (
      instr.mnemonic === 'JUMP' &&
      i > 0 &&
      instructions[i - 1].mnemonic.startsWith('PUSH') &&
      instructions[i - 1].operand
    ) {
      const target = operandToNumber(instructions[i - 1].operand!);
      if (target !== null && !handlerOffsets.includes(target)) {
        fallbackOffset = target;
      }
    }
  }

  const functions: FunctionSelector[] = entries.map((e) => ({
    selector: e.selector,
    signatures: [],
    handlerOffset: e.handlerOffset,
    parameterHints: [],
    isPayable: null,
  }));

  return {
    count: functions.length,
    dispatchEndOffset: dispatchEnd,
    functions,
    fallbackOffset,
  };
}

/**
 * Resolve selectors to human-readable signatures using external APIs.
 * Uses batch querying where possible for performance.
 */
export async function resolveSelectors(
  selectors: FunctionSelector[]
): Promise<void> {
  if (selectors.length === 0) return;

  // OpenChain supports batch lookups — resolve all selectors in one request
  const unresolved = new Set<string>();
  try {
    const allSelectors = selectors.map((f) => f.selector);
    const batchResults = await batchResolveViaOpenChain(allSelectors);
    for (const func of selectors) {
      const sigs = batchResults.get(func.selector);
      if (sigs && sigs.length > 0) {
        func.signatures = sigs;
      } else {
        unresolved.add(func.selector);
      }
    }
  } catch {
    // Batch failed — mark all as unresolved for individual fallback
    for (const func of selectors) {
      unresolved.add(func.selector);
    }
  }

  // Fallback: resolve remaining individually via 4byte.directory
  for (const func of selectors) {
    if (!unresolved.has(func.selector)) continue;
    try {
      const sigs = await resolveVia4byte(func.selector);
      if (sigs.length > 0) {
        func.signatures = sigs;
      }
      await delay(50); // rate limit for sequential fallback
    } catch {
      // API failure — leave empty, don't crash
    }
  }
}

/**
 * Batch resolve selectors via OpenChain API.
 * Sends all selectors in a single request (comma-separated).
 * Returns a map: selector → array of signature strings.
 */
async function batchResolveViaOpenChain(
  selectors: string[]
): Promise<Map<string, string[]>> {
  const results = new Map<string, string[]>();
  if (selectors.length === 0) return results;

  // OpenChain supports comma-separated selectors in a single lookup
  const joined = selectors.map((s) => encodeURIComponent(s)).join(',');
  const url = `https://api.openchain.xyz/signature-database/v1/lookup?function=${joined}&filter=true`;
  const resp = await fetch(url, { signal: AbortSignal.timeout(10000) });
  if (!resp.ok) return results;

  const data: any = await resp.json();
  const funcResults = data?.result?.function;
  if (!funcResults) return results;

  for (const selector of selectors) {
    const entries = funcResults[selector];
    if (entries && Array.isArray(entries)) {
      const sigs = entries.map((r: any) => r.name).filter(Boolean);
      if (sigs.length > 0) {
        results.set(selector, sigs);
      }
    }
  }

  return results;
}

async function resolveVia4byte(selector: string): Promise<string[]> {
  const clean = selector.startsWith('0x') ? selector : '0x' + selector;
  const url = `https://www.4byte.directory/api/v1/signatures/?hex_signature=${encodeURIComponent(clean)}&ordering=created_at`;
  const resp = await fetch(url, { signal: AbortSignal.timeout(5000) });
  if (!resp.ok) return [];
  const data: any = await resp.json();
  if (!data?.results || !Array.isArray(data.results)) return [];
  return data.results.map((r: any) => r.text_signature).filter(Boolean);
}

/**
 * Infer parameter types from bytecode patterns after a function handler JUMPDEST.
 * Heuristics are documented inline at each detection point below.
 */
export function inferParameters(
  instructions: Instruction[],
  handlerOffset: number
): string[] {
  const params: string[] = [];
  const calldataSlots = new Map<number, number>(); // slot offset → instruction index

  // Find the handler start
  let startIdx = -1;
  for (let i = 0; i < instructions.length; i++) {
    if (instructions[i].offset === handlerOffset) {
      startIdx = i;
      break;
    }
  }
  if (startIdx < 0) return params;

  // Scan the next ~60 instructions for CALLDATALOAD patterns
  const endIdx = Math.min(startIdx + 60, instructions.length);
  for (let i = startIdx; i < endIdx; i++) {
    const instr = instructions[i];

    // Heuristic 1: Detect PUSH <offset> + CALLDATALOAD patterns.
    // Solidity ABI packs params as 32-byte slots starting at offset 4 (after the selector).
    // So offset 0x04 = param 0, 0x24 = param 1, 0x44 = param 2, etc.
    if (
      instr.mnemonic === 'CALLDATALOAD' &&
      i > 0 &&
      instructions[i - 1].mnemonic.startsWith('PUSH') &&
      instructions[i - 1].operand
    ) {
      const slotOffset = operandToNumber(instructions[i - 1].operand!);
      if (slotOffset !== null && slotOffset >= 4 && (slotOffset - 4) % 32 === 0) {
        const paramIndex = (slotOffset - 4) / 32;
        calldataSlots.set(paramIndex, i);

        // Heuristic 2: Infer type from operations applied after loading the param.
        // AND with a 20-byte mask → address, ISZERO → bool, etc.
        let paramType = 'uint256'; // default if no mask/type clue found
        for (let j = i + 1; j < Math.min(i + 6, endIdx); j++) {
          const next = instructions[j];

          if (next.mnemonic === 'AND' && j > 0) {
            // Solidity masks calldataload results to truncate to the actual type size
            const prev = instructions[j - 1];
            if (prev.operandHex) {
              const mask = prev.operandHex.toLowerCase().replace('0x', '');
              if (
                mask ===
                'ffffffffffffffffffffffffffffffffffffffff'
              ) {
                paramType = 'address'; // 20-byte mask = address type
              } else if (mask === 'ff') {
                paramType = 'uint8';
              } else if (mask === 'ffff') {
                paramType = 'uint16';
              } else if (
                mask ===
                'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
              ) {
                paramType = 'uint256'; // full 32-byte mask — effectively no truncation
              }
            }
          }

          if (next.mnemonic === 'ISZERO') {
            paramType = 'bool';
            break;
          }
        }

        // Ensure params array is big enough
        while (params.length <= paramIndex) params.push('uint256');
        params[paramIndex] = paramType;
      }
    }
  }

  return params;
}
