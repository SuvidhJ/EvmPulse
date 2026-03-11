import { Instruction, BasicBlock, UncheckedCallDetection, UncheckedCallInfo } from '../types';

const CALL_OPCODES = new Set(['CALL', 'STATICCALL', 'DELEGATECALL', 'CALLCODE']);

export function detectUncheckedCalls(
  instructions: Instruction[],
  blocks: BasicBlock[]
): UncheckedCallDetection {
  const details: UncheckedCallInfo[] = [];

  for (const block of blocks) {
    for (let i = 0; i < block.instructions.length; i++) {
      const instr = block.instructions[i];
      if (!CALL_OPCODES.has(instr.mnemonic)) continue;

      // CALL pushes a success boolean onto the stack.
      // Check if it's consumed by ISZERO (which is the checked pattern)
      let checked = false;

      // Look ahead in this block and potentially the start of next
      const lookAhead = block.instructions.slice(i + 1, i + 8);
      for (let j = 0; j < lookAhead.length; j++) {
        const next = lookAhead[j];

        // Checked: ISZERO → PUSH → JUMPI (reverts on failure)
        if (next.mnemonic === 'ISZERO') {
          checked = true;
          break;
        }

        // Checked: directly compared or stored
        if (next.mnemonic === 'AND' || next.mnemonic === 'EQ') {
          checked = true;
          break;
        }

        // Unchecked: POP discards the return value
        if (next.mnemonic === 'POP') {
          checked = false;
          break;
        }

        // If we hit a SWAP, the return value might be moved — track it
        if (next.mnemonic.startsWith('SWAP')) {
          // Continue looking — it might be checked later
          continue;
        }

        // DUP might duplicate return value for checking
        if (next.mnemonic.startsWith('DUP')) {
          continue;
        }
      }

      details.push({
        offset: instr.offset,
        type: instr.mnemonic,
        checked,
      });
    }
  }

  const uncheckedCount = details.filter((d) => !d.checked).length;

  return {
    detected: uncheckedCount > 0,
    count: uncheckedCount,
    details,
  };
}