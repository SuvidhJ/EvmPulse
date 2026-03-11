import { Instruction, BasicBlock, AccessControlDetection } from '../types';

// Address mask commonly used by Solidity to truncate values to 20 bytes
const ADDRESS_MASK = 'ffffffffffffffffffffffffffffffffffffffff';

export function detectAccessControl(
  instructions: Instruction[],
  blocks: BasicBlock[]
): AccessControlDetection {
  const checks: AccessControlDetection['checks'] = [];
  const seen = new Set<number>(); // avoid duplicate reports at same offset

  for (const block of blocks) {
    for (let i = 0; i < block.instructions.length; i++) {
      const instr = block.instructions[i];
      if (instr.mnemonic !== 'CALLER') continue;
      if (seen.has(instr.offset)) continue;

      // Look ahead for comparison pattern.
      // Window of 25 instructions covers Solidity 0.4.x–0.8.x compiled owner checks,
      // where stack manipulation between CALLER and EQ can span many instructions.
      const lookAhead = block.instructions.slice(i + 1, i + 25);

      let foundSload = false;
      let sloadSlot: string | null = null;
      let foundPush20 = false;
      let hardcodedAddr: string | null = null;
      let foundEq = false;

      for (let j = 0; j < lookAhead.length; j++) {
        const next = lookAhead[j];

        if (next.mnemonic === 'SLOAD') {
          foundSload = true;
          // Try to get the slot from the instruction before SLOAD
          if (j > 0) {
            const prevInstr = lookAhead[j - 1];
            if (
              prevInstr.mnemonic.startsWith('PUSH') &&
              prevInstr.operandHex
            ) {
              sloadSlot = prevInstr.operandHex;
            }
          }
        }

        if (next.mnemonic === 'PUSH20' && next.operandHex) {
          const addrClean = next.operandHex.toLowerCase().replace('0x', '');
          // Skip the address mask — it's used for AND truncation, not comparison
          if (addrClean !== ADDRESS_MASK) {
            foundPush20 = true;
            hardcodedAddr = next.operandHex;
          }
        }

        if (next.mnemonic === 'EQ') {
          foundEq = true;
        }

        // Look for the full pattern: EQ + JUMPI (to revert)
        if (foundEq && next.mnemonic === 'JUMPI') {
          if (foundSload) {
            checks.push({
              offset: instr.offset,
              pattern: 'CALLER_SLOAD_EQ',
              storageSlot: sloadSlot,
              hardcodedAddress: null,
            });
            seen.add(instr.offset);
          } else if (foundPush20) {
            checks.push({
              offset: instr.offset,
              pattern: 'CALLER_PUSH20_EQ',
              storageSlot: null,
              hardcodedAddress: hardcodedAddr,
            });
            seen.add(instr.offset);
          }
          break;
        }
      }
    }
  }

  return {
    detected: checks.length > 0,
    checks,
  };
}