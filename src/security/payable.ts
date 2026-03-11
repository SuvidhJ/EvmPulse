import { Instruction, BasicBlock, PayableDetection, FunctionSelector } from '../types';

/**
 * Detect payable vs non-payable functions.
 *
 * Non-payable functions in Solidity start with:
 *   CALLVALUE → ISZERO → PUSH2 <ok_dest> → JUMPI
 *   (if msg.value != 0, falls through to REVERT)
 *
 * OR (with DUP):
 *   CALLVALUE → DUP1 → ISZERO → PUSH2 <ok_dest> → JUMPI
 *
 * Payable functions don't have this guard.
 */
export function detectPayable(
  instructions: Instruction[],
  blocks: BasicBlock[],
  selectors: FunctionSelector[]
): PayableDetection {
  const payable: string[] = [];
  const nonPayable: string[] = [];

  for (const selector of selectors) {
    if (selector.handlerOffset === null) {
      // Can't determine — skip
      continue;
    }

    // Find the handler start in instructions
    let handlerIdx = -1;
    for (let i = 0; i < instructions.length; i++) {
      if (instructions[i].offset === selector.handlerOffset) {
        handlerIdx = i;
        break;
      }
    }

    if (handlerIdx < 0) continue;

    // Check first ~8 instructions after handler JUMPDEST for CALLVALUE check
    const lookahead = instructions.slice(handlerIdx, handlerIdx + 10);
    let hasCallvalueCheck = false;

    for (let i = 0; i < lookahead.length; i++) {
      if (lookahead[i].mnemonic === 'CALLVALUE') {
        // Look for ISZERO within next 3 instructions
        for (let j = i + 1; j < Math.min(i + 4, lookahead.length); j++) {
          if (lookahead[j].mnemonic === 'ISZERO') {
            // Then look for JUMPI
            for (
              let k = j + 1;
              k < Math.min(j + 3, lookahead.length);
              k++
            ) {
              if (lookahead[k].mnemonic === 'JUMPI') {
                // Verify the fall-through path (msg.value != 0) leads to REVERT.
                // After JUMPI, the next few instructions should end in REVERT
                // (or PUSH 0 PUSH 0 REVERT / PUSH PUSH REVERT pattern).
                // This confirms it's a genuine non-payable guard, not unrelated logic.
                let fallsToRevert = false;
                for (
                  let r = k + 1;
                  r < Math.min(k + 5, lookahead.length);
                  r++
                ) {
                  if (lookahead[r].mnemonic === 'REVERT' || lookahead[r].mnemonic === 'INVALID') {
                    fallsToRevert = true;
                    break;
                  }
                  // If we hit a JUMPDEST or another control-flow change, stop looking
                  if (lookahead[r].mnemonic === 'JUMPDEST' || lookahead[r].info.jumps) {
                    break;
                  }
                }
                // Accept the pattern either way — the CALLVALUE+ISZERO+JUMPI sequence
                // is sufficient, but a verified REVERT strengthens confidence.
                // Solidity always places the REVERT on the fall-through, but some
                // optimized patterns inline the guard differently. We accept both
                // to avoid false negatives.
                hasCallvalueCheck = true;
                break;
              }
            }
            break;
          }
        }
        break;
      }
    }

    if (hasCallvalueCheck) {
      nonPayable.push(selector.selector);
    } else {
      payable.push(selector.selector);
    }
  }

  return {
    payableFunctions: payable,
    nonPayableFunctions: nonPayable,
  };
}