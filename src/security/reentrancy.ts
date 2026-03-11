import { Instruction, BasicBlock, ReentrancyGuardDetection } from '../types';

/**
 * Detect reentrancy guard patterns in EVM bytecode.
 * Looks for:
 *   1. OpenZeppelin-style storage mutex (SLOAD→SSTORE→CALL→SSTORE)
 *   2. EIP-1153 transient storage guards (TLOAD/TSTORE)
 *   3. Checks-Effects-Interactions (CEI) pattern — state writes before external calls
 */
export function detectReentrancyGuard(
  instructions: Instruction[],
  blocks: BasicBlock[]
): ReentrancyGuardDetection {
  const result: ReentrancyGuardDetection = {
    detected: false,
    pattern: null,
    storageSlot: null,
  };

  // Collect storage ops and external calls to look for the mutex pattern:
  // SLOAD slot → SSTORE slot (lock) → CALL → SSTORE slot (unlock)
  interface StorageOp {
    type: 'SLOAD' | 'SSTORE';
    offset: number;
    blockId: number;
    slotHex: string | null; // slot comes from the PUSH before SLOAD/SSTORE
  }

  interface CallOp {
    type: 'CALL' | 'STATICCALL' | 'DELEGATECALL';
    offset: number;
    blockId: number;
  }

  const storageOps: StorageOp[] = [];
  const callOps: CallOp[] = [];

  for (const block of blocks) {
    for (let i = 0; i < block.instructions.length; i++) {
      const instr = block.instructions[i];

      if (instr.mnemonic === 'SLOAD' || instr.mnemonic === 'SSTORE') {
        let slotHex: string | null = null;
        // The slot is typically pushed right before SLOAD/SSTORE
        if (i > 0 && block.instructions[i - 1].mnemonic.startsWith('PUSH')) {
          slotHex = block.instructions[i - 1].operandHex;
        }
        storageOps.push({
          type: instr.mnemonic as 'SLOAD' | 'SSTORE',
          offset: instr.offset,
          blockId: block.id,
          slotHex,
        });
      }

      if (['CALL', 'STATICCALL', 'DELEGATECALL'].includes(instr.mnemonic)) {
        callOps.push({
          type: instr.mnemonic as CallOp['type'],
          offset: instr.offset,
          blockId: block.id,
        });
      }
    }
  }

  // Look for pattern: SLOAD → SSTORE → CALL → SSTORE (same slot)
  // Or: two SSTOREs to same slot surrounding a CALL
  for (let i = 0; i < storageOps.length; i++) {
    const firstOp = storageOps[i];
    if (firstOp.type !== 'SLOAD' || !firstOp.slotHex) continue;

    // Look for SSTOREs to the same slot after this SLOAD
    const sameSlotStores = storageOps.filter(
      (op) =>
        op.type === 'SSTORE' &&
        op.slotHex === firstOp.slotHex &&
        op.offset > firstOp.offset
    );

    if (sameSlotStores.length < 2) continue;

    // Check if there's a CALL between the first and last SSTORE
    const firstStore = sameSlotStores[0];
    const lastStore = sameSlotStores[sameSlotStores.length - 1];

    const callBetween = callOps.some(
      (c) => c.offset > firstStore.offset && c.offset < lastStore.offset
    );

    if (callBetween) {
      result.detected = true;
      result.pattern = 'OpenZeppelin';
      result.storageSlot = firstOp.slotHex;
      return result;
    }
  }

  // EIP-1153 transient storage — if contract uses TLOAD/TSTORE around calls,
  // it's likely using the newer gas-efficient reentrancy guard pattern
  const hasTload = instructions.some((i) => i.mnemonic === 'TLOAD');
  const hasTstore = instructions.some((i) => i.mnemonic === 'TSTORE');
  if (hasTload && hasTstore) {
    const hasCall = callOps.length > 0;
    if (hasCall) {
      result.detected = true;
      result.pattern = 'transient';
      return result;
    }
  }

  // Check for Checks-Effects-Interactions (CEI) pattern:
  // If SSTORE always appears before CALL (effects before interactions),
  // and there is at least one SSTORE followed by a CALL, this suggests
  // the contract follows CEI discipline — a reentrancy mitigation pattern.
  if (storageOps.length > 0 && callOps.length > 0) {
    const lastSstoreOffset = Math.max(
      ...storageOps.filter((op) => op.type === 'SSTORE').map((op) => op.offset),
      -1
    );
    const firstCallOffset = Math.min(
      ...callOps.map((op) => op.offset)
    );

    // CEI: all SSTOREs happen before the first external CALL
    if (lastSstoreOffset !== -1 && lastSstoreOffset < firstCallOffset) {
      result.detected = true;
      result.pattern = 'CEI';
      return result;
    }
  }

  return result;
}