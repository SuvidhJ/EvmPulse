import { Instruction, ProxyDetection } from '../types';
import { getStorageAt } from '../fetcher';
import { ChainConfig } from '../types';
import { bytesToHex } from '../utils';

// EIP-1967 defines standardized storage slots for proxy contracts.
// These slots are derived from keccak256 of known strings minus 1.
// Reference: https://eips.ethereum.org/EIPS/eip-1967
const EIP1967_IMPL_SLOT =
  '0x360894a13ba1a3210667c828492db98dca3e2076fad2ce6e4544b18e73a22d6c';
const EIP1967_BEACON_SLOT =
  '0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50';
const EIP1967_ADMIN_SLOT =
  '0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103';

// EIP-1167 minimal proxy prefix & suffix
const MINIMAL_PROXY_PREFIX = '363d3d373d3d3d363d73';
const MINIMAL_PROXY_SUFFIX = '5af43d82803e903d91602b57fd5bf3';

export async function detectProxy(
  instructions: Instruction[],
  bytecode: Uint8Array,
  address: string,
  chain: ChainConfig
): Promise<ProxyDetection> {
  const result: ProxyDetection = {
    detected: false,
    isMinimalProxy: false,
    pattern: null,
    implementationAddress: null,
    delegatecallCount: 0,
    adminAddress: null,
  };

  // Count DELEGATECALL instructions
  result.delegatecallCount = instructions.filter(
    (i) => i.mnemonic === 'DELEGATECALL'
  ).length;

  // Check EIP-1167 minimal proxy pattern
  const bytecodeHex = bytesToHex(bytecode, false).toLowerCase();

  if (
    bytecodeHex.startsWith(MINIMAL_PROXY_PREFIX) &&
    bytecodeHex.endsWith(MINIMAL_PROXY_SUFFIX)
  ) {
    // Extract implementation address (20 bytes after prefix)
    const addrHex = bytecodeHex.slice(
      MINIMAL_PROXY_PREFIX.length,
      MINIMAL_PROXY_PREFIX.length + 40
    );
    result.detected = true;
    result.isMinimalProxy = true;
    result.pattern = 'EIP-1167';
    result.implementationAddress = '0x' + addrHex;
    return result;
  }

  // Check for DELEGATECALL with storage-loaded target — indicates a proxy.
  // Proxy contracts load the implementation address from storage (SLOAD) and
  // then DELEGATECALL to it. We look back 30 instructions because there may
  // be stack manipulation or small jumps between the SLOAD and DELEGATECALL.
  if (result.delegatecallCount > 0) {
    let hasSloadBeforeDelegatecall = false;
    for (let i = 0; i < instructions.length; i++) {
      if (instructions[i].mnemonic === 'DELEGATECALL') {
        for (let j = Math.max(0, i - 30); j < i; j++) {
          if (instructions[j].mnemonic === 'SLOAD') {
            hasSloadBeforeDelegatecall = true;
            break;
          }
        }
      }
    }

    if (hasSloadBeforeDelegatecall) {
      result.detected = true;
      result.pattern = 'EIP-1967';

      // Try to resolve implementation via EIP-1967 storage slots
      try {
        const implSlotValue = await getStorageAt(
          address,
          EIP1967_IMPL_SLOT,
          chain
        );
        const implAddr = extractAddress(implSlotValue);
        if (implAddr && implAddr !== '0x0000000000000000000000000000000000000000') {
          result.implementationAddress = implAddr;
        }
      } catch {
        // Storage read failed
      }

      // If the standard EIP-1967 slot was empty, fall back to looking at what storage
      // slots the bytecode actually reads. We find PUSH32 values before SLOAD instructions —
      // these are likely custom implementation storage slots used by non-standard proxies.
      if (!result.implementationAddress) {
        const candidateSlots = new Set<string>();
        for (let i = 0; i < instructions.length; i++) {
          if (instructions[i].mnemonic === 'SLOAD') {
            // Look back up to 10 instructions for a PUSH32 that provides the slot
            for (let j = Math.max(0, i - 10); j < i; j++) {
              if (instructions[j].mnemonic === 'PUSH32' && instructions[j].operandHex) {
                candidateSlots.add(instructions[j].operandHex!);
              }
            }
          }
        }
        for (const slot of candidateSlots) {
          try {
            const slotValue = await getStorageAt(address, slot, chain);
            const addr = extractAddress(slotValue);
            if (addr && addr !== '0x0000000000000000000000000000000000000000') {
              result.implementationAddress = addr;
              result.pattern = 'custom';
              break;
            }
          } catch {
            // ok
          }
        }
      }

      // Try admin slot
      try {
        const adminSlotValue = await getStorageAt(
          address,
          EIP1967_ADMIN_SLOT,
          chain
        );
        const adminAddr = extractAddress(adminSlotValue);
        if (adminAddr && adminAddr !== '0x0000000000000000000000000000000000000000') {
          result.adminAddress = adminAddr;
        }
      } catch {
        // ok
      }

      // If we still didn't find implementation, mark as custom proxy
      if (!result.implementationAddress) {
        result.pattern = 'custom';
      }
    }
  }

  return result;
}

function extractAddress(storageValue: string): string | null {
  if (!storageValue || storageValue === '0x') return null;
  // Storage value is 32 bytes, address is last 20 bytes
  // Storage value is 32 bytes (64 hex chars). An address is 20 bytes = last 40 hex chars.
  // So we skip the first 24 hex chars (12 zero-padding bytes) to get the address.
  const clean = storageValue.replace('0x', '').padStart(64, '0');
  const addr = '0x' + clean.slice(24);
  if (addr === '0x' + '0'.repeat(40)) return null;
  return addr;
}