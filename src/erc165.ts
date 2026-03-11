// ============================================================
// ERC-165 Interface Detection via eth_call
//
// ERC-165 defines a standard way for contracts to declare which
// interfaces they support. We call supportsInterface(bytes4) with
// well-known interface IDs to determine the contract type.
//
// Reference: https://eips.ethereum.org/EIPS/eip-165
// ============================================================

import { ChainConfig, ERC165Result } from './types';
import { ethCall } from './fetcher';

// supportsInterface(bytes4) selector: 0x01ffc9a7
const SUPPORTS_INTERFACE_SELECTOR = '0x01ffc9a7';

// Well-known interface IDs to probe
const KNOWN_INTERFACES: Array<{ id: string; name: string }> = [
  { id: '0x01ffc9a7', name: 'ERC-165' },
  { id: '0x80ac58cd', name: 'ERC-721 (NFT)' },
  { id: '0x5b5e139f', name: 'ERC-721Metadata' },
  { id: '0x780e9d63', name: 'ERC-721Enumerable' },
  { id: '0xd9b67a26', name: 'ERC-1155 (Multi-Token)' },
  { id: '0x0e89341c', name: 'ERC-1155MetadataURI' },
  { id: '0x2a55205a', name: 'ERC-2981 (Royalties)' },
  { id: '0x7f5828d0', name: 'ERC-173 (Ownership)' },
  { id: '0x36372b07', name: 'ERC-20' },
  { id: '0x49064906', name: 'ERC-4906 (Metadata Update)' },
];

/**
 * Build the calldata for supportsInterface(bytes4 interfaceId).
 * Layout: 4-byte selector + 32-byte padded interface ID
 */
function buildCalldata(interfaceId: string): string {
  const clean = interfaceId.replace('0x', '').padStart(8, '0');
  return SUPPORTS_INTERFACE_SELECTOR + clean.padEnd(64, '0');
}

/**
 * Detect which ERC-165 interfaces a contract supports.
 * First checks if the contract supports ERC-165 itself, then
 * probes each known interface.
 */
export async function detectERC165(
  address: string,
  chain: ChainConfig
): Promise<ERC165Result> {
  const result: ERC165Result = {
    supportsERC165: false,
    interfaces: [],
  };

  // Step 1: Check if contract supports ERC-165
  const erc165Check = await callSupportsInterface(address, '0x01ffc9a7', chain);
  if (!erc165Check) {
    // Contract doesn't support ERC-165 — can't detect interfaces this way
    return result;
  }

  result.supportsERC165 = true;

  // Step 2: Probe all known interfaces
  // Run queries in parallel for speed (but limited batch size to be polite)
  const batchSize = 4;
  for (let i = 0; i < KNOWN_INTERFACES.length; i += batchSize) {
    const batch = KNOWN_INTERFACES.slice(i, i + batchSize);
    const results = await Promise.all(
      batch.map(async (iface) => {
        const supported = await callSupportsInterface(address, iface.id, chain);
        return { ...iface, supported };
      })
    );
    result.interfaces.push(...results);
  }

  return result;
}

/**
 * Call supportsInterface(bytes4) and return true/false.
 * Returns false if the call reverts or returns non-true value.
 */
async function callSupportsInterface(
  address: string,
  interfaceId: string,
  chain: ChainConfig
): Promise<boolean> {
  const calldata = buildCalldata(interfaceId);
  const response = await ethCall(address, calldata, chain);

  if (!response) return false;

  // ERC-165 returns an ABI-encoded bool (32 bytes): 0x000...001 for true
  const clean = response.replace('0x', '').padStart(64, '0');
  return clean === '0'.repeat(63) + '1';
}
