import { createPublicClient, http, type Hex, type PublicClient } from 'viem';
import { ChainConfig } from './types';
import { hexToBytes } from './utils';

const cachedClients: Map<string, PublicClient> = new Map();

export function getClient(config: ChainConfig): PublicClient {
  if (cachedClients.has(config.rpc)) {
    return cachedClients.get(config.rpc)!;
  }
  const client = createPublicClient({
    transport: http(config.rpc, {
      timeout: 30_000,
      retryCount: 3,
      retryDelay: 1000,
    }),
  });
  cachedClients.set(config.rpc, client);
  return client;
}

export async function fetchBytecode(
  address: string,
  config: ChainConfig
): Promise<{ bytecode: Uint8Array; hex: string }> {
  const client = getClient(config);
  const code = await client.getCode({
    address: address as Hex,
  });

  if (!code || code === '0x' || code === '0x0') {
    throw new Error(
      `No contract bytecode at ${address} on ${config.name}. ` +
        `This may be an EOA, a self-destructed contract, or wrong chain.`
    );
  }

  return {
    bytecode: hexToBytes(code),
    hex: code,
  };
}

export async function getStorageAt(
  address: string,
  slot: string,
  config: ChainConfig
): Promise<string> {
  const client = getClient(config);
  const value = await client.getStorageAt({
    address: address as Hex,
    slot: slot as Hex,
  });
  return value || '0x0000000000000000000000000000000000000000000000000000000000000000';
}

/**
 * Perform an eth_call to a contract address with given calldata.
 * Used for ERC-165 interface detection (supportsInterface).
 * Returns the raw hex result, or null if the call fails/reverts.
 */
export async function ethCall(
  address: string,
  data: string,
  config: ChainConfig
): Promise<string | null> {
  const client = getClient(config);
  try {
    const result = await client.call({
      to: address as Hex,
      data: data as Hex,
    });
    return result.data || null;
  } catch {
    return null;
  }
}