import dotenv from 'dotenv';
import { ChainConfig } from './types';

dotenv.config();

export const CHAINS: Record<string, ChainConfig> = {
  ethereum: {
    name: 'ethereum',
    rpc: process.env.ETH_RPC || 'https://ethereum-rpc.publicnode.com',
    chainId: 1,
  },
  base: {
    name: 'base',
    rpc: process.env.BASE_RPC || 'https://base-rpc.publicnode.com',
    chainId: 8453,
  },
  arbitrum: {
    name: 'arbitrum',
    rpc: process.env.ARBITRUM_RPC || 'https://arbitrum-one-rpc.publicnode.com',
    chainId: 42161,
  },
  polygon: {
    name: 'polygon',
    rpc: process.env.POLYGON_RPC || 'https://polygon-bor-rpc.publicnode.com',
    chainId: 137,
  },
};

export function getChainConfig(chain: string, customRpc?: string): ChainConfig {
  const config = CHAINS[chain.toLowerCase()];
  if (!config) {
    throw new Error(
      `Unsupported chain: ${chain}. Supported: ${Object.keys(CHAINS).join(', ')}`
    );
  }
  if (customRpc) {
    return { ...config, rpc: customRpc };
  }
  return config;
}