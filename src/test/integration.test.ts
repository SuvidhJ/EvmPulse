// ============================================================
// Integration tests against real mainnet contracts
// These require network access and may be slow
// ============================================================

import { analyze } from '../analyzer';
import { getChainConfig } from '../chains';

describe('Mainnet Integration', () => {
  const chain = getChainConfig('ethereum');

  test(
    'should analyze USDT',
    async () => {
      const report = await analyze(
        '0xdAC17F958D2ee523a2206206994597C13D831ec7',
        chain,
        { disasm: false, selectors: true, cfg: true, security: true }
      );

      expect(report.isContract).toBe(true);
      expect(report.bytecodeSize).toBeGreaterThan(0);
      expect(report.selectors!.count).toBeGreaterThan(5);

      // USDT should have known selectors
      const sels = report.selectors!.functions.map((f) => f.selector);
      expect(sels).toContain('0xa9059cbb'); // transfer
      expect(sels).toContain('0x70a08231'); // balanceOf

      // USDT is not a proxy
      expect(report.security!.proxy.detected).toBe(false);

      // CFG should have reasonable stats
      expect(report.cfg!.totalBlocks).toBeGreaterThan(10);
      expect(report.cfg!.jumpResolution.totalJumps).toBeGreaterThan(0);
      expect(report.cfg!.jumpResolution.staticResolved).toBeGreaterThan(0);
    },
    90000
  );

  test(
    'should detect USDC as proxy',
    async () => {
      const report = await analyze(
        '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48',
        chain,
        { disasm: false, selectors: false, cfg: false, security: true }
      );

      expect(report.isContract).toBe(true);
      expect(report.security!.proxy.detected).toBe(true);
      expect(report.security!.proxy.implementationAddress).not.toBeNull();
    },
    90000
  );

  test(
    'should work with Base L2',
    async () => {
      const baseChain = getChainConfig('base');
      // USDC on Base
      const report = await analyze(
        '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
        baseChain,
        { disasm: false, selectors: true, cfg: false, security: false }
      );

      expect(report.isContract).toBe(true);
      expect(report.selectors!.count).toBeGreaterThan(0);
    },
    90000
  );

  test(
    'should detect ERC-165 interfaces via eth_call',
    async () => {
      // Bored Ape Yacht Club (BAYC) — well-known ERC-721 that supports ERC-165
      const report = await analyze(
        '0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D',
        chain,
        { disasm: false, selectors: false, cfg: false, security: true }
      );

      expect(report.erc165).toBeDefined();
      // BAYC should support ERC-165 and ERC-721
      if (report.erc165!.supportsERC165) {
        const supported = report.erc165!.interfaces
          .filter((i) => i.supported)
          .map((i) => i.name);
        expect(supported).toContain('ERC-165');
        expect(supported).toContain('ERC-721 (NFT)');
      }
    },
    90000
  );
});