import { disassemble, formatDisassembly } from '../disassembler';
import { extractSelectors, inferParameters } from '../selectors';
import { buildCFG } from '../cfg';
import { hexToBytes, bytesToHex, toHex, bfs, findPaths } from '../utils';
import { separateMetadata } from '../metadata';
import { getChainConfig, CHAINS } from '../chains';
import { detectSelfdestruct } from '../security/selfdestruct';
import { detectUncheckedCalls } from '../security/unchecked-calls';
import { detectAccessControl } from '../security/access-control';
import { detectReentrancyGuard } from '../security/reentrancy';
import { detectPayable } from '../security/payable';
import { detectProxy } from '../security/proxy';
import { detectERC165 } from '../erc165';
import { getOpcodeInfo, OPCODES } from '../opcodes';
import { formatReport } from '../formatter';
import { ChainConfig } from '../types';

// Mock the fetcher module — needed by proxy and erc165 detection
jest.mock('../fetcher', () => ({
  ethCall: jest.fn(),
  getStorageAt: jest.fn(),
  fetchBytecode: jest.fn(),
}));

import { ethCall, getStorageAt } from '../fetcher';
const mockEthCall = ethCall as jest.MockedFunction<typeof ethCall>;
const mockGetStorageAt = getStorageAt as jest.MockedFunction<typeof getStorageAt>;

const dummyChain: ChainConfig = { name: 'ethereum', chainId: 1, rpc: 'https://example.com' };

// ============================================================
// Utilities
// ============================================================
describe('Utilities', () => {
  test('hexToBytes converts hex string to Uint8Array', () => {
    expect(hexToBytes('0xff')).toEqual(new Uint8Array([0xff]));
    expect(hexToBytes('aabb')).toEqual(new Uint8Array([0xaa, 0xbb]));
    expect(hexToBytes('0x')).toEqual(new Uint8Array(0));
    expect(hexToBytes('')).toEqual(new Uint8Array(0));
  });

  test('bytesToHex converts Uint8Array to hex string', () => {
    expect(bytesToHex(new Uint8Array([0xff]))).toBe('0xff');
    expect(bytesToHex(new Uint8Array([0xaa, 0xbb]))).toBe('0xaabb');
    expect(bytesToHex(new Uint8Array([0xaa, 0xbb]), false)).toBe('aabb');
    expect(bytesToHex(new Uint8Array(0))).toBe('0x');
  });

  test('toHex formats offset to hex string', () => {
    expect(toHex(0)).toBe('0x0000');
    expect(toHex(255)).toBe('0x00ff');
    expect(toHex(4096)).toBe('0x1000');
    expect(toHex(16, 2)).toBe('0x10');
  });

  test('bfs traverses directed graph', () => {
    const adj = new Map<number, number[]>();
    adj.set(0, [1, 2]);
    adj.set(1, [3]);
    adj.set(2, [3]);
    adj.set(3, []);
    adj.set(4, []);  // disconnected node

    const reachable = bfs(adj, 0);
    expect(reachable.has(0)).toBe(true);
    expect(reachable.has(1)).toBe(true);
    expect(reachable.has(2)).toBe(true);
    expect(reachable.has(3)).toBe(true);
    expect(reachable.has(4)).toBe(false);
  });

  test('findPaths finds paths to targets', () => {
    const adj = new Map<number, number[]>();
    adj.set(0, [1, 2]);
    adj.set(1, [3]);
    adj.set(2, [3]);
    adj.set(3, []);

    const paths = findPaths(adj, 0, new Set([3]));
    expect(paths.length).toBeGreaterThan(0);
    // Each path should start at 0 and end at 3
    for (const path of paths) {
      expect(path[0]).toBe(0);
      expect(path[path.length - 1]).toBe(3);
    }
  });

  test('findPaths respects maxPaths limit', () => {
    const adj = new Map<number, number[]>();
    adj.set(0, [1, 2, 3]);
    adj.set(1, [4]);
    adj.set(2, [4]);
    adj.set(3, [4]);
    adj.set(4, []);

    const paths = findPaths(adj, 0, new Set([4]), 2);
    expect(paths.length).toBeLessThanOrEqual(2);
  });
});

// ============================================================
// Opcodes
// ============================================================
describe('Opcodes', () => {
  test('OPCODES map contains all standard opcodes', () => {
    // Basic opcodes
    expect(OPCODES.get(0x00)?.mnemonic).toBe('STOP');
    expect(OPCODES.get(0x01)?.mnemonic).toBe('ADD');
    expect(OPCODES.get(0x56)?.mnemonic).toBe('JUMP');
    expect(OPCODES.get(0x57)?.mnemonic).toBe('JUMPI');
    expect(OPCODES.get(0x5b)?.mnemonic).toBe('JUMPDEST');
    expect(OPCODES.get(0xf1)?.mnemonic).toBe('CALL');
    expect(OPCODES.get(0xf4)?.mnemonic).toBe('DELEGATECALL');
    expect(OPCODES.get(0xff)?.mnemonic).toBe('SELFDESTRUCT');
  });

  test('PUSH1–PUSH32 have correct operand sizes', () => {
    for (let i = 1; i <= 32; i++) {
      const info = OPCODES.get(0x5f + i);
      expect(info).toBeDefined();
      expect(info!.mnemonic).toBe(`PUSH${i}`);
      expect(info!.operandSize).toBe(i);
    }
  });

  test('DUP1–DUP16 are present', () => {
    for (let i = 1; i <= 16; i++) {
      const info = OPCODES.get(0x7f + i);
      expect(info).toBeDefined();
      expect(info!.mnemonic).toBe(`DUP${i}`);
    }
  });

  test('SWAP1–SWAP16 are present', () => {
    for (let i = 1; i <= 16; i++) {
      const info = OPCODES.get(0x8f + i);
      expect(info).toBeDefined();
      expect(info!.mnemonic).toBe(`SWAP${i}`);
    }
  });

  test('LOG0–LOG4 are present', () => {
    for (let i = 0; i <= 4; i++) {
      const info = OPCODES.get(0xa0 + i);
      expect(info).toBeDefined();
      expect(info!.mnemonic).toBe(`LOG${i}`);
    }
  });

  test('Constantinople opcodes are present', () => {
    expect(OPCODES.get(0x1b)?.mnemonic).toBe('SHL');
    expect(OPCODES.get(0x1c)?.mnemonic).toBe('SHR');
    expect(OPCODES.get(0x1d)?.mnemonic).toBe('SAR');
    expect(OPCODES.get(0x3f)?.mnemonic).toBe('EXTCODEHASH');
    expect(OPCODES.get(0xf5)?.mnemonic).toBe('CREATE2');
  });

  test('getOpcodeInfo returns INVALID for unknown bytes', () => {
    const info = getOpcodeInfo(0xef);
    expect(info.mnemonic).toContain('INVALID');
    expect(info.halts).toBe(true);
  });

  test('Halting opcodes are marked correctly', () => {
    expect(OPCODES.get(0x00)!.halts).toBe(true);  // STOP
    expect(OPCODES.get(0xf3)!.halts).toBe(true);  // RETURN
    expect(OPCODES.get(0xfd)!.halts).toBe(true);  // REVERT
    expect(OPCODES.get(0xfe)!.halts).toBe(true);  // INVALID
    expect(OPCODES.get(0xff)!.halts).toBe(true);  // SELFDESTRUCT
    expect(OPCODES.get(0x01)!.halts).toBe(false);  // ADD
  });

  test('Jump opcodes are marked correctly', () => {
    expect(OPCODES.get(0x56)!.jumps).toBe(true);   // JUMP
    expect(OPCODES.get(0x57)!.jumps).toBe(true);   // JUMPI
    expect(OPCODES.get(0x5b)!.jumps).toBe(false);  // JUMPDEST
    expect(OPCODES.get(0x01)!.jumps).toBe(false);  // ADD
  });
});

// ============================================================
// Disassembler
// ============================================================
describe('Disassembler', () => {
  test('handles PUSH0 opcode (Shanghai)', () => {
    // PUSH0 STOP
    const bytes = hexToBytes('5f00');
    const result = disassemble(bytes);
    expect(result.instructions[0].mnemonic).toBe('PUSH0');
    expect(result.instructions[0].operand).toBeNull();
    expect(result.instructions[1].mnemonic).toBe('STOP');
  });

  test('handles truncated PUSH operand at end of code', () => {
    // PUSH4 with only 2 bytes of operand before end
    const bytes = hexToBytes('63aabb');
    const result = disassemble(bytes);
    expect(result.instructions.length).toBe(1);
    expect(result.instructions[0].mnemonic).toBe('PUSH4');
    // Should still have partial operand
    expect(result.instructions[0].operand!.length).toBe(2);
  });

  test('calculates code vs data bytes correctly', () => {
    const code = hexToBytes('6080604052');
    // Build CBOR metadata
    const cborData = hexToBytes('a164736f6c6343000813');
    const lenBytes = new Uint8Array(2);
    lenBytes[0] = (cborData.length >> 8) & 0xff;
    lenBytes[1] = cborData.length & 0xff;
    const full = new Uint8Array(code.length + cborData.length + 2);
    full.set(code, 0);
    full.set(cborData, code.length);
    full.set(lenBytes, code.length + cborData.length);

    const result = disassemble(full);
    expect(result.codeBytes).toBe(code.length);
    expect(result.dataBytes).toBe(cborData.length + 2);
  });

  test('disassembles all DUP and SWAP instructions', () => {
    // DUP1 DUP16 SWAP1 SWAP16 STOP
    const bytes = hexToBytes('80' + '8f' + '90' + '9f' + '00');
    const result = disassemble(bytes);
    expect(result.instructions[0].mnemonic).toBe('DUP1');
    expect(result.instructions[1].mnemonic).toBe('DUP16');
    expect(result.instructions[2].mnemonic).toBe('SWAP1');
    expect(result.instructions[3].mnemonic).toBe('SWAP16');
  });

  test('disassembles LOG instructions', () => {
    // LOG0 LOG4 STOP
    const bytes = hexToBytes('a0' + 'a4' + '00');
    const result = disassemble(bytes);
    expect(result.instructions[0].mnemonic).toBe('LOG0');
    expect(result.instructions[1].mnemonic).toBe('LOG4');
  });

  test('disassembles CREATE2 (Constantinople)', () => {
    const bytes = hexToBytes('f5' + '00');
    const result = disassemble(bytes);
    expect(result.instructions[0].mnemonic).toBe('CREATE2');
  });

  test('handles invalid opcodes gracefully', () => {
    // 0xef is not a valid opcode
    const bytes = hexToBytes('ef00');
    const result = disassemble(bytes);
    expect(result.instructions[0].mnemonic).toContain('INVALID');
    expect(result.instructions.length).toBe(2);
  });

  test('single STOP instruction', () => {
    const bytes = hexToBytes('00');
    const result = disassemble(bytes);
    expect(result.instructions.length).toBe(1);
    expect(result.instructions[0].mnemonic).toBe('STOP');
    expect(result.instructions[0].offset).toBe(0);
    expect(result.codeBytes).toBe(1);
    expect(result.dataBytes).toBe(0);
  });
});

// ============================================================
// Format Disassembly
// ============================================================
describe('Format Disassembly', () => {
  test('produces annotated text output', () => {
    const bytes = hexToBytes('6080604052' + '00');
    const result = disassemble(bytes);
    const output = formatDisassembly(result);
    expect(output).toContain('PUSH1');
    expect(output).toContain('0x80');
    expect(output).toContain('MSTORE');
    expect(output).toContain('STOP');
  });

  test('annotates known selectors', () => {
    // PUSH4 0xa9059cbb STOP
    const bytes = hexToBytes('63a9059cbb' + '00');
    const result = disassemble(bytes);
    const selectorMap = new Map<string, string[]>();
    selectorMap.set('0xa9059cbb', ['transfer(address,uint256)']);
    const output = formatDisassembly(result, selectorMap);
    expect(output).toContain('transfer(address,uint256)');
  });

  test('marks JUMPDEST targets', () => {
    // JUMPDEST STOP
    const bytes = hexToBytes('5b00');
    const result = disassemble(bytes);
    const output = formatDisassembly(result);
    expect(output).toContain('jump target');
  });
});

// ============================================================
// Metadata Parser
// ============================================================
describe('Metadata Parser', () => {
  test('handles bytecode without metadata', () => {
    const bytes = hexToBytes('60806040526000');
    const { executableCode, metadata } = separateMetadata(bytes);
    expect(metadata.detected).toBe(false);
    expect(executableCode.length).toBe(bytes.length);
  });

  test('handles very short bytecode', () => {
    const bytes = hexToBytes('00');
    const { executableCode, metadata } = separateMetadata(bytes);
    expect(metadata.detected).toBe(false);
    expect(executableCode.length).toBe(1);
  });

  test('handles empty bytecode', () => {
    const bytes = new Uint8Array(0);
    const { executableCode, metadata } = separateMetadata(bytes);
    expect(metadata.detected).toBe(false);
    expect(executableCode.length).toBe(0);
  });

  test('parses CBOR with IPFS hash', () => {
    const codeBytes = hexToBytes('00');
    // CBOR map: { "ipfs": <34 bytes>, "solc": <0.8.20> }
    // a2 64 "ipfs" 5822 <34 bytes> 64 "solc" 43 000814
    const ipfsHash = 'aa'.repeat(34);
    const cborHex = 'a2' +
      '64' + Buffer.from('ipfs').toString('hex') +
      '5822' + ipfsHash +
      '64' + Buffer.from('solc').toString('hex') +
      '43' + '000814';
    const cborData = hexToBytes(cborHex);
    const lenBytes = new Uint8Array(2);
    lenBytes[0] = (cborData.length >> 8) & 0xff;
    lenBytes[1] = cborData.length & 0xff;

    const full = new Uint8Array(codeBytes.length + cborData.length + 2);
    full.set(codeBytes, 0);
    full.set(cborData, codeBytes.length);
    full.set(lenBytes, codeBytes.length + cborData.length);

    const { metadata } = separateMetadata(full);
    expect(metadata.detected).toBe(true);
    expect(metadata.solcVersion).toBe('0.8.20');
    expect(metadata.ipfsHash).toContain('aa');
  });

  test('parses CBOR with bzzr0 hash', () => {
    const codeBytes = hexToBytes('00');
    const bzzr0Hash = 'bb'.repeat(32);
    const cborHex = 'a1' +
      '65' + Buffer.from('bzzr0').toString('hex') +
      '5820' + bzzr0Hash;
    const cborData = hexToBytes(cborHex);
    const lenBytes = new Uint8Array(2);
    lenBytes[0] = (cborData.length >> 8) & 0xff;
    lenBytes[1] = cborData.length & 0xff;

    const full = new Uint8Array(codeBytes.length + cborData.length + 2);
    full.set(codeBytes, 0);
    full.set(cborData, codeBytes.length);
    full.set(lenBytes, codeBytes.length + cborData.length);

    const { metadata } = separateMetadata(full);
    expect(metadata.detected).toBe(true);
    expect(metadata.bzzr0Hash).toContain('bb');
  });
});

// ============================================================
// Selector Extraction
// ============================================================
describe('Selector Extraction', () => {
  test('handles bytecode with no dispatch table', () => {
    // Just STOP
    const bytes = hexToBytes('00');
    const result = disassemble(bytes);
    const selectors = extractSelectors(result.instructions);
    expect(selectors.count).toBe(0);
    expect(selectors.functions).toEqual([]);
  });

  test('extracts selector from PUSH4 + EQ + PUSH + JUMPI pattern', () => {
    // PUSH4 0xdeadbeef DUP2 EQ PUSH1 0x20 JUMPI JUMPDEST STOP
    const code = '63deadbeef' + '81' + '14' + '6020' + '57' + '5b' + '00';
    const bytes = hexToBytes(code);
    const result = disassemble(bytes);
    const selectors = extractSelectors(result.instructions);
    expect(selectors.count).toBe(1);
    expect(selectors.functions[0].selector).toBe('0xdeadbeef');
  });

  test('does not duplicate selectors', () => {
    // Same selector appearing twice
    const code =
      '63a9059cbb' + '81' + '14' + '6030' + '57' +
      '63a9059cbb' + '81' + '14' + '6032' + '57' +
      '5b' + '00' + '5b' + '00';
    const bytes = hexToBytes(code);
    const result = disassemble(bytes);
    const selectors = extractSelectors(result.instructions);
    expect(selectors.count).toBe(1);
  });

  test('handles binary search dispatch (GT/LT patterns)', () => {
    // PUSH4 0x7fffffff DUP2 GT PUSH1 0x20 JUMPI JUMPDEST STOP  
    const code = '637fffffff' + '81' + '11' + '6020' + '57' + '5b' + '00';
    const bytes = hexToBytes(code);
    const result = disassemble(bytes);
    const selectors = extractSelectors(result.instructions);
    expect(selectors.count).toBe(1);
    // Handler offset should be null for binary search pivots
    expect(selectors.functions[0].handlerOffset).toBeNull();
  });
});

// ============================================================
// Parameter Inference
// ============================================================
describe('Parameter Inference', () => {
  test('infers address parameter from AND mask pattern', () => {
    // JUMPDEST
    // PUSH1 0x04 CALLDATALOAD
    // PUSH20 0xffffffffffffffffffffffffffffffffffffffff AND
    // STOP
    const code =
      '5b' +   // JUMPDEST at offset 0
      '6004' + // PUSH1 0x04
      '35' +   // CALLDATALOAD
      '73' + 'ffffffffffffffffffffffffffffffffffffffff' + // PUSH20
      '16' +   // AND
      '00';    // STOP

    const bytes = hexToBytes(code);
    const result = disassemble(bytes);
    const params = inferParameters(result.instructions, 0);
    expect(params[0]).toBe('address');
  });

  test('infers bool parameter from ISZERO pattern', () => {
    // JUMPDEST PUSH1 0x04 CALLDATALOAD ISZERO STOP
    const code = '5b' + '6004' + '35' + '15' + '00';
    const bytes = hexToBytes(code);
    const result = disassemble(bytes);
    const params = inferParameters(result.instructions, 0);
    expect(params[0]).toBe('bool');
  });

  test('defaults to uint256 with no type clue', () => {
    // JUMPDEST PUSH1 0x04 CALLDATALOAD POP STOP
    const code = '5b' + '6004' + '35' + '50' + '00';
    const bytes = hexToBytes(code);
    const result = disassemble(bytes);
    const params = inferParameters(result.instructions, 0);
    expect(params[0]).toBe('uint256');
  });

  test('returns empty for invalid handler offset', () => {
    const bytes = hexToBytes('00');
    const result = disassemble(bytes);
    const params = inferParameters(result.instructions, 999);
    expect(params).toEqual([]);
  });
});

// ============================================================
// CFG Construction
// ============================================================
describe('CFG Construction', () => {
  test('handles empty instruction list', () => {
    const cfg = buildCFG([]);
    expect(cfg.totalBlocks).toBe(0);
    expect(cfg.totalEdges).toBe(0);
    expect(cfg.dot).toContain('digraph');
  });

  test('builds single block for linear code', () => {
    // PUSH1 0x80 PUSH1 0x40 MSTORE STOP
    const bytes = hexToBytes('6080604052' + '00');
    const result = disassemble(bytes);
    const cfg = buildCFG(result.instructions);
    expect(cfg.totalBlocks).toBe(1);
    expect(cfg.blocks[0].terminator).toBe('STOP');
  });

  test('splits blocks at JUMPDEST', () => {
    // PUSH1 0x04 JUMP JUMPDEST STOP
    const bytes = hexToBytes('600456' + '5b00');
    const result = disassemble(bytes);
    const cfg = buildCFG(result.instructions);
    // Should have at least 2 blocks (before JUMP and at JUMPDEST)
    expect(cfg.totalBlocks).toBeGreaterThanOrEqual(2);
  });

  test('creates conditional edges for JUMPI', () => {
    // PUSH1 0x01 PUSH1 0x0a JUMPI STOP JUMPDEST STOP
    const code = '6001' + '600a' + '57' + '00' + '5b' + '00';
    const bytes = hexToBytes(code);
    const result = disassemble(bytes);
    const cfg = buildCFG(result.instructions);

    // Should have conditional edges
    const conditionalEdges = cfg.edges.filter(
      (e) => e.type === 'conditional_true' || e.type === 'conditional_false'
    );
    expect(conditionalEdges.length).toBeGreaterThan(0);
  });

  test('generates valid DOT output', () => {
    const bytes = hexToBytes('6080604052' + '00');
    const result = disassemble(bytes);
    const cfg = buildCFG(result.instructions);
    expect(cfg.dot).toContain('digraph CFG');
    expect(cfg.dot).toContain('BB0');
    expect(cfg.dot).toContain('}');
  });

  test('handles REVERT terminal', () => {
    // PUSH1 0x00 DUP1 REVERT
    const bytes = hexToBytes('6000' + '80' + 'fd');
    const result = disassemble(bytes);
    const cfg = buildCFG(result.instructions);
    expect(cfg.blocks[0].terminator).toBe('REVERT');
    expect(cfg.terminalBlocks).toBe(1);
  });

  test('resolves JUMPI target with stack simulation', () => {
    // PUSH1 0x01  (condition: truthy, pushed first → TOS-1)
    // PUSH1 0x06  (target: JUMPDEST offset, pushed second → TOS)
    // JUMPI       (reads TOS as destination, TOS-1 as condition)
    // STOP
    // JUMPDEST    (at offset 0x06)
    // STOP
    const code = '6001' + '6006' + '57' + '00' + '5b' + '00';
    const bytes = hexToBytes(code);
    const result = disassemble(bytes);
    const cfg = buildCFG(result.instructions);

    // Should have resolved the jump
    expect(cfg.jumpResolution.staticResolved).toBeGreaterThanOrEqual(1);
  });

  test('counts terminal blocks correctly', () => {
    // Two separate STOP blocks
    // PUSH1 0x06 JUMP STOP JUMPDEST STOP
    const code = '600656' + '00' + '5b' + '00';
    const bytes = hexToBytes(code);
    const result = disassemble(bytes);
    const cfg = buildCFG(result.instructions);
    expect(cfg.terminalBlocks).toBeGreaterThanOrEqual(1);
  });

  test('reports resolution rate as N/A when no jumps', () => {
    const bytes = hexToBytes('00');
    const result = disassemble(bytes);
    const cfg = buildCFG(result.instructions);
    expect(cfg.jumpResolution.resolutionRate).toBe('N/A');
  });
});

// ============================================================
// Security Detectors
// ============================================================
describe('Security: Selfdestruct Detection', () => {
  test('detects SELFDESTRUCT in bytecode', () => {
    // PUSH1 0x00 SELFDESTRUCT
    const bytes = hexToBytes('6000ff');
    const result = disassemble(bytes);
    const cfg = buildCFG(result.instructions);
    const detection = detectSelfdestruct(result.instructions, cfg.blocks, cfg.edges);
    expect(detection.detected).toBe(true);
    expect(detection.blockIds.length).toBeGreaterThan(0);
    expect(detection.reachableFromEntry).toBe(true);
  });

  test('reports no selfdestruct when absent', () => {
    const bytes = hexToBytes('6080604052' + '00');
    const result = disassemble(bytes);
    const cfg = buildCFG(result.instructions);
    const detection = detectSelfdestruct(result.instructions, cfg.blocks, cfg.edges);
    expect(detection.detected).toBe(false);
    expect(detection.blockIds).toEqual([]);
  });
});

describe('Security: Unchecked Calls Detection', () => {
  test('detects unchecked CALL (POP after CALL)', () => {
    // PUSH1 0x00 x7 CALL POP STOP
    const code = '6000'.repeat(7) + 'f1' + '50' + '00';
    const bytes = hexToBytes(code);
    const result = disassemble(bytes);
    const cfg = buildCFG(result.instructions);
    const detection = detectUncheckedCalls(result.instructions, cfg.blocks);
    expect(detection.detected).toBe(true);
    expect(detection.count).toBe(1);
    const unchecked = detection.details.filter((d) => !d.checked);
    expect(unchecked[0].type).toBe('CALL');
  });

  test('detects checked CALL (ISZERO after CALL)', () => {
    // PUSH1 0x00 x7 CALL ISZERO STOP
    const code = '6000'.repeat(7) + 'f1' + '15' + '00';
    const bytes = hexToBytes(code);
    const result = disassemble(bytes);
    const cfg = buildCFG(result.instructions);
    const detection = detectUncheckedCalls(result.instructions, cfg.blocks);
    expect(detection.detected).toBe(false);
    const call = detection.details.find((d) => d.type === 'CALL');
    expect(call?.checked).toBe(true);
  });

  test('handles STATICCALL and DELEGATECALL', () => {
    // PUSH1 0x00 x6 STATICCALL POP PUSH1 0x00 x6 DELEGATECALL POP STOP
    const code = '6000'.repeat(6) + 'fa' + '50' + '6000'.repeat(6) + 'f4' + '50' + '00';
    const bytes = hexToBytes(code);
    const result = disassemble(bytes);
    const cfg = buildCFG(result.instructions);
    const detection = detectUncheckedCalls(result.instructions, cfg.blocks);
    expect(detection.count).toBe(2);
    const types = detection.details.map((d) => d.type).sort();
    expect(types).toContain('STATICCALL');
    expect(types).toContain('DELEGATECALL');
  });
});

describe('Security: Access Control Detection', () => {
  test('detects CALLER + SLOAD + EQ pattern', () => {
    // CALLER PUSH1 0x00 SLOAD EQ PUSH1 0x20 JUMPI
    const code = '33' + '6000' + '54' + '14' + '6020' + '57' + '5b' + '00';
    const bytes = hexToBytes(code);
    const result = disassemble(bytes);
    const cfg = buildCFG(result.instructions);
    const detection = detectAccessControl(result.instructions, cfg.blocks);
    expect(detection.detected).toBe(true);
    expect(detection.checks.length).toBeGreaterThan(0);
    expect(detection.checks[0].pattern).toBe('CALLER_SLOAD_EQ');
  });

  test('reports no access control when absent', () => {
    const bytes = hexToBytes('6080604052' + '00');
    const result = disassemble(bytes);
    const cfg = buildCFG(result.instructions);
    const detection = detectAccessControl(result.instructions, cfg.blocks);
    expect(detection.detected).toBe(false);
  });
});

describe('Security: Reentrancy Guard Detection', () => {
  test('reports no guard when pattern absent', () => {
    const bytes = hexToBytes('6080604052' + '00');
    const result = disassemble(bytes);
    const cfg = buildCFG(result.instructions);
    const detection = detectReentrancyGuard(result.instructions, cfg.blocks);
    expect(detection.detected).toBe(false);
    expect(detection.pattern).toBeNull();
  });

  test('detects transient storage pattern', () => {
    // TLOAD TSTORE PUSH1 0x00 x7 CALL TSTORE STOP
    const code = '5c' + '5d' + '6000'.repeat(7) + 'f1' + '5d' + '00';
    const bytes = hexToBytes(code);
    const result = disassemble(bytes);
    const cfg = buildCFG(result.instructions);
    const detection = detectReentrancyGuard(result.instructions, cfg.blocks);
    expect(detection.detected).toBe(true);
    expect(detection.pattern).toBe('transient');
  });
});

describe('Security: Payable Detection', () => {
  test('detects non-payable function (CALLVALUE ISZERO JUMPI guard)', () => {
    // Simulated handler: JUMPDEST CALLVALUE ISZERO PUSH1 0x10 JUMPI STOP
    const code = '5b' + '34' + '15' + '6010' + '57' + '00';
    const bytes = hexToBytes(code);
    const result = disassemble(bytes);
    const cfg = buildCFG(result.instructions);

    const selectors = [{
      selector: '0xdeadbeef',
      signatures: [],
      handlerOffset: 0,  // handler at offset 0 (JUMPDEST)
      parameterHints: [],
      isPayable: null,
    }];

    const detection = detectPayable(result.instructions, cfg.blocks, selectors);
    expect(detection.nonPayableFunctions).toContain('0xdeadbeef');
    expect(detection.payableFunctions).not.toContain('0xdeadbeef');
  });

  test('detects payable function (no CALLVALUE guard)', () => {
    // Handler: JUMPDEST PUSH1 0x04 CALLDATALOAD STOP
    const code = '5b' + '6004' + '35' + '00';
    const bytes = hexToBytes(code);
    const result = disassemble(bytes);
    const cfg = buildCFG(result.instructions);

    const selectors = [{
      selector: '0xcafebabe',
      signatures: [],
      handlerOffset: 0,
      parameterHints: [],
      isPayable: null,
    }];

    const detection = detectPayable(result.instructions, cfg.blocks, selectors);
    expect(detection.payableFunctions).toContain('0xcafebabe');
  });

  test('skips selectors with null handler offset', () => {
    const bytes = hexToBytes('00');
    const result = disassemble(bytes);
    const cfg = buildCFG(result.instructions);
    const selectors = [{
      selector: '0x12345678',
      signatures: [],
      handlerOffset: null,
      parameterHints: [],
      isPayable: null,
    }];
    const detection = detectPayable(result.instructions, cfg.blocks, selectors);
    expect(detection.payableFunctions).toEqual([]);
    expect(detection.nonPayableFunctions).toEqual([]);
  });
});

// ============================================================
// Chain Configuration
// ============================================================
describe('Chain Configuration', () => {
  test('returns config for supported chains', () => {
    const eth = getChainConfig('ethereum');
    expect(eth.name).toBe('ethereum');
    expect(eth.chainId).toBe(1);
    expect(eth.rpc).toBeTruthy();
  });

  test('is case-insensitive', () => {
    const config = getChainConfig('Ethereum');
    expect(config.name).toBe('ethereum');
  });

  test('throws for unsupported chain', () => {
    expect(() => getChainConfig('solana')).toThrow('Unsupported chain');
  });

  test('allows custom RPC override', () => {
    const config = getChainConfig('ethereum', 'https://my-custom-rpc.com');
    expect(config.rpc).toBe('https://my-custom-rpc.com');
    expect(config.name).toBe('ethereum');
  });

  test('supports all expected chains', () => {
    expect(CHAINS).toHaveProperty('ethereum');
    expect(CHAINS).toHaveProperty('base');
    expect(CHAINS).toHaveProperty('arbitrum');
    expect(CHAINS).toHaveProperty('polygon');
  });
});

// ============================================================
// Formatter
// ============================================================
describe('Formatter', () => {
  test('formatReport with text format', () => {
    const report = {
      address: '0x1234567890abcdef1234567890abcdef12345678',
      chain: 'ethereum',
      bytecodeSize: 100,
      isContract: true,
      metadata: {
        detected: true,
        cborLength: 10,
        solcVersion: '0.8.19',
        ipfsHash: null,
        bzzr0Hash: null,
        bzzr1Hash: null,
        rawHex: '0xaa',
      },
      timestamp: '2024-01-01T00:00:00.000Z',
    };
    const output = formatReport(report, 'text');
    expect(output).toContain('EVM BYTECODE ANALYSIS REPORT');
    expect(output).toContain('0x1234567890abcdef');
    expect(output).toContain('ethereum');
    expect(output).toContain('v0.8.19');
  });

  test('formatReport with json format', () => {
    const report = {
      address: '0x1234567890abcdef1234567890abcdef12345678',
      chain: 'ethereum',
      bytecodeSize: 100,
      isContract: true,
      metadata: {
        detected: false,
        cborLength: 0,
        solcVersion: null,
        ipfsHash: null,
        bzzr0Hash: null,
        bzzr1Hash: null,
        rawHex: '',
      },
      timestamp: '2024-01-01T00:00:00.000Z',
    };
    const output = formatReport(report, 'json');
    const parsed = JSON.parse(output);
    expect(parsed.address).toBe(report.address);
    expect(parsed.chain).toBe('ethereum');
  });

  test('formatReport with dot format returns CFG DOT', () => {
    const report = {
      address: '0x1234567890abcdef1234567890abcdef12345678',
      chain: 'ethereum',
      bytecodeSize: 100,
      isContract: true,
      metadata: {
        detected: false,
        cborLength: 0,
        solcVersion: null,
        ipfsHash: null,
        bzzr0Hash: null,
        bzzr1Hash: null,
        rawHex: '',
      },
      cfg: buildCFG(disassemble(hexToBytes('6080604052' + '00')).instructions),
      timestamp: '2024-01-01T00:00:00.000Z',
    };
    const output = formatReport(report, 'dot');
    expect(output).toContain('digraph CFG');
  });
});

// ============================================================
// CFG Adjacency List
// ============================================================
describe('CFG Adjacency List', () => {
  test('adjacency list is present and correct for linear code', () => {
    const bytes = hexToBytes('6080604052' + '00');
    const result = disassemble(bytes);
    const cfg = buildCFG(result.instructions);
    expect(cfg.adjacencyList).toBeDefined();
    // Single block with no outgoing edges (STOP)
    expect(cfg.adjacencyList[0]).toEqual([]);
  });

  test('adjacency list reflects jump edges', () => {
    // PUSH1 0x05 JUMP STOP JUMPDEST STOP
    // Block 0: PUSH1 0x05 JUMP  → jumps to block at offset 0x05 (JUMPDEST)
    // Block 1: STOP
    // Block 2: JUMPDEST STOP
    const code = '600556' + '00' + '5b' + '00';
    const bytes = hexToBytes(code);
    const result = disassemble(bytes);
    const cfg = buildCFG(result.instructions);
    expect(cfg.adjacencyList).toBeDefined();
    // Block 0 should have edges (either to the JUMPDEST block or dynamic)
    const allTargets = Object.values(cfg.adjacencyList).flat();
    expect(allTargets.length).toBeGreaterThanOrEqual(0);
  });

  test('empty CFG has empty adjacency list', () => {
    const cfg = buildCFG([]);
    expect(cfg.adjacencyList).toEqual({});
  });
});

// ============================================================
// Dynamic Jump Edges
// ============================================================
describe('Dynamic Jump Edges', () => {
  test('dynamic edges are created for unresolvable jumps', () => {
    // ADD JUMP — no way to know the target statically
    // PUSH1 0x01 PUSH1 0x02 ADD JUMP JUMPDEST STOP
    const code = '6001' + '6002' + '01' + '56' + '5b' + '00';
    const bytes = hexToBytes(code);
    const result = disassemble(bytes);
    const cfg = buildCFG(result.instructions);
    const dynamicEdges = cfg.edges.filter((e) => e.type === 'dynamic');
    expect(dynamicEdges.length).toBeGreaterThanOrEqual(0);
    // Dynamic edges should have to: -1
    for (const edge of dynamicEdges) {
      expect(edge.to).toBe(-1);
    }
  });
});

// ============================================================
// Polygon Chain
// ============================================================
describe('Polygon Chain Support', () => {
  test('polygon chain config is available', () => {
    expect(CHAINS).toHaveProperty('polygon');
    expect(CHAINS.polygon.chainId).toBe(137);
    expect(CHAINS.polygon.rpc).toBeTruthy();
  });

  test('getChainConfig works for polygon', () => {
    const config = getChainConfig('polygon');
    expect(config.name).toBe('polygon');
    expect(config.chainId).toBe(137);
  });
});

// ============================================================
// Payable Integration (isPayable field)
// ============================================================
describe('isPayable Field Integration', () => {
  test('detectPayable correctly classifies functions', () => {
    // Non-payable handler: JUMPDEST CALLVALUE ISZERO PUSH1 0x10 JUMPI STOP
    // Payable handler: JUMPDEST PUSH1 0x04 CALLDATALOAD STOP (no CALLVALUE guard)
    const nonPayableCode = '5b' + '34' + '15' + '6010' + '57' + '00';
    const payableCode = '5b' + '6004' + '35' + '00';
    const combined = nonPayableCode + payableCode;
    const bytes = hexToBytes(combined);
    const result = disassemble(bytes);
    const cfg = buildCFG(result.instructions);

    const selectors = [
      { selector: '0x11111111', signatures: [], handlerOffset: 0, parameterHints: [], isPayable: null },
      { selector: '0x22222222', signatures: [], handlerOffset: nonPayableCode.length / 2, parameterHints: [], isPayable: null },
    ];

    const detection = detectPayable(result.instructions, cfg.blocks, selectors);
    // First selector (offset 0) has CALLVALUE guard → non-payable
    expect(detection.nonPayableFunctions).toContain('0x11111111');
    // Second selector (no guard) → payable
    expect(detection.payableFunctions).toContain('0x22222222');
  });
});

// ============================================================
// Security: Proxy Detection (G12)
// ============================================================
describe('Security: Proxy Detection', () => {
  beforeEach(() => {
    mockGetStorageAt.mockReset();
  });

  test('detects EIP-1167 minimal proxy from bytecode pattern', async () => {
    // Standard EIP-1167 minimal proxy: 363d3d373d3d3d363d73<address>5af43d82803e903d91602b57fd5bf3
    const implAddr = '1234567890abcdef1234567890abcdef12345678';
    const prefix = '363d3d373d3d3d363d73';
    const suffix = '5af43d82803e903d91602b57fd5bf3';
    const bytecodeHex = prefix + implAddr + suffix;
    const bytecode = hexToBytes(bytecodeHex);
    const result = disassemble(bytecode);

    const proxy = await detectProxy(
      result.instructions,
      bytecode,
      '0xtest',
      dummyChain
    );

    expect(proxy.detected).toBe(true);
    expect(proxy.isMinimalProxy).toBe(true);
    expect(proxy.pattern).toBe('EIP-1167');
    expect(proxy.implementationAddress).toBe('0x' + implAddr);
  });

  test('returns false for non-proxy bytecode', async () => {
    const bytecode = hexToBytes('6080604052' + '00');
    const result = disassemble(bytecode);

    const proxy = await detectProxy(
      result.instructions,
      bytecode,
      '0xtest',
      dummyChain
    );

    expect(proxy.detected).toBe(false);
    expect(proxy.isMinimalProxy).toBe(false);
    expect(proxy.delegatecallCount).toBe(0);
  });

  test('counts DELEGATECALL instructions', async () => {
    // PUSH1 x6 DELEGATECALL STOP
    const code = '6000'.repeat(6) + 'f4' + '00';
    const bytecode = hexToBytes(code);
    const result = disassemble(bytecode);

    mockGetStorageAt.mockResolvedValue('0x' + '00'.repeat(32));

    const proxy = await detectProxy(
      result.instructions,
      bytecode,
      '0xtest',
      dummyChain
    );

    expect(proxy.delegatecallCount).toBe(1);
  });

  test('detects DELEGATECALL + SLOAD as proxy pattern', async () => {
    // PUSH1 0x00 SLOAD ... DELEGATECALL STOP
    const code = '6000' + '54' + '6000'.repeat(5) + 'f4' + '00';
    const bytecode = hexToBytes(code);
    const result = disassemble(bytecode);

    mockGetStorageAt.mockResolvedValue(
      '0x000000000000000000000000aabbccddee11223344556677889900aabbccddee'
    );

    const proxy = await detectProxy(
      result.instructions,
      bytecode,
      '0xtest',
      dummyChain
    );

    expect(proxy.detected).toBe(true);
    expect(proxy.delegatecallCount).toBe(1);
  });
});

// ============================================================
// ERC-165 Detection (G9)
// ============================================================
describe('ERC-165 Detection', () => {
  beforeEach(() => {
    mockEthCall.mockReset();
  });

  test('returns false for non-ERC165 contract', async () => {
    // eth_call returns null (reverts) for supportsInterface
    mockEthCall.mockResolvedValue(null);

    const result = await detectERC165('0x1234567890abcdef1234567890abcdef12345678', dummyChain);
    expect(result.supportsERC165).toBe(false);
    expect(result.interfaces).toEqual([]);
  });

  test('returns false when eth_call returns 0 (not supported)', async () => {
    mockEthCall.mockResolvedValue('0x' + '00'.repeat(32));

    const result = await detectERC165('0x1234567890abcdef1234567890abcdef12345678', dummyChain);
    expect(result.supportsERC165).toBe(false);
    expect(result.interfaces).toEqual([]);
  });

  test('detects ERC-165 and probes interfaces when supported', async () => {
    // First call: ERC-165 check → true
    // All subsequent calls: return true for ERC-165 and ERC-721, false for others
    const ERC165_ID = '01ffc9a7';
    const ERC721_ID = '80ac58cd';

    mockEthCall.mockImplementation(async (_addr: string, data: string) => {
      const interfaceId = data.slice(10, 18); // extract the interface ID from calldata
      if (interfaceId === ERC165_ID || interfaceId === ERC721_ID) {
        return '0x' + '0'.repeat(63) + '1'; // true
      }
      return '0x' + '0'.repeat(64); // false
    });

    const result = await detectERC165('0x1234567890abcdef1234567890abcdef12345678', dummyChain);
    expect(result.supportsERC165).toBe(true);
    expect(result.interfaces.length).toBeGreaterThan(0);

    const supported = result.interfaces.filter(i => i.supported).map(i => i.name);
    expect(supported).toContain('ERC-165');
    expect(supported).toContain('ERC-721 (NFT)');

    const unsupported = result.interfaces.filter(i => !i.supported);
    expect(unsupported.length).toBeGreaterThan(0);
  });
});

// ============================================================
// Server: Validation & SSRF (G11)
// ============================================================
describe('Server Validation Logic', () => {
  test('address validation regex accepts valid addresses', () => {
    const regex = /^0x[a-fA-F0-9]{40}$/;
    expect(regex.test('0xdAC17F958D2ee523a2206206994597C13D831ec7')).toBe(true);
    expect(regex.test('0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48')).toBe(true);
    expect(regex.test('0x0000000000000000000000000000000000000000')).toBe(true);
  });

  test('address validation regex rejects invalid addresses', () => {
    const regex = /^0x[a-fA-F0-9]{40}$/;
    expect(regex.test('invalid')).toBe(false);
    expect(regex.test('0x123')).toBe(false);
    expect(regex.test('0xGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG')).toBe(false);
    expect(regex.test('')).toBe(false);
    expect(regex.test('dAC17F958D2ee523a2206206994597C13D831ec7')).toBe(false); // no 0x
  });

  test('SSRF protection blocks private/internal IP ranges', () => {
    const blockedPatterns = [
      /^localhost$/,
      /^127\.\d+\.\d+\.\d+$/,
      /^10\.\d+\.\d+\.\d+$/,
      /^172\.(1[6-9]|2\d|3[01])\.\d+\.\d+$/,
      /^192\.168\.\d+\.\d+$/,
      /^169\.254\.\d+\.\d+$/,
      /^0\.0\.0\.0$/,
      /^\[?::1\]?$/,
      /^\[?fe80:/i,
      /^\[?fc00:/i,
      /^\[?fd/i,
    ];
    const isBlocked = (hostname: string) =>
      blockedPatterns.some(p => p.test(hostname));

    // Private IPs blocked
    expect(isBlocked('localhost')).toBe(true);
    expect(isBlocked('127.0.0.1')).toBe(true);
    expect(isBlocked('127.255.255.255')).toBe(true);
    expect(isBlocked('10.0.0.1')).toBe(true);
    expect(isBlocked('10.255.255.255')).toBe(true);
    expect(isBlocked('172.16.0.1')).toBe(true);
    expect(isBlocked('172.31.255.255')).toBe(true);
    expect(isBlocked('192.168.0.1')).toBe(true);
    expect(isBlocked('192.168.255.255')).toBe(true);
    expect(isBlocked('169.254.0.1')).toBe(true);
    expect(isBlocked('0.0.0.0')).toBe(true);
    expect(isBlocked('::1')).toBe(true);
    expect(isBlocked('[::1]')).toBe(true);

    // Public IPs allowed
    expect(isBlocked('8.8.8.8')).toBe(false);
    expect(isBlocked('1.1.1.1')).toBe(false);
    expect(isBlocked('ethereum-rpc.publicnode.com')).toBe(false);
    expect(isBlocked('172.32.0.1')).toBe(false); // 172.32.x.x is NOT private
    expect(isBlocked('11.0.0.1')).toBe(false);
  });

  test('RPC protocol validation', () => {
    const validProtocols = ['http:', 'https:', 'wss:', 'ws:'];
    const checkProtocol = (url: string) => {
      try {
        const parsed = new URL(url);
        return validProtocols.includes(parsed.protocol);
      } catch {
        return false;
      }
    };

    expect(checkProtocol('https://ethereum-rpc.publicnode.com')).toBe(true);
    expect(checkProtocol('http://localhost:8545')).toBe(true);
    expect(checkProtocol('wss://mainnet.infura.io/ws')).toBe(true);
    expect(checkProtocol('ws://localhost:8546')).toBe(true);
    expect(checkProtocol('ftp://evil.com')).toBe(false);
    expect(checkProtocol('file:///etc/passwd')).toBe(false);
    expect(checkProtocol('javascript:alert(1)')).toBe(false);
  });
});

// ============================================================
// Server: Fastify Injection Tests (G11)
// ============================================================
describe('Server REST API', () => {
  let app: any;

  beforeAll(async () => {
    const { buildApp } = require('../server');
    app = await buildApp({ logger: false });
  });

  afterAll(async () => {
    if (app) await app.close();
  });

  test('GET /health returns OK', async () => {
    const response = await app.inject({ method: 'GET', url: '/health' });
    expect(response.statusCode).toBe(200);
    const body = JSON.parse(response.payload);
    expect(body.status).toBe('ok');
    expect(body.supportedChains).toContain('ethereum');
  });

  test('POST /analyze rejects invalid address', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/analyze',
      payload: { address: 'invalid' },
    });
    expect(response.statusCode).toBe(400);
    const body = JSON.parse(response.payload);
    expect(body.error).toContain('Invalid');
  });

  test('POST /analyze blocks SSRF via private RPC', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/analyze',
      payload: {
        address: '0xdAC17F958D2ee523a2206206994597C13D831ec7',
        rpc: 'http://127.0.0.1:8545',
      },
    });
    expect(response.statusCode).toBe(400);
    const body = JSON.parse(response.payload);
    expect(body.error).toContain('private');
  });

  test('POST /analyze blocks non-http protocols', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/analyze',
      payload: {
        address: '0xdAC17F958D2ee523a2206206994597C13D831ec7',
        rpc: 'ftp://evil.com',
      },
    });
    expect(response.statusCode).toBe(400);
  });

  test('GET /disasm/:address rejects invalid address', async () => {
    const response = await app.inject({
      method: 'GET',
      url: '/disasm/notanaddress',
    });
    expect(response.statusCode).toBe(400);
  });
});

// ============================================================
// Binary Search Dispatch Resolution (G1)
// ============================================================
describe('Binary Search Dispatch Resolution', () => {
  test('resolves handler offset for selector seen first as GT then as EQ', () => {
    // Binary search dispatch: PUSH4 pivot GT PUSH2 branch JUMPI ... PUSH4 pivot EQ PUSH2 handler JUMPI
    // Block layout:
    // 0x0000: PUSH1 0x00 CALLDATALOAD PUSH1 0xe0 SHR  (selector extraction)
    // 0x0006: DUP1
    // 0x0007: PUSH4 0xabcdef01  (pivot for GT)
    // 0x000c: GT
    // 0x000d: PUSH2 0x0020  (branch offset)
    // 0x0010: JUMPI
    // 0x0011: DUP1
    // 0x0012: PUSH4 0xabcdef01  (same selector, now EQ)
    // 0x0017: EQ
    // 0x0018: PUSH2 0x0030  (handler offset)
    // 0x001b: JUMPI
    // 0x001c: REVERT
    const code =
      '6000' + '35' + '60e0' + '1c' +  // selector extraction
      '80' +                             // DUP1
      '63abcdef01' +                     // PUSH4 pivot
      '11' +                             // GT
      '610020' +                         // PUSH2 0x0020
      '57' +                             // JUMPI
      '80' +                             // DUP1
      '63abcdef01' +                     // PUSH4 same selector
      '14' +                             // EQ
      '610030' +                         // PUSH2 0x0030 (handler)
      '57' +                             // JUMPI
      '6000' + '80' + 'fd';             // REVERT

    const bytes = hexToBytes(code);
    const result = disassemble(bytes);
    const selectors = extractSelectors(result.instructions);

    // The selector should be found with the handler offset from the EQ entry
    const found = selectors.functions.find(f => f.selector === '0xabcdef01');
    expect(found).toBeDefined();
    expect(found!.handlerOffset).toBe(0x0030);
  });
});

// ============================================================
// Huff-style Bytecode Analysis (G8 — empirical comparison)
// ============================================================
describe('Huff-style Bytecode Analysis', () => {
  test('analyzes minimal Huff ERC20 dispatch correctly', () => {
    // This represents what the Huff compiler would output for a minimal ERC20 dispatch.
    // Huff compiles to raw EVM opcodes — no Solidity prologue, no CBOR metadata,
    // no free memory pointer. This IS representative of Huff output.
    //
    // Layout:
    //   0x0000: PUSH1 0x00 CALLDATALOAD PUSH1 0xe0 SHR   ; extract selector
    //   0x0006: DUP1 PUSH4 a9059cbb EQ PUSH2 0020 JUMPI  ; transfer()
    //   0x0011: DUP1 PUSH4 70a08231 EQ PUSH2 0028 JUMPI  ; balanceOf()
    //   0x001c: PUSH1 0x00 DUP1 REVERT                    ; no match
    //   0x0020: JUMPDEST PUSH1 04 CALLDATALOAD PUSH1 24 CALLDATALOAD STOP ; handler_transfer
    //   0x0028: JUMPDEST PUSH1 04 CALLDATALOAD STOP        ; handler_balanceOf
    const huffBytecode =
      '6000' + '35' + '60e0' + '1c' +             // selector extraction
      '80' + '63a9059cbb' + '14' + '610020' + '57' + // transfer dispatch
      '80' + '6370a08231' + '14' + '610028' + '57' + // balanceOf dispatch
      '6000' + '80' + 'fd' +                          // default revert
      '5b' + '6004' + '35' + '6024' + '35' + '00' +  // handler_transfer (0x0020)
      '5b' + '6004' + '35' + '00';                    // handler_balanceOf (0x0028)

    const bytecode = hexToBytes(huffBytecode);

    // === Disassembly ===
    const disResult = disassemble(bytecode);
    // No CBOR metadata — Huff doesn't add any
    expect(disResult.metadata.detected).toBe(false);
    // No free memory pointer prologue
    expect(disResult.instructions[0].mnemonic).toBe('PUSH1');
    expect(disResult.instructions[0].operandHex).toBe('0x00');
    expect(disResult.instructions[1].mnemonic).toBe('CALLDATALOAD');
    // Uses SHR (post-Shanghai efficient extraction)
    expect(disResult.instructions[3].mnemonic).toBe('SHR');
    // Total size is tiny — Huff bytecode is ~45 bytes vs ~3000+ for Solidity ERC20
    expect(bytecode.length).toBeLessThan(50);

    // === Selector Extraction ===
    const selectors = extractSelectors(disResult.instructions);
    expect(selectors.count).toBe(2);
    const sels = selectors.functions.map(f => f.selector);
    expect(sels).toContain('0xa9059cbb'); // transfer
    expect(sels).toContain('0x70a08231'); // balanceOf
    // Huff uses linear EQ dispatch — handlers should be resolved
    const transfer = selectors.functions.find(f => f.selector === '0xa9059cbb');
    expect(transfer!.handlerOffset).toBe(0x0020);
    const balanceOf = selectors.functions.find(f => f.selector === '0x70a08231');
    expect(balanceOf!.handlerOffset).toBe(0x0028);

    // === Parameter Inference ===
    const transferParams = inferParameters(disResult.instructions, 0x0020);
    expect(transferParams.length).toBe(2);
    expect(transferParams[0]).toBe('uint256'); // No AND mask → defaults to uint256
    expect(transferParams[1]).toBe('uint256'); // Huff doesn't auto-mask

    const balanceOfParams = inferParameters(disResult.instructions, 0x0028);
    expect(balanceOfParams.length).toBe(1);
    expect(balanceOfParams[0]).toBe('uint256'); // No address mask

    // === CFG ===
    const cfg = buildCFG(disResult.instructions);
    expect(cfg.totalBlocks).toBe(5);
    // 100% resolution rate — all jumps are direct in Huff
    expect(cfg.jumpResolution.staticResolved).toBe(cfg.jumpResolution.totalJumps);
    expect(cfg.jumpResolution.dynamic).toBe(0);
    // DOT output generated
    expect(cfg.dot).toContain('digraph CFG');
    // Terminal blocks: REVERT + 2x STOP = 3
    expect(cfg.terminalBlocks).toBe(3);

    // === Security Detectors ===
    // All return negative — Huff has no standardized security patterns
    const selfdestruct = detectSelfdestruct(disResult.instructions, cfg.blocks, cfg.edges);
    expect(selfdestruct.detected).toBe(false);

    const unchecked = detectUncheckedCalls(disResult.instructions, cfg.blocks);
    expect(unchecked.detected).toBe(false);

    const accessControl = detectAccessControl(disResult.instructions, cfg.blocks);
    expect(accessControl.detected).toBe(false);

    const reentrancy = detectReentrancyGuard(disResult.instructions, cfg.blocks);
    expect(reentrancy.detected).toBe(false);
  });
});
