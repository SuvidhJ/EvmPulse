import { OpcodeInfo } from './types';

// Complete Constantinople+ EVM opcode table
// Reference: https://www.evm.codes/

function op(
  byte: number,
  mnemonic: string,
  operandSize: number,
  stackIn: number,
  stackOut: number,
  category: OpcodeInfo['category'],
  halts = false,
  jumps = false
): OpcodeInfo {
  return { byte, mnemonic, operandSize, stackIn, stackOut, halts, jumps, category };
}

const opcodeList: OpcodeInfo[] = [
  // 0x00: Stop and Arithmetic
  op(0x00, 'STOP', 0, 0, 0, 'flow', true),
  op(0x01, 'ADD', 0, 2, 1, 'arithmetic'),
  op(0x02, 'MUL', 0, 2, 1, 'arithmetic'),
  op(0x03, 'SUB', 0, 2, 1, 'arithmetic'),
  op(0x04, 'DIV', 0, 2, 1, 'arithmetic'),
  op(0x05, 'SDIV', 0, 2, 1, 'arithmetic'),
  op(0x06, 'MOD', 0, 2, 1, 'arithmetic'),
  op(0x07, 'SMOD', 0, 2, 1, 'arithmetic'),
  op(0x08, 'ADDMOD', 0, 3, 1, 'arithmetic'),
  op(0x09, 'MULMOD', 0, 3, 1, 'arithmetic'),
  op(0x0a, 'EXP', 0, 2, 1, 'arithmetic'),
  op(0x0b, 'SIGNEXTEND', 0, 2, 1, 'arithmetic'),

  // 0x10: Comparison & Bitwise Logic
  op(0x10, 'LT', 0, 2, 1, 'comparison'),
  op(0x11, 'GT', 0, 2, 1, 'comparison'),
  op(0x12, 'SLT', 0, 2, 1, 'comparison'),
  op(0x13, 'SGT', 0, 2, 1, 'comparison'),
  op(0x14, 'EQ', 0, 2, 1, 'comparison'),
  op(0x15, 'ISZERO', 0, 1, 1, 'comparison'),
  op(0x16, 'AND', 0, 2, 1, 'bitwise'),
  op(0x17, 'OR', 0, 2, 1, 'bitwise'),
  op(0x18, 'XOR', 0, 2, 1, 'bitwise'),
  op(0x19, 'NOT', 0, 1, 1, 'bitwise'),
  op(0x1a, 'BYTE', 0, 2, 1, 'bitwise'),
  op(0x1b, 'SHL', 0, 2, 1, 'bitwise'),   // Constantinople
  op(0x1c, 'SHR', 0, 2, 1, 'bitwise'),   // Constantinople
  op(0x1d, 'SAR', 0, 2, 1, 'bitwise'),   // Constantinople

  // 0x20: Keccak256
  op(0x20, 'KECCAK256', 0, 2, 1, 'keccak'),

  // 0x30: Environmental Information
  op(0x30, 'ADDRESS', 0, 0, 1, 'environment'),
  op(0x31, 'BALANCE', 0, 1, 1, 'environment'),
  op(0x32, 'ORIGIN', 0, 0, 1, 'environment'),
  op(0x33, 'CALLER', 0, 0, 1, 'environment'),
  op(0x34, 'CALLVALUE', 0, 0, 1, 'environment'),
  op(0x35, 'CALLDATALOAD', 0, 1, 1, 'environment'),
  op(0x36, 'CALLDATASIZE', 0, 0, 1, 'environment'),
  op(0x37, 'CALLDATACOPY', 0, 3, 0, 'environment'),
  op(0x38, 'CODESIZE', 0, 0, 1, 'environment'),
  op(0x39, 'CODECOPY', 0, 3, 0, 'environment'),
  op(0x3a, 'GASPRICE', 0, 0, 1, 'environment'),
  op(0x3b, 'EXTCODESIZE', 0, 1, 1, 'environment'),
  op(0x3c, 'EXTCODECOPY', 0, 4, 0, 'environment'),
  op(0x3d, 'RETURNDATASIZE', 0, 0, 1, 'environment'),
  op(0x3e, 'RETURNDATACOPY', 0, 3, 0, 'environment'),
  op(0x3f, 'EXTCODEHASH', 0, 1, 1, 'environment'), // Constantinople

  // 0x40: Block Information
  op(0x40, 'BLOCKHASH', 0, 1, 1, 'block'),
  op(0x41, 'COINBASE', 0, 0, 1, 'block'),
  op(0x42, 'TIMESTAMP', 0, 0, 1, 'block'),
  op(0x43, 'NUMBER', 0, 0, 1, 'block'),
  op(0x44, 'PREVRANDAO', 0, 0, 1, 'block'), // was DIFFICULTY
  op(0x45, 'GASLIMIT', 0, 0, 1, 'block'),
  op(0x46, 'CHAINID', 0, 0, 1, 'block'),
  op(0x47, 'SELFBALANCE', 0, 0, 1, 'block'),
  op(0x48, 'BASEFEE', 0, 0, 1, 'block'),

  // 0x50: Stack, Memory, Storage and Flow
  op(0x50, 'POP', 0, 1, 0, 'stack'),
  op(0x51, 'MLOAD', 0, 1, 1, 'memory'),
  op(0x52, 'MSTORE', 0, 2, 0, 'memory'),
  op(0x53, 'MSTORE8', 0, 2, 0, 'memory'),
  op(0x54, 'SLOAD', 0, 1, 1, 'storage'),
  op(0x55, 'SSTORE', 0, 2, 0, 'storage'),
  op(0x56, 'JUMP', 0, 1, 0, 'flow', false, true),
  op(0x57, 'JUMPI', 0, 2, 0, 'flow', false, true),
  op(0x58, 'PC', 0, 0, 1, 'flow'),
  op(0x59, 'MSIZE', 0, 0, 1, 'memory'),
  op(0x5a, 'GAS', 0, 0, 1, 'environment'),
  op(0x5b, 'JUMPDEST', 0, 0, 0, 'flow'),

  // 0x5f: PUSH0 (Shanghai)
  op(0x5f, 'PUSH0', 0, 0, 1, 'push'),

  // 0xf0: System operations
  op(0xf0, 'CREATE', 0, 3, 1, 'system'),
  op(0xf1, 'CALL', 0, 7, 1, 'system'),
  op(0xf2, 'CALLCODE', 0, 7, 1, 'system'),
  op(0xf3, 'RETURN', 0, 2, 0, 'flow', true),
  op(0xf4, 'DELEGATECALL', 0, 6, 1, 'system'),
  op(0xf5, 'CREATE2', 0, 4, 1, 'system'),     // Constantinople
  op(0xfa, 'STATICCALL', 0, 6, 1, 'system'),
  op(0xfd, 'REVERT', 0, 2, 0, 'flow', true),
  op(0xfe, 'INVALID', 0, 0, 0, 'invalid', true),
  op(0xff, 'SELFDESTRUCT', 0, 1, 0, 'system', true),

  // Transient storage (EIP-1153, Cancun)
  op(0x5c, 'TLOAD', 0, 1, 1, 'storage'),
  op(0x5d, 'TSTORE', 0, 2, 0, 'storage'),
  // MCOPY (Cancun)
  op(0x5e, 'MCOPY', 0, 3, 0, 'memory'),
];

// Generate PUSH1-PUSH32
for (let i = 1; i <= 32; i++) {
  opcodeList.push(op(0x5f + i, `PUSH${i}`, i, 0, 1, 'push'));
}

// Generate DUP1-DUP16
for (let i = 1; i <= 16; i++) {
  opcodeList.push(op(0x7f + i, `DUP${i}`, 0, i, i + 1, 'dup'));
}

// Generate SWAP1-SWAP16
for (let i = 1; i <= 16; i++) {
  opcodeList.push(op(0x8f + i, `SWAP${i}`, 0, i + 1, i + 1, 'swap'));
}

// Generate LOG0-LOG4
for (let i = 0; i <= 4; i++) {
  opcodeList.push(op(0xa0 + i, `LOG${i}`, 0, i + 2, 0, 'log'));
}

// Build lookup map
export const OPCODES: Map<number, OpcodeInfo> = new Map();
for (const info of opcodeList) {
  OPCODES.set(info.byte, info);
}

export function getOpcodeInfo(byte: number): OpcodeInfo {
  return (
    OPCODES.get(byte) ?? {
      byte,
      mnemonic: `INVALID(0x${byte.toString(16).padStart(2, '0')})`,
      operandSize: 0,
      stackIn: 0,
      stackOut: 0,
      halts: true,
      jumps: false,
      category: 'invalid' as const,
    }
  );
}