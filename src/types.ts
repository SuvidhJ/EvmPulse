// ============================================================
// Core type definitions for the entire analysis pipeline
// ============================================================

export interface OpcodeInfo {
  byte: number;
  mnemonic: string;
  operandSize: number; // 0 for most, 1-32 for PUSH1-PUSH32
  stackIn: number;
  stackOut: number;
  halts: boolean;      // STOP, RETURN, REVERT, INVALID, SELFDESTRUCT
  jumps: boolean;      // JUMP, JUMPI
  category: OpcodeCategory;
}

export type OpcodeCategory =
  | 'arithmetic'
  | 'comparison'
  | 'bitwise'
  | 'keccak'
  | 'environment'
  | 'block'
  | 'stack'
  | 'memory'
  | 'storage'
  | 'flow'
  | 'push'
  | 'dup'
  | 'swap'
  | 'log'
  | 'system'
  | 'invalid';

export interface Instruction {
  offset: number;
  opcodeByte: number;
  mnemonic: string;
  operand: Uint8Array | null; // null for non-PUSH instructions
  operandHex: string | null;
  info: OpcodeInfo;
}

export interface CborMetadata {
  detected: boolean;
  cborLength: number;
  solcVersion: string | null;
  ipfsHash: string | null;
  bzzr0Hash: string | null;
  bzzr1Hash: string | null;
  rawHex: string;
}

export interface DisassemblyResult {
  instructions: Instruction[];
  codeBytes: number;
  dataBytes: number;      // metadata region
  unreachableBytes: number;  // bytes in unreachable (data) regions within executable code
  metadata: CborMetadata;
  rawBytecodeHex: string;
}

export interface FunctionSelector {
  selector: string;         // "0xa9059cbb"
  signatures: string[];     // ["transfer(address,uint256)"]
  handlerOffset: number | null;
  parameterHints: string[]; // ["address", "uint256"]
  isPayable: boolean | null;
}

export interface SelectorResult {
  count: number;
  dispatchEndOffset: number;
  functions: FunctionSelector[];
  fallbackOffset: number | null;
}

export interface BasicBlock {
  id: number;
  startOffset: number;
  endOffset: number;
  instructions: Instruction[];
  terminator: string;       // mnemonic of last instruction
}

export interface CFGEdge {
  from: number;  // block id
  to: number;    // block id
  type: 'jump' | 'conditional_true' | 'conditional_false' | 'fallthrough' | 'dynamic';
}

export interface JumpResolutionStats {
  totalJumps: number;
  staticResolved: number;
  dynamic: number;
  resolutionRate: string;  // "93.3%"
}

export interface CFGResult {
  totalBlocks: number;
  totalEdges: number;
  terminalBlocks: number;
  jumpResolution: JumpResolutionStats;
  blocks: BasicBlock[];
  edges: CFGEdge[];
  adjacencyList: Record<number, number[]>;  // JSON adjacency list (block id → connected block ids)
  dot: string;            // DOT format string
}

// Security pattern results
export interface ProxyDetection {
  detected: boolean;
  isMinimalProxy: boolean;
  pattern: string | null;     // "EIP-1967", "EIP-1167", "custom"
  implementationAddress: string | null;
  delegatecallCount: number;
  adminAddress: string | null;
}

export interface SelfdestructDetection {
  detected: boolean;
  blockIds: number[];
  reachableFromEntry: boolean;
  paths: number[][];           // paths from entry to selfdestruct blocks
}

export interface UncheckedCallInfo {
  offset: number;
  type: string;  // "CALL", "STATICCALL", "DELEGATECALL"
  checked: boolean;
}

export interface UncheckedCallDetection {
  detected: boolean;
  count: number;
  details: UncheckedCallInfo[];
}

export interface AccessControlDetection {
  detected: boolean;
  checks: Array<{
    offset: number;
    pattern: string;   // "CALLER_SLOAD_EQ", "CALLER_PUSH20_EQ"
    storageSlot: string | null;
    hardcodedAddress: string | null;
  }>;
}

export interface ReentrancyGuardDetection {
  detected: boolean;
  pattern: string | null;     // "OpenZeppelin", "custom", "transient"
  storageSlot: string | null;
}

export interface PayableDetection {
  payableFunctions: string[];     // selectors
  nonPayableFunctions: string[];  // selectors
}

export interface SecurityReport {
  proxy: ProxyDetection;
  selfdestruct: SelfdestructDetection;
  uncheckedCalls: UncheckedCallDetection;
  accessControl: AccessControlDetection;
  reentrancyGuard: ReentrancyGuardDetection;
  payable: PayableDetection;
}

export interface ERC165Result {
  supportsERC165: boolean;
  interfaces: Array<{
    id: string;          // interface ID (e.g. "0x80ac58cd")
    name: string;        // human name (e.g. "ERC-721")
    supported: boolean;
  }>;
}

export interface AnalysisReport {
  address: string;
  chain: string;
  bytecodeSize: number;
  isContract: boolean;
  metadata: CborMetadata;
  disassembly?: DisassemblyResult;
  selectors?: SelectorResult;
  cfg?: CFGResult;
  security?: SecurityReport;
  erc165?: ERC165Result;
  timestamp: string;
}

export interface ChainConfig {
  name: string;
  rpc: string;
  chainId: number;
}

export type AnalysisFlags = {
  disasm: boolean;
  selectors: boolean;
  cfg: boolean;
  security: boolean;
};