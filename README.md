# EVM Bytecode Reverse Engineering Toolkit

A comprehensive EVM bytecode analysis toolkit that fetches any deployed smart contract, disassembles it into
human-readable opcodes, reconstructs the control flow graph, extracts the public interface, and identifies
common security patterns — all without access to source code.

**Built for the Luganodes SDE Intern Assessment (Task 2)**

## Features

### 1. Bytecode Fetcher & Disassembler
- Fetches deployed bytecode via `eth_getCode` from any supported chain
- Full Constantinople+ instruction set (including Shanghai's `PUSH0`, Cancun's `TLOAD`/`TSTORE`/`MCOPY`)
- Annotated disassembly: offset, opcode hex, mnemonic, and operand
- Separates CBOR metadata from executable code; extracts Solidity version, IPFS/Swarm hashes

### 2. Function Selector Extraction & Resolution
- Parses both linear scan and binary search dispatch tables
- Resolves selectors to signatures via OpenChain & 4byte.directory APIs
- Handles hash collisions (shows all matching signatures)
- Infers parameter types from ABI encoding patterns (see [documented heuristics](#parameter-inference-heuristics))

### 3. Control Flow Graph
- Partitions code into basic blocks (leaders at `JUMPDEST` and after terminators)
- Directed graph with edges for `JUMP`, `JUMPI` (true/false), fallthrough, and dynamic targets
- Intra-block stack simulation resolves jump targets through `DUP`/`SWAP` operations
- Exports as **DOT (Graphviz)**, **JSON adjacency list**, or **SVG** (if Graphviz installed)
- Reports static vs. dynamic jump resolution percentage

### 4. Security Pattern Detector (all 6 patterns)
| Pattern | Detection Method |
|---------|-----------------|
| **Proxy Contract** | `DELEGATECALL` + `SLOAD` → resolves implementation via EIP-1967 slots + custom storage probing |
| **Selfdestruct** | Flags `SELFDESTRUCT` opcode, traces CFG paths from entry |
| **Unchecked Calls** | `CALL`/`STATICCALL`/`DELEGATECALL` not followed by `ISZERO`/`AND`/`EQ` check |
| **Reentrancy Guard** | Detects OpenZeppelin-style `SLOAD`→`SSTORE`→`CALL`→`SSTORE` mutex + EIP-1153 transient storage |
| **Access Control** | `CALLER` compared against `SLOAD` value or hardcoded `PUSH20` address |
| **Payable Functions** | Classifies each function by presence of `CALLVALUE`→`ISZERO`→`JUMPI` guard |

### 5. ERC-165 Interface Detection
- Calls `supportsInterface(bytes4)` via `eth_call` to detect standard interfaces
- Probes for ERC-20, ERC-721, ERC-1155, ERC-2981, ERC-173, and more

### 6. CLI & REST API
- Feature-rich CLI with `--disasm`, `--selectors`, `--cfg`, `--security` flags
- REST API: `POST /analyze`, `GET /disasm/:address`, `GET /health`
- Supports **Ethereum**, **Base**, **Arbitrum**, and **Polygon** via configurable RPC URLs

## Quick Start

```bash
# Install dependencies
npm install

# Type-check without emitting (verify build)
npm run typecheck

# CLI: Analyze USDT on Ethereum mainnet
npx ts-node src/index.ts 0xdAC17F958D2ee523a2206206994597C13D831ec7 --selectors --security

# CLI: Full analysis with all flags
npx ts-node src/index.ts 0xdAC17F958D2ee523a2206206994597C13D831ec7 --all

# CLI: Output as JSON (includes CFG adjacency list, blocks, edges)
npx ts-node src/index.ts 0xdAC17F958D2ee523a2206206994597C13D831ec7 --all --output json

# CLI: Output CFG as DOT
npx ts-node src/index.ts 0xdAC17F958D2ee523a2206206994597C13D831ec7 --cfg --output dot

# CLI: Generate SVG (requires Graphviz)
npx ts-node src/index.ts 0xdAC17F958D2ee523a2206206994597C13D831ec7 --cfg --svg

# CLI: Analyze on Base L2
npx ts-node src/index.ts 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913 --chain base --selectors

# CLI: Check version
npx ts-node src/index.ts --version

# Start REST API server
npx ts-node src/server.ts
# Then: curl -X POST http://localhost:3000/analyze -H "Content-Type: application/json" \
#   -d '{"address": "0xdAC17F958D2ee523a2206206994597C13D831ec7", "chain": "ethereum"}'

# Run tests
npm test
```

## Environment Variables

Copy `.env.example` to `.env` to customize RPC endpoints:

```bash
cp .env.example .env
```

| Variable | Default | Description |
|----------|---------|-------------|
| `ETH_RPC` | `https://ethereum-rpc.publicnode.com` | Ethereum mainnet RPC |
| `BASE_RPC` | `https://base-rpc.publicnode.com` | Base L2 RPC |
| `ARBITRUM_RPC` | `https://arbitrum-one-rpc.publicnode.com` | Arbitrum L2 RPC |
| `POLYGON_RPC` | `https://polygon-bor-rpc.publicnode.com` | Polygon L2 RPC |
| `PORT` | `3000` | REST API server port |
| `HOST` | `0.0.0.0` | REST API server host |

All default RPCs are free public endpoints — no API keys required.

## Architecture

```
src/
├── index.ts          # CLI entry point (commander)
├── server.ts         # REST API (Fastify)
├── analyzer.ts       # Pipeline orchestrator: fetch → disassemble → selectors → CFG → security → ERC-165
├── fetcher.ts        # RPC client (viem): eth_getCode, eth_getStorageAt, eth_call
├── disassembler.ts   # Linear sweep disassembler
├── selectors.ts      # Dispatch table parser + API resolver + parameter inference
├── cfg.ts            # CFG builder + stack simulation + DOT/SVG export
├── metadata.ts       # CBOR metadata parser (solc version, IPFS/Swarm hash)
├── erc165.ts         # ERC-165 interface detection via eth_call
├── formatter.ts      # Output formatting (text, JSON, DOT)
├── types.ts          # TypeScript type definitions
├── opcodes.ts        # Complete EVM opcode table (Constantinople+)
├── chains.ts         # Chain configs (Ethereum, Base, Arbitrum, Polygon)
├── utils.ts          # Hex utils, BFS, path finding
├── security/
│   ├── index.ts      # Security analysis orchestrator
│   ├── proxy.ts      # Proxy/delegatecall detection (EIP-1167, EIP-1967)
│   ├── selfdestruct.ts # Selfdestruct + CFG path tracing
│   ├── unchecked-calls.ts # Unchecked CALL/STATICCALL/DELEGATECALL
│   ├── reentrancy.ts # Reentrancy guard detection
│   ├── access-control.ts # Owner check detection
│   └── payable.ts    # Payable vs non-payable classification
└── test/
    ├── unit.test.ts        # 75 unit tests
    └── integration.test.ts # 4 integration tests (mainnet)
```

## Parameter Inference Heuristics

The parameter inference system analyzes bytecode patterns after each function's handler `JUMPDEST`:

1. **Slot detection**: `PUSH <offset>` + `CALLDATALOAD` where offset ≥ 4 and (offset-4) % 32 === 0
   maps to parameter index `(offset - 4) / 32`

2. **Type inference from post-load operations**:
   - `AND` with `0xffffffffffffffffffffffffffffffffffffffff` (20 bytes) → `address`
   - `AND` with `0xff` → `uint8`
   - `AND` with `0xffff` → `uint16`
   - `ISZERO` → `bool`
   - No type clue within 6 instructions → `uint256` (default)

3. **Limitations**:
   - Cannot detect dynamic types (`bytes`, `string`, arrays) due to pointer indirection
   - Struct parameters appear as multiple sequential slots
   - Optimizer-reordered code may confuse the lookahead window

## API Endpoints

### `POST /analyze`
Full analysis. Body: `{ address, chain?, rpc?, analyses?: ["disasm","selectors","cfg","security"] }`

### `GET /disasm/:address?chain=ethereum`
Quick disassembly + selector extraction.

### `GET /health`
Server health check, lists supported chains.

## Testing

```bash
# Run all tests
npm test

# Run only unit tests (fast, no network)
npx jest src/test/unit.test.ts --verbose

# Run integration tests (requires network, ~90s)
npx jest src/test/integration.test.ts --verbose
```

**Test coverage**: 93 tests total
- 89 unit tests covering all modules (disassembler, selectors, CFG, all 6 security detectors, proxy detection, ERC-165, server validation/SSRF, formatter, chains, Huff-style bytecode analysis, binary-search dispatch resolution)
- 4 integration tests including:
  - USDT full analysis (selectors, CFG, security)
  - USDC proxy detection (EIP-1967 + custom slot resolution)
  - Base L2 USDC (cross-chain support)
  - BAYC ERC-165 interface detection (ERC-721)

## Tech Stack

- **TypeScript** (strict mode, ES2022 target)
- **viem** — type-safe Ethereum RPC client
- **Fastify** — REST API server
- **Commander** — CLI framework
- **Jest + ts-jest** — test framework

## Design Decisions

### Why Linear Sweep Disassembly?

We use linear sweep (decode sequentially from offset 0) rather than recursive descent. Linear sweep is simpler and guaranteed to visit every byte in the code section. Its main drawback — misinterpreting data as instructions — is mitigated by our CBOR metadata separator, which strips the metadata blob before disassembly. For EVM bytecode specifically, Solidity/Vyper compilers place all executable code contiguously before the metadata, making linear sweep highly effective.

### Why `viem` Instead of `ethers.js`?

`viem` provides first-class TypeScript types for all RPC methods and return values, eliminating an entire class of runtime errors. It also supports tree-shaking (smaller bundle) and has a more explicit API that maps directly to JSON-RPC methods. For a tool that makes raw `eth_getCode`, `eth_getStorageAt`, and `eth_call` requests, viem's low-level approach matches our use case better than ethers.js's higher-level abstractions.

### Stack Simulation for Jump Resolution

Rather than treating all `JUMP`/`JUMPI` as dynamic, we simulate the EVM stack within each basic block to resolve jump targets. We track `PUSH`, `DUP`, and `SWAP` effects on a symbolic stack. When we reach a `JUMP`, if the top-of-stack is a known constant pushed earlier in the same block, we can resolve it statically. This approach resolves ~20-55% of jumps across real contracts (see RESEARCH.md), limited by cross-block jumps like internal function returns.

### Two-Phase Selector Resolution

Selectors are first extracted from bytecode patterns (zero network cost), then resolved via external APIs (OpenChain + 4byte.directory). This two-phase approach means the tool works offline for selector extraction and only hits the network for human-readable names. We batch API requests and try OpenChain first (higher quality data), falling back to 4byte.directory for unresolved selectors.

### Security Detectors as Independent Modules

Each of the 6 security detectors is a standalone module with no dependencies on other detectors. This makes them independently testable, easy to extend (add a new pattern by adding one file), and allows parallel execution. The proxy detector is the only async one (requires RPC calls to read storage slots); it runs concurrently with all sync detectors.

## Known Limitations

1. **Dynamic jump resolution is incomplete** (~20-55% success rate). Cross-block jumps from internal function calls and return trampolines require full symbolic execution or abstract interpretation to resolve — beyond our intra-block stack simulation.
2. **Parameter type inference is heuristic-based.** We detect `address`, `bool`, and small integer types by post-CALLDATALOAD operations, but cannot detect dynamic types (`bytes`, `string`, arrays) that use pointer indirection.
3. **Access control detection misses some patterns.** Solidity 0.4.x's `require(msg.sender == owner)` compiles to a slightly different sequence than the `CALLER + SLOAD + EQ` pattern we match. Role-based access (OpenZeppelin AccessControl) is also not covered.
4. **SVG generation requires Graphviz.** The `dot` command must be installed locally. Without it, DOT format and JSON adjacency list are still available.
5. **Vyper and Huff contracts have reduced detection accuracy.** Our heuristics are optimized for Solidity-compiled bytecode. See RESEARCH.md Section 4 for detailed analysis.

## Deployment

The REST API is deployed on **Render** (free tier). A `render.yaml` is included for one-click deployment:

```bash
# Build and start locally
npm run build
npm start
```

The server reads `PORT` from environment variables (Render sets this automatically) and listens on `0.0.0.0`.
