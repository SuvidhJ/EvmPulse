# EVM Bytecode Reverse Engineering Toolkit

A comprehensive EVM bytecode analysis toolkit that fetches any deployed smart contract, disassembles it into
human-readable opcodes, reconstructs the control flow graph, extracts the public interface, and identifies
common security patterns — all without access to source code.

**Built for the Luganodes SDE Intern Assessment (Task 2)**

---

## Table of Contents

- [Prerequisites](#prerequisites)
- [Installation & Setup](#installation--setup)
- [How to Run](#how-to-run)
  - [CLI Usage](#cli-usage)
  - [REST API](#rest-api)
- [Features](#features)
- [Architecture](#architecture)
- [Testing](#testing)
- [Deployment](#deployment)
- [API Endpoints](#api-endpoints)
- [Environment Variables](#environment-variables)
- [Design Decisions](#design-decisions)
- [Known Limitations](#known-limitations)

---

## Prerequisites

- **Node.js** >= 18.0.0 ([download](https://nodejs.org/))
- **npm** (comes with Node.js)
- **Git** ([download](https://git-scm.com/))
- **Graphviz** (optional, only for SVG graph export — [download](https://graphviz.org/download/))

## Installation & Setup

```bash
# 1. Clone the repository
git clone https://github.com/SuvidhJ/Luganodes-Hiring---Task-2.git
cd Luganodes-Hiring---Task-2

# 2. Install dependencies
npm install

# 3. (Optional) Copy and configure environment variables
cp .env.example .env
# Edit .env if you want to use custom RPC endpoints — defaults work out of the box

# 4. Verify the build compiles cleanly
npm run typecheck

# 5. Run tests to confirm everything works
npm test
```

That's it — no API keys needed. The default RPC endpoints are free public nodes.

---

## How to Run

### CLI Usage

The CLI analyzes any deployed contract by address. Run it with `npx ts-node src/index.ts`:

```bash
# Basic: Disassemble a contract
npx ts-node src/index.ts 0xdAC17F958D2ee523a2206206994597C13D831ec7 --disasm

# Extract function selectors
npx ts-node src/index.ts 0xdAC17F958D2ee523a2206206994597C13D831ec7 --selectors

# Build Control Flow Graph
npx ts-node src/index.ts 0xdAC17F958D2ee523a2206206994597C13D831ec7 --cfg

# Run security analysis
npx ts-node src/index.ts 0xdAC17F958D2ee523a2206206994597C13D831ec7 --security

# Full analysis (all of the above)
npx ts-node src/index.ts 0xdAC17F958D2ee523a2206206994597C13D831ec7 --all
```

#### Output Formats

```bash
# JSON output (machine-readable, includes CFG adjacency list)
npx ts-node src/index.ts 0xdAC17F958D2ee523a2206206994597C13D831ec7 --all --output json

# Save JSON to a file
npx ts-node src/index.ts 0xdAC17F958D2ee523a2206206994597C13D831ec7 --all --output json --out result.json

# DOT format (for Graphviz)
npx ts-node src/index.ts 0xdAC17F958D2ee523a2206206994597C13D831ec7 --cfg --output dot

# Generate SVG image (requires Graphviz installed)
npx ts-node src/index.ts 0xdAC17F958D2ee523a2206206994597C13D831ec7 --cfg --svg
```

#### Multi-Chain Support

```bash
# Analyze on Ethereum (default)
npx ts-node src/index.ts 0xdAC17F958D2ee523a2206206994597C13D831ec7 --all

# Analyze on Base L2
npx ts-node src/index.ts 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913 --chain base --selectors

# Analyze on Arbitrum
npx ts-node src/index.ts <address> --chain arbitrum --all

# Analyze on Polygon
npx ts-node src/index.ts <address> --chain polygon --all

# Use a custom RPC URL
npx ts-node src/index.ts <address> --rpc https://your-rpc-url.com --selectors
```

#### Other CLI Options

```bash
# Check version
npx ts-node src/index.ts --version

# Show help
npx ts-node src/index.ts --help
```

### REST API

```bash
# Start the API server (development mode)
npx ts-node src/server.ts

# Or build and start in production mode
npm run build
npm start
```

The server starts on `http://localhost:3000` by default.

#### Example API Requests

```bash
# Health check
curl http://localhost:3000/health

# Full analysis
curl -X POST http://localhost:3000/analyze \
  -H "Content-Type: application/json" \
  -d '{"address": "0xdAC17F958D2ee523a2206206994597C13D831ec7", "chain": "ethereum"}'

# Analysis with specific modules only
curl -X POST http://localhost:3000/analyze \
  -H "Content-Type: application/json" \
  -d '{"address": "0xdAC17F958D2ee523a2206206994597C13D831ec7", "analyses": ["selectors", "security"]}'

# Quick disassembly
curl http://localhost:3000/disasm/0xdAC17F958D2ee523a2206206994597C13D831ec7?chain=ethereum
```

---

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

---

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
    ├── unit.test.ts        # 93 unit tests
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

**Test coverage**: 97 tests total (all passing)
- 93 unit tests covering all modules (disassembler, selectors, CFG, all 6 security detectors, proxy detection, ERC-165, server validation/SSRF, formatter, chains, Huff-style bytecode analysis, binary-search dispatch resolution)
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

The REST API can be deployed on **Render** (free tier). A `render.yaml` is included for easy setup.

### Deploy to Render

1. Go to [render.com](https://render.com) and sign up / log in
2. Click **New** → **Web Service** → connect your GitHub repo
3. Render auto-detects the `render.yaml`. Verify these settings:
   - **Build Command**: `npm install && npm run build`
   - **Start Command**: `npm start`
   - **Instance Type**: Free
4. Click **Deploy Web Service**

Render sets the `PORT` environment variable automatically. No other env vars are required — the app uses free public RPCs by default.

> **Note:** Render's free tier sleeps after 15 minutes of inactivity. You can use [cron-job.org](https://cron-job.org) (free) to ping your `/health` endpoint every 14 minutes to keep it awake.

### Run Locally in Production Mode

```bash
npm run build
npm start
# Server starts on http://localhost:3000
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
