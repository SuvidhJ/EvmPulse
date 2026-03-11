// ============================================================
// Control Flow Graph construction
//
// Partitions instructions into basic blocks and connects them
// with edges. Uses intra-block stack simulation to resolve
// jump targets through DUP/SWAP operations.
// ============================================================

import {
  Instruction,
  BasicBlock,
  CFGEdge,
  CFGResult,
  JumpResolutionStats,
} from './types';
import { toHex, operandToNumber } from './utils';

/**
 * Build a control flow graph from disassembled instructions.
 */
export function buildCFG(instructions: Instruction[]): CFGResult {
  if (instructions.length === 0) {
    return {
      totalBlocks: 0,
      totalEdges: 0,
      terminalBlocks: 0,
      jumpResolution: {
        totalJumps: 0,
        staticResolved: 0,
        dynamic: 0,
        resolutionRate: 'N/A',
      },
      blocks: [],
      edges: [],
      adjacencyList: {},
      dot: 'digraph CFG {}',
    };
  }

  // Build instruction offset lookup
  const instrByOffset = new Map<number, Instruction>();
  for (const instr of instructions) {
    instrByOffset.set(instr.offset, instr);
  }

  // ---- Step 1: Identify leaders (block start points) ----
  const leaders = new Set<number>();
  leaders.add(instructions[0].offset); // entry point is always a leader

  for (let i = 0; i < instructions.length; i++) {
    const instr = instructions[i];

    if (instr.mnemonic === 'JUMPDEST') {
      leaders.add(instr.offset);
    }

    if (
      instr.info.halts ||
      instr.info.jumps
    ) {
      // The instruction AFTER a terminator starts a new block
      if (i + 1 < instructions.length) {
        leaders.add(instructions[i + 1].offset);
      }
    }
  }

  // ---- Step 2: Form basic blocks ----
  const sortedLeaders = Array.from(leaders).sort((a, b) => a - b);
  const blocks: BasicBlock[] = [];
  const blockByOffset = new Map<number, BasicBlock>();

  // Build an offset→index map for efficient lookup
  const offsetToIdx = new Map<number, number>();
  for (let i = 0; i < instructions.length; i++) {
    offsetToIdx.set(instructions[i].offset, i);
  }

  for (let b = 0; b < sortedLeaders.length; b++) {
    const startOffset = sortedLeaders[b];
    const nextLeaderOffset =
      b + 1 < sortedLeaders.length ? sortedLeaders[b + 1] : Infinity;

    const startIdx = offsetToIdx.get(startOffset);
    if (startIdx === undefined) continue;

    const blockInstrs: Instruction[] = [];
    for (let i = startIdx; i < instructions.length; i++) {
      if (instructions[i].offset >= nextLeaderOffset) break;
      blockInstrs.push(instructions[i]);
    }

    if (blockInstrs.length === 0) continue;

    const lastInstr = blockInstrs[blockInstrs.length - 1];
    let terminator = 'FALLTHROUGH';
    if (lastInstr.info.halts) {
      terminator = lastInstr.mnemonic;
    } else if (lastInstr.info.jumps) {
      terminator = lastInstr.mnemonic;
    }

    const block: BasicBlock = {
      id: blocks.length,
      startOffset,
      endOffset: lastInstr.offset,
      instructions: blockInstrs,
      terminator,
    };

    blocks.push(block);
    blockByOffset.set(startOffset, block);
  }

  // Build offset-to-block lookup for jump targets
  const offsetToBlockId = new Map<number, number>();
  for (const block of blocks) {
    offsetToBlockId.set(block.startOffset, block.id);
  }

  // ---- Step 3: Build edges & resolve jumps ----
  const edges: CFGEdge[] = [];
  let totalJumps = 0;
  let staticResolved = 0;
  let dynamicJumps = 0;

  for (let b = 0; b < blocks.length; b++) {
    const block = blocks[b];
    const lastInstr = block.instructions[block.instructions.length - 1];
    const nextBlock = b + 1 < blocks.length ? blocks[b + 1] : null;

    switch (block.terminator) {
      case 'FALLTHROUGH': {
        if (nextBlock) {
          edges.push({
            from: block.id,
            to: nextBlock.id,
            type: 'fallthrough',
          });
        }
        break;
      }

      case 'JUMP': {
        totalJumps++;
        const target = resolveJumpTarget(block);
        if (target !== null && offsetToBlockId.has(target)) {
          edges.push({
            from: block.id,
            to: offsetToBlockId.get(target)!,
            type: 'jump',
          });
          staticResolved++;
        } else {
          dynamicJumps++;
          // Mark as dynamic — target could not be statically resolved
          edges.push({
            from: block.id,
            to: -1,  // sentinel for dynamic target
            type: 'dynamic',
          });
        }
        break;
      }

      case 'JUMPI': {
        totalJumps++;
        // Fall-through edge (condition false)
        if (nextBlock) {
          edges.push({
            from: block.id,
            to: nextBlock.id,
            type: 'conditional_false',
          });
        }
        // Jump target edge (condition true)
        const target = resolveJumpTarget(block);
        if (target !== null && offsetToBlockId.has(target)) {
          edges.push({
            from: block.id,
            to: offsetToBlockId.get(target)!,
            type: 'conditional_true',
          });
          staticResolved++;
        } else {
          dynamicJumps++;
          // Mark conditional jump target as dynamic
          edges.push({
            from: block.id,
            to: -1,
            type: 'dynamic',
          });
        }
        break;
      }

      // Terminal instructions: STOP, RETURN, REVERT, INVALID, SELFDESTRUCT
      // No outgoing edges
      default:
        break;
    }
  }

  const terminalBlocks = blocks.filter(
    (b) =>
      b.terminator !== 'FALLTHROUGH' &&
      b.terminator !== 'JUMP' &&
      b.terminator !== 'JUMPI'
  ).length;

  const jumpResolution: JumpResolutionStats = {
    totalJumps,
    staticResolved,
    dynamic: dynamicJumps,
    resolutionRate:
      totalJumps > 0
        ? ((staticResolved / totalJumps) * 100).toFixed(1) + '%'
        : 'N/A',
  };

  // Build JSON adjacency list: blockId → [connected block ids]
  const adjacencyList: Record<number, number[]> = {};
  for (const block of blocks) {
    adjacencyList[block.id] = [];
  }
  for (const edge of edges) {
    if (edge.to >= 0) {  // skip dynamic sentinel (-1)
      adjacencyList[edge.from].push(edge.to);
    }
  }

  // Compute reachable blocks via BFS from block 0 for DOT highlighting
  const reachableIds = new Set<number>();
  if (blocks.length > 0) {
    const adjMap = new Map<number, number[]>();
    for (const [k, v] of Object.entries(adjacencyList)) {
      adjMap.set(Number(k), v);
    }
    const queue = [blocks[0].id];
    reachableIds.add(blocks[0].id);
    while (queue.length > 0) {
      const cur = queue.shift()!;
      for (const neighbor of adjMap.get(cur) || []) {
        if (!reachableIds.has(neighbor)) {
          reachableIds.add(neighbor);
          queue.push(neighbor);
        }
      }
    }
  }

  const dot = generateDOT(blocks, edges, reachableIds);

  return {
    totalBlocks: blocks.length,
    totalEdges: edges.length,
    terminalBlocks,
    jumpResolution,
    blocks,
    edges,
    adjacencyList,
    dot,
  };
}

/**
 * Resolve the jump target for a block ending in JUMP or JUMPI.
 * Uses stack simulation first, then falls back to checking the previous PUSH.
 */
function resolveJumpTarget(block: BasicBlock): number | null {
  const instrs = block.instructions;
  if (instrs.length < 2) return null;

  const jumpInstr = instrs[instrs.length - 1];
  if (!jumpInstr.info.jumps) return null;

  // Use stack simulation for both JUMP and JUMPI — handles DUP/SWAP patterns
  const result = resolveByStackSimulation(instrs);
  if (result !== null) return result;

  // Fallback: simple lookback for JUMP
  if (jumpInstr.mnemonic === 'JUMP') {
    const prev = instrs[instrs.length - 2];
    if (prev.mnemonic.startsWith('PUSH') && prev.operand) {
      return operandToNumber(prev.operand);
    }
  }

  return null;
}

/**
 * Simulate the stack within a basic block to determine the jump target
 * for JUMP and JUMPI instructions.
 */
function resolveByStackSimulation(instrs: Instruction[]): number | null {
  // Lightweight stack simulation
  // Track concrete values through the block
  type StackItem = { concrete: number | null };
  const stack: StackItem[] = [];

  for (let i = 0; i < instrs.length; i++) {
    const instr = instrs[i];

    if (instr.mnemonic.startsWith('PUSH') && instr.operand) {
      const val = operandToNumber(instr.operand);
      stack.push({ concrete: val });
      continue;
    }

    if (instr.mnemonic === 'PUSH0') {
      stack.push({ concrete: 0 });
      continue;
    }

    if (instr.mnemonic.startsWith('DUP')) {
      const n = parseInt(instr.mnemonic.slice(3));
      if (stack.length >= n) {
        stack.push({ ...stack[stack.length - n] });
      } else {
        stack.push({ concrete: null });
      }
      continue;
    }

    if (instr.mnemonic.startsWith('SWAP')) {
      const n = parseInt(instr.mnemonic.slice(4));
      if (stack.length > n) {
        const top = stack.length - 1;
        const swapWith = stack.length - 1 - n;
        [stack[top], stack[swapWith]] = [stack[swapWith], stack[top]];
      }
      continue;
    }

    if (instr.mnemonic === 'POP') {
      stack.pop();
      continue;
    }

    if (instr.mnemonic === 'JUMPI') {
      // JUMPI: µ_s[0] = TOS = destination, µ_s[1] = TOS-1 = condition
      if (stack.length >= 2) {
        const target = stack[stack.length - 1];
        return target.concrete;
      }
      return null;
    }

    if (instr.mnemonic === 'JUMP') {
      if (stack.length >= 1) {
        const target = stack[stack.length - 1];
        return target.concrete;
      }
      return null;
    }

    // For all other instructions, approximate stack effect
    const consumed = instr.info.stackIn;
    const produced = instr.info.stackOut;
    for (let c = 0; c < consumed; c++) stack.pop();
    for (let p = 0; p < produced; p++) stack.push({ concrete: null });
  }

  return null;
}



/**
 * Generate DOT (Graphviz) representation of the CFG
 */
function generateDOT(blocks: BasicBlock[], edges: CFGEdge[], reachableIds?: Set<number>): string {
  const lines: string[] = [];
  lines.push('digraph CFG {');
  lines.push('  graph [rankdir=TB, fontname="Helvetica", bgcolor="#1a1a2e"];');
  lines.push(
    '  node [shape=box, style="filled,rounded", fontname="Courier New", fontsize=8, margin="0.1,0.05"];'
  );
  lines.push('  edge [fontsize=7, fontname="Helvetica"];');
  lines.push('');

  for (const block of blocks) {
    // Truncate instructions for display
    const maxDisplay = 10;
    const instrLines: string[] = [];
    const displayInstrs =
      block.instructions.length > maxDisplay
        ? [
            ...block.instructions.slice(0, 7),
            null, // placeholder for "..."
            ...block.instructions.slice(-2),
          ]
        : block.instructions;

    for (const instr of displayInstrs) {
      if (instr === null) {
        instrLines.push('  ...');
        continue;
      }
      let line = `${toHex(instr.offset)}: ${instr.mnemonic}`;
      if (instr.operandHex) {
        const operandDisplay =
          instr.operandHex.length > 18
            ? instr.operandHex.slice(0, 18) + '...'
            : instr.operandHex;
        line += ` ${operandDisplay}`;
      }
      instrLines.push(line);
    }

    const header = `Block ${block.id} [${toHex(block.startOffset)}-${toHex(block.endOffset)}]`;
    const separator = '─'.repeat(Math.min(header.length, 30));
    const label = [header, separator, ...instrLines].join('\\l') + '\\l';

    // Dark theme color scheme for the CFG visualization:
    // - Blue = normal/entry blocks
    // - Green text = successful exit (STOP/RETURN)
    // - Red text = error exit (REVERT/INVALID)
    // - Orange = selfdestruct (dangerous!)
    // - Light blue = blocks with external calls (CALL, DELEGATECALL, etc.)
    let fillColor = '#16213e';
    let fontColor = '#e8e8e8';
    let borderStyle = 'solid';

    // Highlight unreachable blocks with dashed border and gray styling
    if (reachableIds && !reachableIds.has(block.id)) {
      fillColor = '#0d0d0d';
      fontColor = '#666666';
      borderStyle = 'dashed';
    } else if (block.id === 0) {
      fillColor = '#0f3460';
      fontColor = '#94d2bd';
    }

    if (['STOP', 'RETURN'].includes(block.terminator)) {
      fillColor = '#1a1a2e';
      fontColor = '#2dc653';
    }

    if (['REVERT', 'INVALID'].includes(block.terminator)) {
      fillColor = '#2d142c';
      fontColor = '#e63946';
    }

    if (block.terminator === 'SELFDESTRUCT') {
      fillColor = '#ff6b35';
      fontColor = '#ffffff';
    }

    const hasSystemCall = block.instructions.some(
      (i) => i.info.category === 'system'
    );
    if (hasSystemCall) {
      fillColor = '#1b2838';
      fontColor = '#66c0f4';
    }

    const styleAttr = borderStyle === 'dashed'
      ? 'style="filled,rounded,dashed"'
      : 'style="filled,rounded"';
    lines.push(
      `  BB${block.id} [label="${label}", ${styleAttr}, fillcolor="${fillColor}", fontcolor="${fontColor}", color="#333333"];`
    );
  }

  lines.push('');

  // Add a "dynamic" sink node for unresolved jumps
  const hasDynamic = edges.some((e) => e.type === 'dynamic');
  if (hasDynamic) {
    lines.push(
      `  DYNAMIC [label="dynamic\\ltarget\\l", shape=diamond, style="filled", fillcolor="#ff9f1c", fontcolor="#1a1a2e", fontname="Helvetica"];`
    );
  }

  lines.push('');

  // Edge colors: blue=jump, green=true branch, red/dashed=false branch,
  // gray/dotted=fallthrough, orange/bold=dynamic (unresolved)
  for (const edge of edges) {
    let style = '';
    let color = '#666666';
    let label = '';
    const targetNode = edge.to >= 0 ? `BB${edge.to}` : 'DYNAMIC';

    switch (edge.type) {
      case 'jump':
        color = '#4cc9f0';
        label = 'jump';
        break;
      case 'conditional_true':
        color = '#2dc653';
        label = 'true';
        break;
      case 'conditional_false':
        color = '#e63946';
        label = 'false';
        style = 'style=dashed, ';
        break;
      case 'fallthrough':
        color = '#888888';
        style = 'style=dotted, ';
        break;
      case 'dynamic':
        color = '#ff9f1c';
        label = 'dynamic';
        style = 'style=bold, ';
        break;
    }

    lines.push(
      `  BB${edge.from} -> ${targetNode} [${style}color="${color}", fontcolor="${color}", label="${label}"];`
    );
  }

  lines.push('}');
  return lines.join('\n');
}

/**
 * Generate SVG from DOT using Graphviz (if installed)
 */
export function generateSVG(dot: string, outputPath: string): boolean {
  try {
    const { execSync, execFileSync } = require('child_process');
    const fs = require('fs');
    // Check if graphviz is installed (cross-platform)
    const checkCmd = process.platform === 'win32' ? 'where dot' : 'which dot';
    execSync(checkCmd, { stdio: 'ignore' });
    // Generate SVG using execFileSync to avoid shell injection
    const tmpDot = outputPath.replace(/\.svg$/, '.dot');
    fs.writeFileSync(tmpDot, dot);
    execFileSync('dot', ['-Tsvg', '-o', outputPath, tmpDot]);
    fs.unlinkSync(tmpDot);
    return true;
  } catch {
    return false;
  }
}