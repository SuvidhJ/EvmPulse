import {
  Instruction,
  BasicBlock,
  CFGEdge,
  SelfdestructDetection,
} from '../types';
import { bfs, findPaths } from '../utils';

export function detectSelfdestruct(
  instructions: Instruction[],
  blocks: BasicBlock[],
  edges: CFGEdge[]
): SelfdestructDetection {
  const result: SelfdestructDetection = {
    detected: false,
    blockIds: [],
    reachableFromEntry: false,
    paths: [],
  };

  // Find blocks containing SELFDESTRUCT
  for (const block of blocks) {
    if (block.instructions.some((i) => i.mnemonic === 'SELFDESTRUCT')) {
      result.detected = true;
      result.blockIds.push(block.id);
    }
  }

  if (!result.detected) return result;

  // Build adjacency list
  const adjacency = new Map<number, number[]>();
  for (const block of blocks) {
    adjacency.set(block.id, []);
  }
  for (const edge of edges) {
    adjacency.get(edge.from)?.push(edge.to);
  }

  // Check reachability from entry (block 0)
  if (blocks.length > 0) {
    const reachable = bfs(adjacency, blocks[0].id);
    for (const sdBlock of result.blockIds) {
      if (reachable.has(sdBlock)) {
        result.reachableFromEntry = true;
        break;
      }
    }

    // Find paths from entry to selfdestruct blocks
    const targetSet = new Set(result.blockIds);
    result.paths = findPaths(adjacency, blocks[0].id, targetSet, 3, 30);
  }

  return result;
}