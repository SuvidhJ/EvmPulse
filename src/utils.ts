// ============================================================
// Hex conversion and graph traversal utilities
// ============================================================

export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
  if (clean.length === 0) return new Uint8Array(0);
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(clean.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

export function bytesToHex(bytes: Uint8Array, prefix = true): string {
  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, '0');
  }
  return prefix ? '0x' + hex : hex;
}

export function toHex(offset: number, padTo = 4): string {
  return '0x' + offset.toString(16).padStart(padTo, '0');
}

export function readUint16BE(data: Uint8Array, offset: number): number {
  return (data[offset] << 8) | data[offset + 1];
}

export function readUintBE(data: Uint8Array, offset: number, length: number): bigint {
  let result = 0n;
  for (let i = 0; i < length; i++) {
    result = (result << 8n) | BigInt(data[offset + i]);
  }
  return result;
}

/**
 * BFS on a directed graph. Returns all reachable node IDs from startId.
 */
export function bfs(
  adjacency: Map<number, number[]>,
  startId: number
): Set<number> {
  const visited = new Set<number>();
  const queue = [startId];
  visited.add(startId);
  while (queue.length > 0) {
    const current = queue.shift()!;
    const neighbors = adjacency.get(current) || [];
    for (const n of neighbors) {
      if (!visited.has(n)) {
        visited.add(n);
        queue.push(n);
      }
    }
  }
  return visited;
}

/**
 * Find all paths from startId to any target in targetIds.
 * Limited to avoid explosion on large graphs.
 */
export function findPaths(
  adjacency: Map<number, number[]>,
  startId: number,
  targetIds: Set<number>,
  maxPaths = 5,
  maxDepth = 50
): number[][] {
  const paths: number[][] = [];

  function dfs(current: number, path: number[], visited: Set<number>): void {
    if (paths.length >= maxPaths) return;
    if (path.length > maxDepth) return;

    if (targetIds.has(current) && path.length > 1) {
      paths.push([...path]);
      return;
    }

    const neighbors = adjacency.get(current) || [];
    for (const n of neighbors) {
      if (!visited.has(n)) {
        visited.add(n);
        path.push(n);
        dfs(n, path, visited);
        path.pop();
        visited.delete(n);
      }
    }
  }

  const visited = new Set<number>([startId]);
  dfs(startId, [startId], visited);
  return paths;
}

/**
 * Simple delay for rate-limiting API calls
 */
export function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Convert a PUSH operand (Uint8Array) to a JS number.
 * Returns null if the operand is too large for safe integer range.
 */
/**
 * Convert a PUSH operand to a JS number.
 * Returns null for operands > 6 bytes (exceeds safe integer range).
 * This is fine for jump targets (max contract size is 24KB = ~15 bits).
 */
export function operandToNumber(operand: Uint8Array): number | null {
  if (operand.length > 6) return null; // too large for safe integer
  let val = 0;
  for (let i = 0; i < operand.length; i++) {
    val = val * 256 + operand[i];
  }
  return val;
}