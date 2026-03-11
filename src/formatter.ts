// ============================================================
// Output formatting for CLI (text, JSON, DOT)
// ============================================================

import { AnalysisReport } from './types';
import { formatDisassembly } from './disassembler';
import { toHex } from './utils';

export function formatReport(
  report: AnalysisReport,
  format: 'text' | 'json' | 'dot'
): string {
  switch (format) {
    case 'json':
      return formatJSON(report);
    case 'dot':
      return report.cfg?.dot || 'digraph CFG {}';
    case 'text':
    default:
      return formatText(report);
  }
}

function formatJSON(report: AnalysisReport): string {
  // Strip raw instruction objects for cleaner JSON output
  const clean = JSON.parse(JSON.stringify(report, (key, value) => {
    // Convert Uint8Array to hex strings in JSON
    if (value && typeof value === 'object' && value.constructor === Uint8Array) {
      return '0x' + Array.from(value as Uint8Array).map((b: number) => b.toString(16).padStart(2, '0')).join('');
    }
    // Uint8Array may get serialized as { "0": nn, "1": nn, ... } — detect and convert
    if (key === 'operand' && value && typeof value === 'object' && !Array.isArray(value) && typeof value !== 'string') {
      return undefined;
    }
    // Remove verbose instruction info from JSON output
    if (key === 'info' && value?.byte !== undefined) {
      return undefined;
    }
    return value;
  }));

  return JSON.stringify(clean, null, 2);
}

function formatText(report: AnalysisReport): string {
  const lines: string[] = [];
  const divider = '═'.repeat(60);
  const thinDivider = '─'.repeat(60);

  lines.push(divider);
  lines.push(`  EVM BYTECODE ANALYSIS REPORT`);
  lines.push(divider);
  lines.push(`  Address:        ${report.address}`);
  lines.push(`  Chain:          ${report.chain}`);
  lines.push(`  Bytecode Size:  ${report.bytecodeSize} bytes`);
  lines.push(`  Timestamp:      ${report.timestamp}`);

  if (report.metadata.detected) {
    lines.push('');
    lines.push(`  Compiler Metadata:`);
    if (report.metadata.solcVersion) {
      lines.push(`    Solidity:     v${report.metadata.solcVersion}`);
    }
    if (report.metadata.ipfsHash) {
      lines.push(`    IPFS:         ${report.metadata.ipfsHash}`);
    }
    if (report.metadata.bzzr0Hash) {
      lines.push(`    Swarm bzzr0:  ${report.metadata.bzzr0Hash}`);
    }
  }

  // Selectors
  if (report.selectors) {
    lines.push('');
    lines.push(divider);
    lines.push(`  FUNCTION SELECTORS (${report.selectors.count} found)`);
    lines.push(divider);

    for (const func of report.selectors.functions) {
      const sig =
        func.signatures.length > 0
          ? func.signatures[0]
          : '<unresolved>';
      const offset =
        func.handlerOffset !== null
          ? toHex(func.handlerOffset)
          : 'N/A';
      const payableTag = func.isPayable === true ? ' [payable]'
        : func.isPayable === false ? ' [non-payable]'
        : '';

      lines.push(
        `  ${func.selector}  →  ${sig.padEnd(40)} handler: ${offset}${payableTag}`
      );

      if (func.parameterHints.length > 0) {
        lines.push(
          `  ${''.padEnd(12)} params: (${func.parameterHints.join(', ')})`
        );
      }

      // Show hash collisions explicitly — multiple signatures map to same 4-byte selector
      if (func.signatures.length > 1) {
        lines.push(
          `  ${''.padEnd(12)} ⚠ hash collisions (${func.signatures.length} matches):`
        );
        for (const collision of func.signatures.slice(1)) {
          lines.push(
            `  ${''.padEnd(14)} - ${collision}`
          );
        }
      }
    }
  }

  // CFG
  if (report.cfg) {
    lines.push('');
    lines.push(divider);
    lines.push(`  CONTROL FLOW GRAPH`);
    lines.push(divider);
    lines.push(`  Total Blocks:     ${report.cfg.totalBlocks}`);
    lines.push(`  Total Edges:      ${report.cfg.totalEdges}`);
    lines.push(`  Terminal Blocks:  ${report.cfg.terminalBlocks}`);
    lines.push(`  Jump Resolution:`);
    lines.push(`    Total jumps:    ${report.cfg.jumpResolution.totalJumps}`);
    lines.push(`    Resolved:       ${report.cfg.jumpResolution.staticResolved}`);
    lines.push(`    Dynamic:        ${report.cfg.jumpResolution.dynamic}`);
    lines.push(
      `    Resolution Rate: ${report.cfg.jumpResolution.resolutionRate}`
    );
    lines.push('');
    lines.push(`  (Use --output dot for Graphviz DOT output)`);
    lines.push(`  (Use --output json for JSON with adjacency list)`);
    lines.push(`  (Use --svg to generate SVG visualization)`);
  }

  // Security
  if (report.security) {
    lines.push('');
    lines.push(divider);
    lines.push(`  SECURITY ANALYSIS`);
    lines.push(divider);

    // Proxy
    const proxy = report.security.proxy;
    lines.push('');
    lines.push(
      `  Proxy Contract:     ${proxy.detected ? '⚠ YES' : '✓ No'}`
    );
    if (proxy.detected) {
      lines.push(`    Pattern:          ${proxy.pattern}`);
      lines.push(
        `    Implementation:   ${proxy.implementationAddress || 'unknown'}`
      );
      if (proxy.adminAddress) {
        lines.push(`    Admin:            ${proxy.adminAddress}`);
      }
      if (proxy.isMinimalProxy) {
        lines.push(`    Type:             Minimal Proxy (EIP-1167 clone)`);
      }
    }
    lines.push(`    DELEGATECALL count: ${proxy.delegatecallCount}`);

    // Selfdestruct
    const sd = report.security.selfdestruct;
    lines.push('');
    lines.push(
      `  Selfdestruct:       ${sd.detected ? '⚠ YES' : '✓ Not found'}`
    );
    if (sd.detected) {
      lines.push(`    Blocks:           ${sd.blockIds.join(', ')}`);
      lines.push(
        `    Reachable:        ${sd.reachableFromEntry ? 'YES ⚠' : 'No (dead code)'}`
      );
      if (sd.paths.length > 0) {
        lines.push(
          `    Paths:            ${sd.paths.map((p) => p.join('→')).join(' | ')}`
        );
      }
    }

    // Unchecked Calls
    const uc = report.security.uncheckedCalls;
    lines.push('');
    lines.push(
      `  Unchecked Calls:    ${uc.detected ? `⚠ ${uc.count} found` : '✓ All calls checked'}`
    );
    if (uc.detected) {
      for (const detail of uc.details.filter((d) => !d.checked)) {
        lines.push(
          `    ${toHex(detail.offset)}: ${detail.type} — return value NOT checked`
        );
      }
    }

    // Access Control
    const ac = report.security.accessControl;
    lines.push('');
    lines.push(
      `  Access Control:     ${ac.detected ? `✓ ${ac.checks.length} check(s) found` : '⚠ No access control detected'}`
    );
    for (const check of ac.checks) {
      lines.push(
        `    ${toHex(check.offset)}: ${check.pattern}` +
          (check.storageSlot ? ` slot=${check.storageSlot}` : '') +
          (check.hardcodedAddress ? ` addr=${check.hardcodedAddress}` : '')
      );
    }

    // Reentrancy Guard
    const rg = report.security.reentrancyGuard;
    lines.push('');
    lines.push(
      `  Reentrancy Guard:   ${rg.detected ? `✓ Detected (${rg.pattern})` : '⚠ Not detected'}`
    );
    if (rg.storageSlot) {
      lines.push(`    Storage slot:     ${rg.storageSlot}`);
    }

    // Payable
    const pay = report.security.payable;
    lines.push('');
    lines.push(`  Payable Analysis:`);
    lines.push(
      `    Payable functions:     ${pay.payableFunctions.length > 0 ? pay.payableFunctions.join(', ') : 'none'}`
    );
    lines.push(
      `    Non-payable functions: ${pay.nonPayableFunctions.length > 0 ? pay.nonPayableFunctions.join(', ') : 'none'}`
    );
  }

  // ERC-165 Interface Detection
  if (report.erc165) {
    lines.push('');
    lines.push(divider);
    lines.push(`  ERC-165 INTERFACE DETECTION`);
    lines.push(divider);

    if (report.erc165.supportsERC165) {
      lines.push(`  ERC-165 supported: ✓ Yes`);
      const supported = report.erc165.interfaces.filter((i) => i.supported);
      if (supported.length > 0) {
        lines.push(`  Detected interfaces:`);
        for (const iface of supported) {
          lines.push(`    ${iface.id}  →  ${iface.name}`);
        }
      } else {
        lines.push(`  No standard interfaces detected beyond ERC-165`);
      }
    } else {
      lines.push(`  ERC-165 supported: ✗ No (contract does not implement supportsInterface)`);
    }
  }

  // Disassembly (at the end since it's long)
  if (report.disassembly) {
    lines.push('');
    lines.push(divider);
    lines.push(`  DISASSEMBLY`);
    lines.push(divider);

    // Build selector map for annotations
    const selectorMap = new Map<string, string[]>();
    if (report.selectors) {
      for (const func of report.selectors.functions) {
        if (func.signatures.length > 0) {
          selectorMap.set(func.selector, func.signatures);
        }
      }
    }

    lines.push(formatDisassembly(report.disassembly, selectorMap));
  }

  lines.push('');
  lines.push(divider);
  return lines.join('\n');
}