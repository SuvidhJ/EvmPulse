#!/usr/bin/env node

// ============================================================
// CLI entry point
// analyzer <address> [options]
// ============================================================

import { Command } from 'commander';
import { getChainConfig } from './chains';
import { analyze } from './analyzer';
import { formatReport } from './formatter';
import { generateSVG } from './cfg';
import * as fs from 'fs';

const program = new Command();

program
  .name('analyzer')
  .description(
    'EVM Bytecode Reverse Engineering Toolkit — Disassembler, CFG Builder, Security Analyzer'
  )
  .version('1.0.0')
  .argument('<address>', 'Ethereum contract address to analyze')
  .option('--chain <chain>', 'Chain name: ethereum, base, arbitrum, polygon', 'ethereum')
  .option('--rpc <url>', 'Custom RPC URL (overrides --chain)')
  .option(
    '--output <format>',
    'Output format: text, json, dot',
    'text'
  )
  .option('--disasm', 'Show disassembly')
  .option('--selectors', 'Extract and resolve function selectors')
  .option('--cfg', 'Build and export control flow graph')
  .option('--security', 'Run security pattern detection')
  .option('--svg', 'Generate SVG visualization (requires Graphviz)')
  .option('--all', 'Run all analyses (default when no flag specified)')
  .option('-o, --out <file>', 'Write output to file')
  .action(async (address: string, options: any) => {
    try {
      // Validate address format
      if (!/^0x[a-fA-F0-9]{40}$/.test(address)) {
        console.error(`\n  ✗ Invalid Ethereum address format: ${address}`);
        console.error(`    Expected: 0x followed by 40 hex characters\n`);
        process.exit(1);
      }

      const chain = getChainConfig(options.chain, options.rpc);

      // Determine which analyses to run
      const anySpecific =
        options.disasm || options.selectors || options.cfg || options.security;
      const runAll = options.all || !anySpecific;

      const flags = {
        disasm: runAll || !!options.disasm,
        selectors: runAll || !!options.selectors,
        cfg: runAll || !!options.cfg,
        security: runAll || !!options.security,
      };

      console.log(`\n  Analyzing ${address} on ${chain.name}...`);
      console.log(`  RPC: ${chain.rpc}\n`);

      const report = await analyze(address, chain, flags);
      const output = formatReport(report, options.output);

      // SVG generation
      if (options.svg && report.cfg) {
        const svgPath = options.out
          ? options.out.replace(/\.[^.]+$/, '.svg')
          : `cfg-${address.slice(0, 10)}.svg`;
        const success = generateSVG(report.cfg.dot, svgPath);
        if (success) {
          console.log(`  SVG generated: ${svgPath}`);
        } else {
          console.log(
            `  ⚠ Graphviz not installed. DOT file saved. Install with: apt-get install graphviz`
          );
          // Save DOT file instead
          fs.writeFileSync(svgPath.replace('.svg', '.dot'), report.cfg.dot);
        }
      }

      if (options.out) {
        fs.writeFileSync(options.out, output);
        console.log(`  Output written to: ${options.out}`);
      } else {
        console.log(output);
      }
    } catch (err: any) {
      console.error(`\n  ✗ Error: ${err.message}\n`);
      process.exit(1);
    }
  });

program.parse();