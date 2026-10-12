#!/usr/bin/env node
'use strict';

const fs = require('fs');
const { readPcap } = require('./pcap');
const { decode } = require('./decode');
const { summarize } = require('./stats');

const USAGE = `Usage: node src/cli.js <capture.pcap> [options]

Options:
  --top N    how many rows to show in each table (default 10)
  --list     print one line per packet before the summary
  --json     print the summary as JSON
  --help     show this message`;

function parseArgs(argv) {
  const opts = { file: null, topN: 10, list: false, json: false, help: false };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--top') opts.topN = Number(argv[++i]);
    else if (arg === '--list') opts.list = true;
    else if (arg === '--json') opts.json = true;
    else if (arg === '--help' || arg === '-h') opts.help = true;
    else if (!opts.file) opts.file = arg;
    else throw new Error(`Unexpected argument: ${arg}`);
  }
  if (!Number.isInteger(opts.topN) || opts.topN < 1) {
    throw new Error('--top needs a whole number of 1 or more');
  }
  return opts;
}

function describe(pkt) {
  const ip = pkt.ip ? `${pkt.ip.src} -> ${pkt.ip.dst}` : '';
  if (pkt.tcp) return `${ip} TCP ${pkt.tcp.srcPort} -> ${pkt.tcp.dstPort} [${pkt.tcp.flags.join(',')}] ${pkt.tcp.payloadLength}B`;
  if (pkt.dns) {
    const names = pkt.dns.questions.map((q) => q.name).join(', ');
    return `${ip} ${pkt.protocol} ${pkt.dns.isResponse ? 'response' : 'query'} ${names}`;
  }
  if (pkt.udp) return `${ip} UDP ${pkt.udp.srcPort} -> ${pkt.udp.dstPort}`;
  if (pkt.icmp) return `${ip} ${pkt.protocol} type ${pkt.icmp.type} code ${pkt.icmp.code}`;
  if (pkt.arp) return `ARP ${pkt.arp.op} ${pkt.arp.senderIP} -> ${pkt.arp.targetIP}`;
  return `${ip} ${pkt.protocol}`.trim();
}

function formatBytes(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

function table(title, rows, columns) {
  const lines = [`\n${title}`];
  if (!rows.length) return lines.concat('  (none)').join('\n');
  const widths = columns.map(([label, get]) =>
    Math.max(label.length, ...rows.map((r) => String(get(r)).length)));
  lines.push(('  ' + columns.map(([label], i) => label.padEnd(widths[i])).join('  ')).trimEnd());
  for (const row of rows) {
    lines.push(('  ' + columns.map(([, get], i) => String(get(row)).padEnd(widths[i])).join('  ')).trimEnd());
  }
  return lines.join('\n');
}

function report(s) {
  const traffic = [['Packets', (r) => r.packets], ['Bytes', (r) => formatBytes(r.bytes)]];
  return [
    `Packets: ${s.packets}   Bytes: ${formatBytes(s.bytes)}   Duration: ${s.durationSeconds.toFixed(2)} s`,
    `New TCP connections (SYN): ${s.newTcpConnections}   TCP resets: ${s.tcpResets}   Truncated packets: ${s.truncatedPackets}`,
    table('Protocols', s.protocols, [['Protocol', (r) => r.key], ...traffic]),
    table('Top talkers (by bytes sent)', s.topTalkers, [['Address', (r) => r.key], ...traffic]),
    table('Top conversations', s.topConversations, [['Between', (r) => r.key], ...traffic]),
    table('Top services', s.topServices, [['Port', (r) => r.key], ...traffic]),
    table('DNS lookups', s.dnsQueries, [['Name', (r) => r.name], ['Count', (r) => r.count]]),
  ].join('\n');
}

function main(argv) {
  let opts;
  try {
    opts = parseArgs(argv);
  } catch (err) {
    console.error(`${err.message}\n\n${USAGE}`);
    return 2;
  }
  if (opts.help || !opts.file) {
    console.log(USAGE);
    return opts.help ? 0 : 2;
  }

  let capture;
  try {
    capture = readPcap(fs.readFileSync(opts.file));
  } catch (err) {
    console.error(`Could not read ${opts.file}: ${err.message}`);
    return 1;
  }

  const records = capture.packets.map((p) => ({
    time: p.time,
    originalLength: p.originalLength,
    pkt: decode(p.data, capture.linkType),
  }));

  if (opts.list) {
    const t0 = records.length ? records[0].time : 0;
    records.forEach((r, i) => {
      console.log(`${String(i + 1).padStart(5)}  ${(r.time - t0).toFixed(6).padStart(12)}  ${describe(r.pkt)}`);
    });
    console.log('');
  }

  const summary = summarize(records, { topN: opts.topN });
  if (capture.truncated) summary.fileTruncated = true;
  console.log(opts.json ? JSON.stringify(summary, null, 2) : report(summary));
  if (capture.truncated && !opts.json) console.log('\nNote: the file ends in the middle of a packet. The last partial packet was skipped.');
  return 0;
}

if (require.main === module) {
  process.exitCode = main(process.argv.slice(2));
}

module.exports = { main, parseArgs, describe };
