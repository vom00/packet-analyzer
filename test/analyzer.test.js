'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

const { readPcap } = require('../src/pcap');
const { decode, formatIPv6 } = require('../src/decode');
const { summarize } = require('../src/stats');
const b = require('./build');

const CLIENT = '192.0.2.10';
const SERVER = '198.51.100.20';
const RESOLVER = '192.0.2.53';

function samplePackets() {
  return [
    { time: 1.0, data: b.ethernet(0x0806, b.arp(1, CLIENT, RESOLVER)) },
    { time: 1.1, data: b.ethernet(0x0800, b.ipv4(17, CLIENT, RESOLVER, b.udp(50000, 53, b.dnsQuery('example.com')))) },
    { time: 1.2, data: b.ethernet(0x0800, b.ipv4(6, CLIENT, SERVER, b.tcp(50001, 443, ['SYN']))) },
    { time: 1.3, data: b.ethernet(0x0800, b.ipv4(6, SERVER, CLIENT, b.tcp(443, 50001, ['SYN', 'ACK']))) },
    { time: 1.4, data: b.ethernet(0x0800, b.ipv4(6, CLIENT, SERVER, b.tcp(50001, 443, ['ACK', 'PSH'], Buffer.alloc(100)))) },
    { time: 2.0, data: b.ethernet(0x0800, b.ipv4(1, CLIENT, SERVER, Buffer.from([8, 0, 0, 0, 0, 0, 0, 0]))) },
  ];
}

test('reads little-endian and big-endian pcap files', () => {
  for (const little of [true, false]) {
    const cap = readPcap(b.pcapFile(samplePackets(), { little }));
    assert.equal(cap.linkType, 1);
    assert.equal(cap.packets.length, 6);
    assert.equal(cap.truncated, false);
    assert.ok(Math.abs(cap.packets[1].time - 1.1) < 1e-6);
  }
});

test('flags a file that ends mid-packet', () => {
  const file = b.pcapFile(samplePackets());
  const cap = readPcap(file.subarray(0, file.length - 10));
  assert.equal(cap.packets.length, 5);
  assert.equal(cap.truncated, true);
});

test('rejects pcapng and random files with a clear message', () => {
  const pcapng = Buffer.alloc(32);
  pcapng.writeUInt32BE(0x0a0d0d0a, 0);
  assert.throws(() => readPcap(pcapng), /pcapng/);
  assert.throws(() => readPcap(Buffer.alloc(32, 7)), /unknown magic/);
  assert.throws(() => readPcap(Buffer.alloc(4)), /too small/);
});

test('decodes a TCP SYN', () => {
  const pkt = decode(b.ethernet(0x0800, b.ipv4(6, CLIENT, SERVER, b.tcp(50001, 443, ['SYN']))), 1);
  assert.equal(pkt.protocol, 'TCP');
  assert.equal(pkt.ip.src, CLIENT);
  assert.equal(pkt.ip.dst, SERVER);
  assert.equal(pkt.tcp.dstPort, 443);
  assert.deepEqual(pkt.tcp.flags, ['SYN']);
});

test('decodes a DNS query name', () => {
  const pkt = decode(b.ethernet(0x0800, b.ipv4(17, CLIENT, RESOLVER, b.udp(50000, 53, b.dnsQuery('www.example.org')))), 1);
  assert.equal(pkt.protocol, 'DNS');
  assert.equal(pkt.dns.isResponse, false);
  assert.deepEqual(pkt.dns.questions, [{ name: 'www.example.org', type: 1 }]);
});

test('decodes ARP', () => {
  const pkt = decode(b.ethernet(0x0806, b.arp(2, RESOLVER, CLIENT)), 1);
  assert.equal(pkt.protocol, 'ARP');
  assert.deepEqual(pkt.arp, { op: 'reply', senderIP: RESOLVER, targetIP: CLIENT });
});

test('decodes IPv6 + UDP and shortens addresses', () => {
  const src = Buffer.from('20010db8000000000000000000000001', 'hex');
  const dst = Buffer.from('20010db8000000000000000000000002', 'hex');
  const pkt = decode(b.ethernet(0x86dd, b.ipv6(17, src, dst, b.udp(40000, 123, Buffer.alloc(48)))), 1);
  assert.equal(pkt.protocol, 'UDP');
  assert.equal(pkt.ip.src, '2001:db8::1');
  assert.equal(pkt.udp.dstPort, 123);
});

test('formats IPv6 addresses the short way', () => {
  assert.equal(formatIPv6(Buffer.alloc(16)), '::');
  assert.equal(formatIPv6(Buffer.from('fe800000000000000000000000000001', 'hex')), 'fe80::1');
  assert.equal(formatIPv6(Buffer.from('20010db8000100000001000000000001', 'hex')), '2001:db8:1:0:1::1');
});

test('reads raw IP captures (link type 101)', () => {
  const pkt = decode(b.ipv4(17, CLIENT, RESOLVER, b.udp(50000, 53, b.dnsQuery('example.net'))), 101);
  assert.equal(pkt.protocol, 'DNS');
});

test('a cut-off packet is marked truncated instead of crashing', () => {
  const full = b.ethernet(0x0800, b.ipv4(6, CLIENT, SERVER, b.tcp(50001, 443, ['SYN'])));
  const pkt = decode(full.subarray(0, 30), 1);
  assert.equal(pkt.truncated, true);
});

test('summarize counts protocols, talkers, services and DNS names', () => {
  const cap = readPcap(b.pcapFile(samplePackets()));
  const records = cap.packets.map((p) => ({ time: p.time, originalLength: p.originalLength, pkt: decode(p.data, cap.linkType) }));
  const s = summarize(records);

  assert.equal(s.packets, 6);
  assert.equal(s.newTcpConnections, 1);
  assert.ok(Math.abs(s.durationSeconds - 1.0) < 1e-6);

  const protocols = Object.fromEntries(s.protocols.map((p) => [p.key, p.packets]));
  assert.deepEqual(protocols, { TCP: 3, ARP: 1, DNS: 1, ICMP: 1 });

  assert.equal(s.topTalkers[0].key, CLIENT);
  assert.equal(s.topServices[0].key, 'tcp/443 HTTPS');
  assert.deepEqual(s.dnsQueries, [{ name: 'example.com', count: 1 }]);
});

test('CLI prints a report and JSON for a pcap file', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pa-test-'));
  const file = path.join(dir, 'sample.pcap');
  fs.writeFileSync(file, b.pcapFile(samplePackets()));
  const cli = path.join(__dirname, '..', 'src', 'cli.js');
  try {
    const text = execFileSync(process.execPath, [cli, file, '--list'], { encoding: 'utf8' });
    assert.match(text, /Packets: 6/);
    assert.match(text, /tcp\/443 HTTPS/);
    assert.match(text, /example\.com/);

    const json = JSON.parse(execFileSync(process.execPath, [cli, file, '--json'], { encoding: 'utf8' }));
    assert.equal(json.packets, 6);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
