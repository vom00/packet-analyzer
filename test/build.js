'use strict';

// Builds fake packets and pcap files for the tests, so no real
// capture ever needs to be in the repo. Addresses come from the
// ranges set aside for documentation (192.0.2.0/24, 2001:db8::/32).

function ipv4Bytes(addr) {
  return Buffer.from(addr.split('.').map(Number));
}

function mac(str) {
  return Buffer.from(str, 'hex');
}

function ethernet(type, payload, { src = '020000000001', dst = '020000000002' } = {}) {
  const header = Buffer.alloc(14);
  mac(dst).copy(header, 0);
  mac(src).copy(header, 6);
  header.writeUInt16BE(type, 12);
  return Buffer.concat([header, payload]);
}

function ipv4(proto, src, dst, payload, { ttl = 64 } = {}) {
  const header = Buffer.alloc(20);
  header[0] = 0x45; // version 4, 5 x 4-byte words
  header.writeUInt16BE(20 + payload.length, 2);
  header[8] = ttl;
  header[9] = proto;
  ipv4Bytes(src).copy(header, 12);
  ipv4Bytes(dst).copy(header, 16);
  return Buffer.concat([header, payload]);
}

function ipv6(next, src, dst, payload) {
  const header = Buffer.alloc(40);
  header[0] = 0x60;
  header.writeUInt16BE(payload.length, 4);
  header[6] = next;
  header[7] = 64;
  src.copy(header, 8);
  dst.copy(header, 24);
  return Buffer.concat([header, payload]);
}

const FLAG_BITS = { FIN: 1, SYN: 2, RST: 4, PSH: 8, ACK: 16, URG: 32 };

function tcp(srcPort, dstPort, flags, payload = Buffer.alloc(0)) {
  const header = Buffer.alloc(20);
  header.writeUInt16BE(srcPort, 0);
  header.writeUInt16BE(dstPort, 2);
  header.writeUInt32BE(1000, 4);
  header[12] = 5 << 4;
  header[13] = flags.reduce((bits, f) => bits | FLAG_BITS[f], 0);
  return Buffer.concat([header, payload]);
}

function udp(srcPort, dstPort, payload) {
  const header = Buffer.alloc(8);
  header.writeUInt16BE(srcPort, 0);
  header.writeUInt16BE(dstPort, 2);
  header.writeUInt16BE(8 + payload.length, 4);
  return Buffer.concat([header, payload]);
}

function dnsQuery(name, { id = 0x1234, response = false } = {}) {
  const header = Buffer.alloc(12);
  header.writeUInt16BE(id, 0);
  header.writeUInt16BE(response ? 0x8180 : 0x0100, 2);
  header.writeUInt16BE(1, 4);
  const labels = name.split('.').map((l) => Buffer.concat([Buffer.from([l.length]), Buffer.from(l)]));
  const tail = Buffer.alloc(5);
  tail.writeUInt16BE(1, 1); // type A
  tail.writeUInt16BE(1, 3); // class IN
  return Buffer.concat([header, ...labels, tail]);
}

function arp(op, senderIP, targetIP) {
  const body = Buffer.alloc(28);
  body.writeUInt16BE(1, 0); // Ethernet
  body.writeUInt16BE(0x0800, 2); // IPv4
  body[4] = 6;
  body[5] = 4;
  body.writeUInt16BE(op, 6);
  ipv4Bytes(senderIP).copy(body, 14);
  ipv4Bytes(targetIP).copy(body, 24);
  return body;
}

// packets: [{ time, data }]
function pcapFile(packets, { little = true, linkType = 1 } = {}) {
  const w32 = (buf, value, offset) => (little ? buf.writeUInt32LE(value, offset) : buf.writeUInt32BE(value, offset));
  const w16 = (buf, value, offset) => (little ? buf.writeUInt16LE(value, offset) : buf.writeUInt16BE(value, offset));

  const header = Buffer.alloc(24);
  w32(header, 0xa1b2c3d4, 0);
  w16(header, 2, 4);
  w16(header, 4, 6);
  w32(header, 65535, 16);
  w32(header, linkType, 20);

  const parts = [header];
  for (const { time, data } of packets) {
    const rec = Buffer.alloc(16);
    w32(rec, Math.floor(time), 0);
    w32(rec, Math.round((time % 1) * 1e6), 4);
    w32(rec, data.length, 8);
    w32(rec, data.length, 12);
    parts.push(rec, data);
  }
  return Buffer.concat(parts);
}

module.exports = { ethernet, ipv4, ipv6, tcp, udp, dnsQuery, arp, pcapFile };
