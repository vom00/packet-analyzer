'use strict';

// Decodes one captured frame, layer by layer:
// Ethernet -> (ARP | IPv4 | IPv6) -> (TCP | UDP | ICMP) -> DNS.
// Each layer reads fixed offsets out of the raw bytes.

const { LINKTYPE_ETHERNET, LINKTYPE_RAW } = require('./pcap');

const ETHERTYPE_IPV4 = 0x0800;
const ETHERTYPE_ARP = 0x0806;
const ETHERTYPE_VLAN = 0x8100;
const ETHERTYPE_IPV6 = 0x86dd;

const PROTO_ICMP = 1;
const PROTO_TCP = 6;
const PROTO_UDP = 17;
const PROTO_ICMPV6 = 58;

// IPv6 extension headers we step over to reach TCP/UDP.
const IPV6_HOP_BY_HOP = 0;
const IPV6_ROUTING = 43;
const IPV6_FRAGMENT = 44;
const IPV6_DEST_OPTS = 60;

const TCP_FLAGS = ['FIN', 'SYN', 'RST', 'PSH', 'ACK', 'URG'];

function formatMac(buf) {
  return Array.from(buf, (b) => b.toString(16).padStart(2, '0')).join(':');
}

function formatIPv4(buf) {
  return Array.from(buf).join('.');
}

// Writes an IPv6 address the short way: lowercase hex, and the longest
// run of zero groups replaced with "::".
function formatIPv6(buf) {
  const groups = [];
  for (let i = 0; i < 16; i += 2) groups.push(buf.readUInt16BE(i));

  let bestStart = -1;
  let bestLen = 0;
  for (let i = 0; i < 8; i++) {
    if (groups[i] !== 0) continue;
    let j = i;
    while (j < 8 && groups[j] === 0) j++;
    if (j - i > bestLen && j - i > 1) {
      bestStart = i;
      bestLen = j - i;
    }
    i = j;
  }

  const hex = groups.map((g) => g.toString(16));
  if (bestStart === -1) return hex.join(':');
  const left = hex.slice(0, bestStart).join(':');
  const right = hex.slice(bestStart + bestLen).join(':');
  return `${left}::${right}`;
}

function decode(data, linkType) {
  const pkt = { protocol: 'Unknown' };
  try {
    if (linkType === LINKTYPE_ETHERNET) {
      decodeEthernet(data, pkt);
    } else if (linkType === LINKTYPE_RAW) {
      decodeIP(data, pkt);
    } else {
      pkt.protocol = `LinkType ${linkType}`;
    }
  } catch (err) {
    // A short packet makes a Buffer read go past the end.
    if (!(err instanceof RangeError)) throw err;
    pkt.truncated = true;
    if (pkt.protocol === 'Unknown') pkt.protocol = 'Truncated';
  }
  return pkt;
}

function decodeEthernet(data, pkt) {
  pkt.eth = {
    dst: formatMac(data.subarray(0, 6)),
    src: formatMac(data.subarray(6, 12)),
  };
  let type = data.readUInt16BE(12);
  let offset = 14;

  // An 802.1Q VLAN tag adds 4 bytes before the real EtherType.
  if (type === ETHERTYPE_VLAN) {
    pkt.eth.vlan = data.readUInt16BE(14) & 0x0fff;
    type = data.readUInt16BE(16);
    offset = 18;
  }
  pkt.eth.type = type;

  const payload = data.subarray(offset);
  if (type === ETHERTYPE_ARP) decodeARP(payload, pkt);
  else if (type === ETHERTYPE_IPV4 || type === ETHERTYPE_IPV6) decodeIP(payload, pkt);
  else pkt.protocol = `EtherType 0x${type.toString(16).padStart(4, '0')}`;
}

function decodeARP(data, pkt) {
  pkt.protocol = 'ARP';
  const op = data.readUInt16BE(6);
  pkt.arp = {
    op: op === 1 ? 'request' : op === 2 ? 'reply' : String(op),
    senderIP: formatIPv4(data.subarray(14, 18)),
    targetIP: formatIPv4(data.subarray(24, 28)),
  };
}

function decodeIP(data, pkt) {
  const version = data[0] >> 4;
  if (version === 4) decodeIPv4(data, pkt);
  else if (version === 6) decodeIPv6(data, pkt);
  else pkt.protocol = `IP version ${version}`;
}

function decodeIPv4(data, pkt) {
  const headerLength = (data[0] & 0x0f) * 4;
  const totalLength = data.readUInt16BE(2);
  const fragmentOffset = data.readUInt16BE(6) & 0x1fff;
  const proto = data[9];

  pkt.protocol = 'IPv4';
  pkt.ip = {
    version: 4,
    ttl: data[8],
    proto,
    src: formatIPv4(data.subarray(12, 16)),
    dst: formatIPv4(data.subarray(16, 20)),
  };

  // Later fragments carry no TCP/UDP header, so stop here.
  if (fragmentOffset !== 0) {
    pkt.ip.fragment = true;
    return;
  }

  // totalLength drops any Ethernet padding at the end of small frames.
  const payload = data.subarray(headerLength, Math.min(totalLength, data.length));
  decodeTransport(proto, payload, pkt);
}

function decodeIPv6(data, pkt) {
  let next = data[6];
  pkt.protocol = 'IPv6';
  pkt.ip = {
    version: 6,
    ttl: data[7], // called "hop limit" in IPv6
    proto: next,
    src: formatIPv6(data.subarray(8, 24)),
    dst: formatIPv6(data.subarray(24, 40)),
  };

  let offset = 40;
  while (next === IPV6_HOP_BY_HOP || next === IPV6_ROUTING || next === IPV6_DEST_OPTS || next === IPV6_FRAGMENT) {
    if (next === IPV6_FRAGMENT) {
      const fragmentOffset = data.readUInt16BE(offset + 2) >> 3;
      next = data[offset];
      offset += 8;
      if (fragmentOffset !== 0) {
        pkt.ip.proto = next;
        pkt.ip.fragment = true;
        return;
      }
    } else {
      const length = (data[offset + 1] + 1) * 8;
      next = data[offset];
      offset += length;
    }
  }
  pkt.ip.proto = next;

  const payloadLength = data.readUInt16BE(4);
  const payload = data.subarray(offset, Math.min(40 + payloadLength, data.length));
  decodeTransport(next, payload, pkt);
}

function decodeTransport(proto, data, pkt) {
  if (proto === PROTO_TCP) decodeTCP(data, pkt);
  else if (proto === PROTO_UDP) decodeUDP(data, pkt);
  else if (proto === PROTO_ICMP || proto === PROTO_ICMPV6) {
    pkt.protocol = proto === PROTO_ICMP ? 'ICMP' : 'ICMPv6';
    pkt.icmp = { type: data[0], code: data[1] };
  }
}

function decodeTCP(data, pkt) {
  const headerLength = (data[12] >> 4) * 4;
  const flagBits = data[13];
  pkt.protocol = 'TCP';
  pkt.tcp = {
    srcPort: data.readUInt16BE(0),
    dstPort: data.readUInt16BE(2),
    seq: data.readUInt32BE(4),
    ack: data.readUInt32BE(8),
    flags: TCP_FLAGS.filter((_, i) => flagBits & (1 << i)),
    payloadLength: Math.max(0, data.length - headerLength),
  };
}

function decodeUDP(data, pkt) {
  pkt.protocol = 'UDP';
  pkt.udp = {
    srcPort: data.readUInt16BE(0),
    dstPort: data.readUInt16BE(2),
    length: data.readUInt16BE(4),
  };
  const { srcPort, dstPort } = pkt.udp;
  if (srcPort === 53 || dstPort === 53 || srcPort === 5353 || dstPort === 5353) {
    const dns = decodeDNS(data.subarray(8));
    if (dns) {
      pkt.protocol = srcPort === 5353 || dstPort === 5353 ? 'mDNS' : 'DNS';
      pkt.dns = dns;
    }
  }
}

// Reads the DNS header and the question names. Answers are skipped.
function decodeDNS(data) {
  if (data.length < 12) return null;
  const flags = data.readUInt16BE(2);
  const questionCount = data.readUInt16BE(4);
  const questions = [];
  let offset = 12;
  for (let i = 0; i < questionCount && offset < data.length; i++) {
    const { name, end } = readName(data, offset);
    if (end + 4 > data.length) break;
    questions.push({ name, type: data.readUInt16BE(end) });
    offset = end + 4;
  }
  return {
    id: data.readUInt16BE(0),
    isResponse: Boolean(flags & 0x8000),
    questions,
  };
}

// DNS names are length-prefixed labels: 3www7example3com0.
// A byte starting with 0b11 is a pointer to a name earlier in the message.
function readName(data, offset) {
  const labels = [];
  let end = -1;
  let jumps = 0;
  while (offset < data.length) {
    const len = data[offset];
    if (len === 0) {
      offset += 1;
      break;
    }
    if ((len & 0xc0) === 0xc0) {
      if (end === -1) end = offset + 2;
      if (++jumps > 10) break; // guards against pointer loops
      offset = ((len & 0x3f) << 8) | data[offset + 1];
      continue;
    }
    labels.push(data.toString('latin1', offset + 1, offset + 1 + len));
    offset += 1 + len;
  }
  return { name: labels.join('.'), end: end === -1 ? offset : end };
}

module.exports = { decode, formatIPv4, formatIPv6, formatMac };
