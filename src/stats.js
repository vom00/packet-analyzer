'use strict';

// Turns a list of decoded packets into counts: protocols, who talked
// the most, which conversations were biggest, which services were used,
// and which names were looked up in DNS.

const SERVICE_NAMES = {
  20: 'FTP data', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
  67: 'DHCP', 68: 'DHCP', 80: 'HTTP', 110: 'POP3', 123: 'NTP', 137: 'NetBIOS',
  143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 465: 'SMTPS', 993: 'IMAPS',
  1900: 'SSDP', 3389: 'RDP', 5353: 'mDNS', 8080: 'HTTP alt',
};

function bump(map, key, packets, bytes) {
  const entry = map.get(key) || { packets: 0, bytes: 0 };
  entry.packets += packets;
  entry.bytes += bytes;
  map.set(key, entry);
}

function top(map, n) {
  return [...map.entries()]
    .sort((a, b) => b[1].bytes - a[1].bytes || b[1].packets - a[1].packets)
    .slice(0, n)
    .map(([key, value]) => ({ key, ...value }));
}

// Takes [{ time, originalLength, pkt }] where pkt comes from decode().
function summarize(records, { topN = 10 } = {}) {
  const protocols = new Map();
  const talkers = new Map();
  const conversations = new Map();
  const services = new Map();
  const dnsNames = new Map();
  let bytes = 0;
  let synCount = 0;
  let resetCount = 0;
  let truncatedCount = 0;

  for (const { originalLength, pkt } of records) {
    bytes += originalLength;
    bump(protocols, pkt.protocol, 1, originalLength);
    if (pkt.truncated) truncatedCount++;

    if (pkt.ip) {
      bump(talkers, pkt.ip.src, 1, originalLength);
      // Sort the two ends so A->B and B->A count as one conversation.
      const ends = [pkt.ip.src, pkt.ip.dst].sort();
      bump(conversations, `${ends[0]} <-> ${ends[1]}`, 1, originalLength);
    }

    const l4 = pkt.tcp || pkt.udp;
    if (l4) {
      // The lower port is usually the server side (443, 53, ...).
      const port = Math.min(l4.srcPort, l4.dstPort);
      const name = SERVICE_NAMES[port] ? ` ${SERVICE_NAMES[port]}` : '';
      bump(services, `${pkt.tcp ? 'tcp' : 'udp'}/${port}${name}`, 1, originalLength);
    }

    if (pkt.tcp) {
      const { flags } = pkt.tcp;
      // SYN without ACK is the first packet of a new connection.
      if (flags.includes('SYN') && !flags.includes('ACK')) synCount++;
      if (flags.includes('RST')) resetCount++;
    }

    if (pkt.dns && !pkt.dns.isResponse) {
      for (const q of pkt.dns.questions) bump(dnsNames, q.name, 1, 0);
    }
  }

  const times = records.map((r) => r.time);
  const start = times.length ? Math.min(...times) : 0;
  const end = times.length ? Math.max(...times) : 0;

  return {
    packets: records.length,
    bytes,
    durationSeconds: end - start,
    newTcpConnections: synCount,
    tcpResets: resetCount,
    truncatedPackets: truncatedCount,
    protocols: top(protocols, Infinity),
    topTalkers: top(talkers, topN),
    topConversations: top(conversations, topN),
    topServices: top(services, topN),
    dnsQueries: [...dnsNames.entries()]
      .sort((a, b) => b[1].packets - a[1].packets)
      .slice(0, topN)
      .map(([name, v]) => ({ name, count: v.packets })),
  };
}

module.exports = { summarize };
