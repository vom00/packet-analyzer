'use strict';

// Reads classic libpcap files, the format `tcpdump -w` writes.
// File layout: a 24-byte global header, then records of
// [16-byte record header][captured bytes].

const LINKTYPE_ETHERNET = 1;
const LINKTYPE_RAW = 101;

function readPcap(buf) {
  if (buf.length < 24) {
    throw new Error('File is too small to be a pcap file.');
  }

  // The magic number tells us the byte order and the timestamp unit.
  let little;
  let nano;
  switch (buf.readUInt32BE(0)) {
    case 0xa1b2c3d4: little = false; nano = false; break;
    case 0xd4c3b2a1: little = true; nano = false; break;
    case 0xa1b23c4d: little = false; nano = true; break;
    case 0x4d3cb2a1: little = true; nano = true; break;
    case 0x0a0d0d0a:
      throw new Error('This is a pcapng file. In Wireshark use File > Save As > "pcap", or capture with tcpdump -w.');
    default:
      throw new Error('Not a pcap file (unknown magic number).');
  }

  const u32 = (offset) => (little ? buf.readUInt32LE(offset) : buf.readUInt32BE(offset));

  // The top 4 bits of the link type field can carry FCS info, so mask them off.
  const linkType = u32(20) & 0x0fffffff;

  const packets = [];
  let truncated = false;
  let offset = 24;
  while (offset + 16 <= buf.length) {
    const seconds = u32(offset);
    const fraction = u32(offset + 4);
    const capturedLength = u32(offset + 8);
    const originalLength = u32(offset + 12);
    offset += 16;

    if (offset + capturedLength > buf.length) {
      truncated = true; // the capture was cut off mid-record
      break;
    }

    packets.push({
      time: seconds + fraction / (nano ? 1e9 : 1e6),
      data: buf.subarray(offset, offset + capturedLength),
      originalLength,
    });
    offset += capturedLength;
  }

  return { linkType, packets, truncated };
}

module.exports = { readPcap, LINKTYPE_ETHERNET, LINKTYPE_RAW };
