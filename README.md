# packet-analyzer

A small command line tool that reads a packet capture (`.pcap`) and shows what was on the wire: which protocols showed up, who talked the most, which services were used, and which names were looked up in DNS.

It has no dependencies. Every header is decoded by hand from the raw bytes, so you can read the code and see exactly where each field lives in a packet.

## Why I built it

I wanted to see how networks behave. Tools like Wireshark show you everything at once. I wanted something small enough to read line by line, so I could follow a packet from the Ethernet header down to the DNS name inside it.

## AI help

AI (Claude) wrote the code, the tests and this README.

## What it decodes

- pcap files in either byte order, with micro or nanosecond timestamps
- Ethernet, including 802.1Q VLAN tags
- ARP requests and replies
- IPv4 (stops at later fragments, which have no TCP/UDP header)
- IPv6, stepping over extension headers to reach TCP/UDP
- TCP ports and flags (SYN, ACK, FIN, RST, PSH, URG)
- UDP ports
- ICMP and ICMPv6 type and code
- DNS and mDNS question names, including compressed names

It does not read pcapng files yet. In Wireshark, use File > Save As and pick "pcap".

## How it works

| File | What it does |
| --- | --- |
| [`src/pcap.js`](src/pcap.js) | Reads the 24-byte file header, works out byte order from the magic number, then walks each packet record. |
| [`src/decode.js`](src/decode.js) | Peels off one layer at a time: Ethernet, then ARP / IPv4 / IPv6, then TCP / UDP / ICMP, then DNS. A packet that is too short gets marked as truncated instead of crashing the tool. |
| [`src/stats.js`](src/stats.js) | Adds everything up: protocol counts, top talkers, top conversations (A to B and B to A count as one), top services and DNS lookups. |
| [`src/cli.js`](src/cli.js) | Reads the arguments, runs the steps above and prints a text report or JSON. |
| [`test/`](test) | Builds fake packets and pcap files in memory and checks each decoder. No real captures are stored in the repo. |

## How to run it

You need [Node.js](https://nodejs.org/) 18 or newer.

```bash
git clone https://github.com/vom00/packet-analyzer.git
cd packet-analyzer
npm test
```

Capture some traffic (only on a network you own or have permission to monitor):

```bash
sudo tcpdump -i any -w capture.pcap -c 500
```

Then analyze it:

```bash
node src/cli.js capture.pcap
node src/cli.js capture.pcap --list --top 5
node src/cli.js capture.pcap --json
```

`--list` prints one line per packet first. `--top N` sets how many rows each table shows. `--json` prints the summary as JSON.

### Example output

This is from a small fake capture made with the test helpers (documentation-only addresses):

```
    1      0.000000  ARP request 192.0.2.10 -> 192.0.2.53
    2      0.100000  192.0.2.10 -> 192.0.2.53 DNS query example.com
    3      0.200000  192.0.2.10 -> 198.51.100.20 TCP 50001 -> 443 [SYN] 0B
    4      0.300000  198.51.100.20 -> 192.0.2.10 TCP 443 -> 50001 [SYN,ACK] 0B
    5      0.400000  192.0.2.10 -> 198.51.100.20 TCP 50001 -> 443 [PSH,ACK] 100B

Packets: 5   Bytes: 375 B   Duration: 0.40 s
New TCP connections (SYN): 1   TCP resets: 0   Truncated packets: 0

Top services
  Port           Packets  Bytes
  tcp/443 HTTPS  3        262 B
  udp/53 DNS     1        71 B
```

## What I learned

TODO (Vyom): write this part yourself after running it on your own traffic.

## Privacy

Captures can hold private data, so `.gitignore` blocks `*.pcap` and `*.pcapng` files from being committed.
