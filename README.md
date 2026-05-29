# Wireshark Fundamentals Lab

**Environment:** Kali Linux (VirtualBox NAT)  
**Tool:** Wireshark  
**Objective:** Capture and analyze real network traffic across four core protocols — ICMP, DNS, TCP/HTTP, and HTTPS/TLS.

---

## Setup

### Interface
Identified active interface using:
```bash
ip a
```
Interface used: `eth0` (IP: `10.0.2.15` — VirtualBox NAT gateway)

### Permissions
Added user to Wireshark group to capture without root:
```bash
sudo usermod -aG wireshark $USER
newgrp wireshark
```

---

## Module 1: ICMP

### Objective
Understand how `ping` works at the packet level — request/reply cycle, TTL behavior, and OS fingerprinting.

### Traffic Generation
```bash
ping -c 4 8.8.8.8
```

### Display Filter
```
icmp
```

### Captures

**ICMP Echo Request (Type 8):**

![ICMP Echo Request](https://github.com/iQ-coder/network-security-wireshark-lab/blob/main/icmp%20request%20message.png)

**ICMP Echo Reply (Type 0):**

![ICMP Echo Reply](https://github.com/iQ-coder/network-security-wireshark-lab/blob/main/icm%20reply%20messaege.png)

### Findings

**Packet count:** 8 packets (4 Echo Requests + 4 Echo Replies)

**Echo Request (Type 8):**
| Field | Value | Notes |
|-------|-------|-------|
| Type | 8 | Echo Request |
| Code | 0 | Plain ping, no subtype |
| Checksum | Correct | Packet integrity verified |
| TTL (IP header) | 64 | Linux default outgoing TTL |
| Sequence number | 1, 2, 3, 4 | Increments per ping |

**Echo Reply (Type 0):**
| Field | Value | Notes |
|-------|-------|-------|
| Type | 0 | Echo Reply |
| Code | 0 | |
| TTL (IP header) | 255 | Google's starting TTL — network appliance default |

### Key Observations

- TTL is set by the **sender**, not inherited. Different OS/device defaults:
  - Linux: 64
  - Windows: 128
  - Network appliances (Cisco, Google): 255
- TTL on the reply can be used for **OS fingerprinting** and **hop count estimation**:
  ```
  Hops traveled = Starting TTL - Received TTL
  ```
- Wireshark automatically links requests to replies: `(reply in packet #XXXX)`

---

## Module 2: DNS

### Objective
Capture a full DNS query/response cycle and understand how hostnames are resolved to IPs.

### Traffic Generation
```bash
ping -c 1 <random-domain>
```

### Display Filter
```
udp.port == 53
```
Narrowed further with:
```
dns.qry.name == "<domain>"
```

### Captures

**DNS Query:**

![DNS Query](https://github.com/iQ-coder/network-security-wireshark-lab/blob/main/dns%20query%201.png)

**DNS Response:**

![DNS Response](https://github.com/iQ-coder/network-security-wireshark-lab/blob/main/dns%20query%20response.png)

### Findings

**DNS runs over UDP port 53.** Each lookup produces exactly 2 packets.

**Query packet:**
| Field | Value | Notes |
|-------|-------|-------|
| Transaction ID | (random) | Ties query to response |
| Flags | Standard query | Response bit = 0 |
| Questions | 1 | Hostname being looked up |
| Answer RRs | 0 | No answer yet — this is the question |
| Recursion Desired | 1 | Asking resolver to do the work |

**Response packet:**
| Field | Value | Notes |
|-------|-------|-------|
| Transaction ID | (same as query) | Matched by DNS client |
| Flags | Standard query response | Response bit = 1 |
| Answer RRs | 1 | IP returned |
| Resolved IP | 157.240.196.35 | Meta/Facebook infrastructure |
| DNS TTL | 33 seconds | Short TTL typical of parked/load-balanced domains |

**Round-trip time:** 252ms

### Key Observations

- DNS TTL (cache duration) is **separate** from IP TTL (hop limit) — same name, completely different purposes
- Transaction ID is DNS's equivalent of ICMP's sequence number — it pairs requests to responses
- Short TTLs (like 33s) are common on load-balanced infrastructure
- Browser background traffic generates constant DNS queries — use `dns.qry.name` filter to isolate specific lookups

---

## Module 3: TCP + HTTP

### Objective
Capture the full TCP connection lifecycle (handshake → data transfer → teardown) and observe plaintext HTTP data.

### Traffic Generation
```bash
curl -v http://neverssl.com
```
> `neverssl.com` used because it serves plain HTTP with no redirects — ideal for cleartext analysis.

### Display Filters
```
tcp and ip.addr == 34.223.124.45
http
```

### Captures

**TCP SYN (connection initiation):**

![TCP SYN](https://github.com/iQ-coder/network-security-wireshark-lab/blob/main/tcp%20syn%20packet.png)

**TCP SYN+ACK (server response):**

![TCP SYN ACK](https://github.com/iQ-coder/network-security-wireshark-lab/blob/main/tcp%20syn%20ack.png)

**TCP PSH+ACK (data transfer):**

![TCP PSH ACK](https://github.com/iQ-coder/network-security-wireshark-lab/blob/main/tcp%20ack%2Bpsh.png)

**HTTP GET Request:**

![HTTP Request](https://github.com/iQ-coder/network-security-wireshark-lab/blob/main/http%20request.png)

**HTTP Response (plaintext body):**

![HTTP Plain Text](https://github.com/iQ-coder/network-security-wireshark-lab/blob/main/reading%20http%20plain%20text.png)

### TCP Lifecycle Observed

```
[Handshake]
SYN          ──►   "I want to connect"
SYN, ACK     ◄──   "Ready"
ACK          ──►   "Connected"

[Data Transfer]
PSH, ACK     ──►   HTTP GET request
ACK          ◄──   Acknowledged
PSH, ACK     ◄──   HTTP 200 response + HTML body
ACK          ──►   Acknowledged

[Teardown]
FIN, ACK     ──►   "Done, closing"
FIN, ACK     ◄──   "Closing too"
ACK          ──►   "Confirmed"
```

### TCP Header Findings

**SYN packet (outgoing):**
| Field | Value | Notes |
|-------|-------|-------|
| Sequence number | 0 (relative) | Wireshark normalizes to 0 for readability |
| Window size | 64,240 bytes | Max buffer before sender must wait — flow control |

**SYN+ACK (server response):**
| Field | Value | Notes |
|-------|-------|-------|
| Sequence number | Different (raw) | Server picks its own random ISN independently |

### HTTP Layer Findings

**GET Request (PSH+ACK from client):**
```
GET / HTTP/1.1
Host: neverssl.com
User-Agent: curl/8.19.0
Accept: */*
```

### Key Observations

- HTTP traffic is **fully readable** in Wireshark — headers, User-Agent, Host, and response body all visible in plaintext
- Anyone on the same network can capture this data — passwords, cookies, form data all exposed
- Wireshark uses **relative sequence numbers** by default — raw values visible in parentheses

---

## Module 4: HTTPS / TLS

### Objective
Contrast HTTP with HTTPS — observe the TLS handshake and confirm that application data is unreadable when encrypted.

### Traffic Generation
```bash
curl -v https://example.com
```

### Display Filter
```
tls and ip.addr == 93.184.216.34
```

### Capture

**HTTPS — Application Data is encrypted (unreadable):**

![HTTPS Encrypted](https://github.com/iQ-coder/network-security-wireshark-lab/blob/main/not%20being%20able%20to%20read%20https.png)

### TLS Handshake Observed

```
Client Hello     ──►   "I support these cipher suites and TLS versions"
Server Hello     ◄──   "Use this cipher, here's my certificate"
Change Cipher Spec ──► "Switching to encrypted mode"
Application Data ──►   ████████████████ (encrypted)
Application Data ◄──   ████████████████ (encrypted)
```

### Comparison: HTTP vs HTTPS

| | HTTP | HTTPS |
|--|------|-------|
| Application layer | Fully readable | Encrypted — unreadable |
| Headers visible | Yes | No |
| User-Agent visible | Yes | No |
| Response body visible | Yes | No |
| Transport layer | TCP | TCP + TLS |
| Wireshark can decode | Yes | No (without private key) |

---

## Summary

| Module | Protocol | Filter Used | Key Concept |
|--------|----------|-------------|-------------|
| 1 | ICMP | `icmp` | Type 8/0, TTL, OS fingerprinting |
| 2 | DNS | `udp.port == 53` | Query/response, Transaction ID, DNS TTL |
| 3 | TCP + HTTP | `tcp and ip.addr == X` / `http` | Handshake, sequence numbers, plaintext exposure |
| 4 | HTTPS/TLS | `tls and ip.addr == X` | Encryption, TLS handshake, why HTTPS matters |

## Wireshark Skills Developed

- Applying display filters to isolate specific traffic
- Reading all three panes: Packet List, Packet Details, Packet Bytes
- Navigating the protocol stack (Ethernet → IP → TCP/UDP → Application)
- Matching request/response pairs across ICMP, DNS, and TCP
- Interpreting TTL, sequence numbers, window size, and DNS TTL fields
- Contrasting plaintext HTTP with encrypted HTTPS at the packet level

