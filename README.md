# LAB02 – Denial of Service (DoS): Concepts & Question Notes

**Course:** IKB31603 Ethical Hacking

> This is a concept and reasoning write-up for your report, not an execution guide. DoS techniques degrade availability for everyone on a network, including shared infrastructure, so I'm not providing ready-to-run attack commands — only the "why it works" explanation you need to answer the lab questions and write your analysis section.

## Core concept

Every server has finite resources: CPU cycles, memory, open sockets/file descriptors, and bandwidth. A DoS attack doesn't "break in" — it makes **legitimate requests impossible to serve** by consuming one of these finite resources faster than it can be freed. The three techniques in this lab attack three different resources:

| Technique | Layer | Resource exhausted |
|---|---|---|
| ICMP Ping Flood | Network (L3) | Bandwidth / packet-processing capacity |
| SYN Flood | Transport (L4) | The TCP backlog queue (half-open connections) |
| Slowloris | Application (L7) | The web server's pool of worker threads/connections |

## Why each technique works

**ICMP Ping Flood.** Sending ICMP Echo Requests far faster than they can be answered saturates the network interface and the kernel's packet-handling path. It's volumetric — it doesn't target any specific application, just the pipe and the CPU cycles spent processing packets.

**SYN Flood.** TCP connections start with a three-way handshake: SYN → SYN-ACK → ACK. The server allocates a small table entry (the backlog) for each SYN it receives, waiting for the final ACK. If the attacker sends SYNs with spoofed/random source IPs and never completes the handshake, each entry sits in the backlog until it times out. Once the backlog is full, the server can't accept new TCP connections from anyone — legitimate or not.

**Slowloris.** Instead of overwhelming bandwidth, Slowloris opens many HTTP connections and sends request headers *very slowly* — just enough data every so often to keep each connection alive without ever completing the request. Each open-but-incomplete connection occupies one worker/thread/socket on the server. With a thread-per-connection server and a low connection cap, a modest number of slow connections is enough to exhaust the pool, so new legitimate clients can't get a worker.

## Lab02 Questions

### Q1. What tool can we use to execute DoS via HTTP?

Slowloris — it operates entirely over HTTP, opening many connections and trickling partial request headers to keep them open, rather than operating at the network or transport layer like a ping flood or SYN flood.

### Q2. How does DoS lead to the target system being drastically slow or crashing?

A flood of requests arrives faster than the server can process and clear them. Queues (connection backlog, request queue, memory buffers) grow because incoming work outpaces outgoing work. Once a finite resource — CPU, RAM, open sockets, or bandwidth — is saturated:
- **Slow:** the server is still functioning but spends most of its time context-switching between an enormous number of pending connections/requests, so legitimate requests queue behind the flood and response times balloon.
- **Crash:** if a resource like memory is exhausted entirely (e.g. too many open connection objects), the OS may kill the process (OOM), or an unhandled exception in the application crashes it outright.

### Q3. How does Ping of Death cause DoS to the target?

This is worth distinguishing from the Ping *Flood* used earlier in the lab:

- **Ping Flood** (what `ping -f` does) is **volumetric** — it's just a huge volume of normal-sized ICMP packets, exhausting bandwidth/CPU through sheer quantity.
- **Ping of Death** is a **malformed-packet** attack — it sends an ICMP packet whose reassembled size exceeds the maximum legal IP packet size (65,535 bytes), built by sending deliberately oversized/malicious IP fragments. When a vulnerable host reassembles the fragments into a single oversized packet, it overflows a fixed-size buffer in the OS's network stack, which can crash or destabilize the system.
- Ping of Death exploited a flaw in how older (pre-mid-1990s/2000s-patched) TCP/IP stacks handled fragment reassembly. Modern operating systems validate reassembled packet size and drop/reject oversized packets, so this specific exploit is largely historical — but it's a good example of a **single malformed packet** causing DoS, versus the **volume-based** flood you performed in this lab.

### Q4. Why did the Ping Flood fail to trigger the HTTP 500 error in `dos_target.py`?

This comes down to **OSI layer separation**.

- ICMP operates at **Layer 3 (Network layer)**. When `ping -f` floods the target, those Echo Request packets are received and answered by the **OS kernel's network stack** — they never reach the Flask/HTTP application at all.
- `dos_target.py`'s `CONN_CAP = 20` logic lives at **Layer 7 (Application layer)** — it only counts and rejects connections made to its HTTP **socket** (its listening TCP port).
- Because ICMP and HTTP are handled by completely different layers and different code paths (kernel vs. application), flooding one does not consume the other's resource pool. The network interface can be visibly saturated with ICMP traffic in Wireshark while the HTTP listener's 20-connection cap remains untouched, because no actual TCP connections to the HTTP port were being opened by the ping flood.
- In short: **volume at Layer 3 doesn't translate into connection-count pressure at Layer 7** unless the flood is large enough to cause packet loss/congestion that also disrupts the TCP connections carrying HTTP traffic — which wasn't the case here.

### Q5. Why does a spoofed-source SYN flood exhaust the backlog, and why does IP-based blocking fail?

**Why the backlog fills:** Every SYN packet that arrives causes the server to allocate a half-open connection entry in its backlog (`request_queue_size`) and reply with a SYN-ACK, then wait for the final ACK. With `--rand-source`, each SYN carries a different, usually non-existent or unreachable source IP. The server's SYN-ACK goes out to that random address and is never answered, so the entry can't be completed — it just sits there until it times out (which can take seconds). Because new SYNs keep arriving far faster than old entries expire, the backlog fills and stays full, so the server starts silently dropping or refusing new SYNs, including from legitimate clients.

**Why IP-based blocking fails:** A firewall rule that blocks a specific source IP only works if that IP is the **actual persistent attacker** sending repeated traffic. Here, every single packet carries a different, essentially random source address. There's no stable IP to add to a blocklist — by the time you've identified and blocked one address, the attacker (really, the flood) has already moved on to thousands of others. The attacker's real IP is never exposed, since the packets are spoofed. This is exactly why SYN flood defenses rely on mechanisms like **SYN cookies** (not maintaining per-connection state until the handshake completes) rather than IP blocklisting.

### Q6. Slowloris against `dos_target.py` vs. Apache2 — compare the behavior

**Experience of the client/monitor:**
- Against **`dos_target.py`** (`CONN_CAP = 20`): once the 20th connection is held open, the application **actively and explicitly rejects further requests** with an HTTP 500 and a JSON error body. This is a clean, fast, visible failure — `monitor.py` immediately sees a clear error response rather than a hang.
- Against an **unhardened Apache2**: if `MaxRequestWorkers` were the only limit, the behavior would be very different — no explicit error. New connections would simply **hang/queue** waiting for a free worker (or eventually get connection-refused at the TCP level once the listen queue is also full), and clients would experience a stall/timeout rather than a clean error message.

**Why default Apache2 resists a basic Slowloris out-of-the-box:**
Apache on Ubuntu ships with **`mod_reqtimeout`** enabled by default. This module enforces a maximum time allowed to receive the complete request headers and body (and a minimum data rate after an initial grace period). A Slowloris connection that trickles a few bytes every so often to stay "alive" violates this timeout and rate requirement, so Apache closes it and frees the worker well before an attacker can accumulate enough slow connections to exhaust `MaxRequestWorkers`. A custom script like `dos_target.py` has no such protection unless its author explicitly adds one — it just accepts and holds connections up to its connection cap indefinitely, which is why a handful of slow connections is enough to deny it service, while a production Apache2 instance needs a much larger, sustained attack (or specifically targets a server with `mod_reqtimeout` disabled/misconfigured) to have the same effect.

## Countermeasures (for your report)

| Attack | Countermeasure |
|---|---|
| ICMP Flood | Rate-limit ICMP at the firewall/router; disable ICMP responses on exposed interfaces where not needed |
| SYN Flood | Enable **SYN cookies**, reduce SYN-RECV timeout, use a stateful firewall/load balancer that absorbs the handshake (e.g. a reverse proxy or DDoS-mitigation service) |
| Slowloris | Enable/keep **`mod_reqtimeout`** (Apache) or equivalent timeout modules, set low header/body timeouts, use an event-driven server (e.g. nginx) rather than thread-per-connection, and front the app with a reverse proxy that buffers slow clients |
| General | Rate limiting, connection caps tuned to capacity, auto-scaling/load balancing, and monitoring (as `monitor.py` demonstrates) to detect degradation early |

## Key takeaways

- DoS attacks target **availability**, the third leg of the CIA triad — they don't need to read or alter any data.
- Different techniques exhaust resources at different OSI layers, which is why a flood at one layer can leave another layer's resources untouched (Q4).
- Spoofed source addresses defeat simple reputation/IP-based defenses, which is why modern mitigations focus on **not committing resources** until a connection is verified (SYN cookies) or **timing out** slow/incomplete activity (`mod_reqtimeout`).
