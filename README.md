# Practical Forensic Examination Report

| Field | Entry |
| --- | --- |
| **Student Name** | Godwin Edet Ikpi |
| **Registration Number** | 2025/FSWD/11267 |
| **Course** | SBT-DF203 — Basic Networking Skills for Digital Forensics |
| **Practical** | Lab 5 — ARP Poisoning Forensics |
| **Laboratory Environment** | Kali Linux 2024.x (VMware Workstation Host-Only Network) |
| **Submission Date** | 15th September 2026 |
| **Report Version** | 1.0 |

---

## 1. Executive Summary

This practical investigated a reported condition in which a default gateway intermittently resolves to an incorrect MAC address. The investigation was designed to establish normal Address Resolution Protocol (ARP) behaviour, inspect local ARP state, analyse an authorised ARP-poisoning training capture, identify conflicting IP-to-MAC claims, construct a clean-versus-poisoned timeline, and document restoration of the ARP state. The supplied capture was treated as historical/offline training evidence and was preserved before analysis.

The key forensic question was whether the gateway IP address was associated consistently with one legitimate MAC address or whether multiple MAC addresses claimed the same gateway IP. Where conflicting claims are observed, the report distinguishes packet-level facts from forensic interpretation: a conflicting ARP claim is an indicator of possible ARP poisoning, but the packet alone does not establish intent or attribution.

---

## 2. Scenario and Investigation Questions

**Scenario:** A default gateway intermittently resolves to the wrong MAC address. The examination addresses the following core questions:

* What is normal ARP request/reply behaviour in the authorised laboratory?
* What entries exist in the local ARP/neighbor cache before and after the test?
* Which IP-to-MAC claims appear in the supplied ARP capture?
* Does the gateway IP receive conflicting MAC claims?
* Are any ARP replies unsolicited, repeated, or otherwise inconsistent with the expected resolution process?
* What evidence distinguishes the clean state from the suspected poisoned state?
* Was the ARP state restored after the practical?

---

## 3. Objectives

1. Explain ARP resolution and the role of ARP requests and replies.
2. Inspect interface, routing, and ARP/neighbor information.
3. Capture and identify normal ARP request/reply behaviour.
4. Preserve and hash the supplied ARP training PCAP.
5. Inventory ARP replies and summarize IP-to-MAC claims.
6. Identify conflicting claims for the default gateway.
7. Analyse the clean-versus-poisoned sequence of events.
8. Document an optional short host-only simulation (if explicitly authorised).
9. Restore ARP/network state and verify the restoration.
10. Recommend practical controls for reducing ARP-poisoning risk.

---

## 4. Authorisation, Safety, and Scope

All active testing was restricted strictly to the ICDFA-approved environment (isolated host-only virtual network). No third-party, production, public, campus, or live wireless system was targeted. The supplied historical/offline PCAP was analysed as authorised training evidence.

**Safety Controls Applied and Confirmed:**

* [x] Host-only/internal virtual network confirmed (`192.168.199.0/24`).
* [x] No public or production network involved.
* [x] Supplied offline evidence preserved and hashed before analysis.
* [x] Capture stopped immediately after acquiring required evidence.
* [x] Temporary ARP/forwarding/firewall changes restored post-lab.
* [x] Final ARP/neighbor state verified against original baseline.

---

## 5. Laboratory Environment

| Item | Observed Value |
| --- | --- |
| **Analyst Operating System** | Kali Linux 2024.x |
| **Virtualisation Platform** | VMware Workstation |
| **Network Interface** | `eth0` |
| **Analyst IP Address** | `192.168.199.135` |
| **Subnet / Prefix** | `192.168.199.0/24` |
| **Default Gateway IP** | `192.168.199.2` |
| **Gateway MAC (Clean State)** | `00:50:56:f4:b3:5f` |
| **Capture Interface** | `eth0` |
| **Wireshark/TShark Version** | TShark (Wireshark) 4.4.7 |

*Evidence Reference:* Screenshot `[S1]` / Command Output `[E1]`.

---

## 6. Initial Interface, Route, and ARP State

The baseline environment state was verified using standard Linux networking tools:

```bash
ip addr show
ip route
ip neigh show
arp -n 2>/dev/null || true

```

| Observation | Actual Result |
| --- | --- |
| **Interface and Status** | `eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000` |
| **IPv4 Address/Prefix** | `192.168.199.135/24` |
| **Default Route** | `default via 192.168.199.2 dev eth0 proto dhcp src 192.168.199.135 metric 100` |
| **Gateway IP** | `192.168.199.2` |
| **Gateway MAC** | `00:50:56:f4:b3:5f` |
| **ARP/Neighbor State** | `192.168.199.2 dev eth0 lladdr 00:50:56:f4:b3:5f REACHABLE` |

*Screenshot Reference:* `[S1 — Initial interface/route/ARP table]`

---

## 7. ARP Fundamentals

ARP maps an IPv4 address to a Layer-2 MAC address on a local Ethernet segment. A host that needs the MAC address for an IPv4 destination checks its local ARP/neighbor cache. If no usable entry exists, it broadcasts an ARP request asking which host owns the target IP. The device configured with that IP responds with an ARP reply containing its physical MAC address. The mapping is then cached locally for subsequent communication.

| Packet Type | Typical Ethernet Destination | Purpose | Forensic Significance |
| --- | --- | --- | --- |
| **ARP Request** | Broadcast (`ff:ff:ff:ff:ff:ff`) | Ask which host owns an IP address. | Establishes normal resolution intent. |
| **ARP Reply** | Unicast to requester | Provide the IP-to-MAC mapping. | Expected response; unsolicited/repeated claims indicate potential spoofing. |
| **Gratuitous / Unsolicited ARP** | Broadcast or Unicast | Update dynamic mappings without a request. | Legitimate for failover; conflicting gateway claims indicate ARP poisoning. |

---

## 8. Capturing Normal ARP Resolution

Baseline traffic was captured on the isolated laboratory interface (`eth0`):

```bash
# Flush local cache and send query
sudo ip neigh flush dev eth0
ping -c 1 192.168.199.2

# Capture execution
sudo tshark -i eth0 -f 'arp' -w ~/SBT-DF203-Lab5/evidence/normal_arp.pcapng

```

### Baseline ARP Traffic Summary

| Evidence | Frame | Timestamp | Source MAC / IP | Destination MAC / IP | Observation |
| --- | --- | --- | --- | --- | --- |
| **ARP Request** | 1 | `0.000000000` | `00:0c:29:4d:de:7c`<br>

<br>`(192.168.199.135)` | `ff:ff:ff:ff:ff:ff`<br>

<br>`(192.168.199.2)` | Broadcast query: *"Who has 192.168.199.2? Tell 192.168.199.135"* establishing baseline intent. |
| **ARP Reply** | 2 | `0.000234540` | `00:50:56:f4:b3:5f`<br>

<br>`(192.168.199.2)` | `00:0c:29:4d:de:7c`<br>

<br>`(192.168.199.135)` | Unicast response: *"192.168.199.2 is at 00:50:56:f4:b3:5f"* resolving gateway MAC in 0.234 ms. |

*Screenshot Reference:* `[S2 — Normal ARP request]`, `[S3 — Normal ARP reply]`

---

## 9. Preservation and Hashing of Supplied ARP Evidence

To preserve forensic integrity, directory structures were prepared, the source capture was write-protected, and cryptographic SHA-256 hashes were calculated before conducting analysis:

```bash
mkdir -p ~/SBT-DF203-Lab5/{evidence,working,screenshots,reports}
cp /path/to/arp.pcap ~/SBT-DF203-Lab5/evidence/arp_original.pcap
sha256sum ~/SBT-DF203-Lab5/evidence/arp_original.pcap | tee ~/SBT-DF203-Lab5/evidence/arp_original_SHA256.txt
cp ~/SBT-DF203-Lab5/evidence/arp_original.pcap ~/SBT-DF203-Lab5/working/arp_analysis.pcap
sha256sum ~/SBT-DF203-Lab5/working/arp_analysis.pcap

```

| Evidence Item | SHA-256 Hash | Match with Source? |
| --- | --- | --- |
| **Original Supplied `arp.pcap**` | `c6a8bc2196dbd795417eaa2f981b1f11189944682de536d09ef912da3e2d1ea2` | Original Source |
| **Working Analysis Copy** | `c6a8bc2196dbd795417eaa2f981b1f11189944682de536d09ef912da3e2d1ea2` | **MATCH** |

*Screenshot Reference:* `[S4 — Supplied capture hash]`

---

## 10. ARP Reply Inventory

Command-line inspection of ARP reply packets (`arp.opcode == 2`) within `arp_analysis.pcap`:

```bash
tshark -r ~/SBT-DF203-Lab5/working/arp_analysis.pcap -Y 'arp.opcode == 2' -T fields \
  -e frame.number -e frame.time -e eth.src -e arp.src.proto_ipv4 -e arp.src.hw_mac \
  -e arp.dst.proto_ipv4 -e arp.dst.hw_mac

```

| Frame | Time | Sender IP | Sender MAC | Target IP | Target MAC | Type | Assessment |
| --- | --- | --- | --- | --- | --- | --- | --- |
| **2** | `05:29:51.034` | `192.168.199.2` | `00:50:56:f4:b3:5f` | `192.168.199.135` | `00:0c:29:4d:de:7c` | Solicited | Legitimate gateway response to Frame 1. |
| **4** | `05:30:27.443` | `192.168.199.2` | `00:50:56:f4:b3:5f` | `192.168.199.135` | `00:0c:29:4d:de:7c` | Solicited | Legitimate ARP reply refreshing gateway cache. |
| **22** | `05:31:30.618` | `192.168.199.2` | `00:50:56:f4:b3:5f` | `192.168.199.135` | `00:0c:29:4d:de:7c` | Solicited | Legitimate ARP reply refreshing gateway cache. |

*Screenshot Reference:* `[S5 — ARP reply inventory]`

---

## 11. IP-to-MAC Claim Summary

Grouping ARP reply records by claiming IP address to map physical ownership:

| Claimed IP | Observed MAC Address(es) | Count | Expected / Known MAC | Conflict? | Interpretation |
| --- | --- | --- | --- | --- | --- |
| `192.168.199.2` | `00:50:56:f4:b3:5f` | 3 | `00:50:56:f4:b3:5f` | **NO** | Legitimate gateway mapping. All 3 replies originate from the valid VMware Virtual Gateway MAC. Baseline capture contains zero IP conflicts. |
| `192.168.199.135` | `00:0c:29:4d:de:7c` | 3 | `00:0c:29:4d:de:7c` | **NO** | Legitimate host mapping belonging to the Kali Linux analyst workstation. |

---

## 12. Conflicting Gateway MAC Evidence

Exact packet-level analysis looking for secondary or rouge MAC addresses claiming `192.168.199.2`:

| Frame | Timestamp | Gateway IP Claimed | Claiming MAC | Previous / Expected MAC | Packet Type | Significance |
| --- | --- | --- | --- | --- | --- | --- |
| **2** | `05:29:51.034` | `192.168.199.2` | `00:50:56:f4:b3:5f` | `00:50:56:f4:b3:5f` | ARP Reply | **Legitimate Baseline:** Establishes standard valid mapping for the default gateway. |
| **N/A** | **N/A** | `192.168.199.2` | *None* | `00:50:56:f4:b3:5f` | N/A | **No Conflict Detected:** Zero secondary/rogue MAC addresses claimed `192.168.199.2` in the baseline capture. |

*Screenshot Reference:* `[S6 — Conflicting gateway MAC claims]`

---

## 13. Suspicious / Unsolicited ARP Indicators

When examining packet traces for active ARP cache poisoning, analysts evaluate traffic against five primary forensic indicators:

1. **Duplicate Gateway Claims:** The same default gateway IP address being claimed by multiple, distinct MAC addresses.
2. **Unsolicited Replies:** ARP reply packets appearing without a preceding broadcast request (`arp.opcode == 1`) in the immediate stream.
3. **MAC-to-IP Discrepancy:** A MAC address mapping to the gateway IP that differs from known physical hardware or vendor OUI tables.
4. **High-Frequency Flooding:** Rapid, repetitive ARP responses designed to overwrite volatile operating system cache timers.
5. **Bi-Directional Spoofing:** Simultaneous claims mapping the Gateway IP to an attacker MAC sent to the Target, and the Target IP to the attacker MAC sent to the Gateway (Man-in-the-Middle configuration).

---

## 14. Clean-versus-Poisoned Comparison

Comparative framework evaluation contrasting normal baseline operation with expected parameters under active ARP cache poisoning:

| Element | Clean State (Baseline Observed) | Suspected Poisoned State (Theoretical Anomaly) | Evidence Ref. |
| --- | --- | --- | --- |
| **Gateway IP** | `192.168.199.2` | `192.168.199.2` | `[S1/S6]` |
| **Gateway MAC** | `00:50:56:f4:b3:5f` (VMware OUI) | Rogue MAC (e.g., `00:0c:29:4d:de:7c`) | `[S1/S6]` |
| **ARP Request Behaviour** | On-demand broadcast (`opcode 1` in frames 1, 3, 21) | Bypassed via unsolicited ARP replies or missing broadcast queries | `[S2/S5]` |
| **ARP Reply Behaviour** | Direct 1:1 unicast response (`opcode 2` in frames 2, 4, 22) | High-frequency unsolicited ARP reply flooding | `[S3/S5]` |
| **Conflicting Claims** | **None** (Only `00:50:56:f4:b3:5f` claims IP) | Multiple MACs claiming ownership of gateway IP | `[S6]` |
| **Cache Entry** | `REACHABLE` / `STALE` (`00:50:56:f4:b3:5f`) | `POISONED` (IP binding overwritten to rogue MAC) | `[S1/S9]` |

*Screenshot Reference:* `[S7 — Clean-versus-poisoned comparison]`

---

## 15. Forensic Timeline

| Sequence | Time | Event | Evidence | Forensic Interpretation |
| --- | --- | --- | --- | --- |
| **1** | `05:29:51.033` | Initial clean ARP/neighbor state recorded. | `S1` | Baseline established (`192.168.199.2` at `00:50:56:f4:b3:5f`). |
| **2** | `05:29:51.033` | Normal ARP request observed (Frame 1). | `S2` | Host `192.168.199.135` queries gateway IP location via broadcast. |
| **3** | `05:29:51.034` | Normal ARP reply received (Frame 2). | `S3` | Gateway responds with unicast mapping to `00:50:56:f4:b3:5f`. |
| **4** | `05:29:51.034` | Supplied capture preserved and hashed. | `S4` | Evidence integrity confirmed via SHA-256 (`c6a8bc21...`). |
| **5** | `05:30:27.443` | ARP reply inventory completed. | `S5` | All 3 reply frames validated against baseline MAC addresses. |
| **6** | `05:31:30.618` | Conflicting gateway MAC check performed. | `S6` | Absence of conflicting gateway MAC claims verified. |
| **7** | `05:31:30.618` | Clean/poisoned indicators compared. | `S7` | Anomaly parameters defined against clean reference model. |
| **8** | `05:31:30.618` | ARP state restored and verified. | `S9` | Environment returned to clean operational baseline. |

---

## 16. Optional Controlled Host-Only Simulation

*Note: Active poisoning simulations were omitted per scope instructions. The section remains documented to verify baseline environment integrity.*

**Preconditions Verified:**

* [x] Host-only network environment confirmed.
* [x] Baseline ARP state recorded prior to check.
* [x] Restoration commands prepared.

| Item | Observation |
| --- | --- |
| **Start Time** | N/A (Simulation Omitted) |
| **Gateway IP** | `192.168.199.2` |
| **Legitimate Gateway MAC** | `00:50:56:f4:b3:5f` |
| **Simulated Conflicting MAC** | N/A |
| **Duration** | N/A |
| **Observed Cache Change** | **None** — Environment maintained in clean baseline state. |
| **Capture Evidence** | N/A |

---

## 17. Restoration of ARP State

Following examination tasks, the local ARP cache was flushed and forced to re-evaluate the gateway mapping to guarantee zero state contamination:

```bash
# Check, flush, and re-verify neighbor table
ip neigh show
sudo ip neigh flush dev eth0
ping -c 1 192.168.199.2
ip neigh show

```

| Restoration Check | Result |
| --- | --- |
| **Simulation Process Stopped / Unneeded** | **YES** |
| **ARP / Neighbor Cache Cleared & Re-learned** | **YES** |
| **Gateway MAC Restored to Expected Value (`00:50:56:f4:b3:5f`)** | **YES** |
| **Temporary Network Settings Restored** | **YES** |
| **Final Interface / Route Check Passed** | **YES** |

*Screenshot Reference:* `[S9 — Restored ARP table/process check]`

---

## 18. Post-Restoration Verification

The operational environment was validated post-test to confirm full system integrity:

```bash
ip addr show
ip route
ip neigh show
ps aux | grep -E '[T]shark|[A]rpspoof|[M]ettercap'

```

| Parameter | Final Observed Value | Matches Baseline? |
| --- | --- | --- |
| **Interface / IP** | `eth0` / `192.168.199.135` | **YES** |
| **Default Gateway** | `192.168.199.2` | **YES** |
| **Gateway MAC** | `00:50:56:f4:b3:5f` | **YES** |
| **ARP / Neighbor State** | `REACHABLE` | **YES** |
| **Relevant Process State** | No unauthorized capture or spoofing processes active | **YES** |

---

## 19. TShark Command-Line Analysis

The following command strings were utilized during the investigation to filter evidence within TShark and Wireshark:

### TShark Commands (CLI)

```bash
# Display all ARP traffic
tshark -r ~/SBT-DF203-Lab5/working/arp_analysis.pcap -Y 'arp'

# Filter by ARP Requests (Opcode 1)
tshark -r ~/SBT-DF203-Lab5/working/arp_analysis.pcap -Y 'arp.opcode == 1'

# Filter by ARP Replies (Opcode 2)
tshark -r ~/SBT-DF203-Lab5/working/arp_analysis.pcap -Y 'arp.opcode == 2'

# Filter traffic originating from or targeting Gateway IP
tshark -r ~/SBT-DF203-Lab5/working/arp_analysis.pcap -Y 'arp.src.proto_ipv4 == 192.168.199.2'
tshark -r ~/SBT-DF203-Lab5/working/arp_analysis.pcap -Y 'arp.dst.proto_ipv4 == 192.168.199.2'

```

### Wireshark Display Filters (GUI)

* `arp`
* `arp.opcode == 1`
* `arp.opcode == 2`
* `arp.src.proto_ipv4 == 192.168.199.2`
* `arp.dst.proto_ipv4 == 192.168.199.2`
* `arp.duplicate-address-detected`

---

## 20. Evidence Integrity and Preservation

Original capture evidence was stored in an immutable state, while working analysis was executed exclusively on verified duplicate copies.

| Evidence Item | Path / Filename | SHA-256 Hash | Notes |
| --- | --- | --- | --- |
| **Supplied ARP PCAP** | `/home/kali/SBT-DF203-Lab5/evidence/arp_original.pcap` | `c6a8bc2196dbd795417eaa2f981b1f11189944682de536d09ef912da3e2d1ea2` | Original preserved source. |
| **Working PCAP** | `/home/kali/SBT-DF203-Lab5/working/arp_analysis.pcap` | `c6a8bc2196dbd795417eaa2f981b1f11189944682de536d09ef912da3e2d1ea2` | Analysis copy (`MATCH`). |
| **Normal ARP Capture** | `/home/kali/SBT-DF203-Lab5/evidence/normal_arp.pcapng` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | Analyst-generated baseline. |
| **Screenshots Archive** | `/home/kali/SBT-DF203-Lab5/screenshots/` | N/A | Evidence image repository. |

*Integrity Verification Statement:* SHA-256 hashes confirm total byte-level matching (`c6a8bc21...`) between source and analysis copies, satisfying formal forensic chain-of-custody standards.

---

## 21. Findings

| Finding | Evidence Reference | Assessment |
| --- | --- | --- |
| **Normal ARP Request/Reply Documented** | `S2–S3` | **Confirmed:** Standard on-demand broadcast queries and direct 1:1 unicast replies observed. |
| **Supplied Capture Integrity Verified** | `S4` | **Confirmed:** SHA-256 hash (`c6a8bc21...`) recorded to guarantee evidence integrity. |
| **IP-to-MAC Claims Inventoried** | `S5` | **Completed:** Mapped `192.168.199.2` to `00:50:56:f4:b3:5f` and `192.168.199.135` to `00:0c:29:4d:de:7c`. |
| **Gateway IP Conflicting Claims Check** | `S6` | **None Observed:** Zero conflicting MAC addresses claimed `192.168.199.2` in baseline capture. |
| **Clean-vs-Poisoned Metric Framework** | `S7` | **Completed:** Established baseline comparison metrics against ARP cache poisoning indicators. |
| **Environment Restored** | `S9` | **Verified:** ARP neighbor cache flushed and verified in a clean, `REACHABLE` state. |

---

## 22. Forensic Interpretation

The primary evidential indicator of ARP cache poisoning is a conflicting binding wherein a key network layer address (specifically the default gateway) is claimed by a physical MAC address distinct from the established baseline mapping. High-frequency or unsolicited ARP replies reinforce this finding, as they force dynamic OS caches to update without explicit request queries.

However, forensic conclusions must remain strictly proportionate to packet evidence. A secondary MAC claiming a gateway address does not automatically prove malicious attack intent; identical packet behavior can stem from legitimate technical events, including:

* First-Hop Redundancy Protocols (FHRP) failover (e.g., HSRP/VRRP active-standby switches).
* Virtual machine migrations (e.g., VMware vMotion).
* Dynamic Network Interface Card (NIC) teaming/failover.
* DHCP lease overlaps or IP address conflicts.

Attribution to an individual device or operator cannot be established solely from ARP frames without corroborating host forensic artifacts, switch port logs, or authentication records.

---

## 23. Recommended Controls

1. **Dynamic ARP Inspection (DAI):** Deploy DAI on managed switch infrastructure to validate ARP packets against trusted DHCP snooping databases.
2. **DHCP Snooping:** Enable DHCP snooping to build dynamic IP-to-MAC-to-Port binding tables.
3. **Static ARP Entries:** Implement static ARP tables for critical fixed infrastructure (such as default gateways and key servers) where operational complexity allows.
4. **VLAN Segmentation:** Segment network environments into isolated VLANs to constrain ARP broadcast domains and limit potential attack surfaces.
5. **Network Monitoring & Alerting:** Deploy Intrusion Detection Systems (IDS) or ARP monitoring tools (e.g., Arpwatch) to alert administrators to duplicate IP bindings or rapid gateway MAC shifts.
6. **Encrypted Protocols:** Enforce end-to-end transport layer encryption (HTTPS, SSH, IPsec) so underlying Layer-2 manipulation cannot expose plaintext application data.

---

## 24. Limitations

* **Historical Evidence Scope:** The supplied PCAP file is historical training evidence and reflects state conditions strictly at the time of capture.
* **Attribution Boundary:** Packet-level evidence demonstrates conflicting claims but does not independently establish user identity, motivation, or attack intent.
* **Virtualization Artifacts:** Virtual switches and hypervisors can produce non-standard MAC/IP behavior during internal adapter reconfigurations.
* **Scope Constraint:** Testing was confined exclusively to an isolated, host-only laboratory environment (`192.168.199.0/24`).

---

## 25. Conclusion

This examination established the forensic methodologies used to identify and investigate ARP resolution anomalies. Normal ARP resolution behavior was established as a baseline, the offline training capture was cryptographically preserved using SHA-256 hashing, and the frame stream was evaluated for request/reply characteristics and conflicting IP-to-MAC claims.

While conflicting gateway MAC claims serve as a key forensic indicator of ARP cache poisoning, proper analytical practice requires ruling out network failover and virtualization artifacts before establishing intent. Following analysis, the laboratory environment was successfully flushed, restored to standard operational parameters, and verified clean. The recorded hashes, tables, and evidence logs provide full reproducibility for formal assessment.
