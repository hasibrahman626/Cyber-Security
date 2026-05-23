# Labtainers Snort Lab — Assignment Report

**Student:** Hasib Rahman
**Email:** a57540@alunos.ipb.pt
**Lab:** Snort – Intrusion Detection (NPS Labtainers)
**Due:** 27 May 2026
**Framework:** Labtainers (Naval Postgraduate School)

---

## 1. Overview

This lab introduces the use of the **Snort IDS** within a Linux environment running inside the Labtainers framework. The objective was to:

- Configure custom Snort rules in `/etc/snort/rules/local.rules`
- Observe how port mirroring (via `iptables -t mangle ... TEE`) feeds traffic to the Snort sensor
- Understand how NAT and encryption (HTTPS/TLS) affect IDS visibility
- Differentiate between internal and external traffic in Snort rule logic
- Validate the configuration with `checkwork`

---

## 2. Network Topology

| Component | Address | Role |
|---|---|---|
| Gateway (WAN) | `203.0.113.10` | External NAT interface |
| Gateway (LAN1) | `192.168.1.10` | Internal — webserver side |
| Gateway (LAN2) | `192.168.2.10` | Internal — Mary's workstation side |
| Webserver | `192.168.1.2` | Apache + SSL (`www.example.com`) |
| Snort sensor | `192.168.3.1` | Receives mirrored traffic via TEE |
| Remote workstation (Hank) | `203.0.113.x` | External client |
| Internal workstation (Mary / ws2) | `192.168.2.x` | Internal client |

Mirroring is performed on the gateway with:

```bash
iptables -t mangle -A PREROUTING -i $wan  -j TEE --gateway 192.168.3.1
iptables -t mangle -A PREROUTING -i $lan1 -j TEE --gateway 192.168.3.1
iptables -t mangle -A PREROUTING -i $lan2 -j TEE --gateway 192.168.3.1
```

> Note: In this build of the lab, the `$lan2` mirroring line was already present in `/etc/rc.local` from the start, so Mary's traffic was mirrored to Snort without requiring manual addition.

---

## 3. Steps Performed

### 3.1 Starting the Lab

On the host:

```bash
cd ~/labtainer/labtainer-student
labtainer snort
```

This opened terminals for: **snort**, **gateway**, **webserver**, **remote_ws**, **ws2**.

### 3.2 Reviewing Gateway Configuration

On the gateway terminal:

```bash
cat /etc/rc.local
```

Confirmed presence of:
- NAT rules (`MASQUERADE` on WAN; DNAT for ports 80/443/22/4444 to webserver `192.168.1.2`)
- Three TEE mirroring rules (WAN, LAN1, LAN2 → `192.168.3.1`)

### 3.3 Starting Snort (Section 4.1)

On the snort terminal:

```bash
cd ~
./start_snort.sh
```

Snort initialized successfully and began packet processing.

### 3.4 Pre-Configured Rules Test (Section 4.2)

On `remote_ws`:

```bash
sudo nmap www.example.com
```

Result on Snort console: `ICMP PING NMAP` and other scan-related alerts fired from pre-installed rule files in `/etc/snort/rules/`. ✅

### 3.5 The "Bad Rule" Demonstration (Section 4.3)

Stopped Snort (`Ctrl+C`) and edited `/etc/snort/rules/local.rules`:

```snort
alert tcp any any -> any any (msg:"TCP detected"; sid:00002;)
```

Restarted Snort and browsed `www.example.com` from Firefox on remote_ws. The Snort console was flooded with `TCP detected` alerts, illustrating why overly-broad rules are unusable. The rule was then removed.

### 3.6 CONFIDENTIAL Content Rule (Section 4.4)

Viewed `http://www.example.com/plan.html` from remote_ws Firefox (page contains the word **CONFIDENTIAL**).

Added to `local.rules`:

```snort
alert tcp any any -> any any (content:"CONFIDENTIAL"; msg:"CONFIDENTIAL data detected"; sid:1000010; rev:1;)
```

After clearing the Firefox cache and reloading the page, the Snort console fired the `CONFIDENTIAL data detected` alert. ✅

### 3.7 HTTPS / Encryption Test (Section 4.5)

Cleared Firefox cache, then navigated to:

```
https://www.example.com/plan.html
```

After bypassing the self-signed certificate warning (Advanced → Accept the Risk and Continue), the page loaded but **no CONFIDENTIAL alert** fired on the Snort console.

**Explanation:** TLS encrypts the HTTP payload, so Snort sees only ciphertext on the wire. The string `CONFIDENTIAL` is never present in plaintext, so the `content:` match cannot trigger. Detecting payload content in encrypted streams would require TLS termination upstream of the IDS (e.g., a reverse proxy).

### 3.8 Watching Internal Traffic (Section 4.6)

On ws2 (Mary):

```bash
sudo nmap www.example.com
```

Because `$lan2` mirroring was already configured, the `ICMP PING NMAP` alert fired on Snort for Mary's scan as well. ✅

### 3.9 Distinguishing Traffic by Address (Section 4.7)

Updated `local.rules` so the CONFIDENTIAL alert only fires when the plan is sent to a destination **outside** Mary's internal network:

```snort
alert tcp any any -> !192.168.2.0/24 any (content:"CONFIDENTIAL"; msg:"CONFIDENTIAL data sent externally"; sid:1000010; rev:1;)
```

**Reasoning:**
- Webserver → external client: destination is `192.168.1.10` (gateway SNAT), **not** in `192.168.2.0/24` → alert fires ✅
- Webserver → Mary: destination is `192.168.2.x`, **in** `192.168.2.0/24` → no alert ✅
- Pre-configured ICMP PING NMAP rule still fires for both networks since LAN2 mirroring is active ✅

### 3.10 Testing All Three Criteria in One Snort Session

| # | Action | Expected | Observed |
|---|---|---|---|
| 1 | Remote loads `http://www.example.com/plan.html` | CONFIDENTIAL alert | ✅ Fired |
| 2 | Mary (ws2) loads `http://www.example.com/plan.html` | No CONFIDENTIAL alert | ✅ Silent |
| 3 | Remote `sudo nmap www.example.com` | ICMP PING NMAP | ✅ Fired |
| 4 | Mary (ws2) `sudo nmap www.example.com` | ICMP PING NMAP | ✅ Fired |

---

## 4. Verification with `checkwork`

### 4.1 First `checkwork` Run

```
Labname snort
Student: a57540_at_alunos.ipb.pt
N - snort_local_conf
Y - snort_remote_conf
Y - snort_remote_fire
N - snort_local_fire
N - proper_config
Y - snort_local_nmap
```

**Analysis of failures:**

- `snort_local_fire` failed → the webserver had no log entry showing ws2 accessing `plan.html` during a Snort session. Most likely Firefox served the page from cache, so no real HTTP request reached Apache.
- `snort_local_conf` failed as a consequence — without a real request, the "no alert on local access" condition could not be verified.
- `proper_config` failed because the required sequence (remote alert + no local alert + local nmap alert + both accesses logged) was not all observed within a single Snort session.

### 4.2 Fix Strategy

To bypass Firefox caching entirely, use `curl` on both workstations so that every access is guaranteed to reach Apache and be logged:

```bash
# On snort:
./start_snort.sh

# On remote_ws:
curl http://www.example.com/plan.html

# On ws2:
curl http://www.example.com/plan.html
sudo nmap www.example.com

# On snort: Ctrl+C
# On host:
checkwork
```

This sequence ensures:
1. Both accesses produce real HTTP requests → webserver log entries are created.
2. CONFIDENTIAL alert fires only for the remote access.
3. ICMP PING NMAP fires for the internal scan.
4. All events occur within a single Snort session → `proper_config` passes.

---

## 5. Final `local.rules` Contents

```snort
alert tcp any any -> !192.168.2.0/24 any (content:"CONFIDENTIAL"; msg:"CONFIDENTIAL data sent externally"; sid:1000010; rev:1;)
```

---

## 6. Submission Procedure

On the host machine:

```bash
stoplab snort
```

This generates the results file at:

```
/home/student/labtainer_xfer/snort/a57540_at_alunos.ipb.pt.snort.lab
```

This `.lab` file is then uploaded to the IPB virtual platform via the assignment's **Choose File** button and submitted.

---

## 7. Key Concepts Demonstrated

- **Snort rule syntax:** protocol, source/dest addresses with negation (`!`), content matching, SID/rev fields.
- **Traffic mirroring with iptables TEE:** required for an IDS to observe traffic it doesn't physically route through.
- **NAT effects on IDS visibility:** source/destination addresses seen by the sensor depend on where mirroring occurs relative to NAT translation.
- **Encryption defeats content-based IDS:** TLS-encrypted payloads cannot be inspected without termination upstream of the sensor.
- **Selective alerting:** address-based qualification (`!192.168.2.0/24`) lets the same content rule behave differently for internal vs. external traffic.

---

## 8. Status

| Item | Status |
|---|---|
| Sections 4.1 – 4.6 | ✅ Completed |
| Section 4.7 rule written | ✅ Completed |
| Initial `checkwork` | ⚠️ 3 of 6 goals failed (caching issue) |
| Fix planned via `curl`-based retest | 🔄 Ready to execute |
| Final submission | ⏳ Pending successful `checkwork` |

---

