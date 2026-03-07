# 🔐 CySec Home Lab

A hands-on cybersecurity home lab built to develop practical 
offensive and defensive security skills as part of a career 
transition into cybersecurity (SOC Analyst / Junior Security Analyst).

## 🖥️ Lab Environment

| Component | Details |
|---|---|
| Host Machine | Windows 11, 32GB RAM |
| Hypervisor | Oracle VirtualBox 7.2.6 |
| Attacker VM | Kali Linux 2025.4 — 192.168.56.102 |
| Victim VM | Windows 10 — 192.168.56.101 |
| Target VM | Metasploitable 2 — 192.168.56.103 |
| Network | Host-Only (fully isolated) |

## 📋 Exercises

| # | Title | Category | Tools |
|---|---|---|---|
| 01 | [Network Reconnaissance Scan](exercises/01-nmap-recon.md) | Recon | Nmap |
| 02 | [SMB Enumeration](exercises/02-smb-enumeration.md) | Enumeration | enum4linux |
| 03 | [vsftpd Backdoor Exploit](exercises/03-vsftpd-exploit.md) | Exploitation | Metasploit |
| 04 | [Samba Usermap Exploit](exercises/04-samba-exploit.md) | Exploitation | Metasploit |
| 05 | [distcc RCE + Privilege Escalation](exercises/05-distcc-privesc.md) | Exploitation / PrivEsc | Metasploit, nmap SUID |

## 🎯 Learning Path

- [x] Home lab setup
- [x] Network reconnaissance
- [x] Service enumeration
- [x] Remote exploitation
- [x] Privilege escalation
- [ ] pfSense firewall configuration
- [ ] Microsoft Sentinel SIEM setup
- [ ] Splunk SIEM setup
- [ ] Detection rule engineering
- [ ] CTF writeups

## 📜 Certifications
*In progress:*
- CompTIA Tech+
- CompTIA A+
- CompTIA Network+
- CompTIA Security+
- CompTIA CySA+
- Google Cybersecurity Professional Certificate
- Microsoft Azure Fundamentals (AZ-900)
- AWS Cloud Practitioner

## 🛠️ Tools Used
Nmap · Metasploit · enum4linux · Wireshark · Kali Linux · 
VirtualBox · Microsoft Sentinel *(coming soon)* · Splunk *(coming soon)*
