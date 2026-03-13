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
| Firewall VM | pfSense 2.7.2 — WAN 192.168.56.104 / LAN 192.168.1.1 |
| Target VM | Metasploitable 2 — 192.168.1.100 |
| SIEM | Splunk Enterprise — http://localhost:8000 |
| Network | Host-Only (Kali + pfSense WAN) / Internal Network (pfSense LAN + Metasploitable) |

## 📋 Exercises

| # | Title | Category | Tools |
|---|---|---|---|
| 01 | [Network Reconnaissance Scan](exercises/01-reconnaissance/01-nmap-recon.md) | Recon | Nmap |
| 02 | [SMB Enumeration](exercises/01-reconnaissance/02-smb-enumeration.md) | Enumeration | enum4linux |
| 03 | [vsftpd Backdoor Exploit](exercises/02-exploitation/03-vsftpd-backdoor.md) | Exploitation | Metasploit |
| 04 | [Samba Usermap Exploit](exercises/02-exploitation/04-samba-usermap.md) | Exploitation | Metasploit |
| 05 | [distcc RCE + Privilege Escalation](exercises/02-exploitation/05-distcc-privesc.md) | Exploitation / PrivEsc | Metasploit, nmap SUID |
| 06 | [pfSense Firewall Setup & Traffic Control](exercises/03-defense-and-detection/06-pfsense-firewall.md) | Defense / Detection | pfSense, Metasploit, Nmap |
| 07 | [Splunk SIEM Setup & Real-Time Detection](exercises/04-soc-analysis/07-splunk-siem-detection.md) | SOC Analysis / SIEM | Splunk, pfSense, Metasploit |

## 🎯 Learning Path

- [x] Home lab setup
- [x] Network reconnaissance
- [x] Service enumeration
- [x] Remote exploitation
- [x] Privilege escalation
- [x] pfSense firewall configuration
- [ ] Microsoft Sentinel SIEM setup
- [x] Splunk SIEM setup
- [ ] Detection rule engineering
- [ ] CTF writeups

## 📜 Certifications
*In progress:*
- CompTIA Security+
- CompTIA Network+
- CompTIA CySA+
- Google Cybersecurity Professional Certificate
- Microsoft Azure Fundamentals (AZ-900)
- AWS Cloud Practitioner

## 🛠️ Tools Used
Nmap · Metasploit · enum4linux · Wireshark · Kali Linux · 
VirtualBox · Microsoft Sentinel *(coming soon)* · Splunk *(coming soon)*
