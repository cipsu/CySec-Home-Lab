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
| Domain Controller | Windows Server 2022 — 192.168.56.105 (lab.local) |
| SIEM | Splunk Enterprise — http://localhost:8000 |
| Network | Host-Only (Kali + pfSense WAN + DC) / Internal Network (pfSense LAN + Metasploitable) |

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
| 08 | [SSH Brute Force Attack & Detection](exercises/04-soc-analysis/08-ssh-brute-force.md) | SOC Analysis / Attack Detection | Hydra, Splunk, pfSense |
| 09 | [Port Scan Detection via Splunk SIEM](exercises/01-reconnaissance/09-port-scan-detection.md) | Reconnaissance / SOC Detection | Nmap, Splunk, pfSense |
| 10 | [SQL Injection Attack (DVWA)](exercises/05-web-attacks/10-dvwa-sql-injection.md) | Web Attacks | DVWA, Firefox, MySQL |
| 11 | [Cross-Site Scripting XSS (DVWA)](exercises/05-web-attacks/11-dvwa-xss.md) | Web Attacks | DVWA, Firefox |
| 12 | [Offline Password Cracking with Hashcat](exercises/02-exploitation/12-password-cracking-hashcat.md) | Exploitation / Credential Access | Hashcat, Metasploit |
| 13 | [Hydra Brute Force: Web Form & SSH](exercises/04-soc-analysis/13-hydra-brute-force-web-ssh.md) | SOC Analysis / Attack Detection | Hydra, OpenVPN |
| 14 | [Metasploit Post-Exploitation: Crontab Persistence](exercises/08-post-exploitation/14-crontab-persistence.md) | Post-Exploitation / Persistence | Metasploit, Netcat, pfSense |
| 15 | [Active Directory Enumeration & Kerberoasting](exercises/06-active-directory/15-active-directory-kerberoasting.md) | Active Directory / Credential Access | CrackMapExec, Impacket, Hashcat, BloodHound |
| 16 | [Web Reconnaissance: Nmap & Gobuster](exercises/01-reconnaissance/16-nmap-gobuster-web-recon.md) | Reconnaissance | Nmap, Gobuster |
| 17 | [Command Injection Attack (DVWA)](exercises/05-web-attacks/17-dvwa-command-injection.md) | Web Attacks | DVWA, Firefox |
| 18 | [File Upload Attack & PHP Webshell (DVWA)](exercises/05-web-attacks/18-dvwa-file-upload-webshell.md) | Web Attacks | DVWA, Firefox |
| 19 | [Nikto Web Vulnerability Scanner](exercises/01-reconnaissance/19-nikto-web-scanner.md) | Reconnaissance | Nikto |
| 20 | [Credential Reuse Attack](exercises/02-exploitation/20-credential-reuse-attack.md) | Exploitation / Credential Access | SSH |
| 21 | [Pass-the-Hash Attack](exercises/06-active-directory/21-pass-the-hash.md) | Active Directory / Lateral Movement | Impacket, CrackMapExec |
| 22 | [Wireshark Packet Analysis](exercises/01-reconnaissance/22-wireshark-packet-analysis.md) | Reconnaissance / SOC Analysis | Wireshark, Nmap, CrackMapExec |
| 23 | [Splunk Detection Engineering](exercises/04-soc-analysis/23-splunk-detection-engineering.md) | SOC Analysis / Detection Engineering | Splunk, Nmap, Hydra |

## 🎯 Learning Path

- [x] Home lab setup
- [x] Network reconnaissance
- [x] Service enumeration
- [x] Remote exploitation
- [x] Privilege escalation
- [x] Post-exploitation & persistence
- [x] pfSense firewall configuration
- [x] Splunk SIEM setup
- [x] Detection rule engineering
- [x] Brute force attacks & detection
- [x] Web application attacks (SQLi, XSS, Command Injection, File Upload)
- [x] Offline password cracking
- [x] Credential reuse attacks
- [x] Active Directory enumeration & Kerberoasting
- [x] Automated web vulnerability scanning
- [ ] Active Directory — Pass-the-Hash & lateral movement
- [ ] Active Directory — BloodHound attack path analysis
- [ ] Microsoft Sentinel SIEM setup & KQL detection queries
- [ ] Wireshark packet analysis
- [ ] Snort/Suricata IDS deployment
- [ ] Malware analysis & IOC extraction
- [ ] CTF writeups (TryHackMe)
- [ ] OSCP preparation

## 📜 Certifications
*In progress:*
- CompTIA Security+
- CompTIA Network+
- Google Cybersecurity Professional Certificate
- Microsoft Azure Fundamentals (AZ-900)
- AWS Cloud Practitioner
- CompTIA CySA+
- and more

## 🛠️ Tools Used
Nmap · Metasploit · enum4linux · Wireshark · Kali Linux · VirtualBox · Splunk · Microsoft Sentinel · pfSense · Hydra · DVWA · Firefox · MySQL · Hashcat · CrackMapExec · Impacket · BloodHound · nano · Gobuster · Nikto · SSH
