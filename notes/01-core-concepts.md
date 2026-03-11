# Security Concepts — Core Keywords

## Networking Fundamentals

**1. IP Address**
A unique numerical label assigned to every device on a network. Like a
home address but for computers. Your Kali is 192.168.56.102,
Metasploitable is 192.168.1.100.

**2. Port**
A numbered door on a device through which specific services communicate.
Port 21 = FTP, port 445 = SMB, port 22 = SSH. A device has 65,535 ports.

**3. TCP**
Transmission Control Protocol. The most common way data is sent across
networks. Establishes a connection before sending data, guarantees
delivery. Most exploits use TCP.

**4. Protocol**
A set of rules defining how computers communicate. FTP, SMB, HTTP, SSH
are all protocols — each has its own port and behaviour.

**5. Default Gateway**
The router a device sends traffic to when the destination is not on its
local network. pfSense (192.168.1.1) was added as Metasploitable's
default gateway so it knew how to send replies back to Kali.

---

## Reconnaissance

**6. Network Scan (Nmap)**
Mapping what devices exist on a network and what ports/services they are
running. Always the first step of any attack or security audit.

**7. Service Version Detection**
Identifying not just that a port is open but exactly what software is
running on it and which version. Version matters because specific
versions have known vulnerabilities.

**8. Enumeration**
After finding open ports, gathering detailed information about what is
running — usernames, shares, OS version, hostnames. enum4linux does
this for SMB/Samba.

---

## Vulnerabilities & Exploitation

**9. CVE**
Common Vulnerabilities and Exposures. A standardised ID for a known
vulnerability. CVE-2011-2523 is the vsftpd backdoor. Every real
vulnerability has one.

**10. Exploit**
Code that takes advantage of a vulnerability to make software behave in
an unintended way — usually to gain access.

**11. Payload**
What the exploit delivers after it succeeds. The exploit breaks in, the
payload is what runs once inside — usually a shell or a reverse
connection.

**12. Backdoor**
Hidden access intentionally built into software, either maliciously or
accidentally. The vsftpd backdoor was inserted by an attacker who
compromised the source code — typing a username ending in :) triggered it.

**13. SMB**
Server Message Block. A Windows file sharing protocol running on ports
139 and 445. Extremely common attack surface in corporate environments
— WannaCry used SMB.

**14. FTP**
File Transfer Protocol. Port 21. An old, unencrypted protocol for
transferring files. The vsftpd 2.3.4 backdoor was deliberately planted
in a compromised version of the FTP server software.

**15. Metasploit**
The most widely used exploitation framework. Contains thousands of
exploits, payloads, and auxiliary tools. Used in exercises 03, 04, 05.

**16. RHOSTS**
Remote Hosts. The target IP you set in Metasploit. Who you are attacking.

**17. LHOST**
Local Host. Your own IP set in Metasploit. Where the reverse shell calls
back to.

---

## Shells & Access

**18. Shell**
A command line interface giving you control over a system. When an
exploit gives you a shell on a remote machine, you can run commands on
it as if you were sitting at the keyboard.

**19. Bind Shell**
The compromised machine opens a port and waits for the attacker to
connect to it. Used by vsftpd exploit — Metasploitable opened port 6200
and Kali connected to it.

**20. Reverse Shell**
The compromised machine connects back to the attacker. Used by Samba
exploit — Metasploitable called back to Kali on port 4444. Harder to
block because the victim initiates the connection.

**21. Root / Privilege**
The highest level of access on a Linux system. uid=0 means root — you
can do anything. Most exploits aim for root.

**22. SUID**
Set User ID. A Linux file permission that runs a program as its owner
rather than the person running it. Nmap had SUID set as root on
Metasploitable — running it gave you root regardless of who you were
logged in as.

**23. Privilege Escalation**
Moving from a low-privilege account to a higher one, usually root.
Exercise 05 chain: daemon shell → SUID nmap → root.

---

## Linux System Files

**24. /etc/passwd**
A Linux file listing all user accounts on the system. Readable by
everyone — exposes usernames and account info but not passwords.

**25. /etc/shadow**
A Linux file containing hashed passwords for all accounts. Only readable
by root — getting this means you can attempt to crack the password
hashes offline.

---

## Defense & Detection

**26. Firewall**
A system that monitors and controls network traffic based on rules.
pfSense is your firewall — it decides what traffic passes between Kali
and Metasploitable.

**27. Firewall Rule**
A defined condition telling the firewall what to do with matching
traffic. Action (pass/block) + Protocol + Source + Destination + Port.
Rules are processed top to bottom, first match wins.

**28. Network Segmentation**
Dividing a network into separate zones with controlled access between
them. Your lab now has two segments — Kali on Host-Only, Metasploitable
on Internal Network — with pfSense controlling what crosses between them.

**29. Firewall Log**
A record of traffic handled by the firewall. Shows action, time, source,
destination, and which rule triggered. In a real SOC these logs feed
into a SIEM for alerting.

**30. SIEM**
Security Information and Event Management. A system that collects logs
from across the network (firewalls, endpoints, servers), correlates
them, and generates alerts. Splunk and Microsoft Sentinel are the two
most common platforms — and the closest simulation to actual SOC
analyst work.

| 18-23 | Shells & access | ✅ | ✅ |
| 24-25 | Linux files | ⬜ | ✅ |
| 26-30 | Defense & detection | ✅ | ✅ |
