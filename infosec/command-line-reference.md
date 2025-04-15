# Command Line Reference Across Different Shells

| Operation | Linux/macOS (Bash/Zsh) | PowerShell | Command Prompt (CMD) | Git Bash (Windows) |
|-----------|------------------------|------------|----------------------|-------------------|
| **File System Navigation** |||||
| List directory contents | `ls` | `Get-ChildItem` or `dir` or `ls` | `dir` | `ls` |
| List with details | `ls -l` | `Get-ChildItem \| Format-Table` or `ls -l` | `dir /p` | `ls -l` |
| List hidden files | `ls -a` | `Get-ChildItem -Hidden` or `ls -Force` | `dir /a` | `ls -a` |
| Change directory | `cd path/to/dir` | `Set-Location path/to/dir` or `cd path/to/dir` | `cd path\to\dir` | `cd path/to/dir` |
| Go to parent directory | `cd ..` | `cd ..` | `cd ..` | `cd ..` |
| Go to home directory | `cd` or `cd ~` | `cd ~` | `cd %USERPROFILE%` | `cd ~` |
| Print working directory | `pwd` | `Get-Location` or `pwd` | `cd` | `pwd` |
| **File Operations** |||||
| Create new file | `touch filename` | `New-Item -Path filename -ItemType File` | `type nul > filename` | `touch filename` |
| Create directory | `mkdir dirname` | `New-Item -Path dirname -ItemType Directory` or `mkdir dirname` | `mkdir dirname` | `mkdir dirname` |
| Copy file | `cp source dest` | `Copy-Item source dest` or `cp source dest` | `copy source dest` | `cp source dest` |
| Move/rename file | `mv source dest` | `Move-Item source dest` or `mv source dest` | `move source dest` | `mv source dest` |
| Delete file | `rm filename` | `Remove-Item filename` or `rm filename` | `del filename` | `rm filename` |
| Delete directory | `rm -r dirname` | `Remove-Item dirname -Recurse` | `rmdir /s /q dirname` | `rm -r dirname` |
| View file content | `cat filename` | `Get-Content filename` or `cat filename` | `type filename` | `cat filename` |
| Edit text file | `nano filename` or `vim filename` | `notepad filename` | `notepad filename` | `nano filename` or `vi filename` |
| **System Information** |||||
| Current user | `whoami` | `$env:USERNAME` | `echo %USERNAME%` | `whoami` |
| System information | `uname -a` | `Get-ComputerInfo` | `systeminfo` | `uname -a` |
| Show processes | `ps` or `ps aux` | `Get-Process` | `tasklist` | `ps` |
| **Networking** |||||
| Check connectivity | `ping host` | `Test-Connection host` or `ping host` | `ping host` | `ping host` |
| Show IP address | `ip addr` or `ifconfig` | `Get-NetIPAddress` | `ipconfig` | `ipconfig` or `ip addr` |
| Download file | `wget url` or `curl -O url` | `Invoke-WebRequest -Uri url -OutFile file` | `curl url -o file` | `wget url` or `curl -O url` |
| **File Permissions** |||||
| Change permissions | `chmod permissions file` | `icacls file /grant user:permission` | `icacls file /grant user:permission` | `chmod permissions file` |
| Change owner | `chown user:group file` | `Set-Acl` | N/A | `chown user:group file` |
| **Process Management** |||||
| Run in background | `command &` | `Start-Process command` | `start command` | `command &` |
| Kill process | `kill PID` or `pkill name` | `Stop-Process -Id PID` or `Stop-Process -Name name` | `taskkill /PID PID` | `kill PID` |
| **Miscellaneous** |||||
| Clear screen | `clear` | `Clear-Host` or `cls` | `cls` | `clear` |
| Environment variables | `echo $VARIABLE` | `$env:VARIABLE` | `echo %VARIABLE%` | `echo $VARIABLE` |
| Command history | `history` | `Get-History` | `doskey /history` | `history` |
| Piping | `command1 \| command2` | `command1 \| command2` | `command1 \| command2` | `command1 \| command2` |
| Redirect output | `command > file` | `command > file` | `command > file` | `command > file` |
| Append output | `command >> file` | `command >> file` | `command >> file` | `command >> file` |
| **File Searching** |||||
| Find files by name | `find /path -name "pattern"` | `Get-ChildItem -Path /path -Filter "pattern" -Recurse` | `dir /s /b "pattern"` | `find /path -name "pattern"` |
| Find files containing text | `grep -r "text" /path` | `Get-ChildItem -Path /path -Recurse \| Select-String "text"` | `findstr /s /i "text" *.*` | `grep -r "text" /path` |
| Find recent files | `find /path -mtime -7` | `Get-ChildItem -Path /path -Recurse \| Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-7)}` | N/A | `find /path -mtime -7` |
| Find files by size | `find /path -size +10M` | `Get-ChildItem -Path /path -Recurse \| Where-Object {$_.Length -gt 10MB}` | N/A | `find /path -size +10M` |
| **Text Processing** |||||
| Search text in file | `grep "pattern" file` | `Select-String -Pattern "pattern" -Path file` | `findstr "pattern" file` | `grep "pattern" file` |
| Count lines in file | `wc -l file` | `(Get-Content file).Length` | `find /c /v "" file` | `wc -l file` |
| Replace text in file | `sed 's/old/new/g' file` | `(Get-Content file) -replace 'old','new' \| Set-Content file` | N/A | `sed 's/old/new/g' file` |
| Sort file content | `sort file` | `Get-Content file \| Sort-Object` | `sort file` | `sort file` |
| First 10 lines of file | `head -n 10 file` | `Get-Content file -TotalCount 10` | `type file \| find /v /n "" \| find " 1:" > " 10:"` | `head -n 10 file` |
| Last 10 lines of file | `tail -n 10 file` | `Get-Content file -Tail 10` | N/A | `tail -n 10 file` |
| **Disk Usage** |||||
| File/dir size | `du -sh path` | `Get-ChildItem path \| Measure-Object -Property Length -Sum` | `dir path` | `du -sh path` |
| Disk space usage | `df -h` | `Get-PSDrive` | `fsutil volume diskfree C:` | `df -h` |
| **Compression** |||||
| Create zip archive | `zip -r archive.zip dir/` | `Compress-Archive -Path dir -DestinationPath archive.zip` | N/A | `zip -r archive.zip dir/` |
| Extract zip archive | `unzip archive.zip` | `Expand-Archive -Path archive.zip -DestinationPath dir` | N/A | `unzip archive.zip` |
| Create tar archive | `tar -cvf archive.tar dir/` | N/A | N/A | `tar -cvf archive.tar dir/` |
| Extract tar archive | `tar -xvf archive.tar` | N/A | N/A | `tar -xvf archive.tar` |
| Create tar.gz archive | `tar -czvf archive.tar.gz dir/` | N/A | N/A | `tar -czvf archive.tar.gz dir/` |
| **User Management** |||||
| Add user | `useradd username` | `New-LocalUser -Name "username"` | `net user username password /add` | N/A |
| Delete user | `userdel username` | `Remove-LocalUser -Name "username"` | `net user username /delete` | N/A |
| Change password | `passwd username` | `Set-LocalUser -Name "username" -Password (ConvertTo-SecureString "password" -AsPlainText -Force)` | `net user username newpassword` | N/A |
| **Network Connections** |||||
| Show listening ports | `netstat -tuln` | `Get-NetTCPConnection -State Listen` | `netstat -an \| find "LISTENING"` | `netstat -tuln` |
| Trace route to host | `traceroute host` | `Test-NetConnection -TraceRoute host` | `tracert host` | `traceroute host` |
| Show DNS info | `dig domain` | `Resolve-DnsName domain` | `nslookup domain` | `dig domain` |
| **Process Control** |||||
| Process tree | `pstree` or `ps -ejH` | `Get-Process \| Format-Table -GroupBy Parent` | `tasklist /svc` | `ps -ejH` |
| Top processes by resource | `top` | `Get-Process \| Sort-Object -Property CPU -Descending` | `tasklist /v /fo list /fi "MEMUSAGE gt 1000"` | `top` |
| Background process status | `jobs` | `Get-Job` | N/A | `jobs` |
| Schedule a task | `crontab -e` | `New-ScheduledTask` | `schtasks /create` | `crontab -e` |
| **Shell Scripting** |||||
| Run shell script | `bash script.sh` | `.\script.ps1` | `script.bat` | `bash script.sh` |
| Make script executable | `chmod +x script.sh` | `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` | N/A | `chmod +x script.sh` |
| Define variable | `var="value"` | `$var = "value"` | `set var=value` | `var="value"` |
| Export variable | `export var="value"` | `$env:var = "value"` | `set var=value` | `export var="value"` |
| If statement | `if [ condition ]; then commands; fi` | `if ($condition) { commands }` | `if condition commands` | `if [ condition ]; then commands; fi` |
| Loop through items | `for i in items; do commands; done` | `foreach ($i in $items) { commands }` | `for %%i in (items) do commands` | `for i in items; do commands; done` |
| **Remote Access** |||||
| SSH to server | `ssh user@host` | `New-SSHSession -ComputerName host -Credential user` | N/A | `ssh user@host` |
| Secure copy file | `scp file user@host:/path` | `scp file user@host:/path` (if installed) | N/A | `scp file user@host:/path` |
| Remote shell command | `ssh user@host command` | `Invoke-Command -HostName host -ScriptBlock { command }` | N/A | `ssh user@host command` |
