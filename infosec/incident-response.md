# Security Incident Response Cheatsheet

| Phase | Actions | Tools/Commands | Documentation |
|-------|---------|----------------|--------------|
| **Preparation** ||||
| Asset inventory | Document critical systems | `nmap -sP 192.168.1.0/24` | Asset register |
| Baseline establishment | Record normal behavior | `top`, `netstat -tuln` | Baseline document |
| IRT contacts | Establish escalation paths | N/A | Contact sheet |
| Response kit | Prepare forensic tools | FTK, volatility, wireshark | Kit checklist |
| **Detection & Analysis** ||||
| Initial triage | Verify incident occurrence | `grep 'Failed password' /var/log/auth.log` | Incident ticket |
| Scope determination | Identify affected systems | `lsof -i`, `netstat -antp` | Scope document |
| Evidence collection | Capture volatile data | `memory_dump.sh`, `dd if=/dev/sda of=disk.img` | Evidence log |
| Timeline creation | Establish sequence of events | `log2timeline.py` | Timeline document |
| **Containment** ||||
| Short-term containment | Isolate affected systems | Network segregation, `iptables -A INPUT -s malicious_ip -j DROP` | Containment log |
| System backup | Create forensic copies | `dd`, FTK Imager | Backup verification |
| Long-term remediation | Patch vulnerabilities | `apt update && apt upgrade` | Patch log |
| **Eradication** ||||
| Malware removal | Eliminate persistence | `find / -name "suspicious_file"`, AV scan | Cleanup report |
| Vulnerability patching | Address security gaps | `yum update package`, `apt install security-patch` | Patch verification |
| System hardening | Strengthen security posture | `chmod 600 /etc/shadow`, `ufw enable` | Hardening checklist |
| **Recovery** ||||
| System restoration | Return to operation | Restore from backup, `service start` | Recovery log |
| Monitoring | Watch for repeat incidents | SIEM alerts, `tail -f /var/log/syslog` | Monitoring plan |
| Validation testing | Verify system integrity | Penetration test, `tripwire --check` | Test results |
| **Lessons Learned** ||||
| Documentation | Complete incident report | N/A | Final report |
| Process improvement | Update response procedures | N/A | Updated playbooks |
| Team debrief | Review response effectiveness | N/A | Debrief minutes |

## Key Evidence Collection Commands

| Data Type | Linux | Windows | macOS |
|-----------|-------|---------|-------|
| Running processes | `ps aux` | `tasklist /v` | `ps aux` |
| Network connections | `netstat -antup` | `netstat -ano` | `netstat -anv` |
| Open files | `lsof` | `handle.exe` | `lsof` |
| Users logged in | `who` | `query user` | `who` |
| Scheduled tasks | `crontab -l` | `schtasks /query` | `crontab -l` |
| Process tree | `pstree` | `tasklist /v /fi "username eq system"` | `pstree` |
| Loaded modules | `lsmod` | `driverquery` | `kextstat` |
