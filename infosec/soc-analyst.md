# Entry-Level SOC Analyst Cheatsheet

## Security Monitoring Fundamentals

| Concept | Description | Examples |
|---------|-------------|----------|
| **Security Incident** | Any event that potentially threatens security | Malware infection, unauthorized access, data breach |
| **Alert Triage** | Process of evaluating and prioritizing alerts | Critical (1), High (2), Medium (3), Low (4) |
| **False Positive** | Alert that incorrectly indicates malicious activity | Legitimate admin activity flagged as suspicious |
| **False Negative** | Failure to detect actual malicious activity | Intrusion not generating alerts |
| **IOC (Indicator of Compromise)** | Evidence of potential security breach | Malicious IP, hash, domain, unusual behavior |
| **TTP (Tactics, Techniques, Procedures)** | Patterns of adversary behavior | MITRE ATT&CK framework behaviors |
| **SIEM (Security Information and Event Management)** | Centralized log collection and analysis platform | Splunk, ELK Stack, QRadar, LogRhythm |
| **Use Case** | Specific detection scenario with defined logic | Detect multiple failed logins across systems |
| **Playbook** | Step-by-step response procedure | Malware containment playbook |

## Log Analysis Fundamentals

| Log Type | Key Information | Important Fields |
|----------|-----------------|------------------|
| **Windows Event Logs** | Windows system and security events | EventID, Account Name, Process ID, Logon Type |
| **Authentication Logs** | Login attempts and session data | Username, Source IP, Timestamp, Success/Failure |
| **Firewall Logs** | Network traffic allowed/blocked | Source/Destination IP, Port, Action, Protocol |
| **Web Server Logs** | HTTP/HTTPS request details | Client IP, Request URL, Status Code, User-Agent |
| **DNS Logs** | Domain resolution requests | Query Name, Query Type, Response, Client IP |
| **Proxy Logs** | Web traffic details | URL, User, Category, Action, Bytes Transferred |
| **VPN Logs** | Remote access connections | Username, Source IP, Connection Duration, Bytes |
| **Email Logs** | Email transaction details | Sender, Recipient, Subject, Attachments, Headers |

## Critical Windows Event IDs

| Event ID | Description | Why It Matters |
|----------|-------------|----------------|
| 4624 | Successful logon | Establish access patterns & identify unusual logins |
| 4625 | Failed logon | May indicate brute force attempts |
| 4720 | User account created | Potential unauthorized account creation |
| 4722 | User account enabled | Account status changes |
| 4724 | Password reset attempt | Potential credential compromise |
| 4728/4732/4756 | User added to security group | Privilege escalation |
| 4776 | Successful/failed account authentication | Credential validation activity |
| 7045 | Service installed | Potential persistence mechanism |
| 4688 | Process creation | Command execution monitoring |
| 4698 | Scheduled task created | Potential persistence technique |
| 1102 | Audit log cleared | Potential evidence tampering |
| 4672 | Special privileges assigned to new logon | Admin or sensitive privilege assignment |

## Linux Logs to Monitor

| Log File | Content | Suspicious Signs |
|----------|---------|------------------|
| `/var/log/auth.log` or `/var/log/secure` | Authentication attempts | Multiple failed logins, unusual login times |
| `/var/log/syslog` | General system logs | Unexpected service restarts, errors |
| `/var/log/messages` | General system messages | System errors, hardware failures |
| `/var/log/apache2/access.log` | Web server access | Directory traversal, unusual user agents |
| `/var/log/apache2/error.log` | Web server errors | SQL injection attempts, execution errors |
| `/var/log/cron` | Scheduled task execution | Unauthorized cron jobs |
| `/var/log/lastlog` | Last login information | Login from unusual locations |
| `/var/log/wtmp` & `/var/log/btmp` | Login records & failed attempts | Multiple failed logins |
| `~/.bash_history` | Command history | Suspicious commands, data exfiltration |

## SIEM Query Examples (Splunk SPL)

| Use Case | Example Query | Purpose |
|----------|--------------|---------|
| Failed Logins | `index=windows EventCode=4625 \| stats count by src_ip, user` | Detect potential brute force |
| Suspicious PowerShell | `index=windows EventCode=4688 process="*powershell*" "-enc*" \| table Computer, user, process, CommandLine` | Find encoded PowerShell commands |
| Account Creation | `index=windows EventCode=4720 \| table _time, user, Account_Name` | Monitor user creation |
| Privilege Escalation | `index=windows (EventCode=4728 OR EventCode=4732 OR EventCode=4756) Group_Name="*admin*" \| table _time, user, Account_Name, Group_Name` | Detect admin group additions |
| Lateral Movement | `index=windows EventCode=4624 Logon_Type=3 \| stats count by dest, src, user` | Identify network logons |
| Suspicious DNS | `index=dns query_type=A \| stats count by query, answer \| where count < 5` | Find rare DNS queries |
| Persistence | `index=windows (EventCode=4698 OR EventCode=7045) \| table _time, Computer, user, Service_Name, Service_File_Name` | Detect scheduled tasks or services |
| C2 Traffic | `index=proxy method=POST \| stats sum(bytes_out) as outbound by url, src_ip \| where outbound > 1000000` | Find large data uploads |

## Common SOC Tools

| Tool Type | Examples | Use Cases |
|-----------|----------|-----------|
| **SIEM** | Splunk, ELK Stack, QRadar | Centralized log analysis, alert generation |
| **EDR** | CrowdStrike, SentinelOne, Microsoft Defender for Endpoint | Endpoint protection and response |
| **Network Monitoring** | Wireshark, Zeek, Suricata | Packet analysis, network IDS |
| **Threat Intelligence** | VirusTotal, OTX, MISP | IOC lookup, threat data correlation |
| **Sandbox** | Cuckoo, ANY.RUN, Hybrid Analysis | Malware analysis in isolated environment |
| **Vulnerability Scanner** | Nessus, OpenVAS, Qualys | Identify system vulnerabilities |
| **Case Management** | TheHive, RTIR, ServiceNow | Track and manage incidents |
| **Phishing Analysis** | PhishTool, URL2PNG, Email Header Analyzer | Analyze suspicious emails |

## Incident Response Steps

| Phase | Actions | Documentation |
|-------|---------|---------------|
| **1. Preparation** | Develop IR plans, implement security controls | IR policy, playbooks, contact lists |
| **2. Identification** | Detect and validate security incidents | Alert data, initial findings report |
| **3. Containment** | Isolate affected systems to prevent spread | Containment actions report |
| **4. Eradication** | Remove malware/compromise from systems | Cleanup procedures performed |
| **5. Recovery** | Restore systems to normal operation | Recovery validation checklist |
| **6. Lessons Learned** | Document findings and improve process | Post-incident report |

## Common Attack Vectors & Detection Methods

| Attack Type | Indicators | Detection Methods |
|-------------|------------|-------------------|
| **Phishing** | Suspicious emails, malicious links/attachments | Email filtering logs, user reports, URL analysis |
| **Malware** | Unusual processes, network connections, file modifications | AV/EDR alerts, file hash analysis, behavioral analysis |
| **Brute Force** | Multiple failed authentication attempts | Auth logs, threshold alerting, account lockouts |
| **Credential Stuffing** | Successful logins from various locations/devices | Auth logs, impossible travel detection |
| **Web Application Attacks** | SQL injection, XSS, path traversal in web logs | WAF logs, web server logs, error patterns |
| **Privilege Escalation** | Unexpected admin actions, permission changes | User permission auditing, process monitoring |
| **Data Exfiltration** | Large outbound transfers, unusual destinations | Proxy/firewall logs, DLP alerts, NetFlow analysis |
| **Living Off The Land** | Abuse of legitimate tools (PowerShell, WMI, etc.) | Command-line logging, script block logging, behavioral analysis |

## Network Traffic Analysis Basics

| Protocol | Port | Suspicious Indicators |
|----------|------|------------------------|
| **HTTP/HTTPS** | 80/443 | Unusual user-agents, base64 in URLs, unusual domains/paths |
| **DNS** | 53 | Domain generation algorithms, DNS tunneling, unusual TXT records |
| **SMB** | 445 | Unauthorized access attempts, unusual file operations |
| **RDP** | 3389 | Brute force attempts, unauthorized connections |
| **SSH** | 22 | Brute force attempts, connections from unusual locations |
| **FTP** | 21 | Anonymous access, unauthorized file transfers |
| **SMTP/POP3/IMAP** | 25, 110, 143 | Unusual volume, unauthorized relay attempts |
| **NetFlow Indicators** | N/A | Unusual data volume, beaconing, scan patterns |

## Malware Types & Characteristics

| Malware Type | Behavior | Common Indicators |
|--------------|----------|-------------------|
| **Virus** | Self-replicating, infects other files | Modified system files, integrity failures |
| **Worm** | Self-propagating across networks | Unusual network traffic, port scanning |
| **Trojan** | Disguised as legitimate software | Unexpected network connections, hidden processes |
| **Ransomware** | Encrypts data for ransom | File encryption, ransom notes, destruction of backups |
| **Rootkit** | Hides deep in system to avoid detection | Hidden processes, modified system calls |
| **Backdoor** | Provides persistent remote access | Unexpected listening ports, unusual connections |
| **Keylogger** | Records keystrokes | Unusual process access to input devices, suspicious files |
| **Fileless Malware** | Operates in memory without files | PowerShell/WMI activity, unusual registry changes |
| **Cryptominer** | Uses resources to mine cryptocurrency | High CPU usage, mining pool connections |

## Basic Threat Hunting Concepts

| Concept | Description | Example Implementation |
|---------|-------------|------------------------|
| **Threat Hunting Hypothesis** | Question-based approach to investigate potential compromise | "Are users running unsigned PowerShell scripts?" |
| **IOC Searching** | Hunting for known indicators | Search for known malicious hashes or domains |
| **TTP Hunting** | Hunting for attack techniques regardless of tools | Search for any evidence of credential dumping behavior |
| **Baselining** | Establishing normal to find abnormal | Document normal authentication patterns to spot anomalies |
| **Stacking** | Analyzing frequency distributions to find outliers | Stack process names to find rare processes |
| **Clustering** | Grouping similar events to spot anomalies | Cluster login times to find unusual access patterns |

## MITRE ATT&CK Framework Fundamentals

| Tactic | Description | Example Techniques |
|--------|-------------|-------------------|
| **Initial Access** | How attackers get in | Phishing, exploitation of public-facing application |
| **Execution** | Running malicious code | Command line interface, PowerShell, scripts |
| **Persistence** | Maintaining access | Registry Run keys, scheduled tasks, startup items |
| **Privilege Escalation** | Getting higher permissions | Access token manipulation, bypass UAC |
| **Defense Evasion** | Avoiding detection | File deletion, clearing logs, obfuscation |
| **Credential Access** | Stealing credentials | Credential dumping, keylogging, brute force |
| **Discovery** | Learning the environment | Network/account/system discovery |
| **Lateral Movement** | Moving through environment | Pass the hash, remote services |
| **Collection** | Gathering data of interest | Input capture, screen capture, data from local system |
| **Command and Control** | Communicating with victims | Encrypted communications, web protocols |
| **Exfiltration** | Stealing data | Data compressed, encrypted, transferred |
| **Impact** | Disrupting business/operations | Data encryption, system shutdown, defacement |

## Useful CLI Commands for Incident Response

| OS | Command | Purpose |
|----|---------|---------|
| **Windows** | `Get-Process \| Where-Object {$_.Company -eq $null}` | Find processes with no company name |
| | `Get-WinEvent -FilterHashtable @{Logname='Security';ID=4624} -MaxEvents 10` | View recent successful logons |
| | `netstat -ano \| findstr ESTABLISHED` | View established connections |
| | `schtasks /query /fo LIST /v` | List all scheduled tasks with details |
| | `wmic startup list full` | List all startup items |
| | `wmic process get caption,commandline,processid` | List running processes with command lines |
| **Linux** | `ps auxf` | Show process tree |
| | `netstat -tulpn` | Show active connections and listening ports |
| | `lsof -i` | List open files and network connections |
| | `grep -i "failed password" /var/log/auth.log` | Find failed login attempts |
| | `find / -mtime -1 -ls` | Find files modified in the last day |
| | `cat /var/log/auth.log \| grep -E 'session opened\|session closed'` | Find user sessions |

## Cyber Threat Intelligence Resources

| Resource Type | Examples | Use Cases |
|---------------|----------|-----------|
| **Open Source Feeds** | AlienVault OTX, MISP, ThreatFox | Collect IOCs, research campaigns |
| **Vendor Blogs** | Mandiant, CrowdStrike, Microsoft Security | Technical analysis of threats |
| **Government Resources** | US-CERT, MS-ISAC, CISA Advisories | Vulnerability and threat alerts |
| **Malware Databases** | VirusTotal, Hybrid Analysis, MalwareBazaar | File reputation, malware analysis |
| **IP/Domain Reputation** | AbuseIPDB, Cisco Talos, URLhaus | Check for known malicious addresses |
| **Sandbox Analysis** | ANY.RUN, Joe Sandbox, Cuckoo | Dynamic malware analysis |
