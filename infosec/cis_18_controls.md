# CIS 18 Controls Cheatsheet

## Overview

The CIS Controls are a prioritized set of safeguards to mitigate the most prevalent cyber-attacks against systems and networks. This cheatsheet provides a quick reference to the 18 CIS Controls (v8), implementation guidance, and mappings to major frameworks.

## CIS Controls Summary

| # | Control | Category | Purpose |
|---|---------|----------|---------|
| 1 | Inventory and Control of Enterprise Assets | Basic | Know what's on your network |
| 2 | Inventory and Control of Software Assets | Basic | Know what's running on your network |
| 3 | Data Protection | Basic | Protect sensitive information |
| 4 | Secure Configuration of Enterprise Assets and Software | Basic | Reduce the attack surface |
| 5 | Account Management | Basic | Manage access rights |
| 6 | Access Control Management | Basic | Limit user privileges |
| 7 | Continuous Vulnerability Management | Foundational | Find and fix vulnerabilities |
| 8 | Audit Log Management | Foundational | Collect and review logs |
| 9 | Email and Web Browser Protections | Foundational | Secure common attack vectors |
| 10 | Malware Defenses | Foundational | Block and detect malicious code |
| 11 | Data Recovery | Foundational | Plan for the worst |
| 12 | Network Infrastructure Management | Foundational | Secure network devices |
| 13 | Network Monitoring and Defense | Foundational | Detect and prevent attacks |
| 14 | Security Awareness and Skills Training | Foundational | Human firewall |
| 15 | Service Provider Management | Foundational | Secure your supply chain |
| 16 | Application Software Security | Foundational | Develop secure applications |
| 17 | Incident Response Management | Organizational | Prepare and practice |
| 18 | Penetration Testing | Organizational | Test your defenses |

## Detailed Controls with Implementation Guidance

### CIS Control 1: Inventory and Control of Enterprise Assets

| Safeguard | Description | Implementation |
|-----------|-------------|----------------|
| 1.1 | Establish Asset Inventory | Use automated tools (CMDB, network scanning, etc.) |
| 1.2 | Address Unauthorized Assets | Implement NAC or 802.1x port security |
| 1.3 | Utilize DHCP Logging | Configure DHCP servers to log lease information |
| 1.4 | Use Dynamic Host Configuration Protocol (DHCP) | Standardize IP assignment |
| 1.5 | Use a Passive Asset Discovery Tool | Deploy passive monitoring tools |

**Key Tools:**
- Network scanners (Nmap, Nessus)
- Asset management systems (ServiceNow, Lansweeper)
- NAC solutions (Cisco ISE, FortiNAC)
- CMDB systems

**Framework Mappings:**
- NIST CSF: ID.AM-1, ID.AM-2, ID.AM-5
- ISO 27001: A.8.1.1, A.8.1.2
- NIST 800-53: CM-8, PM-5
- GDPR: Article 30

### CIS Control 2: Inventory and Control of Software Assets

| Safeguard | Description | Implementation |
|-----------|-------------|----------------|
| 2.1 | Establish Software Inventory | Deploy software inventory tools |
| 2.2 | Ensure Authorized Software is Currently Supported | Track EOL/EOS dates |
| 2.3 | Address Unauthorized Software | Implement application whitelisting |
| 2.4 | Utilize Automated Software Inventory Tools | Use agent-based inventory tools |
| 2.5 | Allow Only Authorized Software | Implement application control |
| 2.6 | Allow Only Authorized Libraries | Control libraries and dependencies |
| 2.7 | Allow Only Authorized Scripts | Implement script control (PowerShell, etc.) |

**Key Tools:**
- Software inventory tools (Microsoft SCCM, Lansweeper)
- Application whitelisting (AppLocker, Carbon Black)
- Package managers with inventory capabilities
- Script control (PowerShell execution policies)

**Framework Mappings:**
- NIST CSF: ID.AM-2, PR.DS-6, PR.IP-1
- ISO 27001: A.12.6.2, A.8.1.1, A.8.1.2
- NIST 800-53: CM-7, CM-8, SA-4
- PCI DSS: 2.4, 6.2

### CIS Control 3: Data Protection

| Safeguard | Description | Implementation |
|-----------|-------------|----------------|
| 3.1 | Establish Data Management Process | Implement data classification |
| 3.2 | Establish Data Inventory | Document sensitive data locations |
| 3.3 | Configure Data Access Control Lists | Implement need-to-know permissions |
| 3.4 | Enforce Data Retention | Deploy automated policies |
| 3.5 | Securely Delete Data | Implement secure deletion tools |
| 3.6 | Encrypt Data on End-User Devices | Deploy full-disk encryption |
| 3.7 | Establish Data Classification | Define sensitivity levels |
| 3.8 | Document Data Flows | Map how data moves through systems |
| 3.9 | Encrypt Data in Transit | Implement TLS for communications |
| 3.10 | Encrypt Sensitive Data at Rest | Deploy database/storage encryption |
| 3.11 | Encrypt Sensitive Data in Use | Utilize privacy-preserving technologies |
| 3.12 | Segment Data Processing and Storage | Separate sensitive data environments |
| 3.13 | Deploy a Data Loss Prevention Solution | Implement DLP tools |
| 3.14 | Log Sensitive Data Access | Monitor access to classified data |

**Key Tools:**
- DLP solutions (Symantec, Digital Guardian)
- Encryption tools (BitLocker, VeraCrypt)
- Data classification tools (Microsoft AIP, Titus)
- Access monitoring tools

**Framework Mappings:**
- NIST CSF: PR.DS-1, PR.DS-2, PR.DS-5, PR.PT-2
- ISO 27001: A.8.2.1, A.8.2.2, A.8.2.3, A.10.1.1
- NIST 800-53: SC-8, SC-28, MP-2, MP-3, MP-4
- GDPR: Articles 5, 6, 25, 32
- PCI DSS: 3.1, 3.2, 3.4, 3.5, 3.6

### CIS Control 4: Secure Configuration of Enterprise Assets and Software

| Safeguard | Description | Implementation |
|-----------|-------------|----------------|
| 4.1 | Establish Secure Configuration Process | Document hardening standards |
| 4.2 | Establish Secure Configuration Management | Use secure baselines |
| 4.3 | Configure Automatic Session Locking | Set screen timeout policies |
| 4.4 | Implement Strong Authentication | Use MFA where possible |
| 4.5 | Implement Secure Boot | Enable secure boot on systems |
| 4.6 | Securely Manage Enterprise Assets | Use trusted software/images |
| 4.7 | Manage Default Accounts | Change defaults, disable when possible |
| 4.8 | Uninstall or Disable Unnecessary Services | Remove unneeded services |
| 4.9 | Configure Trusted DNS Servers | Use secure DNS providers |
| 4.10 | Enforce Secure Configuration | Monitor and enforce compliance |
| 4.11 | Apply Host-Based Firewalls | Deploy on all endpoints |
| 4.12 | Separate Management Network | Isolate management traffic |

**Key Tools:**
- Configuration management (Chef, Puppet, Ansible)
- Secure configuration scanners (CIS-CAT, Nessus)
- Group Policy/MDM solutions
- Baseline management tools

**Framework Mappings:**
- NIST CSF: PR.IP-1, PR.PT-3
- ISO 27001: A.12.1.2, A.14.2.2, A.14.2.3, A.14.2.4
- NIST 800-53: CM-2, CM-6, CM-7, IA-5
- PCI DSS: 2.2, 2.3, 2.6

### CIS Control 5: Account Management

| Safeguard | Description | Implementation |
|-----------|-------------|----------------|
| 5.1 | Establish Account Management Process | Document user lifecycle |
| 5.2 | Use Unique Passwords | Implement password policies |
| 5.3 | Disable Dormant Accounts | Auto-disable after inactivity |
| 5.4 | Restrict Administrator Privileges | Limit admin accounts |
| 5.5 | Establish Account Monitoring | Alert on suspicious activities |
| 5.6 | Centralize Account Management | Use directory services |
| 5.7 | Implement MFA for Privileged Users | Require strong auth for admins |
| 5.8 | Implement MFA for Remote Network Access | Secure VPN/external connections |
| 5.9 | Implement MFA for Internet-Accessible Services | Protect external services |

**Key Tools:**
- Identity Management (Active Directory, Okta)
- Privileged Access Management (CyberArk, BeyondTrust)
- MFA solutions (Duo, RSA)
- Account monitoring tools

**Framework Mappings:**
- NIST CSF: PR.AC-1, PR.AC-4, PR.AC-7
- ISO 27001: A.9.2.1, A.9.2.2, A.9.2.3, A.9.2.5, A.9.2.6
- NIST 800-53: AC-2, AC-3, AC-6, IA-2, IA-5
- PCI DSS: 7.1, 7.2, 8.1, 8.2, 8.3

### CIS Control 6: Access Control Management

| Safeguard | Description | Implementation |
|-----------|-------------|----------------|
| 6.1 | Establish Access Control Management Process | Define access request/approval process |
| 6.2 | Establish Access Revoking Process | Document termination procedures |
| 6.3 | Require MFA for Externally-Exposed Applications | Protect public-facing services |
| 6.4 | Require MFA for Remote Network Access | Secure remote connections |
| 6.5 | Require MFA for Administrative Access | Use strong auth for all privileged actions |
| 6.6 | Establish An Access Governance Process | Implement periodic reviews |
| 6.7 | Centralize Access Control | Use single access platform |
| 6.8 | Define Acceptable Use | Create policy for proper system use |
| 6.9 | Control Credential Disclosure | Protect secrets |

**Key Tools:**
- Role-based access control systems
- Identity Governance solutions (SailPoint, Saviynt)
- Access certification tools
- PAM solutions

**Framework Mappings:**
- NIST CSF: PR.AC-1, PR.AC-3, PR.AC-4
- ISO 27001: A.9.1.1, A.9.1.2, A.9.2.3, A.9.4.1
- NIST 800-53: AC-1, AC-2, AC-3, AC-5, AC-6, AC-17
- PCI DSS: 7.1, 7.2, 8.3

### CIS Control 7: Continuous Vulnerability Management

| Safeguard | Description | Implementation |
|-----------|-------------|----------------|
| 7.1 | Establish Vulnerability Management Process | Define scanning schedule |
| 7.2 | Establish a Remediation Process | Document patching procedures |
| 7.3 | Perform Automated Operating System Patch Management | Use patch management tools |
| 7.4 | Perform Automated Application Patch Management | Automate app updates |
| 7.5 | Perform Automated Vulnerability Scans | Schedule regular scans |
| 7.6 | Remediate Detected Vulnerabilities | Track and manage fixes |
| 7.7 | Utilize Industry-Recommended Vulnerability Sources | Subscribe to advisory feeds |

**Key Tools:**
- Vulnerability scanners (Nessus, Qualys, OpenVAS)
- Patch management (WSUS, SCCM, Ivanti)
- Vulnerability management platforms
- Threat intelligence feeds

**Framework Mappings:**
- NIST CSF: ID.RA-1, ID.RA-2, PR.IP-12
- ISO 27001: A.12.6.1, A.12.6.2, A.14.2.3
- NIST 800-53: RA-3, RA-5, SI-2
- PCI DSS: 6.1, 6.2, 11.2

### CIS Control 8: Audit Log Management

| Safeguard | Description | Implementation |
|-----------|-------------|----------------|
| 8.1 | Establish Audit Log Management | Define logging strategy |
| 8.2 | Collect Audit Logs | Configure logging for all assets |
| 8.3 | Ensure Adequate Audit Log Storage | Size storage appropriately |
| 8.4 | Standardize Time Synchronization | Implement NTP |
| 8.5 | Collect Detailed Audit Logs | Capture comprehensive events |
| 8.6 | Collect DNS Query Logs | Monitor DNS activity |
| 8.7 | Collect URL Request Logs | Track web browsing |
| 8.8 | Collect Command-Line Audit Logs | Monitor command execution |
| 8.9 | Centralize Audit Logs | Aggregate to SIEM |
| 8.10 | Retain Audit Logs | Define retention period |
| 8.11 | Conduct Audit Log Reviews | Regular log analysis |
| 8.12 | Collect Service Provider Logs | Include cloud services |

**Key Tools:**
- SIEM solutions (Splunk, ELK Stack, QRadar)
- Log aggregation tools (NXLog, Syslog-ng)
- NTP servers
- Log storage solutions

**Framework Mappings:**
- NIST CSF: PR.PT-1, DE.CM-1, DE.CM-3, DE.CM-7
- ISO 27001: A.12.4.1, A.12.4.2, A.12.4.3, A.12.4.4
- NIST 800-53: AU-2, AU-3, AU-6, AU-7, AU-8, AU-9, AU-11, AU-12
- PCI DSS: 10.1, 10.2, 10.3, 10.4, 10.5, 10.6, 10.7

### CIS Control 9: Email and Web Browser Protections

| Safeguard | Description | Implementation |
|-----------|-------------|----------------|
| 9.1 | Ensure Use of Only Fully Supported Browsers and Email Clients | Keep updated |
| 9.2 | Use DNS Filtering Services | Block malicious domains |
| 9.3 | Maintain Network-Based URL Filters | Implement web filtering |
| 9.4 | Restrict Unnecessary or Unauthorized Browser and Email Client Extensions | Control plugins |
| 9.5 | Implement DMARC | Enable email authentication |
| 9.6 | Block Unnecessary File Types | Filter risky attachments |
| 9.7 | Deploy and Maintain Email Server Anti-Malware Protections | Scan emails for threats |

**Key Tools:**
- Secure email gateways (Proofpoint, Mimecast)
- DNS filtering (Cisco Umbrella, Quad9)
- Web proxies (Zscaler, Blue Coat)
- Email authentication (DKIM, SPF, DMARC)

**Framework Mappings:**
- NIST CSF: PR.DS-6, PR.DS-7, DE.CM-5
- ISO 27001: A.13.1.1, A.13.1.2
- NIST 800-53: SC-7, SC-8
- PCI DSS: 1.3, 4.1, 5.1, 5.3

### CIS Control 10: Malware Defenses

| Safeguard | Description | Implementation |
|-----------|-------------|----------------|
| 10.1 | Deploy and Maintain Anti-Malware Software | Install on all endpoints |
| 10.2 | Configure Automatic Anti-Malware Signature Updates | Enable auto-updates |
| 10.3 | Disable Autorun and Autoplay for Removable Media | Prevent auto-execution |
| 10.4 | Configure Automatic Anti-Malware Scanning | Schedule regular scans |
| 10.5 | Enable Anti-Exploitation Features | Use OS security features |
| 10.6 | Centrally Manage Anti-Malware Software | Deploy management console |
| 10.7 | Use Behavior-Based Anti-Malware Software | Implement advanced protection |

**Key Tools:**
- Endpoint protection platforms (CrowdStrike, Symantec, Microsoft Defender)
- Application whitelisting
- Behavioral analysis tools
- Anti-exploitation (EMET, Windows Defender Exploit Guard)

**Framework Mappings:**
- NIST CSF: DE.CM-4, DE.CM-5, PR.DS-5
- ISO 27001: A.12.2.1
- NIST 800-53: SI-3, SI-4, SI-8
- PCI DSS: 5.1, 5.2, 5.3

### CIS Control 11: Data Recovery

| Safeguard | Description | Implementation |
|-----------|-------------|----------------|
| 11.1 | Establish Data Recovery Process | Document backup procedures |
| 11.2 | Perform Automated Backups | Schedule regular backups |
| 11.3 | Protect Recovery Data | Secure backup infrastructure |
| 11.4 | Establish Secure Recovery Process | Document restoration procedures |
| 11.5 | Test Data Recovery | Regular restore testing |

**Key Tools:**
- Backup solutions (Veeam, Veritas, Commvault)
- Cloud backup (AWS Backup, Azure Backup)
- Immutable storage
- Air-gapped backups

**Framework Mappings:**
- NIST CSF: PR.IP-4, RC.RP-1
- ISO 27001: A.12.3.1, A.17.1.2, A.17.1.3
- NIST 800-53: CP-9, CP-10
- PCI DSS: 9.5, 9.6, 9.7, 12.10.1

### CIS Control 12: Network Infrastructure Management

| Safeguard | Description | Implementation |
|-----------|-------------|----------------|
| 12.1 | Ensure Network Infrastructure is Up-to-Date | Patch networking devices |
| 12.2 | Establish Network Infrastructure Management Process | Document procedures |
| 12.3 | Securely Manage Network Infrastructure | Use secure protocols |
| 12.4 | Establish and Maintain Dedicated, Secure Management Network | Separate management plane |
| 12.5 | Centralize Network Authentication, Authorization, and Auditing | Implement AAA |
| 12.6 | Use Standard Secure Signaling and Transport Protocols | Secure communications |
| 12.7 | Ensure Remote Devices Utilize a VPN | Secure remote connections |
| 12.8 | Establish and Maintain Dedicated Computing Resources for Critical Networks | Segment sensitive functions |

**Key Tools:**
- Network management platforms (Cisco, Aruba, Juniper)
- AAA servers (RADIUS, TACACS+)
- Network configuration management
- VPN solutions

**Framework Mappings:**
- NIST CSF: PR.AC-5, PR.PT-4
- ISO 27001: A.13.1.1, A.13.1.3
- NIST 800-53: AC-17, AC-18, IA-3, SC-7, SC-8
- PCI DSS: 1.1, 1.2, 1.3, 2.2

### CIS Control 13: Network Monitoring and Defense

| Safeguard | Description | Implementation |
|-----------|-------------|----------------|
| 13.1 | Centralize Security Event Alerting | Implement SIEM |
| 13.2 | Deploy a Host-Based IDS or IPS | Install endpoint detection |
| 13.3 | Deploy a Network-Based IDS, IPS or NDR | Monitor network traffic |
| 13.4 | Perform Traffic Filtering | Deploy firewalls |
| 13.5 | Manage Access Control for Remote Assets | Control remote connections |
| 13.6 | Collect Network Traffic Flow Logs | Capture NetFlow |
| 13.7 | Deploy a Network-Based DLP | Monitor for data exfiltration |
| 13.8 | Deploy a Network-Based Sandbox | Analyze suspicious files |
| 13.9 | Deploy Port-Level Access Control | Implement 802.1X |
| 13.10 | Perform Application Layer Filtering | Use web application firewalls |
| 13.11 | Tune Security Event Alerting Thresholds | Reduce false positives |

**Key Tools:**
- Network IDS/IPS (Suricata, Snort, Cisco)
- SIEM solutions (Splunk, QRadar)
- NDR solutions (Darktrace, ExtraHop)
- NetFlow analyzers
- Next-gen firewalls

**Framework Mappings:**
- NIST CSF: DE.AE-1, DE.AE-2, DE.AE-3, DE.CM-1, DE.CM-7
- ISO 27001: A.12.4.1, A.13.1.1, A.13.1.2
- NIST 800-53: SI-4, AU-6
- PCI DSS: 10.6, 11.4, 11.5

### CIS Control 14: Security Awareness and Skills Training

| Safeguard | Description | Implementation |
|-----------|-------------|----------------|
| 14.1 | Establish Security Awareness Program | Document training strategy |
| 14.2 | Train Workforce Members | Implement regular training |
| 14.3 | Train Workforce on Authentication Best Practices | Password/MFA education |
| 14.4 | Train Workforce on Data Handling Best Practices | Sensitive data procedures |
| 14.5 | Train Workforce on Causes of Unintentional Data Exposure | Prevent mistakes |
| 14.6 | Train Workforce on Recognizing and Reporting Security Incidents | Incident reporting process |
| 14.7 | Train Workforce on How to Identify and Report Phishing Attacks | Phishing recognition |
| 14.8 | Train Workforce on Secure Use of Social Media | Social media risks |
| 14.9 | Train Workforce on Secure Use of Mobile Devices | Mobile security |

**Key Tools:**
- Security awareness platforms (KnowBe4, Proofpoint)
- Phishing simulation tools
- Learning management systems
- Training content providers

**Framework Mappings:**
- NIST CSF: PR.AT-1, PR.AT-2, PR.AT-5
- ISO 27001: A.7.2.2, A.7.2.3
- NIST 800-53: AT-1, AT-2, AT-3
- PCI DSS: 12.6, 12.6.1, 12.6.2

### CIS Control 15: Service Provider Management

| Safeguard | Description | Implementation |
|-----------|-------------|----------------|
| 15.1 | Establish Service Provider Management Process | Document vendor management |
| 15.2 | Establish Service Provider Requirements | Define security expectations |
| 15.3 | Monitor Service Provider Compliance | Regular reviews |
| 15.4 | Ensure Service Provider Contracts Include Security Requirements | Contract requirements |
| 15.5 | Assess Service Providers | Due diligence process |
| 15.6 | Monitor Service Provider Security | Ongoing validation |
| 15.7 | Securely Decommission Service Providers | Offboarding process |

**Key Tools:**
- Vendor risk management platforms
- Contract management systems
- Security questionnaires
- Continuous monitoring tools

**Framework Mappings:**
- NIST CSF: ID.SC-1, ID.SC-2, ID.SC-3, ID.SC-4, ID.SC-5
- ISO 27001: A.15.1.1, A.15.1.2, A.15.1.3, A.15.2.1, A.15.2.2
- NIST 800-53: SA-9, SA-12
- PCI DSS: 12.8, 12.8.1-5, 12.9

### CIS Control 16: Application Software Security

| Safeguard | Description | Implementation |
|-----------|-------------|----------------|
| 16.1 | Establish Application Security Program | Document SDLC security |
| 16.2 | Perform Application Classification | Assess application criticality |
| 16.3 | Implement Secure Software Development Practices | Secure coding standards |
| 16.4 | Establish a Secure Software Development Lifecycle | Include security in SDLC |
| 16.5 | Use Up-to-Date and Trusted Third-Party Components | Manage dependencies |
| 16.6 | Establish Secure Coding Practices | Developer guidelines |
| 16.7 | Use Standard Hardening Configuration Templates | Application hardening |
| 16.8 | Separate Production and Non-Production Systems | Environment segregation |
| 16.9 | Train Developers in Application Security Concepts and Secure Coding | Developer education |
| 16.10 | Apply Secure Design Principles in Application Architectures | Security architecture |
| 16.11 | Leverage Vetted Modules or Services | Use proven components |
| 16.12 | Implement Code-Level Security Checks | SAST/DAST |
| 16.13 | Conduct Application Penetration Testing | Security testing |
| 16.14 | Conduct Threat Modeling | Identify attack vectors |

**Key Tools:**
- SAST tools (SonarQube, Checkmarx)
- DAST tools (OWASP ZAP, Burp Suite)
- Dependency scanners (OWASP Dependency-Check)
- SCA tools (Snyk, Black Duck)

**Framework Mappings:**
- NIST CSF: PR.DS-7, PR.IP-2
- ISO 27001: A.14.1.1, A.14.2.1, A.14.2.2, A.14.2.5, A.14.2.6, A.14.2.8
- NIST 800-53: SA-3, SA-4, SA-8, SA-11, SA-15, SA-16
- PCI DSS: 6.3, 6.4, 6.5, 6.6

### CIS Control 17: Incident Response Management

| Safeguard | Description | Implementation |
|-----------|-------------|----------------|
| 17.1 | Establish Incident Response Process | Document IR plan |
| 17.2 | Establish and Maintain Contact Information for Reporting Security Incidents | Define escalation paths |
| 17.3 | Establish and Maintain an Enterprise Process for Reporting Incidents | Report procedures |
| 17.4 | Establish and Maintain An Incident Response Process | IR workflows |
| 17.5 | Assign Key Roles and Responsibilities | Define IR team |
| 17.6 | Define Mechanisms for Communicating During Incident Response | Communication plans |
| 17.7 | Conduct Routine Incident Response Exercises | Tabletop exercises |
| 17.8 | Conduct Post-Incident Reviews | Lessons learned process |
| 17.9 | Establish and Maintain Security Incident Thresholds | Event classification |

**Key Tools:**
- Incident response platforms (TheHive, RTIR)
- Digital forensics tools
- Threat intelligence platforms
- Communication platforms

**Framework Mappings:**
- NIST CSF: RS.RP-1, RS.CO-1, RS.AN-1, RS.MI-1, RS.MI-2, RC.RP-1
- ISO 27001: A.16.1.1, A.16.1.2, A.16.1.3, A.16.1.4, A.16.1.5, A.16.1.6, A.16.1.7
- NIST 800-53: IR-1, IR-2, IR-3, IR-4, IR-5, IR-6, IR-7, IR-8
- PCI DSS: 12.10, 12.10.1, 12.10.2, 12.10.3, 12.10.4, 12.10.5, 12.10.6

### CIS Control 18: Penetration Testing

| Safeguard | Description | Implementation |
|-----------|-------------|----------------|
| 18.1 | Establish Penetration Testing Program | Document testing strategy |
| 18.2 | Perform Regular External Penetration Tests | Test external perimeter |
| 18.3 | Perform Regular Internal Penetration Tests | Test internal network |
| 18.4 | Validate Security Measures | Verify control effectiveness |
| 18.5 | Document Penetration Testing Results | Report all findings |
| 18.6 | Test Critical Systems and Services | Focus on key assets |
| 18.7 | Remediate Penetration Test Findings | Fix identified issues |
| 18.8 | Use Qualified Penetration Testers | Engage skilled professionals |
| 18.9 | Conduct Application Penetration Testing | Test web applications |
| 18.10 | Conduct Physical Penetration Testing | Test physical security |

**Key Tools:**
- Penetration testing tools (Metasploit, Nmap, Burp Suite)
- Vulnerability scanners (Nessus, OpenVAS)
- Social engineering tools (SET, Gophish)
- Physical penetration testing equipment

**Framework Mappings:**
- NIST CSF: ID.RA-1, DE.CM-8
- ISO 27001: A.14.2.8, A.18.2.1, A.18.2.3
- NIST 800-53: CA-8, RA-5, SA-11
- PCI DSS: 11.3, 11.3.1, 11.3.2, 11.3.3, 11.3.4

## Framework Mapping Matrix

| CIS Control | NIST CSF | ISO 27001 | NIST 800-53 | PCI DSS | HIPAA | GDPR |
|-------------|----------|-----------|-------------|---------|-------|------|
| 1. Inventory and Control of Enterprise Assets | ID.AM-1, ID.AM-2 | A.8.1.1, A.8.1.2 | CM-8, PM-5 | 2.4, 9.9, 11.1 | §164.310(d) | Art 30, 32 |
| 2. Inventory and Control of Software Assets | ID.AM-2, PR.DS-6 | A.12.6.2, A.8.1.1 | CM-7, CM-8 | 2.4, 6.2 | §164.310(d) | Art 30 |
| 3. Data Protection | PR.DS-1, PR.DS-2, PR.DS-5 | A.8.2.1-3, A.10.1.1 | SC-8, SC-28, MP-2-4 | 3.1-6, 4.1-2 | §164.312(a)(2)(iv) | Art 5, 6, 25, 32 |
| 4. Secure Configuration of Enterprise Assets and Software | PR.IP-1, PR.PT-3 | A.12.1.2, A.14.2.2-4 | CM-2, CM-6, CM-7 | 2.2, 2.3, 2.6 | §164.310(c) | Art 25, 32 |
| 5. Account Management | PR.AC-1, PR.AC-4, PR.AC-7 | A.9.2.1-6 | AC-2, AC-3, AC-6, IA-2, IA-5 | 7.1, 7.2, 8.1-3 | §164.308(a)(3), §164.308(a)(4) | Art 25, 32 |
| 6. Access Control Management | PR.AC-1, PR.AC-3, PR.AC-4 | A.9.1.1-2, A.9.2.3, A.9.4.1 | AC-1-6, AC-17 | 7.1, 7.2, 8.3 | §164.308(a)(4) | Art 25, 32 |
| 7. Continuous Vulnerability Management | ID.RA-1, ID.RA-2, PR.IP-12 | A.12.6.1-2, A.14.2.3 | RA-3, RA-5, SI-2 | 6.1, 6.2, 11.2 | §164.308(a)(1)(ii)(A) | Art 32 |
| 8. Audit Log Management | PR.PT-1, DE.CM-1, DE.CM-3 | A.12.4.1-4 | AU-2-3, AU-6-12 | 10.1-7 | §164.308(a)(1)(ii)(D), §164.312(b) | Art 30, 32 |
| 9. Email and Web Browser Protections | PR.DS-6, PR.DS-7, DE.CM-5 | A.13.1.1-2 | SC-7, SC-8 | 1.3, 4.1, 5.1, 5.3 | §164.308(a)(5)(ii)(B) | Art 32 |
| 10. Malware Defenses | DE.CM-4, DE.CM-5, PR.DS-5 | A.12.2.1 | SI-3, SI-4, SI-8 | 5.1-3 | §164.308(a)(5)(ii)(B) | Art 32 |
| 11. Data Recovery | PR.IP-4, RC.RP-1 | A.12.3.1, A.17.1.2-3 | CP-9, CP-10 | 9.5-7, 12.10.1 | §164.308(a)(7) | Art 32 |
| 12. Network Infrastructure Management | PR.AC-5, PR.PT-4 | A.13.1.1, A.13.1.3 | AC-17-18, IA-3, SC-7-8 | 1.1-3, 2.2 | §164.312(a)(1) | Art 32 |
| 13. Network Monitoring and Defense | DE.AE-1-3, DE.CM-1, DE.CM-7 | A.12.4.1, A.13.1.1-2 | SI-4, AU-6 | 10.6, 11.4, 11.5 | §164.308(a)(1)(ii)(D), §164.312(b) | Art 32 |
| 14. Security Awareness and Skills Training | PR.AT-1, PR.AT-2, PR.AT-5 | A.7.2.2-3 | AT-1, AT-2, AT-3 | 12.6, 12.6.1-2 | §164.308(a)(5) | Art 32, 39 |
| 15. Service Provider Management | ID.SC-1-5 | A.15.1.1-3, A.15.2.1-2 | SA-9, SA-12 | 12.8, 12.8.1-5, 12.9 | §164.308(b) | Art 28, 32 |
| 16. Application Software Security | PR.DS-7, PR.IP-2 | A.14.1.1, A.14.2.1-2, A.14.2.5-6, A.14.2.8 | SA-3-4, SA-8, SA-11, SA-15-16 | 6.3-6 | §164.312(a)(1) | Art 25, 32 |
| 17. Incident Response Management | RS.RP-1, RS.CO-1, RS.AN-1, RS.MI-1-2, RC.RP-1 | A.16.1.1-7 | IR-1-8 | 12.10, 12.10.1-6 | §164.308(a)(6) | Art 33, 34 |
| 18. Penetration Testing | ID.RA-1, DE.CM-8 | A.14.2.8, A.18.2.1, A.18.2.3 | CA-8, RA-5, SA-11 | 11.3, 11.3.1-4 | §164.308(a)(8) | Art 32 |

## Implementation Priorities by Organization Size

### Small Organizations (Limited Resources)

**Essential Controls to Implement First:**
1. CIS Control 1: Inventory and Control of Enterprise Assets
2. CIS Control 2: Inventory and Control of Software Assets
3. CIS Control 3: Data Protection (focus on encryption)
4. CIS Control 4: Secure Configuration (basic hardening)
5. CIS Control 5: Account Management (focus on privileged accounts)
6. CIS Control 7: Continuous Vulnerability Management (basic patching)
7. CIS Control 10: Malware Defenses (endpoint protection)
8. CIS Control 11: Data Recovery (basic backup strategy)
9. CIS Control 14: Security Awareness Training (basic program)

**Implementation Tips:**
- Use free/open source tools where possible
- Focus on cloud-based security solutions with minimal infrastructure
- Implement managed security services for areas requiring expertise
- Prioritize protecting the most critical systems and data
- Consider outsourcing complex controls

### Medium Organizations (Moderate Resources)

**Implementation Order:**
1. Implement all Basic controls (1-6) thoroughly
2. Implement Foundational controls (7-16) with focus on:
   - CIS Control 7: Continuous Vulnerability Management
   - CIS Control 8: Audit Log Management
   - CIS Control 10: Malware Defenses
   - CIS Control 11: Data Recovery
   - CIS Control 12: Network Infrastructure Management
   - CIS Control 13: Network Monitoring and Defense
3. Begin implementing Organizational controls (17-18)

**Implementation Tips:**
- Establish formal security program with dedicated resources
- Implement automation where possible
- Consider hybrid of in-house and outsourced security services
- Establish metrics to measure control effectiveness

### Large Organizations (Significant Resources)

**Implementation Approach:**
1. Implement all 18 CIS Controls comprehensively
2. Focus on automation and integration
3. Establish continuous monitoring and improvement
4. Customize controls for industry-specific requirements
5. Implement advanced capabilities within each control

**Implementation Tips:**
- Develop custom security architecture aligned with controls
- Implement defense-in-depth strategy
- Establish centralized security operations capability
- Integrate controls with risk management program
- Establish control validation and testing program

## Implementation Challenges and Solutions

| Challenge | Description | Potential Solutions |
|-----------|-------------|---------------------|
| **Resource Constraints** | Limited budget, staff, or time | Start with critical controls, use free tools, consider managed services |
| **Technical Complexity** | Some controls require specialized expertise | Outsource complex controls, invest in training, use simplified solutions |
| **Legacy Systems** | Older systems may not support modern security | Implement compensating controls, isolate legacy systems, prioritize replacement |
| **Organizational Resistance** | User pushback to security measures | Focus on user experience, demonstrate business value, executive sponsorship |
| **Lack of Visibility** | Incomplete view of environment | Implement asset discovery tools, start with known assets, incremental improvement |
| **Monitoring Fatigue** | Too many alerts, not enough analysts | Tune detections, prioritize alerts, automate responses where possible |
| **Integration Challenges** | Making tools work together | Select integration-friendly solutions, use APIs, standardize data formats |
| **Measuring Effectiveness** | Difficulty proving control value | Establish baseline metrics, track improvements, use maturity models |

## CIS Controls Implementation Roadmap

### Phase 1: Foundation (Months 1-3)
- Complete initial asset inventory (CIS 1, 2)
- Implement basic account controls (CIS 5)
- Deploy endpoint protection (CIS 10)
- Establish backup solution (CIS 11)
- Begin security awareness program (CIS 14)

### Phase 2: Basic Security Posture (Months 4-6)
- Implement secure configurations (CIS 4)
- Establish vulnerability management (CIS 7)
- Deploy basic log management (CIS 8)
- Secure email and web browsing (CIS 9)
- Document incident response procedures (CIS 17)

### Phase 3: Enhanced Protection (Months 7-12)
- Implement data protection controls (CIS 3)
- Enhance access control (CIS 6)
- Secure network infrastructure (CIS 12)
- Deploy network monitoring (CIS 13)
- Review vendor security (CIS 15)

### Phase 4: Advanced Capabilities (Months 13-18)
- Implement application security (CIS 16)
- Conduct penetration testing (CIS 18)
- Enhance and refine all controls
- Establish metrics and reporting
- Integrate with risk management

## Key Performance Indicators by Control

| Control | Key Metrics | Target Values |
|---------|-------------|---------------|
| **1. Inventory** | % of assets inventoried, Unauthorized device detection time | >95% inventoried, <24h detection |
| **2. Software Inventory** | % of software inventoried, % of unauthorized software | >95% inventoried, <2% unauthorized |
| **3. Data Protection** | % of sensitive data encrypted, data loss incidents | >99% encrypted, 0 incidents |
| **4. Secure Configuration** | % of systems with secure baseline, configuration drift rate | >95% compliant, <5% drift |
| **5. Account Management** | % of accounts reviewed, dormant account count | 100% reviewed annually, <5% dormant |
| **6. Access Control** | Excessive privilege rate, access review completion | <5% with excessive rights, 100% reviewed |
| **7. Vulnerability Management** | Mean time to patch critical vulnerabilities, scan coverage | <7 days MTTR, >98% coverage |
| **8. Audit Logging** | Logging coverage, log retention compliance | >98% coverage, 100% retention compliance |
| **9. Email/Web Protection** | Phishing simulation success rate, malware blocked | <5% click rate, >99% block rate |
| **10. Malware Defense** | Endpoint protection coverage, detection time | >99% coverage, <1 hour detection |
| **11. Data Recovery** | Backup success rate, recovery time objective achievement | >99% success, 100% RTO met |
| **12. Network Management** | Network device compliance, unauthorized change rate | >98% compliance, <1% unauthorized |
| **13. Network Monitoring** | Alert triage time, true positive rate | <30 min triage, >80% true positive |
| **14. Security Training** | Training completion rate, knowledge assessment scores | >95% completion, >85% score |
| **15. Service Providers** | % of providers assessed, contract compliance | 100% assessed, 100% compliant |
| **16. Application Security** | % of apps security tested, critical vulnerability remediation | 100% critical apps tested, <7 days remediation |
| **17. Incident Response** | Mean time to respond, exercise completion | <4 hours MTTR, ≥2 exercises annually |
| **18. Penetration Testing** | Test coverage, findings remediation rate | 100% critical systems, >95% remediation |
