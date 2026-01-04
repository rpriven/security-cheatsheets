# OSINT Cheatsheet

Quick reference for Open Source Intelligence gathering, reconnaissance, and information discovery.

---

## Search Engine Operators

### Google Dorking

| Operator | Description | Example |
|----------|-------------|---------|
| `site:` | Search within site | `site:example.com` |
| `filetype:` | Find file types | `filetype:pdf` |
| `intitle:` | Search in title | `intitle:"index of"` |
| `inurl:` | Search in URL | `inurl:admin` |
| `intext:` | Search in body | `intext:password` |
| `cache:` | Cached version | `cache:example.com` |
| `"..."` | Exact match | `"admin login"` |
| `*` | Wildcard | `"admin * password"` |
| `-` | Exclude | `site:example.com -www` |
| `OR` | Either term | `admin OR login` |
| `..` | Number range | `$100..$500` |

### Useful Dorks
```
# Find exposed directories
intitle:"index of" "parent directory"

# Find login pages
inurl:login OR inurl:admin OR inurl:portal

# Find exposed files
site:example.com filetype:pdf OR filetype:doc OR filetype:xls

# Find config files
filetype:env OR filetype:cfg OR filetype:conf

# Find backup files
filetype:bak OR filetype:old OR filetype:backup

# Find exposed databases
filetype:sql "insert into" OR "create table"

# Find credentials
intext:password filetype:log
"username" "password" filetype:csv

# Find vulnerable pages
inurl:php?id=
inurl:index.php?id=
```

### Other Search Engines
- **Bing**: Similar operators, sometimes different results
- **DuckDuckGo**: Privacy-focused, `site:`, `filetype:`
- **Yandex**: Better for Russian/Eastern European content
- **Baidu**: Chinese content

---

## Domain & Website OSINT

### DNS & Whois
```bash
# Whois lookup
whois example.com

# DNS records
dig example.com ANY
dig example.com MX
dig example.com TXT
nslookup -type=any example.com

# Zone transfer (if allowed)
dig axfr @ns1.example.com example.com
```

### Online Tools
| Tool | URL | Purpose |
|------|-----|---------|
| ViewDNS | viewdns.info | DNS, IP, whois |
| SecurityTrails | securitytrails.com | Historical DNS |
| DNSDumpster | dnsdumpster.com | DNS recon |
| crt.sh | crt.sh | Certificate transparency |
| Shodan | shodan.io | Internet-connected devices |
| Censys | censys.io | Similar to Shodan |
| BuiltWith | builtwith.com | Technology profiler |
| Wappalyzer | wappalyzer.com | Tech detection |
| Wayback Machine | web.archive.org | Historical snapshots |

### Subdomain Enumeration
```bash
# Amass
amass enum -d example.com

# Subfinder
subfinder -d example.com

# Sublist3r
sublist3r -d example.com

# Certificate transparency
curl -s "https://crt.sh/?q=%.example.com&output=json" | jq -r '.[].name_value' | sort -u

# DNS brute force
gobuster dns -d example.com -w wordlist.txt
```

### Technology Detection
```bash
# Whatweb
whatweb example.com

# Wappalyzer CLI
wappalyzer https://example.com
```

---

## Email OSINT

### Email Verification
| Tool | URL |
|------|-----|
| Hunter.io | hunter.io |
| EmailHippo | emailhippo.com |
| Verify Email | verify-email.org |
| Email-Checker | email-checker.net |

### Email Discovery
```bash
# theHarvester
theHarvester -d example.com -b all

# Hunter.io API
curl "https://api.hunter.io/v2/domain-search?domain=example.com&api_key=YOUR_KEY"
```

### Email Header Analysis
| Tool | URL |
|------|-----|
| MXToolbox | mxtoolbox.com/EmailHeaders.aspx |
| Google Admin Toolbox | toolbox.googleapps.com/apps/messageheader |

---

## Username & People OSINT

### Username Search
| Tool | URL | Purpose |
|------|-----|---------|
| Namechk | namechk.com | Username availability |
| WhatsMyName | whatsmyname.app | Cross-platform search |
| Sherlock | github.com/sherlock-project | CLI username search |
| Maigret | github.com/soxoj/maigret | Sherlock alternative |

```bash
# Sherlock
python3 sherlock username

# Maigret
maigret username
```

### People Search
| Tool | Purpose |
|------|---------|
| Pipl | People search engine |
| Spokeo | US people search |
| BeenVerified | Background checks |
| ThatsThem | Free people search |
| TruePeopleSearch | Free US lookup |
| Webmii | Aggregated web presence |

### Social Media
| Platform | OSINT Approach |
|----------|----------------|
| LinkedIn | Company employees, roles, connections |
| Twitter/X | Public posts, followers, connections |
| Facebook | Public profiles, photos, check-ins |
| Instagram | Photos, locations, stories |
| GitHub | Code, email in commits, contributions |

---

## Image OSINT

### Reverse Image Search
| Tool | URL |
|------|-----|
| Google Images | images.google.com |
| TinEye | tineye.com |
| Yandex Images | yandex.com/images |
| Bing Images | bing.com/images |

### Metadata Extraction
```bash
# ExifTool
exiftool image.jpg

# View GPS coordinates
exiftool -gpslatitude -gpslongitude image.jpg

# Remove metadata
exiftool -all= image.jpg
```

### Geolocation
| Tool | URL |
|------|-----|
| GeoGuessr | geoguessr.com |
| Google Earth | earth.google.com |
| Mapillary | mapillary.com |
| SunCalc | suncalc.org |

---

## Password & Breach OSINT

### Breach Databases
| Tool | URL | Notes |
|------|-----|-------|
| Have I Been Pwned | haveibeenpwned.com | Check if email breached |
| DeHashed | dehashed.com | Paid breach search |
| LeakCheck | leakcheck.io | Email/username search |
| IntelX | intelx.io | Multiple data types |
| Snusbase | snusbase.com | Breach database |

### Password Policy Discovery
```bash
# Check password policies in AD
crackmapexec smb target -u user -p pass --pass-pol
```

---

## Business & Company OSINT

### Company Information
| Tool | URL | Purpose |
|------|-----|---------|
| OpenCorporates | opencorporates.com | Global company database |
| Crunchbase | crunchbase.com | Startup/company info |
| LinkedIn | linkedin.com | Employees, structure |
| SEC EDGAR | sec.gov/edgar | US public filings |
| Companies House | companieshouse.gov.uk | UK company data |

### Financial
| Tool | URL |
|------|-----|
| Bloomberg | bloomberg.com |
| Yahoo Finance | finance.yahoo.com |
| Google Finance | google.com/finance |

---

## Network & Infrastructure OSINT

### Shodan
```bash
# CLI
shodan search "hostname:example.com"
shodan host 1.2.3.4

# Common queries
org:"Target Company"
hostname:example.com
port:22
product:Apache
ssl.cert.subject.cn:example.com
```

### Censys
```bash
# Search syntax
services.http.response.html_title:"Example"
ip:1.2.3.4
autonomous_system.name:"Example ISP"
```

### BGP & ASN
| Tool | URL |
|------|-----|
| BGP.he.net | bgp.he.net |
| ASN Lookup | asnlookup.com |
| BGPView | bgpview.io |

---

## Wireless OSINT

| Tool | URL | Purpose |
|------|-----|---------|
| Wigle | wigle.net | WiFi network database |
| WifiMap | wifimap.io | WiFi passwords |

---

## OSINT Tools - CLI

### theHarvester
```bash
# All sources
theHarvester -d example.com -b all

# Specific sources
theHarvester -d example.com -b google,linkedin,twitter
```

### Recon-ng
```bash
# Start
recon-ng

# Install modules
marketplace search
marketplace install all

# Set workspace
workspaces create example
db insert domains
domains add example.com

# Run modules
modules load recon/domains-hosts/hackertarget
run
```

### SpiderFoot
```bash
# Run scan
spiderfoot -s example.com -o output.html
```

### Maltego
- GUI-based relationship mapping
- Entity transformations
- Visualize connections

---

## OSINT Workflow

```
1. Define scope and objectives
   ↓
2. Passive reconnaissance
   - Search engines
   - Social media
   - Public records
   ↓
3. Domain/Infrastructure
   - DNS, Whois
   - Subdomains
   - Technology stack
   ↓
4. People/Organization
   - Employees
   - Email addresses
   - Usernames
   ↓
5. Breach data
   - Exposed credentials
   - Data leaks
   ↓
6. Document findings
   - Organize data
   - Create report
```

---

## Sock Puppets

### Creating Fake Identities
- Use AI-generated photos (thispersondoesnotexist.com)
- Create dedicated email (ProtonMail)
- Use VPN/Tor
- Build history over time
- Keep consistent persona

### Operational Security
- Separate browser/profile
- No real personal info
- Different IP addresses
- Avoid linking accounts

---

## Resources

### Websites
- [OSINT Framework](https://osintframework.com/)
- [IntelTechniques](https://inteltechniques.com/)
- [OSINT Dojo](https://www.osintdojo.com/)
- [Bellingcat](https://www.bellingcat.com/)

### Books
- "Open Source Intelligence Techniques" by Michael Bazzell
- "The OSINT Handbook" by Dale Meredith

### Training
- [TCM Security OSINT Fundamentals](https://academy.tcm-sec.com/)
- [SANS SEC487](https://www.sans.org/cyber-security-courses/open-source-intelligence-gathering/)
