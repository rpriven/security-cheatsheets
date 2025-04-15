# Privacy Protection Cheatsheet

| Category | Technique | Tools | Implementation |
|----------|-----------|-------|----------------|
| **Web Browsing** ||||
| Private browsing | Use incognito/private mode | Firefox, Chrome, Brave | Ctrl+Shift+N (Chrome), Ctrl+Shift+P (Firefox) |
| Search engines | Use privacy-focused search | DuckDuckGo, Startpage, Searx | Set as browser default |
| Browser hardening | Disable tracking features | uBlock Origin, Privacy Badger | Install extensions, adjust settings |
| Fingerprint resistance | Prevent browser identification | Firefox privacy settings, Brave shields | Enable "Strict" tracking protection |
| Cookies management | Control persistent data | Cookie AutoDelete | Configure to delete on tab close |
| **Communication** ||||
| Encrypted messaging | Use E2E encrypted apps | Signal, Matrix, Session | Install apps, verify contacts |
| Email privacy | Use encrypted email | ProtonMail, Tutanota | Create account, use encryption |
| Metadata protection | Minimize communication metadata | Signal disappearing messages | Enable advanced privacy features |
| VoIP security | Secure voice communications | Signal, Jitsi | Use encrypted voice calls |
| File sharing | Secure document transfer | OnionShare | Share files via Tor |
| **Device Security** ||||
| Disk encryption | Encrypt storage devices | VeraCrypt, LUKS, BitLocker | Enable system-wide encryption |
| Secure deletion | Permanently erase data | BleachBit, `shred` | `shred -vzu file`, use secure wipe |
| Password management | Use password manager | KeePassXC, Bitwarden | Generate unique passwords |
| Screen privacy | Prevent shoulder surfing | Privacy screen, timeout locks | Install filters, set short timeouts |
| Device hardening | Remove unnecessary services | OS settings | Disable unused features/services |
| **Network Privacy** ||||
| VPN usage | Encrypt network traffic | Mullvad, ProtonVPN | Install VPN, enable kill switch |
| Tor browsing | Anonymous web browsing | Tor Browser | Use for sensitive activities |
| DNS privacy | Encrypt DNS requests | DNS over HTTPS/TLS | Configure in browser/OS |
| Wi-Fi security | Secure wireless connections | WPA3, random MAC | Enable MAC randomization |
| Traffic analysis | Prevent traffic inspection | Obfs4, Snowflake | Use bridge relays with Tor |
| **Identity Protection** ||||
| Account separation | Compartmentalize identities | Multiple browsers/profiles | Use different accounts per context |
| Alternative identities | Use pseudonyms | Temp email services | Create context-specific emails |
| Financial privacy | Anonymous payments | Cash, privacy coins | Use cash for sensitive purchases |
| Metadata removal | Clean document metadata | ExifTool, mat2 | `exiftool -all= document.pdf` |
| Location privacy | Minimize location tracking | GPS spoofing, airplane mode | Disable location services when not needed |

## GDPR Data Subject Rights Reference

| Right | Description | How to Exercise |
|-------|-------------|----------------|
| Access | Obtain your personal data | Submit Subject Access Request (SAR) |
| Rectification | Correct inaccurate data | Request correction in writing |
| Erasure | Delete your data | Submit "Right to be Forgotten" request |
| Restriction | Limit data processing | Request processing limitation |
| Portability | Receive/transfer your data | Request data in machine-readable format |
| Object | Stop certain processing | Express objection to processing |
| Auto-decisions | Avoid automated profiling | Opt out of automated decision systems |
