# Cryptography Cheatsheet

| Category | Algorithm/Method | Description | Example Usage | Security Level |
|----------|------------------|-------------|--------------|----------------|
| **Symmetric Encryption** |||||
| Block Ciphers | AES-256 | Advanced Encryption Standard | `openssl enc -aes-256-cbc -in plain.txt -out encrypted.bin` | Strong (Recommended) |
| | AES-128 | AES with 128-bit key | `openssl enc -aes-128-cbc -in plain.txt -out encrypted.bin` | Adequate |
| | 3DES | Triple Data Encryption Standard | `openssl enc -des3 -in plain.txt -out encrypted.bin` | Legacy (Avoid) |
| Stream Ciphers | ChaCha20 | Modern stream cipher | `openssl enc -chacha20 -in plain.txt -out encrypted.bin` | Strong |
| | RC4 | Rivest Cipher 4 | `openssl enc -rc4 -in plain.txt -out encrypted.bin` | Broken (Avoid) |
| Operation Modes | GCM | Galois/Counter Mode (authenticated) | `openssl enc -aes-256-gcm -in plain.txt -out encrypted.bin` | Strong (Recommended) |
| | CBC | Cipher Block Chaining | `openssl enc -aes-256-cbc -in plain.txt -out encrypted.bin` | Adequate with proper IV |
| | ECB | Electronic Codebook | `openssl enc -aes-256-ecb -in plain.txt -out encrypted.bin` | Weak (Avoid) |
| | CTR | Counter Mode | `openssl enc -aes-256-ctr -in plain.txt -out encrypted.bin` | Strong with unique nonce |
| **Asymmetric Encryption** |||||
| Key Exchange | RSA-2048+ | Rivest-Shamir-Adleman | `openssl genrsa -out private.pem 4096` | Strong (≥2048 bits) |
| | ECC (P-256) | Elliptic Curve Cryptography | `openssl ecparam -genkey -name prime256v1 -out ecc.key` | Strong (≥256 bits) |
| | DH | Diffie-Hellman | `openssl dhparam -out dhparams.pem 2048` | Strong (≥2048 bits) |
| | ECDH | Elliptic Curve Diffie-Hellman | Used in TLS handshakes | Strong |
| Modern Standards | X25519 | Curve25519 for key exchange | Used in Signal Protocol | Very Strong |
| | Ed25519 | Edwards-curve for signatures | `ssh-keygen -t ed25519` | Very Strong |
| **Hashing Algorithms** |||||
| Modern | SHA-256 | Secure Hash Algorithm 256-bit | `openssl dgst -sha256 file.txt` | Strong |
| | SHA-3 | Secure Hash Algorithm 3 | `openssl dgst -sha3-256 file.txt` | Very Strong |
| | BLAKE2 | Fast secure hash function | `b2sum file.txt` | Very Strong |
| Legacy | SHA-1 | Secure Hash Algorithm 1 | `openssl dgst -sha1 file.txt` | Broken (Avoid) |
| | MD5 | Message Digest 5 | `openssl dgst -md5 file.txt` | Broken (Avoid) |
| Password Hashing | Argon2id | Memory-hard function | `argon2 password -id -t 3 -m 16 -p 4` | Strongest (Recommended) |
| | bcrypt | Blowfish-based hash | `htpasswd -B -C 12 passfile user` | Strong |
| | PBKDF2 | Key derivation function | `openssl pkeyutl -kdf PBKDF2` | Adequate (high iterations) |
| | Scrypt | Memory-hard function | `scrypt password salt 16384 8 1 32` | Strong |
| **Message Authentication** |||||
| HMAC | HMAC-SHA256 | Hash-based Message Authentication | `openssl dgst -sha256 -hmac "key" file.txt` | Strong |
| Authenticated Encryption | AES-GCM | Encryption with built-in auth | `openssl enc -aes-256-gcm -in file.txt` | Strong (Recommended) |
| | ChaCha20-Poly1305 | Authenticated stream cipher | Used in TLS 1.3 | Strong (Recommended) |
| **Digital Signatures** |||||
| RSA-based | RSA-PSS | Probabilistic Signature Scheme | `openssl dgst -sha256 -sign key.pem -sigopt rsa_padding_mode:pss file` | Strong |
| | PKCS#1 v1.5 | Traditional RSA signature | `openssl dgst -sha256 -sign key.pem file` | Adequate |
| EC-based | ECDSA | Elliptic Curve Digital Signature | `openssl dgst -sha256 -sign ec.key file` | Strong |
| | Ed25519 | Edwards-curve Digital Signature | `openssl dgst -sign ed.key file` | Very Strong (Recommended) |
| **Key Derivation** |||||
| Password-based | PBKDF2 | Password-Based Key Derivation | `openssl pkeyutl -kdf PBKDF2 -kdflen 32` | Adequate (≥10k iterations) |
| | Argon2 | Memory-hard KDF | `argon2 password -id -t 3 -m 16 -p 4` | Strong (Recommended) |
| | scrypt | Memory-hard KDF | `openssl kdf -kdf scrypt -password pass -key-length 32` | Strong |
| Key-based | HKDF | HMAC-based Extract-and-Expand | `openssl kdf -kdf hkdf -salt salt -key key -out output.key` | Strong |
| **Random Number Generation** |||||
| Cryptographic PRNGs | /dev/urandom | OS random source (Unix) | `dd if=/dev/urandom of=rand bs=32 count=1` | Strong |
| | CryptGenRandom | Windows API | Used via programming languages | Strong |
| | RDRAND | CPU instruction | Used in newer CPUs | Strong when combined |
| **Protocols & Standards** |||||
| TLS | TLS 1.3 | Transport Layer Security | `openssl s_client -tls1_3 -connect example.com:443` | Strong (Recommended) |
| | TLS 1.2 | Transport Layer Security | `openssl s_client -tls1_2 -connect example.com:443` | Adequate |
| | SSL 3.0, TLS 1.0/1.1 | Legacy protocols | Disable in configurations | Weak (Avoid) |
| SSH | SSH-2 | Secure Shell v2 | `ssh -o "Protocol 2" user@host` | Strong |
| | SSH-1 | Legacy Secure Shell | Disable in configurations | Broken (Avoid) |
| PGP/GPG | GPG | GNU Privacy Guard | `gpg --encrypt --recipient user@example.com file` | Strong |

## Common Cryptographic Operations

| Operation | OpenSSL Command | Example |
|-----------|-----------------|---------|
| Generate RSA key pair | `openssl genrsa` | `openssl genrsa -out private.pem 4096` |
| Extract public key | `openssl rsa` | `openssl rsa -in private.pem -pubout -out public.pem` |
| Generate ECC key | `openssl ecparam` | `openssl ecparam -genkey -name prime256v1 -out ec.key` |
| Create CSR | `openssl req` | `openssl req -new -key private.pem -out cert.csr` |
| Sign file | `openssl dgst` | `openssl dgst -sha256 -sign private.pem -out sig.bin file.txt` |
| Verify signature | `openssl dgst` | `openssl dgst -sha256 -verify public.pem -signature sig.bin file.txt` |
| Encrypt file (symmetric) | `openssl enc` | `openssl enc -aes-256-gcm -salt -in file.txt -out file.enc` |
| Decrypt file | `openssl enc` | `openssl enc -d -aes-256-gcm -in file.enc -out file.txt` |
| Generate random bytes | `openssl rand` | `openssl rand -base64 32` |

## Key Length Recommendations (2023+)

| Algorithm Type | Minimum Secure Length | Recommended Length | Notes |
|----------------|------------------------|-------------------|-------|
| AES | 128 bits | 256 bits | No known practical attacks |
| RSA | 2048 bits | 4096 bits | Increases computational cost |
| ECC | 256 bits | 384 bits | NIST P-256 or Curve25519 |
| Hash functions | 256 bits | 384+ bits | SHA-256 or stronger |
| HMAC | 256 bits | 384+ bits | Based on the underlying hash |
| Symmetric key | 128 bits | 256 bits | For long-term security |

## Common Vulnerabilities & Mitigations

| Vulnerability | Description | Mitigation |
|---------------|-------------|------------|
| Padding Oracle | Leaks info about padding validity | Use authenticated encryption (GCM, ChaCha20-Poly1305) |
| Key Reuse | Same key for multiple messages | Use unique keys/IVs for each encryption |
| Weak RNG | Predictable random numbers | Use cryptographically secure RNGs (/dev/urandom, CryptGenRandom) |
| Side-Channel Attacks | Timing, power analysis | Use constant-time implementations |
| Downgrade Attacks | Force use of weaker protocols | Disable legacy protocols, use strict configurations |
| Known Plaintext | Predictable plaintext locations | Add randomization where possible |
| Insufficient Key Size | Too small keys are brute-forceable | Follow key length recommendations above |
| Certificate Issues | Invalid/expired certificates | Automate certificate management, use HSTS |
| Hash Collisions | Finding two inputs with same hash | Use collision-resistant algorithms (SHA-256+) |
