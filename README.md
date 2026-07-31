# CyberSec Toolkit

A modern, comprehensive cybersecurity utility built in Python. Designed for security professionals, students, and anyone who wants practical, everyday security tools in one place.

---

## Features

| Module | Description |
|---|---|
| 🔐 Password Analyzer | Score password strength against 5 security criteria, detect keyboard patterns & common passwords |
| 🔑 Password Generator | Generate cryptographically secure passwords, passphrases (word-based), or PINs; estimate brute-force crack time |
| #️⃣ Hash Tools | Hash text/files with MD5, SHA-1, SHA-256, SHA-512, SHA-3, BLAKE2; HMAC generation & verification |
| 🛡️ File Integrity | Create SHA-256 manifests for files/directories; verify for tampering or corruption |
| 🔭 Port Scanner | Multi-threaded TCP port scanner with service identification, risk flagging, and optional banner grabbing |
| 🔒 Cipher Tools | Caesar cipher (+ brute-force), Vigenère cipher, XOR encryption, ROT13, Base64, URL/hex encoding, One-Time Pad |
| 🌐 Network Tools | DNS forward/reverse lookup, SSL certificate inspection, IP geolocation, host profiling |

---

## Requirements

- Python 3.10 or higher
- [rich](https://github.com/Textualize/rich) library

---

## Installation

```bash
# Clone the repository
git clone https://github.com/Dj221981/darren.git
cd darren

# Install dependencies
pip install -r requirements.txt

# Optional: install as a command-line tool
pip install -e .
```

---

## Usage

### Interactive CLI

```bash
# Run the interactive menu
python -m cybersec_toolkit.main

# Or if installed via pip:
cybersec
```

The interactive menu lets you navigate all modules with numbered options.

### Module Quick-Reference

#### Password Analyzer

```python
from cybersec_toolkit.modules.password_analyzer import analyze_password

result = analyze_password("MyS3cur3P@ssw0rd!")
print(result.strength)     # "Very Strong"
print(result.percentage)   # 92
print(result.entropy_bits) # 104.6
```

#### Password Generator

```python
from cybersec_toolkit.modules.password_generator import (
    generate_password, generate_passphrase, GeneratorConfig
)

# 24-character random password
pwd = generate_password(GeneratorConfig(length=24))

# Memorable passphrase: e.g. "Amber-Tiger-Quartz-Ocean-472"
phrase = generate_passphrase(num_words=4)
```

#### Hash Tools

```python
from cybersec_toolkit.modules.hash_tools import hash_text, hash_file, verify_hash

result = hash_text("hello world", "sha256")
print(result["digest"])  # b94d27b9934d3e...

# Verify (constant-time, safe against timing attacks)
verify_hash("hello world", result["digest"], "sha256")  # True

# Hash a file
file_result = hash_file("/path/to/file.txt", "sha256")
```

#### File Integrity

```python
from cybersec_toolkit.modules.file_integrity import create_manifest, verify_manifest

# Create a manifest for a directory
create_manifest(["/var/www"], "manifest.json", "sha256")

# Later, verify nothing has changed
report = verify_manifest("manifest.json")
print(report["overall_status"])  # "PASS" or "FAIL"
```

#### Port Scanner

```python
from cybersec_toolkit.modules.port_scanner import scan

# Scan common ports
result = scan("192.168.1.1")
for port in result.open_ports:
    print(f"{port.port}/tcp  {port.service}  {port.risk_level}")

# Scan a range
result = scan("example.com", port_range=(1, 1024), timeout=0.5)
```

> ⚠️ **Only scan hosts you own or have explicit written permission to scan.**

#### Cipher Tools

```python
from cybersec_toolkit.modules.cipher_tools import (
    caesar_encrypt, vigenere_encrypt, base64_encode, otp_generate_key, otp_encrypt
)

# Caesar cipher
caesar_encrypt("Hello World", shift=13)  # "Uryyb Jbeyq"

# Vigenere cipher
vigenere_encrypt("ATTACKATDAWN", "LEMON")  # "LXFOPVEFRNHR"

# One-Time Pad (theoretically unbreakable)
key = otp_generate_key(64)
result = otp_encrypt("Top secret message", key)
```

#### Network Tools

```python
from cybersec_toolkit.modules.network_tools import (
    dns_lookup, get_ssl_certificate_info, get_ip_info
)

dns = dns_lookup("github.com")
ssl = get_ssl_certificate_info("github.com")
print(ssl["certificate"]["days_until_expiry"])

ip_info = get_ip_info("8.8.8.8")
print(ip_info["isp"])  # "Google LLC"
```

---

## Security Notes

- Passwords entered in the analyzer are **never stored or transmitted**.
- Password generation uses Python's `secrets` module (cryptographically secure).
- Hash verification uses **constant-time comparison** (`hmac.compare_digest`) to prevent timing attacks.
- Classical ciphers (Caesar, Vigenère, XOR) are **for educational use only** — use AES or similar for real encryption.
- Only use the port scanner on systems you own or have **explicit authorization** to test.

---

## Project Structure

```
cybersec_toolkit/
├── __init__.py
├── main.py                    # Interactive CLI entry point
└── modules/
    ├── password_analyzer.py   # Password strength analysis
    ├── password_generator.py  # Secure password/passphrase generation
    ├── hash_tools.py          # Hashing and HMAC
    ├── file_integrity.py      # File integrity manifest system
    ├── port_scanner.py        # Multi-threaded TCP port scanner
    ├── cipher_tools.py        # Classical ciphers and encodings
    └── network_tools.py       # DNS, SSL, IP geo utilities
```

---

## License

MIT
