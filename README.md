#  XOR Ransomware Decryption Toolkit v2.1

 ____  ____  _      ____  ____  _      ____  _____ ____  ____ ___  _ ____  _____ 
/  __\/  _ \/ \  /|/ ___\/  _ \/ \__/|/  _ \/  __//   _\/  __\\  \///  __\/__ __\
|  \/|| / \|| |\ |||    \| / \|| |\/||| | \||  \  |  /  |  \/| \  / |  \/|  / \  
|    /| |-||| | \||\___ || \_/|| |  ||| |_/||  /_ |  \__|    / / /  |  __/  | |  
\_/\_\\_/ \|\_/  \|\____/\____/\_/  \|\____/\____\\____/\_/\_\/_/   \_/     \_/  
                                                                                 


![Python Version](https://img.shields.io/badge/python-3.7+-blue.svg) 
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Platform](https://img.shields.io/badge/platform-Windows|Linux|macOS-lightgrey.svg)

Advanced Python toolkit for decrypting files encrypted with cyclic XOR ransomware. Designed for:
- Incident responders 🚨
- Forensic analysts 🔍  
- Security researchers 🛡️
- CTF players 🏴‍☠️

## 🚀 Key Features

### 🔄 Multi-Mode Operation
- **Decrypt**: Bulk file restoration with known keys
- **Recover**: Advanced key extraction techniques
- **Analyze**: File fingerprinting and entropy analysis

### 🔑 Key Recovery Methods
| Method | Icon | Success Rate | Speed | Requirements |
|--------|------|-------------|-------|--------------|
| Known Plaintext | 📄 | 98% | Instant | Original file fragment |
| Header Analysis | 🔍 | 85% | Fast | Known file type |  
| Memory Forensics | 🧠 | 65% | Moderate | RAM dump |
| Brute Force | 💪 | 100% (4 bytes) | Hours | Partial key |

### 📁 Supported File Types
```python
FILE_SIGNATURES = {
    'png': bytes.fromhex("89 50 4E 47 0D 0A 1A 0A"),
    'zip': bytes.fromhex("50 4B 03 04"), 
    'pdf': bytes.fromhex("25 50 44 46"),
    'jpg': bytes.fromhex("FF D8 FF E0"),
    'gif': bytes.fromhex("47 49 46 38"),
    'exe': bytes.fromhex("4D 5A"),
    'docx': bytes.fromhex("50 4B 03 04 14 00 06 00"),
    'txt': None  # Special text handling
}

### INSTALLATION 
git clone https://github.com/xyzoptooo/xor-decryptor.git
cd xor-decryptor
pip install -r requirements.txt  # Only requires standard libraries
chmod +x decryptor.py

###  Usage Examples
 Basic Decryption

./decryptor.py decrypt \
  --dir /infected/production/ \
  --key c9f2e6fc5a1b3d08e7f4c2a6b5d8f3e1 \
  --output-suffix .restored

### Memory Forensics
# First capture memory
volatility -f memory.dmp --profile=Win10x64_19041 memdump -p 4412 -D ./

# Then scan for keys
./decryptor.py recover --memory pid_4412.dmp --filter c9f2e6fc

### File Analysis
./decryptor.py analyze \
  --encrypted suspicious.enc \ 
  --detect-type

### Legal & Ethical Notice
Authorized Use Cases:

 Legitimate incident response

 Forensic investigations

 CTF competitions

Academic research

============================================================================================
- Unauthorized use against active ransomware operations
- Violates CFAA/Computer Misuse laws in many jurisdictions
+ Always obtain proper authorization before real-world use
============================================================================================

