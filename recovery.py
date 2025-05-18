#!/usr/bin/env python3
"""
Enhanced Ransomware Decryption Toolkit with TXT file support
For files encrypted with XOR cipher using cyclic 16-byte key
"""

import os
import re
import math
import argparse
from itertools import cycle, product
from typing import Optional, List

# Constants
FILE_SIGNATURES = {
    'png': bytes.fromhex("89 50 4E 47 0D 0A 1A 0A"),
    'zip': bytes.fromhex("50 4B 03 04"),
    'pdf': bytes.fromhex("25 50 44 46"),
    'jpg': bytes.fromhex("FF D8 FF E0"),
    'gif': bytes.fromhex("47 49 46 38"),
    'exe': bytes.fromhex("4D 5A"),
    'docx': bytes.fromhex("50 4B 03 04 14 00 06 00"),
    'txt': None  # Special handling for text files
}

TEXT_CHARS = bytearray({7,8,9,10,12,13,27} | set(range(0x20, 0x100)) - {0x7f})

def is_text_file(filepath: str, chunk_size: int = 1024) -> bool:
    """Check if a file is likely to be text"""
    with open(filepath, 'rb') as f:
        chunk = f.read(chunk_size)
    return not bool(chunk.translate(None, TEXT_CHARS))

def decrypt_file(filename: str, key: bytes, output_suffix: str = ".dec") -> str:
    """Decrypt a single file using XOR cipher with cyclic key"""
    with open(filename, "rb") as f:
        encrypted_data = f.read()
    
    decrypted_data = bytes(a ^ b for a, b in zip(encrypted_data, cycle(key)))
    
    if filename.endswith(".enc"):
        output_filename = filename[:-4] + output_suffix
    else:
        output_filename = filename + output_suffix
    
    with open(output_filename, "wb") as f:
        f.write(decrypted_data)
    
    print(f"[+] Decrypted {filename} to {output_filename}")
    return output_filename

def batch_decrypt(directory: str, key: bytes, output_suffix: str = ".dec"):
    """Decrypt all .enc files in a directory recursively"""
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(".enc"):
                filepath = os.path.join(root, file)
                decrypt_file(filepath, key, output_suffix)

def recover_key_from_known_file(encrypted_file: str, known_original_file: str, key_length: int = 16) -> bytes:
    """Recover key by comparing encrypted file with known original"""
    with open(encrypted_file, "rb") as f_enc, open(known_original_file, "rb") as f_orig:
        encrypted = f_enc.read()
        original = f_orig.read()
    
    min_length = min(len(encrypted), len(original))
    key = bytes(a ^ b for a, b in zip(original[:min_length], encrypted[:min_length]))
    
    return key[:key_length]

def recover_key_from_signature(encrypted_file: str, file_type: str, key_length: int = 16) -> bytes:
    """Recover partial key from known file signatures"""
    if file_type.lower() == 'txt':
        # Special handling for text files - try common patterns
        common_prefixes = [
            b"#!/",                  # Scripts
            b"# ",                    # Comments
            b"<?xml",                 # XML
            b"\xef\xbb\xbf",          # UTF-8 BOM
            b"\xff\xfe",              # UTF-16 LE BOM
            b"\xfe\xff",              # UTF-16 BE BOM
            b"---",                   # YAML
            b"{\n",                   # JSON
            b"From: ",                # Email
            b"Received: ",            # Email headers
            b"Date: "                 # Common header
        ]
        
        with open(encrypted_file, "rb") as f:
            encrypted_data = f.read(128)  # Read first 128 bytes for analysis
            
        for prefix in common_prefixes:
            if len(encrypted_data) >= len(prefix):
                partial_key = bytes(a ^ b for a, b in zip(prefix, encrypted_data[:len(prefix)]))
                if is_high_entropy(partial_key):
                    return partial_key.ljust(key_length, b'\x00')
        
        raise ValueError("Could not determine text file structure for key recovery")
    else:
        signature = FILE_SIGNATURES.get(file_type.lower())
        if not signature:
            raise ValueError(f"Unknown file type: {file_type}. Supported: {', '.join(FILE_SIGNATURES.keys())}")
        
        with open(encrypted_file, "rb") as f:
            encrypted_header = f.read(len(signature))
        
        if len(encrypted_header) < len(signature):
            raise ValueError("Encrypted file is smaller than the signature length")
        
        partial_key = bytes(a ^ b for a, b in zip(signature, encrypted_header))
        return partial_key

def is_high_entropy(data: bytes, threshold: float = 7.0) -> bool:
    """Check if data has high entropy (likely random)"""
    if not data:
        return False
    
    byte_counts = [0] * 256
    for byte in data:
        byte_counts[byte] += 1
    
    entropy = 0.0
    for count in byte_counts:
        if count > 0:
            probability = count / len(data)
            entropy -= probability * (probability and math.log(probability, 2))
    
    return entropy > threshold

def find_key_in_memory_dump(dump_file: str, key_length: int = 16) -> List[bytes]:
    """Search for potential XOR keys in memory dump"""
    with open(dump_file, "rb") as f:
        memory = f.read()
    
    potential_keys = set()
    for i in range(len(memory) - key_length + 1):
        candidate = memory[i:i+key_length]
        if is_high_entropy(candidate):
            potential_keys.add(candidate)
    
    return list(potential_keys)

def brute_force_key(partial_key: bytes, encrypted_sample: bytes, 
                   known_plaintext_fragment: bytes, max_missing: int = 4) -> Optional[bytes]:
    """Brute force missing key bytes with progress indicator"""
    known_len = len(known_plaintext_fragment)
    missing_bytes = 16 - len(partial_key)
    
    if missing_bytes > max_missing:
        print(f"Warning: Brute-forcing {missing_bytes} bytes may take too long (max recommended: {max_missing})")
        return None
    
    encrypted_sample = encrypted_sample[:known_len]
    total = 256 ** missing_bytes
    progress_interval = max(1, total // 100)
    
    print(f"Brute-forcing {missing_bytes} missing bytes ({total} combinations)...")
    
    for i, attempt in enumerate(product(range(256), repeat=missing_bytes)):
        if i % progress_interval == 0:
            print(f"Progress: {i}/{total} ({i/total*100:.1f}%)", end='\r')
        
        test_key = partial_key + bytes(attempt)
        decrypted = bytes(a ^ b for a, b in zip(encrypted_sample, cycle(test_key)))
        
        if decrypted.startswith(known_plaintext_fragment):
            print("\n[+] Key found!")
            return test_key
    
    print("\n[-] Key not found")
    return None

def main():
    parser = argparse.ArgumentParser(
        description="Enhanced Ransomware Decryption Toolkit with TXT support",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    # Main arguments
    parser.add_argument("action", choices=["decrypt", "recover", "analyze"], 
                       help="Action to perform")
    parser.add_argument("--dir", default="./files/", 
                       help="Target directory")
    parser.add_argument("--output-suffix", default=".dec", 
                       help="Suffix for decrypted files")
    
    # Decryption options
    parser.add_argument("--key", 
                       help="Encryption key in hex format")
    
    # Recovery options
    parser.add_argument("--encrypted", 
                       help="Encrypted file for key recovery")
    parser.add_argument("--original", 
                       help="Original file for known plaintext attack")
    parser.add_argument("--type", 
                       help="File type for header analysis", 
                       choices=FILE_SIGNATURES.keys())
    parser.add_argument("--memory", 
                       help="Memory dump file for key search")
    parser.add_argument("--known-text", 
                       help="Known plaintext fragment (for brute force)")
    parser.add_argument("--max-brute", type=int, default=4, 
                       help="Max bytes to brute force")
    
    # Analysis options
    parser.add_argument("--detect-type", action="store_true",
                       help="Attempt to detect file type of encrypted file")
    
    args = parser.parse_args()
    
    if args.action == "decrypt":
        if not args.key:
            parser.error("Decryption requires --key")
        
        try:
            key = bytes.fromhex(args.key)
            if len(key) != 16:
                raise ValueError
        except ValueError:
            parser.error("Key must be 16 bytes (32 hex characters)")
        
        print(f"[*] Starting decryption of {args.dir} with key {args.key}")
        batch_decrypt(args.dir, key, args.output_suffix)
        print("[+] Decryption complete")
    
    elif args.action == "recover":
        if args.original and args.encrypted:
            print("[*] Attempting known plaintext attack...")
            key = recover_key_from_known_file(args.encrypted, args.original)
            print(f"[+] Recovered key: {key.hex()}")
        
        elif args.type and args.encrypted:
            print(f"[*] Attempting header analysis for {args.type} file...")
            try:
                partial_key = recover_key_from_signature(args.encrypted, args.type)
                print(f"[+] Partial key from header: {partial_key.hex()}")
                
                if args.known_text:
                    with open(args.encrypted, "rb") as f:
                        encrypted_sample = f.read(len(args.known_text))
                    
                    full_key = brute_force_key(
                        partial_key,
                        encrypted_sample,
                        args.known_text.encode(),
                        args.max_brute
                    )
                    
                    if full_key:
                        print(f"[+] Full key found: {full_key.hex()}")
            except Exception as e:
                print(f"[-] Error: {str(e)}")
        
        elif args.memory:
            print("[*] Searching memory dump for potential keys...")
            potential_keys = find_key_in_memory_dump(args.memory)
            
            if potential_keys:
                print("[+] Potential keys found:")
                for i, key in enumerate(potential_keys, 1):
                    print(f"{i}. {key.hex()}")
            else:
                print("[-] No high-entropy 16-byte sequences found")
        
        else:
            parser.error("Recovery requires either --original/--encrypted, --type/--encrypted, or --memory")
    
    elif args.action == "analyze":
        if not args.encrypted:
            parser.error("Analysis requires --encrypted")
        
        print("[*] Analyzing encrypted file...")
        
        # Try to detect file type
        if args.detect_type:
            print("[*] Attempting file type detection...")
            with open(args.encrypted, "rb") as f:
                header = f.read(32)
            
            detected_types = []
            for file_type, sig in FILE_SIGNATURES.items():
                if sig and len(header) >= len(sig):
                    possible_key = bytes(a ^ b for a, b in zip(sig, header[:len(sig)]))
                    if is_high_entropy(possible_key):
                        detected_types.append(file_type)
            
            if detected_types:
                print(f"[+] Possible original file types: {', '.join(detected_types)}")
            else:
                print("[-] Could not determine file type from header")
        
        # Check if it might be a text file
        print("[*] Checking if file might be encrypted text...")
        if is_text_file(args.encrypted):
            print("[+] File appears to be encrypted text (high percentage of printable characters)")
            print("    Try recovery with --type txt and --known-text 'common prefix'")
        else:
            print("[-] File doesn't appear to be encrypted text")

if __name__ == "__main__":
    main()