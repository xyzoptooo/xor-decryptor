from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import base64
from itertools import cycle

# Base64 decoded AES keys (256-bit each)
key1 = base64.b64decode("h+NvKyaJFRhpn7lRWo0JGGcSk7TOd2ltibSSI1CGDCk=")
key2 = base64.b64decode("CznIYU0rBgmzSb7WyqYfj+WKyDSXbbnsa8Wp/IRvUOc=")
key3 = base64.b64decode("ihpLsXPURUTwH4ULO9/87rHRCQibQO6+V4/QKJL7Bgg=")

# The actual ciphertexts (properly formatted as strings)
ciphertexts = [
    "rOkz0hogqrrjVXe8KhfwPmTXqy0NI5BaaVRwg8g4490Gi//XIIYY6t7pMpw/0DN4V26tcdwmmOOne75oEt4/oQ==",
    "t+WZSn6H1mA9XUQJrQ2xxt33nVh6orKFygb7Q+8xMe9JSk7XgMdZ8Fwq9rSMw9SuCZWoIJ8qYOSOKwmyyvMmW7/kkPDoWNEezfme08HmEWi3DrPAefIpNVVewbfVzt5j",
    "dNMxxcWRHkxNxHu17gw5g5IE/Jf6tNmxw4OfBHEXfRv0cx4pKVKYjZofSRAgFspLnWcdR5GGasKxCgpOANPyS4liypMrPFKlXy/pm2BG7bM=",
    "k8JzsMNxiG5KPGSdM/YjGjW7y8dzgG8vsQ3RB062Kz1/EzwUaWz5Sr2UFNuq0jcWqDdj3Y9I0UKz0rYdZuTxMHZ+oKVEqI8Xv9CuvOmOzkdBoBgsjaWT9ke6+BPcMH9Kpwq/jgoYVQ7SfJDKx5GCAxzSLyyS6tXGIZRrUny6jiU="
]

def try_alternating_ecb(ciphertext_b64):
    try:
        ciphertext = base64.b64decode(ciphertext_b64)
        block_size = 16
        decrypted = bytearray()
        
        for i in range(0, len(ciphertext), block_size):
            block = ciphertext[i:i+block_size]
            key = [key1, key2, key3][(i//block_size) % 3]  # Rotate through keys
            cipher = AES.new(key, AES.MODE_ECB)
            decrypted.extend(cipher.decrypt(block))
        
        try:
            return unpad(decrypted, block_size).decode('utf-8')
        except:
            return decrypted.decode('utf-8', errors='ignore')
    except Exception as e:
        return f"Error: {str(e)}"

def try_key_combination(ciphertext_b64, operation='xor'):
    try:
        ciphertext = base64.b64decode(ciphertext_b64)
        
        if operation == 'xor':
            combined_key = bytes(k1 ^ k2 ^ k3 for k1,k2,k3 in zip(key1, key2, key3))
        elif operation == 'concat':
            combined_key = key1 + key2 + key3
        
        # Use first 32 bytes for AES-256
        cipher = AES.new(combined_key[:32], AES.MODE_ECB)
        decrypted = cipher.decrypt(ciphertext)
        
        try:
            return unpad(decrypted, AES.block_size).decode('utf-8')
        except:
            return decrypted.decode('utf-8', errors='ignore')
    except Exception as e:
        return f"Error: {str(e)}"

print("Attempting decryption with all methods...\n")

for i, ct in enumerate(ciphertexts):
    print(f"\nMessage {i+1}:")
    print(f"Original length: {len(base64.b64decode(ct))} bytes")
    
    # Try alternating key ECB
    result = try_alternating_ecb(ct)
    print(f"\nAlternating ECB result:\n{result}")
    
    # Try XOR combined key
    result = try_key_combination(ct, 'xor')
    print(f"\nXOR Combined Key result:\n{result}")
    
    # Try concatenated key
    result = try_key_combination(ct, 'concat')
    print(f"\nConcatenated Key result:\n{result}")