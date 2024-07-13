from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

# Generation of Keys
def generate_des_key():
    return get_random_bytes(8)  # DES key size is 8 bytes

# Convert plaintext to bytes and pad to match DES block size
def encrypt_step1(plaintext):
    padded_plaintext = pad(plaintext.encode(), DES.block_size)
    return padded_plaintext

# Generate DES cipher object with ECB mode
def encrypt_step2(key):
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher

# Encrypt the padded plaintext
def encrypt_step3(plaintext, key):
    padded_plaintext = pad(plaintext.encode(), DES.block_size)
    cipher = DES.new(key, DES.MODE_ECB)
    ciphertext = cipher.encrypt(padded_plaintext)
    return ciphertext

# Encode ciphertext to base64 for transmission/storage
def encrypt_step4(plaintext, key):
    padded_plaintext = pad(plaintext.encode(), DES.block_size)
    cipher = DES.new(key, DES.MODE_ECB)
    ciphertext = cipher.encrypt(padded_plaintext)
    encoded_ciphertext = base64.b64encode(ciphertext).decode('utf-8')
    return encoded_ciphertext

# Decode base64 and return ciphertext
def decrypt_step1(encoded_ciphertext):
    ciphertext = base64.b64decode(encoded_ciphertext)
    return ciphertext

# Create DES cipher object with ECB mode and key
def decrypt_step2(encoded_ciphertext, key):
    ciphertext = base64.b64decode(encoded_ciphertext)
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher

# Decrypt the ciphertext and unpad the plaintext
def decrypt_step3(cipher, ciphertext):
    padded_plaintext = cipher.decrypt(ciphertext)
    plaintext = unpad(padded_plaintext, DES.block_size).decode('utf-8')
    return plaintext
