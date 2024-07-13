from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64
import streamlit as st
from display import display_cryptographic_result
# Generation of Keys
def generate_aes_key():
    st.write("The selected random value is :")
    x = get_random_bytes(16)
    display_cryptographic_result(x)
    return x

# Convert plaintext to bytes and pad to match AES block size
def encrypt_step1(plaintext):
    padded_plaintext = pad(plaintext.encode(), AES.block_size)
    return padded_plaintext

def encrypt_step2(key):
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv, cipher


# Encrypt the padded plaintext
def encrypt_step3(plaintext, key):
    padded_plaintext = pad(plaintext.encode(), AES.block_size)
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(padded_plaintext)
    return ciphertext


def encrypt_step4(plaintext, key):
    padded_plaintext = pad(plaintext.encode(), AES.block_size)
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Encrypt the padded plaintext
    ciphertext = cipher.encrypt(padded_plaintext)

    # Encode IV and ciphertext to base64 for transmission/storage
    iv_encoded = base64.b64encode(iv).decode('utf-8')
    ciphertext_encoded = base64.b64encode(ciphertext).decode('utf-8')
    return iv_encoded, ciphertext_encoded


def decrypt_step1(iv_encoded, ciphertext_encoded):
    iv = base64.b64decode(iv_encoded)
    ciphertext = base64.b64decode(ciphertext_encoded)
    return iv, ciphertext


def decrypt_step2(iv_encoded, ciphertext_encoded, key):
    iv = base64.b64decode(iv_encoded)
    ciphertext = base64.b64decode(ciphertext_encoded)

    # Create AES cipher object with CBC mode and IV
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher


def decrypt_step3(iv_encoded, ciphertext_encoded, key):
    iv = base64.b64decode(iv_encoded)
    ciphertext = base64.b64decode(ciphertext_encoded)

    # Create AES cipher object with CBC mode and IV
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Decrypt the ciphertext and unpad the plaintext
    padded_plaintext = cipher.decrypt(ciphertext)
    plaintext = unpad(padded_plaintext, AES.block_size).decode('utf-8')
    return plaintext

