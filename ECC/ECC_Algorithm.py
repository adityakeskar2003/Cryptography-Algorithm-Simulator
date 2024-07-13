import hashlib
import random

# Elliptic Curve Parameters (P-256 curve for example)
p = 2 ** 256 - 2 ** 224 + 2 ** 192 + 2 ** 96 - 1
a = -3
b = int('5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b', 16)
Gx = int('6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296', 16)
Gy = int('4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5', 16)
n = int('ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551', 16)

# Point at infinity
INF = (None, None)


# Modular arithmetic
def modinv(a, n):
    return pow(a, n - 2, n)


def hash_message(message):
    hash_obj = hashlib.sha256()
    hash_obj.update(message.encode('utf-8'))
    return int(hash_obj.hexdigest(), 16)


# Point addition
def point_add(p1, p2):
    if p1 == INF:
        return p2
    if p2 == INF:
        return p1
    x1, y1 = p1
    x2, y2 = p2

    if x1 == x2 and (y1 != y2 or y1 == 0):
        return INF

    if x1 == x2:
        m = (3 * x1 * x1 + a) * modinv(2 * y1, p) % p
    else:
        m = (y2 - y1) * modinv(x2 - x1, p) % p

    x3 = (m * m - x1 - x2) % p
    y3 = (m * (x1 - x3) - y1) % p

    return (x3, y3)


# Scalar multiplication
def scalar_multiply(k, P):
    result = INF
    addend = P
    while k > 0:
        if k % 2 == 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k //= 2
    return result


# Key generation
def generate_keys():
    private_key = random.randint(1, n - 1)
    public_key = scalar_multiply(private_key, (Gx, Gy))
    return private_key, public_key


# Hash message
def hash_message(message):
    hash_obj = hashlib.sha256()
    hash_obj.update(message.encode('utf-8'))
    return int(hash_obj.hexdigest(), 16)


# Encrypt message
def encrypt(message, public_key):
    k = random.randint(1, n - 1)
    C1 = scalar_multiply(k, (Gx, Gy))
    shared_secret = scalar_multiply(k, public_key)
    hashed_message = hash_message(message)
    C2 = point_add((hashed_message, 0), shared_secret)
    return k, C1, C2


# Decrypt message
def decrypt(C1, C2, private_key):
    shared_secret = scalar_multiply(private_key, C1)
    decrypted_hash = point_add(C2, (shared_secret[0], -shared_secret[1]))[0]
    decrypted_message = hashlib.sha256(hex(decrypted_hash).encode()).hexdigest()
    return shared_secret, decrypted_message


def sign_message(message, private_key):
    k = random.randint(1, n - 1)
    R = scalar_multiply(k, (Gx, Gy))
    r = R[0] % n
    if r == 0:
        return None, None  # Retry with a different k

    e = hash_message(message)
    s = modinv(k, n) * (e + private_key * r) % n
    if s == 0:
        return None, None  # Retry with a different k

    return k,r, s

# Verifying signature
def verify_signature(message,r,s, public_key):
    if r <= 0 or r >= n or s <= 0 or s >= n:
        return False

    e = hash_message(message)
    w = modinv(s, n)
    u1 = (e * w) % n
    u2 = (r * w) % n

    R = point_add(scalar_multiply(u1, (Gx, Gy)), scalar_multiply(u2, public_key))
    if R == INF:
        return False

    return w,u1,u2,R[0] % n == r



def verify(decrypted_message_hash, message):
    if decrypted_message_hash == hash_message(message):
        return message
    else:
        print("Decryption failed. Original message might have been tampered with.")

# # Example usage
# private_key, public_key = generate_keys()
# message = "Hello, ECC!"
#
# # Signing the message
# signature = sign_message(message, private_key)
# print("Original message:", message)
# print("Signature:", signature)
#
# # Encrypting the message
# C1, C2 = encrypt(message, public_key)
# print("Encrypted message:", (C1, C2))
#
# # Decrypting the message
# decrypted_message_hash = decrypt(C1, C2, private_key)
# decrypted_message = hashlib.sha256(hex(decrypted_message_hash).encode()).hexdigest()
# print("Decrypted message:", decrypted_message)
#
# # Verifying the signature
# verified = verify_signature(message, signature, public_key)
# print("Signature verified:", verified)
