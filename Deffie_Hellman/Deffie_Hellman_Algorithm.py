import random
import sympy  # Used for checking prime numbers

def generate_large_prime(bits=256):
    # Generate a large prime number of specified bits
    return sympy.randprime(2**(bits-1), 2**bits)

def generate_primitive_root(p):
    # Find a primitive root modulo p
    # A primitive root g modulo p is a number g such that every number from 1 to p-1 can be obtained as g^k mod p for some k
    # For simplicity, we will choose a random primitive root for demonstration
    return random.randint(2, p - 2)

def generate_dh_parameters(bits=256):
    # Step 1: Choose a large prime p
    p = generate_large_prime(bits)
    # Step 2: Choose a primitive root g
    g = generate_primitive_root(p)

    return p, g

def generate_dh_keypair(p, g):
    # Step 3: Choose a secret integer a for Alice
    a = random.randint(2, p - 2)  # Alice's secret key
    # Step 4: Compute public key A = g^a mod p
    A = pow(g, a, p)

    return a, A

def generate_dh_shared_secret(p, B, a):
    # Step 5: Choose a secret integer b for Bob
    b = random.randint(2, p - 2)  # Bob's secret key
    # Step 6: Compute public key B = g^b mod p
    # This is usually computed by Bob, but for simplicity, we'll pass it as an argument
    # Step 7: Compute shared secret S = B^a mod p
    S = pow(B, a, p)

    return S

# Example usage:
