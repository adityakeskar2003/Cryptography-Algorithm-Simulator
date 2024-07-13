import streamlit as st
from Elgamal import Elgamal_Algorithm
from display import display_cryptographic_result


def GUI():
    if 'encryption_steps' not in st.session_state:
        st.session_state.encryption_steps = []
    if 'decryption_steps' not in st.session_state:
        st.session_state.decryption_steps = []
    st.header("Elgamal Algorithm")
    st.write("The ElGamal encryption algorithm is an asymmetric key encryption algorithm for public-key cryptography. It is based on the Diffie-Hellman key exchange and was described by Taher ElGamal in 1985. ElGamal encryption consists of three main components: key generation, encryption, and decryption")
    st.write(" ")
    st.subheader("Key Generation")
    st.write("Step 1: Choose a large prime number p")
    st.write("Step 2: Choose a generator g of the multiplicative group of integers modulo p")
    st.write("Step 3: Choose a random integer x such that 1 < x < p-2, where x is private key")
    st.write("Step 4: Compute y : y = g^(x) mod (p)")
    st.write("Public key : (p,q,y)")
    st.write("Private key : (x)")
    if st.button('Generate p, g, y, x'):
        st.session_state.p,st.session_state.g,st.session_state.y,st.session_state.x = Elgamal_Algorithm.generate_keys()

    if 'p' in st.session_state and 'g' in st.session_state and 'y' in st.session_state and 'x' in st.session_state:
        st.write("Generated p:")
        display_cryptographic_result(st.session_state.p)
        st.write("Generated g:")
        display_cryptographic_result(st.session_state.g)
        st.write("Generated y:")
        display_cryptographic_result(st.session_state.y)
        st.write("Generated x:")
        display_cryptographic_result(st.session_state.x)
        st.write("Public Key:")
        display_cryptographic_result([st.session_state.p,st.session_state.g,st.session_state.y])
        st.write("Private Key:")
        display_cryptographic_result(st.session_state.x)

        st.write(" ")
        st.header("Encryption")
        st.write("Step 1. Choose a random integer k such that 1 < k < (p-2)")
        st.write("Step 2. Compute c1 = g^(k) mod (p)")
        st.write("Step 3. Compute c2 = m * y^(k) mod (p) ")
        st.write("Write the message")
        message = st.text_input("Enter the plain text:", key="plain_text_input")
        if message:
            st.session_state.message = message

            if st.button("Get ciphertext"):
                st.session_state.encryption_steps,st.session_state.ciphertext = Elgamal_Algorithm.encrypt(
                    st.session_state.p, st.session_state.g,st.session_state.y,st.session_state.message
                )

            if 'ciphertext' in st.session_state:
                for encryption_step in st.session_state.encryption_steps:
                    st.write(encryption_step)
                st.write("Ciphertext:")
                display_cryptographic_result(st.session_state.ciphertext)

                st.subheader("Decryption")
                st.write("Step 1: Compute a shared secret s : s = c1^(x)mod(p)")
                st.write("Step 2: Compute the modular inverse for s as s^(-1)")
                st.write("Step 3: Compute the plaintext message m = c2 . s^(-1)mod(p)")
                if st.button("Decryption by receiver"):

                    st.session_state.decryption_steps,st.session_state.decrypted_message = Elgamal_Algorithm.decrypt(
                        st.session_state.x, st.session_state.p, st.session_state.ciphertext
                    )
                    if 'decrypted_message' in st.session_state:
                        for decryption_step in st.session_state.decryption_steps:
                            st.write(decryption_step)
                        st.write("Value of message decrypted is")
                        display_cryptographic_result(st.session_state.decrypted_message)


def GUI_Signing():
    if 'encryption_steps' not in st.session_state:
        st.session_state.encryption_steps = []
    if 'decryption_steps' not in st.session_state:
        st.session_state.decryption_steps = []
    st.header("Elgamal Algorithm")
    st.write(
        "The ElGamal encryption algorithm is an asymmetric key encryption algorithm for public-key cryptography. It is based on the Diffie-Hellman key exchange and was described by Taher ElGamal in 1985. ElGamal encryption consists of three main components: key generation, encryption, and decryption")
    st.write(" ")
    st.subheader("Key Generation")
    st.write("Step 1: Choose a large prime number p")
    st.write("Step 2: Choose a generator g of the multiplicative group of integers modulo p")
    st.write("Step 3: Choose a random integer x such that 1 < x < p-2, where x is private key")
    st.write("Step 4: Compute y : y = g^(x) mod (p)")
    st.write("Public key : (p,q,y)")
    st.write("Private key : (x)")
    if st.button('Generate p, g, y, x'):
        st.session_state.p1, st.session_state.g1, st.session_state.y1, st.session_state.x1 = Elgamal_Algorithm.generate_keys()
        st.session_state.p2, st.session_state.g2, st.session_state.y2, st.session_state.x2 = Elgamal_Algorithm.generate_keys()

    if 'p1' in st.session_state and 'g1' in st.session_state and 'y1' in st.session_state and 'x1' in st.session_state and 'p2' in st.session_state and 'g2' in st.session_state and 'y2' in st.session_state and 'x2' in st.session_state:
        st.write("Generated Private Key for Sender (x1):")
        display_cryptographic_result(st.session_state.x1)
        st.write("Generated Public Key for Sender (p1,g1,y1):")
        display_cryptographic_result([st.session_state.p1,st.session_state.g1,st.session_state.y1])
        st.write(" ")
        st.write("Generated Private Key for Receiver (x2):")
        display_cryptographic_result(st.session_state.x2)
        st.write("Generated Public Key for Receiver (p2,g2,y2):")
        display_cryptographic_result([st.session_state.p2,st.session_state.g2,st.session_state.y2])

        st.subheader("Encryption")
        st.write("Sender encrypts message with Receiver's Public Key")
        message = st.text_input("Enter the plain text:", key="plain_text_input")
        if message:
            st.session_state.message = message

            if st.button("Encrypt with Receiver's Public Key"):
                st.session_state.encryption_steps,st.session_state.ciphertext = Elgamal_Algorithm.encrypt(
                    st.session_state.p2, st.session_state.g2,st.session_state.y2, st.session_state.message
                )

        if 'ciphertext' in st.session_state and 'encryption_steps' in st.session_state:
            for step in st.session_state.encryption_steps:
                st.write(step)
            st.write("Ciphertext:")
            display_cryptographic_result(st.session_state.ciphertext)
            st.subheader("Signing")
            st.write("Step 1: Choose a random integer k  such that 0 < k < (p1-2) and gcd(k,p1 - 1)")
            st.write("Step 2: Compute r = g1^(k) mod p1")
            st.write("Step 3: Compute s = (m - x1*r)k^(-1) mod (p-1) where k^(-1) is k inverse")
            st.write("Signature is (r,s)")
            if st.button("Sign with Sender's Private Key and Public Key"):
                st.session_state.k,st.session_state.k_inv,st.session_state.r,st.session_state.s = Elgamal_Algorithm.sign(
                    st.session_state.message, st.session_state.x1, st.session_state.p1,st.session_state.g1
                )

            if 's' in st.session_state and 'r' in st.session_state and 'k' in st.session_state and 'k_inv' in st.session_state:
                st.write("Value of k is")
                display_cryptographic_result(st.session_state.k)
                st.write("Value of k_inv is")
                display_cryptographic_result(st.session_state.k_inv)
                st.write("Value of r is:")
                display_cryptographic_result(st.session_state.r)
                st.write("Value of s is:")
                display_cryptographic_result(st.session_state.s)

                st.markdown("---")
                st.header("The message flows through the network")
                st.markdown("---")

                st.subheader("Verification")
                st.write("Step 1: Compute v1 = y^(r)r^(s)mod(p)")
                st.write("Step 2: Compute v2 = g^(m) mod (p)")
                if st.button("Verify with Sender's Public Key"):
                    st.session_state.v1,st.session_state.v2,st.session_state.is_verified = Elgamal_Algorithm.verify(
                        st.session_state.message, st.session_state.r,st.session_state.s, st.session_state.p1,st.session_state.g1,st.session_state.y1
                    )


                if 'is_verified' in st.session_state and 'v1' in st.session_state and 'v2' in st.session_state:
                    st.write("v1")
                    display_cryptographic_result(st.session_state.v1)
                    st.write("v2")
                    display_cryptographic_result(st.session_state.v2)
                    st.write("Verification result:")
                    display_cryptographic_result(st.session_state.is_verified)

                    if st.session_state.is_verified:
                        st.subheader("Decryption")
                        st.write("Step 1: Compute a shared secret s : s = c1^(x2)mod(p2)")
                        st.write("Step 2: Compute the modular inverse for s as s^(-1)")
                        st.write("Step 3: Compute the plaintext message m = c2 . s^(-1)mod(p2)")
                        if st.button("Decrypt with Receiver's Private Key"):
                            st.session_state.decryption_steps,st.session_state.decrypted_plaintext = Elgamal_Algorithm.decrypt(
                                st.session_state.x2, st.session_state.p2, st.session_state.ciphertext
                            )

                        if 'decrypted_plaintext' in st.session_state and 'decryption_steps' in st.session_state:
                            for step in st.session_state.decryption_steps:
                                st.write(step)
                            st.write("Decrypted Plaintext:")
                            display_cryptographic_result(st.session_state.decrypted_plaintext)