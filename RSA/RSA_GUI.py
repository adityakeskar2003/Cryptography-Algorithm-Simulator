import streamlit as st
from RSA import RSA_Algorithm
from display import display_cryptographic_result


def GUI():
    st.header("RSA (Rivest-Shamir-Adleman) Algorithm")
    st.write("RSA (Rivest-Shamir-Adleman) is a widely used public-key cryptographic algorithm that provides secure data transmission. It was introduced in 1977 and is based on the mathematical difficulty of factoring large integers. RSA involves two keys: a public key, which is used for encryption, and a private key, which is used for decryption")
    st.write(" ")
    st.write("RSA's security relies on the difficulty of factoring the product of two large prime numbers. This problem is computationally hard and not feasible to solve with current technology for sufficiently large primes")
    st.write(" ")
    st.subheader("Key Generation")
    st.write("Step 1. Select Two Large Prime Numbers:")
    st.write("Press the Generate Key button to produce two large prime numbers")

    if st.button('Generate p, q'):
        st.session_state.p, st.session_state.q = RSA_Algorithm.generate_rsa_parameters(100)

    if 'p' in st.session_state and 'q' in st.session_state:
        st.write("p:")
        display_cryptographic_result(st.session_state.p)
        st.write("q:")
        display_cryptographic_result(st.session_state.q)

        st.write(" ")
        st.write("Step 2: a) Compute n: n = p * q")
        st.write("        b) Compute Euler's Totient Function ϕ(n) = (p - 1) * (q - 1)")
        if st.button("Generate n and Compute ϕ(n)"):
            st.session_state.phi, st.session_state.n = RSA_Algorithm.generate_eular_totient(st.session_state.p, st.session_state.q)

        if 'phi' in st.session_state and 'n' in st.session_state:
            st.write("Eular totient Function ϕ(n):")
            display_cryptographic_result(st.session_state.phi)
            st.write("n:")
            display_cryptographic_result(st.session_state.n)

            st.write(" ")
            st.write("Step 3: a) Choose an integer 'e': Such that 1 < e < ϕ(n), note that 'e' is public exponent")
            st.write("        b) Compute 'd': The modular multiplicative inverse of e mod ϕ(n), note that d is private exponent")

            if st.button("Generate Keys"):
                st.session_state.e,st.session_state.d = RSA_Algorithm.generate_keys(st.session_state.phi)

            if 'e' in st.session_state and 'd' in st.session_state:
                st.write("e:")
                display_cryptographic_result(st.session_state.e)
                st.write("d:")
                display_cryptographic_result(st.session_state.d)
                st.write(" ")
                st.write("Public Key:")
                pub = [st.session_state.e,st.session_state.n]
                display_cryptographic_result(pub)
                st.write(" ")
                st.write("Private Key:")
                pri = [st.session_state.d, st.session_state.n]
                display_cryptographic_result(pri)


                st.write(" ")
                st.subheader("Encryption")
                st.write("Write the message")
                message = st.text_input("Enter the plain text:", key="plain_text_input")
                st.write("Encrypting our message with Private key")
                st.write("We compute each character in plaintext as c^(e) mod n")
                if message:
                    st.session_state.message = message

                    if st.button("Get ciphertext"):
                        st.session_state.ciphertext = RSA_Algorithm.encrypt_rsa(
                            st.session_state.message,st.session_state.e,st.session_state.n
                        )

                    if 'ciphertext' in st.session_state:
                        st.write("Ciphertext:")
                        display_cryptographic_result(st.session_state.ciphertext)

                        st.header("Decryption")
                        st.write("Decrypting our message with Public key")
                        st.write("We compute each character in ciphertext as c^(d) mod n")
                        if st.button("Decryption by receiver"):

                            st.session_state.decrypted_message = RSA_Algorithm.decrypt_rsa(
                                st.session_state.ciphertext,st.session_state.d,st.session_state.n
                            )
                            if 'decrypted_message' in st.session_state:
                                st.write("Value of message decrypted is")
                                display_cryptographic_result(st.session_state.decrypted_message)


def GUI_Signing():
    st.header("RSA (Rivest-Shamir-Adleman) Algorithm")
    st.write(
        "RSA (Rivest-Shamir-Adleman) is a widely used public-key cryptographic algorithm that provides secure data transmission. It was introduced in 1977 and is based on the mathematical difficulty of factoring large integers. RSA involves two keys: a public key, which is used for encryption, and a private key, which is used for decryption")
    st.write(" ")
    st.write(
        "RSA's security relies on the difficulty of factoring the product of two large prime numbers. This problem is computationally hard and not feasible to solve with current technology for sufficiently large primes")
    st.write(" ")
    st.subheader("Key Generation")
    st.write("Step 1. Select Two Large Prime Numbers:")
    st.write("Press the Generate Key button to produce two large prime numbers")
    if st.button('Generate p1, q1, p2, q2'):
        st.session_state.p1, st.session_state.q1 = RSA_Algorithm.generate_rsa_parameters(50)
        st.session_state.p2, st.session_state.q2 = RSA_Algorithm.generate_rsa_parameters(50)

    if 'p1' in st.session_state and 'q1' in st.session_state and 'p2' in st.session_state and 'q2' in st.session_state:
        st.write("p for Sender:")
        display_cryptographic_result(st.session_state.p1)
        st.write("q for Sender:")
        display_cryptographic_result(st.session_state.q1)
        st.write("p for Receiver:")
        display_cryptographic_result(st.session_state.p2)
        st.write("q for Receiver:")
        display_cryptographic_result(st.session_state.q2)

        st.write(" ")
        st.write("Step 2: a) Compute n: n = p * q")
        st.write("        b) Compute Euler's Totient Function ϕ(n) = (p - 1) * (q - 1)")
        if st.button("Generate n1 and Compute ϕ1(n) and  n2 and Compute ϕ2(n)"):
            st.session_state.phi1, st.session_state.n1 = RSA_Algorithm.generate_eular_totient(st.session_state.p1,
                                                                                            st.session_state.q1)
            st.session_state.phi2, st.session_state.n2 = RSA_Algorithm.generate_eular_totient(st.session_state.p2,
                                                                                            st.session_state.q2)

        if 'phi1' in st.session_state and 'n1' in st.session_state and 'phi2' in st.session_state and 'n2' in st.session_state:
            st.write("Eular totient Function ϕ(n) for Sender:")
            display_cryptographic_result(st.session_state.phi1)
            st.write("n for Sender:")
            display_cryptographic_result(st.session_state.n1)
            st.write("Eular totient Function ϕ(n) for Receiver:")
            display_cryptographic_result(st.session_state.phi2)
            st.write("n for Receiver:")
            display_cryptographic_result(st.session_state.n2)

            st.write(" ")
            st.write("Step 3: a) Choose an integer 'e': Such that 1 < e < ϕ(n), note that 'e' is public exponent")
            st.write(
                "        b) Compute 'd': The modular multiplicative inverse of e mod ϕ(n), note that d is private exponent")

            if st.button("Generate Keys"):
                st.session_state.e1, st.session_state.d1 = RSA_Algorithm.generate_keys(st.session_state.phi1)
                st.session_state.e2, st.session_state.d2 = RSA_Algorithm.generate_keys(st.session_state.phi2)

            if 'e1' in st.session_state and 'd1' in st.session_state and 'e2' in st.session_state and 'd2' in st.session_state:
                st.write("e1 for Sender:")
                display_cryptographic_result(st.session_state.e1)
                st.write("d1 for Sender:")
                display_cryptographic_result(st.session_state.d1)
                st.write(" ")
                st.write("e2 for Receiver:")
                display_cryptographic_result(st.session_state.e2)
                st.write("d2 for Receiver:")
                display_cryptographic_result(st.session_state.d2)
                st.write("Public Key for Sender:")
                pub1 = [st.session_state.e1, st.session_state.n1]
                display_cryptographic_result(pub1)
                st.write(" ")
                st.write("Private Key for Sender:")
                pri1 = [st.session_state.d1, st.session_state.n1]
                display_cryptographic_result(pri1)
                st.write("Public Key for Receiver:")
                pub2 = [st.session_state.e2, st.session_state.n2]
                display_cryptographic_result(pub2)
                st.write(" ")
                st.write("Private Key for Receiver:")
                pri2 = [st.session_state.d2, st.session_state.n2]
                display_cryptographic_result(pri2)

                st.write(" ")
                st.subheader("Encryption")
                st.write("Write the message")
                message = st.text_input("Enter the plain text:", key="plain_text_input")
                st.write("Encrypting our message with Private key")
                st.write("We compute each character in plaintext as c^(d1) mod n1")
                if message:
                    st.session_state.message = message

                    if st.button("Get ciphertext"):
                        st.session_state.ciphertext = RSA_Algorithm.encrypt_rsa(
                            st.session_state.message, st.session_state.d1, st.session_state.n1
                        )

                    if 'ciphertext' in st.session_state:
                        st.write("Ciphertext:")
                        display_cryptographic_result(st.session_state.ciphertext)

                        st.subheader("Signing the Ciphertext")
                        st.write("We sign the ciphertext using Receiver's public key")
                        st.write("We compute using formula as c^(e2) mod n2")
                        if st.button("Sign with Sender Private Key"):
                            st.session_state.signed_ciphertext = RSA_Algorithm.sign(
                                st.session_state.ciphertext, st.session_state.e2,st.session_state.n2
                            )

                        if 'signed_ciphertext' in st.session_state:
                            st.write("Value of Signed Ciphertext is")
                            display_cryptographic_result(st.session_state.signed_ciphertext)

                            st.markdown("---")
                            st.header("The message flows through the network")
                            st.markdown("---")

                            st.subheader("Verification")
                            st.write("The message reaches the Receiver")
                            st.write("The verification takes place using Receiver's Private key")
                            st.write("The Receiver computes c^(d2)mod(n2)")
                            if st.button("Verify with Receiver Private Key"):
                                st.session_state.verified_ciphertext = RSA_Algorithm.verify(
                                    st.session_state.signed_ciphertext, st.session_state.d2,st.session_state.n2
                                )

                            if 'verified_ciphertext' in st.session_state:
                                st.write("Value of Verified Ciphertext is")
                                display_cryptographic_result(st.session_state.verified_ciphertext)

                                st.subheader("Decryption")
                                st.write("Decrypting our message with Public key of Sender")
                                st.write("We compute each character in ciphertext as c^(e1) mod n1")
                                if st.button("Decrypt with Sender Public Key"):
                                    st.session_state.decrypted_plaintext = RSA_Algorithm.decrypt_rsa(
                                        st.session_state.verified_ciphertext, st.session_state.e1,st.session_state.n1
                                    )

                                if 'decrypted_plaintext' in st.session_state:
                                    st.write("Decrypted Plaintext:")
                                    display_cryptographic_result(st.session_state.decrypted_plaintext)