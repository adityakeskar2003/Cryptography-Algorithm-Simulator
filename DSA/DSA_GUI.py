import streamlit as st

from DSA import DSA_algorithm
from display import display_cryptographic_result


def GUI():
    st.write(" ")
    st.header("Digital Signature Algorithm (DSA)")
    st.write("The Digital Signature Algorithm (DSA) is a Federal Information Processing Standard for digital signatures. It was proposed by the National Institute of Standards and Technology (NIST) in 1991 and adopted as FIPS-186 in 1993. DSA is used to generate a digital signature for data integrity and authenticity verification")

    st.subheader("Key Generation")
    st.write("Step 1. Generate a key which is necessary for the encryption")
    st.write("Prime number p: A large prime, usually 1024 to 3072 bits in length.")
    st.write("Subprime q: A 160 to 256-bit prime factor of p - 1")
    st.write("Generate g: A number is g = h^(p-1)/q mod p, where h is an integer less than p and greater than 1")
    if st.button('Generate p, q, g'):
        st.session_state.p, st.session_state.q, st.session_state.g = DSA_algorithm.generate_dsa_parameters()

    if 'p' in st.session_state and 'q' in st.session_state and 'g' in st.session_state:
        st.write("Generated prime number 1, p:")
        display_cryptographic_result(st.session_state.p)
        st.write("Generated prime number 2, q:")
        display_cryptographic_result(st.session_state.q)
        st.write("Generated generator, g:")
        display_cryptographic_result(st.session_state.g)

        st.write(" ")
        st.write("Step 2. Generating Public and Private Key")
        st.write("Private Key x: A randomly chosen integer such that 0 < x < q")
        st.write("Public Key y: Computed as y = g^(x) mod p")
        if st.button("Generate Keys"):
            st.session_state.private_key, st.session_state.public_key = DSA_algorithm.generate_dsa_keys(
                st.session_state.p, st.session_state.q, st.session_state.g)

        if 'private_key' in st.session_state and 'public_key' in st.session_state:
            st.write("Private Key:")
            display_cryptographic_result(st.session_state.private_key)
            st.write("Public Key:")
            display_cryptographic_result(st.session_state.public_key)

            st.write(" ")
            st.subheader("Signature")
            st.write("Signing our message with Private key")
            st.write("Write the message")
            message = st.text_input("Enter the plain text:", key="plain_text_input")
            if message:
                st.session_state.message = message

                if st.button("Get r and s"):
                    st.session_state.H_m,st.session_state.k, st.session_state.k_inv,st.session_state.H_m_str,st.session_state.r, st.session_state.s = DSA_algorithm.sign_message(
                        st.session_state.message, st.session_state.p, st.session_state.q,
                        st.session_state.g, st.session_state.private_key)

                if 'r' in st.session_state and 's' in st.session_state and 'H_m' in st.session_state and 'k' in st.session_state and 'k_inv' in st.session_state and 'H_m_str' in st.session_state:
                    st.write(
                        "Hash the message: Compute the hash of message M using cryptographic Hash function SHA-256 and H(M)")
                    display_cryptographic_result(st.session_state.H_m_str)
                    st.write("Converting the hashed message to integer")
                    display_cryptographic_result(st.session_state.H_m)
                    st.write("Select a random integer k: 0 < k < q")
                    display_cryptographic_result(st.session_state.k)
                    st.write("Calculate k inverse")
                    display_cryptographic_result(st.session_state.k_inv)
                    st.write("Compute r: r = (g^(k) mod p) mod q")
                    display_cryptographic_result(st.session_state.r)
                    st.write("Compute s: s = (k_inv(H(M) + xr)) mod q")
                    display_cryptographic_result(st.session_state.s)

                    st.write("Would you like to tamper with the data?")
                    tamper_choice = st.radio("Choose an option:", ('No', 'Yes'))
                    if tamper_choice == 'Yes':
                        tampered_message = DSA_algorithm.tamper_message(st.session_state.message)
                        st.session_state.message = st.text_input("Tampered Message:", value=tampered_message)

                    if st.button("Verification by receiver"):

                        st.session_state.w,st.session_state.u1,st.session_state.u2,st.session_state.v = DSA_algorithm.verify_signature(
                            st.session_state.message, st.session_state.p, st.session_state.q,
                            st.session_state.g, st.session_state.public_key,
                            st.session_state.r, st.session_state.s)
                        if 'v' in st.session_state and 'w' in st.session_state and 'u1' in st.session_state and 'u2' in st.session_state:
                            st.write("Compute w : w = s^(-1) mod q")
                            display_cryptographic_result(st.session_state.w)
                            st.write("Calculate u1 : u1 = (H(M).w) mod q")
                            display_cryptographic_result(st.session_state.u1)
                            st.write("Calculate u2 : u2 = (r . w) mod q")
                            display_cryptographic_result(st.session_state.u2)
                            st.write("Calculate v: v = ((g^(u1).y^(u2)) mod p)mod q")
                            display_cryptographic_result(st.session_state.v)
                            st.write("Value of r is")
                            display_cryptographic_result(st.session_state.v)
                            display_cryptographic_result(DSA_algorithm.valid(st.session_state.v, st.session_state.r))
