from DES import DES_algorithm
import streamlit as st

from display import display_cryptographic_result


def GUI():
    st.write(" ")
    st.subheader("Data Encryption Standard (DES)")
    st.subheader("Key Generation")
    st.write("DES uses a 56-bit key for encryption, typically represented as an 8-byte (64-bit) value where 8 bits are used for parity")
    if st.button('Generate Key'):
        st.session_state.key = DES_algorithm.generate_des_key()

    if 'key' in st.session_state:
        st.write("Generated key:")
        display_cryptographic_result(st.session_state.key)

        st.write(" ")
        st.write("Step 1. Convert plaintext to bytes and pad to match DES block size")
        st.write("Plaintext is converted to bytes and padded to make its length a multiple of the DES block size (8 bytes).")
        plaintext = st.text_input("Enter the plain text:", key="plain_text_input")

        if plaintext:
            st.session_state.plaintext = plaintext
            st.session_state.padded_plaintext = DES_algorithm.encrypt_step1(plaintext)

        if 'padded_plaintext' in st.session_state:
            st.write("Padded Plaintext:")
            display_cryptographic_result(st.session_state.padded_plaintext)

            st.write(" ")
            st.write("Step 2. Generate DES cipher object with ECB mode")
            st.write("A DES cipher object is created in ECB (Electronic Codebook) mode. In ECB mode, each block is encrypted independently, which can be less secure due to the lack of randomness.")

            if st.button("Generate Cipher"):
                st.session_state.cipher = DES_algorithm.encrypt_step2(st.session_state.key)

            if 'cipher' in st.session_state:
                st.write("Cipher:")
                display_cryptographic_result(st.session_state.cipher)

                st.write(" ")
                st.write("Step 3. Encrypt the padded plaintext")
                st.write("The padded plaintext is encrypted using the DES cipher object.")
                if st.button("Encrypt Padded Plaintext to Ciphertext"):
                    st.session_state.ciphertext = DES_algorithm.encrypt_step3(st.session_state.plaintext,
                                                                              st.session_state.key)

                if 'ciphertext' in st.session_state:
                    st.write("Ciphertext:")
                    display_cryptographic_result(st.session_state.ciphertext)

                    st.write(" ")
                    st.write("Step 4. Full Encryption with Base64 encoding")
                    st.write("The padded plaintext is encrypted, and the ciphertext is encoded in Base64 for safe transmission/storage.")
                    if st.button("Encode Ciphertext"):
                        st.session_state.encoded_ciphertext = DES_algorithm.encrypt_step4(
                            st.session_state.plaintext, st.session_state.key)

                    if 'encoded_ciphertext' in st.session_state:
                        st.write("Encoded Ciphertext:")
                        display_cryptographic_result(st.session_state.encoded_ciphertext)

                        st.write(" ")
                        st.header("Decryption")

                        st.write("Step 1. Decode Base64 and return ciphertext")
                        st.write("The Base64-encoded ciphertext is decoded back to its original byte form.")
                        if st.button("Decode Ciphertext"):
                            st.session_state.decoded_ciphertext = DES_algorithm.decrypt_step1(
                                st.session_state.encoded_ciphertext)
                            st.session_state.decode_clicked = True

                        if 'decode_clicked' in st.session_state and st.session_state.decode_clicked:
                            if 'ciphertext' in st.session_state:
                                st.write("Decoded Ciphertext:")
                                display_cryptographic_result(st.session_state.decoded_ciphertext)

                                st.write(" ")
                                st.write("Step 2. Create DES cipher object with ECB mode and key")
                                st.write(" A DES cipher object in ECB mode is created with the given key.")

                                if st.button("Create DES Cipher"):
                                    st.session_state.decoded_cipher = DES_algorithm.decrypt_step2(
                                        st.session_state.encoded_ciphertext,
                                        st.session_state.key)
                                    st.session_state.create_cipher_clicked = True

                                if 'create_cipher_clicked' in st.session_state and st.session_state.create_cipher_clicked:
                                    if 'decoded_cipher' in st.session_state:
                                        st.write("Decoded Cipher Object:")
                                        display_cryptographic_result(st.session_state.decoded_cipher)
                                        st.write("DES Cipher created with provided Encoded Ciphertext and Key")

                                        st.write(" ")
                                        st.write("Step 3. Decrypt the ciphertext and unpad the plaintext")
                                        st.write("The ciphertext is decrypted, the padding is removed, and the original plaintext is obtained.")
                                        if st.button("Decrypt Ciphertext to Plaintext"):
                                            st.session_state.decoded_plaintext = DES_algorithm.decrypt_step3(
                                                st.session_state.decoded_cipher,
                                                st.session_state.decoded_ciphertext)

                                        if 'decoded_plaintext' in st.session_state:
                                            st.write("Decoded Plaintext:")
                                            display_cryptographic_result(st.session_state.decoded_plaintext)

    st.markdown("""
            <hr><hr>
            """, unsafe_allow_html=True)
    st.header("Glossary")
    st.subheader("Initialisation Vector: ")
    st.write(
        "An Initialization Vector (IV) is a random or pseudo-random value that is used in combination with a secret key to provide an additional layer of security for encryption algorithms.")
    st.write(
        "Purpose: The IV ensures that the same plaintext block will encrypt to different ciphertext blocks each time, even if the same key is used. This prevents attackers from inferring any patterns in the encrypted data.")

    st.subheader("Electronic Codebook (ECB) Mode: ")
    st.write(
        "Electronic Codebook (ECB) mode is an encryption mode for block ciphers. It is the simplest mode, where each block of plaintext is encrypted independently of any other block.")
    st.write("Encryption:")
    st.write(
            "Step 1: Each plaintext block is encrypted separately using the same key. Ci = Ek(Pi) where Ci = is the current ciphertext block, Pi = is the current plaintext block, and Ek = is the encryption function with key K")
    st.write("")
    st.write("Decryption:")
    st.write("Step 1: Each ciphertext block is decrypted separately using the same key. Pi = Dk(Ci) where Ci = is the current ciphertext block, Pi = is the current plaintext block, and Dk = is the decryption function with key K")
