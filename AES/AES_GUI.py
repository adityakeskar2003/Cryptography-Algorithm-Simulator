import streamlit as st
from AES import AES_algorithm
from display import display_cryptographic_result


def GUI():
    st.write(" ")
    st.subheader("Advanced Encryption Standard (AES)")
    st.write("Key Features of AES:")
    st.write("1. Symmetric Key Encryption: AES uses the same key for both encryption and decryption.")
    st.write("2. Block Cipher: It encrypts data in fixed-size blocks. The standard block size is 128 bits.")
    st.write("3. Key Sizes: AES supports three key sizes: 128, 192, and 256 bits. The different key sizes affect the number of rounds used in the encryption process.")

    st.subheader("Key Generation")
    st.write(" A 128-bit (16-byte) random key is generated for AES encryption")

    if st.button('Generate Key'):
        st.session_state.key = AES_algorithm.generate_aes_key()

    if 'key' in st.session_state:
        st.write("Generated key:")
        display_cryptographic_result(st.session_state.key)

        st.write(" ")
        st.subheader("Encryption")
        st.write("Step 1. Pad a plaintext to make its length a multiple of AES cipher block")
        st.write("Enter the plain text and press Enter to update")

        plaintext = st.text_input("Enter the plain text:", key="plain_text_input")

        if plaintext:
            st.session_state.plaintext = plaintext
            st.session_state.padded_plaintext = AES_algorithm.encrypt_step1(plaintext)

        if 'padded_plaintext' in st.session_state:
            st.write("Padded Plaintext:")
            display_cryptographic_result(st.session_state.padded_plaintext)

            st.write(" ")
            st.write("Step 2. An initialization vector (IV) is generated, and an AES cipher object in CBC mode is created with the key and IV")

            if st.button("Generate IV and Cipher"):
                st.session_state.iv, st.session_state.cipher = AES_algorithm.encrypt_step2(st.session_state.key)

            if 'iv' in st.session_state and 'cipher' in st.session_state:
                st.write("Initialization Vector (IV):")
                display_cryptographic_result(st.session_state.iv)

                st.write("Cipher:")
                display_cryptographic_result(st.session_state.cipher)

                st.write(" ")
                st.write("Step 3. Encrypt Padded Plaintext to Ciphertext")
                st.write("The padded plaintext is encrypted using the AES cipher object")
                if st.button("Encrypt Padded Plaintext to Ciphertext"):
                    st.session_state.ciphertext = AES_algorithm.encrypt_step3(st.session_state.plaintext,
                                                                              st.session_state.key)

                if 'ciphertext' in st.session_state:
                    st.write("Ciphertext:")
                    display_cryptographic_result(st.session_state.ciphertext)

                    st.write(" ")
                    st.write("Step 4. Full Encryption with Base64 encoding")
                    st.write("The padded plaintext is encrypted, and both IV and ciphertext are encoded in Base64 for safe transmission/storage.")
                    if st.button("Encode Ciphertext"):
                        st.session_state.encoded_iv, st.session_state.encoded_ciphertext = AES_algorithm.encrypt_step4(
                            st.session_state.plaintext, st.session_state.key)

                    if 'encoded_iv' in st.session_state and 'encoded_ciphertext' in st.session_state:
                        st.write("Encoded IV:")
                        display_cryptographic_result(st.session_state.encoded_iv)
                        st.write("Encoded Ciphertext:")
                        display_cryptographic_result(st.session_state.encoded_ciphertext)

                        st.write(" ")
                        st.subheader("Decryption")

                        st.write("Step 1. Decode Base64 IV and ciphertext")
                        st.write("The Base64-encoded IV and ciphertext are decoded back to their original byte forms")
                        if st.button("Decode IV and Ciphertext"):
                            st.session_state.iv, st.session_state.ciphertext = AES_algorithm.decrypt_step1(
                                st.session_state.encoded_iv, st.session_state.encoded_ciphertext)
                            st.session_state.decode_clicked = True

                        if 'decode_clicked' in st.session_state and st.session_state.decode_clicked:
                            if 'iv' in st.session_state and 'ciphertext' in st.session_state:
                                st.write("Decoded IV:")
                                display_cryptographic_result(st.session_state.iv)

                                st.write("Decoded Ciphertext:")
                                display_cryptographic_result(st.session_state.ciphertext)

                                st.write(" ")
                                st.write("Step 2. Create AES cipher object for decryption")
                                st.write("An AES cipher object in CBC mode is created with the key and decoded IV.")

                                if st.button("Create AES Cipher"):
                                    st.session_state.decoded_cipher = AES_algorithm.decrypt_step2(
                                        st.session_state.encoded_iv, st.session_state.encoded_ciphertext,
                                        st.session_state.key)
                                    st.session_state.create_cipher_clicked = True

                                if 'create_cipher_clicked' in st.session_state and st.session_state.create_cipher_clicked:
                                    if 'decoded_cipher' in st.session_state:
                                        st.write("Decoded Cipher Object:")
                                        display_cryptographic_result(st.session_state.decoded_cipher)
                                        st.write("AES Cipher created with provided IV and Key")

                                        st.write(" ")
                                        st.write("Step 3. Decrypt the Ciphertext to Plaintext")

                                        if st.button("Decrypt Ciphertext to Plaintext"):
                                            st.session_state.decoded_plaintext = AES_algorithm.decrypt_step3(
                                                st.session_state.encoded_iv, st.session_state.encoded_ciphertext,
                                                st.session_state.key)

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

    st.subheader("Cipher Block Chaining (CBC) Mode: ")
    st.write(
        "Cipher Block Chaining (CBC) mode is an encryption mode for block ciphers. It uses the previously encrypted block to influence the encryption of the current block.")
    st.write("Encryption:")
    st.write("Step 1: XOR the plaintext block with the IV (for the first block) or the previous ciphertext block (for subsequent blocks).")
    st.write("Step 2: Encrypt the result using the block cipher (e.g., AES).")
    st.write("Step 3: The output ciphertext block becomes the input for the next block: Ci = Ek(Pi XOR Ci-1 , where Ci is the current ciphertext block, Pi is the current plaintext block, Ek is the encryption function with key K and Ci-1 is the previous ciphertext block or IV for the first block")
    st.write("")
    st.write("Decryption:")
    st.write("Step 1: Decrypt the ciphertext block using the block cipher")
    st.write("Step 2: XOR the decrypted block with the IV (for the first block) or the previous ciphertext block (for subsequent blocks) to get the plaintext block: Pi = Dk(Ci) XOR Ci-1 where Pi is the current plaintext block, Dk is the decryption function with key k, Ci-1 is the previous ciphertext block or IV for the first block.")
