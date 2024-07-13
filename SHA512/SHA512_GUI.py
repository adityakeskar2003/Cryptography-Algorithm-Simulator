import streamlit as st
from SHA512 import SHA512_Algorithm  # Adjust import based on your module structure
from SHA512.SHA512_Algorithm import K, H
from display import display_cryptographic_result


def GUI():
    st.header("Secure Hash Algorithm 512-bit")
    st.write("SHA-512 is a member of the SHA-2 (Secure Hash Algorithm 2) family, designed by the National Security Agency (NSA). It is used in various applications for data integrity, authentication, and cryptographic security")
    st.write(" ")
    st.write("K: Contains the SHA-512 constants used in the compression function")
    display_cryptographic_result(K)
    st.write("")
    st.write("H: Initial hash values (also known as the initial state) used at the start of hashing")
    display_cryptographic_result(H)
    message = st.text_input("Enter the plain text:", key="plain_text_input")

    if st.button("Get Hashed Key") and message:
        encoded_message = message.encode('utf-8')
        hashed_value = SHA512_Algorithm.sha512(encoded_message)
        st.write("SHA512 Hash:")
        display_cryptographic_result(hashed_value.hex())

    # st.markdown("""
    #             <hr><hr>
    #             """, unsafe_allow_html=True)
    # st.header("Glossary")
    # st.subheader("right_rotate(x, n): ((x >> n) | (x << (64 - n))) & 0xFFFFFFFFFFFFFFFF")
    # st.write(
    #     "Perform a right shift on x by n bits: (x >> n).")
    # st.write(
    #     "Perform a left shift on x by (64 - n) bits: (x << (64 - n)).")
    # st.write(
    #     "Combine the results of the right and left shifts using the bitwise OR operation: (x >> n) | (x << (64 - n))")
    # st.write(
    #     "Mask the result with 0xFFFFFFFFFFFFFFFF to ensure it is a 64-bit value: ((x >> n) | (x << (64 - n))) & 0xFFFFFFFFFFFFFFFF")
    # st.write(" ")
    # st.subheader("chunks(message, chunk_size) function")
    # st.write("Split the message into chunks of chunk_size bytes")
