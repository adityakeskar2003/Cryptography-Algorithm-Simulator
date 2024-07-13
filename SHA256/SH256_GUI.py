import streamlit as st
from SHA256 import SHA256_Algorithm
from SHA256.SHA256_Algorithm import K, H
from display import display_cryptographic_result

def GUI():
    st.header("Secure Hash Algorithm 256-bit (SHA-256)")
    st.write("SHA-256 (Secure Hash Algorithm 256-bit) is a member of the SHA-2 (Secure Hash Algorithm 2) family, designed by the National Security Agency (NSA). It is widely used for its strong security features in various applications, including data integrity verification and cryptographic functions. ")
    st.write("The K array contains 64 constant values used in the SHA-256 compression function's main loop. These constants are the first 32 bits of the fractional parts of the cube roots of the first 64 prime numbers.")
    display_cryptographic_result(K)
    st.write("")
    st.write("The H array contains the initial hash values for the SHA-256 algorithm. These values are the first 32 bits of the fractional parts of the square roots of the first 8 prime numbers.")
    display_cryptographic_result(H)
    message = st.text_input("Enter the plain text:", key="plain_text_input")
    if message:
        st.session_state.message = message

    if st.button("Get Hashed Key"):
        st.session_state.hashed_value = SHA256_Algorithm.sha256_hash(st.session_state.message.encode('utf-8'))
        if 'hashed_value' in st.session_state:
            encoded_message = message.encode('utf-8')
            hashed_value = SHA256_Algorithm.sha256_hash(encoded_message)
            st.write("SHA256 Hash:")
            display_cryptographic_result(hashed_value.hex())

    # st.markdown("""
    #         <hr><hr>
    #         """, unsafe_allow_html=True)
    # st.header("Glossary")
    # st.subheader("rotr(x, n): (x >> n) | (x << (32 - n)) & 0xFFFFFFFF")
    # st.write(
    #     "This function performs a left rotation (circular shift) on a 32-bit integer x by n positions.")
    # st.write(
    #     "(x >> n): Right shifts the value x by n bits. Bits that are shifted out from the right are discarded.")
    # st.write(
    #     "(x << (32 - n)): Left shifts the value x by (32 - n) bits. This fills the rightmost n bits with zeros.")
    # st.write(
    #     "(x >> n) | (x << (32 - n)): Combines the results of the right and left shifts using the bitwise OR (|) operation")
    # st.write(
    #     "& 0xFFFFFFFF: This bitwise AND operation ensures that the result fits within a 32-bit unsigned integer. It masks out any bits beyond the 32-bit boundary to maintain the integer size and prevent overflow.")
    # st.write(" ")
    # st.subheader("Example")
    # st.write("If x = 0x12345678 (32-bit hexadecimal representation) and n = 8:")
    # st.write("x >> n shifts 0x12345678 right by 8 bits: 0x00123456.")
    # st.write("x << (32 - n) shifts 0x12345678 left by (32 - 8) bits: 0x56780000.")
    # st.write("(x >> n) | (x << (32 - n)) combines 0x00123456 and 0x56780000")