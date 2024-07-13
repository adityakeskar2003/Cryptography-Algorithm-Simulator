import streamlit as st
from MD5 import MD5_Algorithm  # Adjust import based on your module structure
from display import display_cryptographic_result


def GUI():
    st.header("Message Digest Algorithm 5 (MD5)")
    st.write("Message Digest Algorithm 5, is a widely used cryptographic hash function that produces a 128-bit (16-byte) hash value from an input message. It is commonly expressed as a 32-digit hexadecimal number. MD5 is primarily used to verify data integrity, ensuring that a message has not been altered during transmission")
    st.write("")
    message = st.text_input("Enter the plain text:", key="plain_text_input")

    if st.button("Get Hashed Key") and message:
        st.write("Input message:")
        display_cryptographic_result(message)
        encoded_message = message.encode('utf-8')
        hashed_value = MD5_Algorithm.md5(encoded_message)
        st.write("MD5 Hash:")
        display_cryptographic_result(hashed_value)

    st.markdown("""
        <hr><hr>
        """, unsafe_allow_html=True)
    st.header("Glossary")
    st.subheader("left_rotate Function(x,c) : ((x << c) & 0xFFFFFFFF) | (x >> (32 - c))")
    st.write(
        "This function performs a left rotation (circular shift) on a 32-bit integer x by c positions.")
    st.write(
        "x << c: Shifts x to the left by c bits. Bits shifted out on the left are discarded.")
    st.write(
        "& 0xFFFFFFFF: Ensures that the result is a 32-bit integer by masking the upper bits.")
    st.write(
        "x >> (32 - c): Shifts x to the right by (32 - c) bits. Bits shifted out on the right are discarded, but since we are dealing with unsigned integers, the leftmost bits are filled with zeros.")
    st.write(
        "|: Combines the left and right shifts, effectively rotating the bits.")
    st.write(" ")
    st.subheader("F(X,Y,Z) Function : (X & Y) | (~X & Z)")
    st.write(
        "The F function is used in the first round of the MD5 transformation.")
    st.write("X & Y: Bitwise AND operation between X and Y.")
    st.write("~X & Z: Bitwise AND operation between the bitwise NOT of X and Z.")
    st.write("|: Combines the results using bitwise OR.")
    st.write("")
    st.subheader("G(X,Y,Z) Function : (X & Z) | (Y & ~Z)")
    st.write(
        "The G function is used in the second round of the MD5 transformation")
    st.write("X & Z: Bitwise AND operation between X and Z.")
    st.write("Y & ~Z: Bitwise AND operation between Y and the bitwise NOT of Z")
    st.write("|: Combines the results using bitwise OR.")
    st.write("")
    st.subheader("H(X, Y, Z) Function : X ^ Y ^ Z")
    st.write(
        "The H function is used in the third round of the MD5 transformation.")
    st.write("X ^ Y ^ Z: Bitwise XOR operation between X, Y, and Z.")
    st.write("")
    st.subheader("I(X, Y, Z)) Function : Y ^ (X | ~Z)")
    st.write(
        "The I function is used in the fourth round of the MD5 transformation.")
    st.write("X | ~Z: Bitwise OR operation between X and the bitwise NOT of Z.")
    st.write("Y ^: Bitwise XOR operation between Y and the result of the previous operation.")
    st.write("")
    st.subheader("T constant : T = [int(abs(math.sin(i + 1)) * 2 ** 32) & 0xFFFFFFFF for i in range(64)]")
    st.write("The T list contains 64 precomputed constants derived from the sine function. These constants are used in each round of the MD5 algorithm to introduce non-linearity.")


