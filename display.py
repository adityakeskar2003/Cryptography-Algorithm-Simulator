import streamlit as st

def display_cryptographic_result(ciphertext):
    st.markdown("---")

    st.code(ciphertext, language='plaintext')  # Display ciphertext in a code block

    st.markdown("---")  # Horizontal divider
