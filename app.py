import streamlit as st
from AES import AES_GUI
from DES import DES_GUI
from DSA import DSA_GUI
from Elgamal import Elgamal_GUI
from SHA256 import SH256_GUI
from MD5 import MD5_GUI
from SHA512 import SHA512_GUI
from RSA import RSA_GUI
from ECC import ECC_GUI
from Deffie_Hellman import Deffie_Hellman_GUI

# Set the title of the Streamlit app
st.set_page_config(page_title="Cryptographic Algorithm Simulator", page_icon="🔒")

# Inject custom CSS to set the background image
# Add your Streamlit content below
st.title("Cryptographic Algorithm Simulator")
st.write(
    "An Interactive Educational Tool to Explore and Understand Cryptographic Algorithms Including Symmetric Encryption, Asymmetric Encryption, Hashing, and Digital Signatures."
)

col1, col2 = st.columns(2)

# Initialize session state if not already set
if 'prev_algorithm_type' not in st.session_state:
    st.session_state.prev_algorithm_type = None
if 'prev_algorithm_options' not in st.session_state:
    st.session_state.prev_algorithm_options = None

with col1:
    algorithm_type = st.selectbox('Algorithm Type', ['Cipher', 'Public Key', 'Signature', 'Hash', 'Symmetric Key Exchange'], key='algorithm_type')

with col2:
    if algorithm_type == 'Cipher':
        algorithm_options = st.selectbox('Algorithm', ['AES(Advanced Encryption System)', 'DES(Data Encryption Standard)'], key='algorithm_options')
    elif algorithm_type == 'Public Key':
        algorithm_options = st.selectbox('Algorithm', ['Elgamal', 'RSA(Rivest–Shamir–Adleman) Algorithm', 'ECC'], key='algorithm_options')
    elif algorithm_type == 'Signature':
        algorithm_options = st.selectbox('Algorithm', ['DSA(Digital Signature Algorithm)', 'RSA(Rivest–Shamir–Adleman) Signing', 'Elgamal Signing', 'ECC_Signing'], key='algorithm_options')
    elif algorithm_type == 'Hash':
        algorithm_options = st.selectbox('Algorithm', ['MD5', 'SHA256', 'SHA512'], key='algorithm_options')
    elif algorithm_type == 'Symmetric Key Exchange':
        algorithm_options = st.selectbox('Algorithm', ['Deffie-Hellman Key Exchange Protocol'], key='algorithm_options')

# Check if the selection has changed and reset if necessary
if st.session_state.prev_algorithm_type != algorithm_type or st.session_state.prev_algorithm_options != algorithm_options:
    st.session_state.prev_algorithm_type = algorithm_type
    st.session_state.prev_algorithm_options = algorithm_options
    st.experimental_rerun()

st.write("When you want to rerun the code please press 'result' button and choose the algorithm")
if st.button("Reset"):
    st.session_state.clear()
    st.rerun()

if algorithm_options == 'AES(Advanced Encryption System)':
    AES_GUI.GUI()

if algorithm_options == 'DES(Data Encryption Standard)':
    DES_GUI.GUI()

if algorithm_options == 'DSA(Digital Signature Algorithm)':
    DSA_GUI.GUI()

if algorithm_options == 'Elgamal':
    Elgamal_GUI.GUI()

if algorithm_options == 'SHA256':
    SH256_GUI.GUI()

if algorithm_options == 'MD5':
    MD5_GUI.GUI()

if algorithm_options == 'SHA512':
    SHA512_GUI.GUI()

if algorithm_options == 'RSA(Rivest–Shamir–Adleman) Algorithm':
    RSA_GUI.GUI()

if algorithm_options == 'RSA(Rivest–Shamir–Adleman) Signing':
    RSA_GUI.GUI_Signing()

if algorithm_options == 'Elgamal Signing':
    Elgamal_GUI.GUI_Signing()

if algorithm_options == 'Deffie-Hellman Key Exchange Protocol':
    Deffie_Hellman_GUI.GUI()

if algorithm_options == 'ECC':
    ECC_GUI.GUI()

if algorithm_options == 'ECC_Signing':
    ECC_GUI.GUI_Signing()
