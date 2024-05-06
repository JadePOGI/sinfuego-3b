from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
import os
import streamlit as st

st.header("Welcome to AES(Advanced Encryption Standard)!🔐")
st.write("AES has been extensively studied and analyzed by cryptographers, and it has stood the test of time as a highly secure and efficient encryption algorithm. Its adoption has been widespread across various applications, including securing communication, protecting data at rest, and ensuring the confidentiality of sensitive information.")

def encrypt_AES(data, key):
    # Convert data to bytes
    data_bytes = data.encode()

    # Generate a random initialization vector
    iv = os.urandom(16)

    # Create an AES cipher object
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

    # Create a padder using PKCS7 padding scheme
    padder = padding.PKCS7(128).padder()

    # Apply padding to the data
    padded_data = padder.update(data_bytes) + padder.finalize()

    # Encrypt the padded data
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(padded_data) + encryptor.finalize()

    return iv, cipher_text

def decrypt_AES(iv, cipher_text, key):
    # Create an AES cipher object
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

    # Create an unpadder using PKCS7 padding scheme
    unpadder = padding.PKCS7(128).unpadder()

    # Decrypt the cipher text
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(cipher_text) + decryptor.finalize()

    # Remove padding
    unpadded_data = unpadder.update(padded_data) + unpadder.finalize()

    # Convert bytes to string
    decrypted_data = unpadded_data.decode()

    return decrypted_data

option = st.radio(
    "Choose Input:",
    ["Text", "File"])

if option == 'Text':
    # Generate a random 256-bit (32-byte) key
    key = os.urandom(32)

    # Data to be encrypted
    data = st.text_input("Enter your text to Encrypt")
    btn_submit = st.button('Encrypt')
    if btn_submit:
        # Encrypt the data
        iv, cipher_text = encrypt_AES(data, key)
        st.write("Encrypted data:", cipher_text)
    
        # Data to be encrypted

    data_ = st.text_input("Enter your text to Decrypt")
    btn_decrypt = st.button('Decrypt')
        
    if btn_decrypt:
        # Decrypt the data
        iv, cipher_text = encrypt_AES(data, key)
        decrypted_data = decrypt_AES(iv, cipher_text, key)
        st.write("Decrypted data:", decrypted_data)

elif option == 'File':
    st.write('Enter Your Selected File.')
    uploaded_file = st.file_uploader("Choose a file")
    if uploaded_file is not None:
        # Read file contents as string
        file_contents = uploaded_file.getvalue().decode("utf-8")
        st.write("File contents:", file_contents)
        # Generate a random 256-bit (32-byte) key
        key = os.urandom(32)
        # Encrypt the file contents
        iv, cipher_text = encrypt_AES(file_contents, key)
        st.write("Encryption of file contents:", cipher_text)
        
        # Decrypt the file contents
        decrypted_data = decrypt_AES(iv, cipher_text, key)
        st.write("Decryption of file contents:", decrypted_data)

   
