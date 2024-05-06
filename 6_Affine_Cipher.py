import string
import streamlit as st

st.header("Welcome to Affine Cipher!🔐")
st.write("The Affine Cipher is based on mathematical principles and has roots in ancient cryptography. It is believed to have been used by civilizations such as the Greeks and Romans for secret communication.")

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('Modular inverse does not exist')
    else:
        return x % m

def affine_encrypt(plaintext, a, b):
    alphabet = string.ascii_lowercase
    ciphertext = ''
    for char in plaintext.lower():
        if char in alphabet:
            idx = alphabet.index(char)
            encrypted_idx = (a * idx + b) % 26
            ciphertext += alphabet[encrypted_idx]
        else:
            ciphertext += char
    return ciphertext

def affine_decrypt(ciphertext, a, b):
    alphabet = string.ascii_lowercase
    plaintext = ''
    a_inv = modinv(a, 26)
    for char in ciphertext:
        if char.lower() in alphabet:
            idx = alphabet.index(char.lower())
            decrypted_idx = (a_inv * (idx - b)) % 26
            plaintext += alphabet[decrypted_idx]
        else:
            plaintext += char
    return plaintext


genre = st.radio(
    "Choose Input:",
    ["Text", "File"])

if genre == 'Text':
    # Example usage:
    plaintext = st.text_area('Enter a plaintext')
    a = 5
    b = 8

    encrypt_submit = st.button('Submit')
    if encrypt_submit:
        encrypted_text = affine_encrypt(plaintext, a, b)
        st.write("Encrypted:", encrypted_text)

        # Decrypting the ciphertext
        decrypted_text = affine_decrypt(encrypted_text, a, b)
        st.write("Decrypted:", decrypted_text)

elif genre == 'File':
    st.write('Enter Your Selected File.')
    uploaded_file = st.file_uploader("Choose a file")
    if uploaded_file is not None:
        # Read file contents as string
        file_contents = uploaded_file.getvalue().decode("utf-8")
        st.write("File contents:", file_contents)
        
        encrypt_btn = st.radio('Choose one', options=('Encrypt', 'Decrypt'))

        if encrypt_btn == 'Encrypt':
            a = 5
            b = 8
            # # Prompt user to input values of 'a' and 'b' for encryption
            # a = st.number_input("Enter the value of 'a' for encryption", value=5)
            # b = st.number_input("Enter the value of 'b' for encryption", value=8)

            # Encrypt the file contents using the provided 'a' and 'b' values
            encrypted_text = affine_encrypt(file_contents, a, b)
            st.write("Encrypted of file contents:", encrypted_text)
        
        elif encrypt_btn == 'Decrypt':
            # Prompt user to input values of 'a' and 'b' for decryption
            # a = st.number_input("Enter the value of 'a' for decryption", value=5)
            # b = st.number_input("Enter the value of 'b' for decryption", value=8)
            a = 5
            b = 8
            encrypted_text = affine_encrypt(file_contents, a, b)
            # Decrypt the file contents using the provided 'a' and 'b' values
            decrypted_text = affine_decrypt(encrypted_text, a, b)
            st.write("Decrypted of file contents:", decrypted_text)
