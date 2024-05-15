import string
import streamlit as st
import fitz  # PyMuPDF

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

def extract_text_from_pdf(file):
    doc = fitz.open(stream=file.read(), filetype="pdf")
    text = ""
    for page in doc:
        text += page.get_text()
    return text

genre = st.radio("Choose Input:", ["Text", "File"])

if genre == 'Text':
    plaintext = st.text_area('Enter a plaintext')
    a = st.number_input("Enter the value of 'a' (must be coprime with 26)", value=5, min_value=1, step=1)
    b = st.number_input("Enter the value of 'b'", value=8, min_value=0, step=1)

    encrypt_submit = st.button('Submit')
    if encrypt_submit:
        encrypted_text = affine_encrypt(plaintext, a, b)
        st.write("Encrypted:", encrypted_text)

        decrypted_text = affine_decrypt(encrypted_text, a, b)
        st.write("Decrypted:", decrypted_text)

elif genre == 'File':
    st.write('Choose an option:')
    option = st.radio('', ['Encrypt', 'Decrypt'])

    if option == 'Encrypt':
        st.write('Upload Your File to Encrypt:')
        uploaded_file = st.file_uploader("Choose a file", type=["txt", "pdf"])
        if uploaded_file is not None:
            file_type = uploaded_file.type
            if file_type == "application/pdf":
                file_contents = extract_text_from_pdf(uploaded_file)
            else:
                file_contents = uploaded_file.getvalue().decode("utf-8")

            a = st.number_input("Enter the value of 'a' (must be coprime with 26)", value=5, min_value=1, step=1)
            b = st.number_input("Enter the value of 'b'", value=8, min_value=0, step=1)

            if not egcd(a, 26)[0] == 1:
                st.error("'a' must be coprime with 26 for the cipher to work.")
            else:
                encrypted_text = affine_encrypt(file_contents, a, b)
                st.write("Encryption completed.")
                st.download_button("Download Encrypted File", encrypted_text, file_name="encrypted_file.txt")

    elif option == 'Decrypt':
        st.write('Upload Your Encrypted File to Decrypt:')
        uploaded_file = st.file_uploader("Choose a file", type=["txt"])
        if uploaded_file is not None:
            encrypted_contents = uploaded_file.getvalue().decode("utf-8")

            a = st.number_input("Enter the value of 'a' (must be coprime with 26)", value=5, min_value=1, step=1)
            b = st.number_input("Enter the value of 'b'", value=8, min_value=0, step=1)

            if not egcd(a, 26)[0] == 1:
                st.error("'a' must be coprime with 26 for the cipher to work.")
            else:
                decrypted_text = affine_decrypt(encrypted_contents, a, b)
                st.write("Decryption completed.")
                st.download_button("Download Decrypted File", decrypted_text, file_name="decrypted_file.txt")
