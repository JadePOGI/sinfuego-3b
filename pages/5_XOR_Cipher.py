import streamlit as st

st.header("Welcome to XOR Cipher!🔐")

def xor_encrypt(plaintext, key):
    ciphertext = bytearray()
    for i in range(len(plaintext)):
        plaintext_byte = plaintext[i]
        key_byte = key[i % len(key)]

        xor_result = plaintext_byte ^ key_byte
        st.write('Plaintext byte:', format(plaintext_byte, '08b'), "=", chr(plaintext_byte))
        st.write('Key byte:            ', format(key_byte, '08b'), "=", chr(key_byte))
        st.write('XOR result:    ', format(xor_result, '08b'), "=", chr(xor_result))
        st.write('--------------------')
        ciphertext.append(xor_result)

    return ciphertext

def xor_decrypt(ciphertext, key):
    plaintext = bytearray()
    for i in range(len(ciphertext)):
        ciphertext_byte = ciphertext[i]
        key_byte = key[i % len(key)]

        xor_result = ciphertext_byte ^ key_byte
        plaintext.append(xor_result)

    return plaintext

option = st.radio("Choose input type:", ("Text", "File"))

if option == "Text":
    plaintext = bytes(st.text_area("Plaintext").encode())
    key = bytes(st.text_area("Key").encode())
elif option == "File":
    uploaded_file = st.file_uploader("Upload a file")
    if uploaded_file is not None:
        plaintext = uploaded_file.read()
        key = bytes(st.text_input("Key").encode())  # Encode the key input
    else:
        st.warning("Please upload a file.")

if st.button('Submit', key=1, type="primary"):
    if not key:
        st.error('Invalid Key!')
    else:
        if plaintext == key:
            st.warning('Plaintext should not be equal to the key')
        elif len(plaintext.decode()) < len(key.decode()):
            st.warning('Plaintext length should be equal or greater than the length of key')
        else:
            col1, col2 = st.columns(2)
            with col1:
                encrypted = xor_encrypt(plaintext, key)
                st.write('Ciphertext:', encrypted.decode())
            with col2:
                decrypted = xor_decrypt(encrypted, key)
                st.write('Decrypted:', decrypted.decode())
