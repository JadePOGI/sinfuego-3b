import streamlit as st

st.header("Welcome to Caesar Cipher!🔐")
st.write("Caesar Cipher Technique is the simple and easy method of encryption technique.")

def caesar_cipher(text, shift):
    encrypted_text = ""
    for char in text:
        if char.isalpha():  # Check if the character is a letter
            shifted = ord(char) + shift
            if char.islower():
                if shifted > ord('z'):
                    shifted -= 26
                elif shifted < ord('a'):
                    shifted += 26
            elif char.isupper():
                if shifted > ord('Z'):
                    shifted -= 26
                elif shifted < ord('A'):
                    shifted += 26
            encrypted_text += chr(shifted)
        else:
            encrypted_text += char
    return encrypted_text

def caesar_decipher(text, shift):
    return caesar_cipher(text, -shift)

genre = st.radio(
    "Choose Input:",
    ["Text", "File"])

if genre == 'Text':
    plaintext = st.text_area('Enter your text to Encrypt')
    a = 5

    encrypt_submit = st.button('Submit')
    if encrypt_submit:
        encrypted_text = caesar_cipher(plaintext, a)
        st.write("Encrypted:", encrypted_text)

        # Decrypting the ciphertext
        decrypted_text = caesar_decipher(encrypted_text, a)
        st.write("Decrypted:", decrypted_text)

elif genre == 'File':
    st.write('Enter Your Selected File.')
    uploaded_file = st.file_uploader("Choose a file")
    if uploaded_file is not None:
        file_contents = uploaded_file.getvalue().decode("utf-8")
        st.write("File contents:", file_contents)
        
        encrypt_btn = st.radio('Choose one', options=('Encrypt', 'Decrypt'))

        if encrypt_btn == 'Encrypt':
            a = 5
            encrypted_text = caesar_cipher(file_contents, a)
            st.write("Encrypted file contents:", encrypted_text)
        
        elif encrypt_btn == 'Decrypt':
            a = 5
            encrypted_text = caesar_cipher(file_contents, a)
            decrypted_text = caesar_decipher(encrypted_text, a)
            st.write("Decrypted file contents:", decrypted_text)
