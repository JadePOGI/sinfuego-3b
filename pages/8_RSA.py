import streamlit as st
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
import base64
import os

# Function to generate RSA keys
def generate_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

# Function to encrypt a message using hybrid RSA and AES
def encrypt_message(public_key, message):
    # Generate AES session key
    session_key = get_random_bytes(16)
    
    # Encrypt the session key with RSA public key
    rsa_key = RSA.import_key(public_key)
    rsa_cipher = PKCS1_OAEP.new(rsa_key)
    encrypted_session_key = rsa_cipher.encrypt(session_key)
    
    # Encrypt the message with AES session key
    aes_cipher = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = aes_cipher.encrypt_and_digest(message)
    
    return encrypted_session_key + aes_cipher.nonce + tag + ciphertext

# Function to decrypt a message using hybrid RSA and AES
def decrypt_message(private_key, encrypted_message):
    # Extract the components
    rsa_encrypted_session_key = encrypted_message[:256]
    nonce = encrypted_message[256:272]
    tag = encrypted_message[272:288]
    ciphertext = encrypted_message[288:]
    
    # Decrypt the session key with RSA private key
    rsa_key = RSA.import_key(private_key)
    rsa_cipher = PKCS1_OAEP.new(rsa_key)
    session_key = rsa_cipher.decrypt(rsa_encrypted_session_key)
    
    # Decrypt the message with AES session key
    aes_cipher = AES.new(session_key, AES.MODE_EAX, nonce=nonce)
    decrypted_message = aes_cipher.decrypt_and_verify(ciphertext, tag)
    
    return decrypted_message

# Streamlit App
st.title("RSA Encryption/Decryption App")

option = st.selectbox(
    "Choose the input type",
    ("Text Input", "File Upload")
)

if 'private_key' not in st.session_state:
    private_key, public_key = generate_keys()
    st.session_state['private_key'] = private_key
    st.session_state['public_key'] = public_key

if option == "Text Input":
    message = st.text_area("Enter the message you want to encrypt or decrypt:")
    
    if st.button("Encrypt"):
        encrypted_message = encrypt_message(st.session_state['public_key'], message.encode())
        st.session_state['encrypted_message'] = base64.b64encode(encrypted_message).decode('utf-8')
        st.session_state['last_action'] = 'encrypt'
        
    if st.button("Decrypt"):
        if 'encrypted_message' in st.session_state:
            decrypted_message = decrypt_message(st.session_state['private_key'], base64.b64decode(st.session_state['encrypted_message']))
            st.text_area("Decrypted Message", value=decrypted_message.decode('utf-8'), height=200)
            st.session_state['last_action'] = 'decrypt'
        else:
            st.error("No encrypted message found. Please encrypt a message first.")

    if 'encrypted_message' in st.session_state and st.session_state.get('last_action') == 'encrypt':
        st.text_area("Encrypted Message", value=st.session_state['encrypted_message'], height=200)
    
elif option == "File Upload":
    file_operation = st.selectbox("Choose operation:", ["Encrypt a file", "Decrypt a file"])

    if file_operation == "Encrypt a file":
        uploaded_file = st.file_uploader("Choose a file to encrypt", key="encrypt")

        if uploaded_file is not None:
            file_data = uploaded_file.read()

            if st.button("Encrypt File"):
                encrypted_file_data = encrypt_message(st.session_state['public_key'], file_data)
                
                # Save encrypted file
                encrypted_file_name = uploaded_file.name + ".enc"
                st.session_state['encrypted_file_data'] = encrypted_file_data
                
                st.download_button(
                    label="Download Encrypted File",
                    data=encrypted_file_data,
                    file_name=encrypted_file_name,
                    mime="application/octet-stream"
                )

    elif file_operation == "Decrypt a file":
        encrypted_file = st.file_uploader("Choose a file to decrypt", key="decrypt")

        if encrypted_file is not None:
            encrypted_file_data = encrypted_file.read()

            if st.button("Decrypt File"):
                decrypted_file_data = decrypt_message(st.session_state['private_key'], encrypted_file_data)
                
                # Save decrypted file
                decrypted_file_name = "decrypted_" + os.path.splitext(encrypted_file.name)[0]
                st.session_state['decrypted_file_data'] = decrypted_file_data
                
                st.download_button(
                    label="Download Decrypted File",
                    data=decrypted_file_data,
                    file_name=decrypted_file_name,
                    mime="application/octet-stream"
                )
