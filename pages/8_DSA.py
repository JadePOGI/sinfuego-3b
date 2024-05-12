import streamlit as st
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.exceptions import InvalidSignature

st.header("Welcome to DSA (Digital Signature Algorithm)!🔐")
st.write("Digital Signature Algorithm (DSA) is a public-key cryptography algorithm used for digital signatures. It provides a method for signing and verifying digital messages to ensure their integrity and authenticity.")

def generate_key_pair():
    # Generate DSA key pair
    private_key = dsa.generate_private_key(key_size=1024)
    public_key = private_key.public_key()
    return private_key, public_key

def sign_message(private_key, message):
    # Sign the message using the private key
    signature = private_key.sign(
        message.encode(),
        hashes.SHA256()
    )
    return signature

def verify_signature(public_key, message, signature):
    # Verify the signature using the public key
    try:
        public_key.verify(
            signature,
            message.encode(),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False

st.write('Input Your Text.')
plaintext = st.text_area('Plaintext', placeholder="Input Text...")

generate_submit = st.button('Generate Key Pair')
if generate_submit:
    # Generate DSA key pair
    private_key, public_key = generate_key_pair()

    st.text("Private Key:")
    st.text(private_key)
    st.text("Public Key:")
    st.text(public_key)

    sign_submit = st.button('Sign Message')
    if sign_submit:
        if plaintext:  # Check if plaintext is not empty
            # Sign the message
            signature = sign_message(private_key, plaintext)

            st.text("Signature:")
            st.text(signature.hex())
        else:
            st.warning("Please input text to sign!")

        verify_submit = st.button('Verify Signature')
        if verify_submit:
            if signature:  # Check if signature is available
                # Verify the signature
                verified = verify_signature(public_key, plaintext, signature)
                if verified:
                    st.success("Signature verified successfully!")
                else:
                    st.error("Signature verification failed!")
            else:
                st.warning("Please sign the message first!")
