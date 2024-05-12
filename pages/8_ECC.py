import streamlit as st
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

st.header("Welcome to ECC (Elliptic Curve Cryptography)!🔐")
st.write("Elliptic Curve Cryptography (ECC) is a public-key cryptography method based on the algebraic structure of elliptic curves over finite fields. It offers strong security with relatively small key sizes, making it suitable for constrained environments like mobile devices and IoT.")

def generate_key_pair():
    # Generate ECC key pair
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

def sign_message(private_key, message):
    # Sign the message using the private key
    signature = private_key.sign(
        message.encode(),
        ec.ECDSA(hashes.SHA256())
    )
    return signature

def verify_signature(public_key, message, signature):
    # Verify the signature using the public key
    try:
        public_key.verify(
            signature,
            message.encode(),
            ec.ECDSA(hashes.SHA256())
        )
        return True
    except InvalidSignature:
        return False

st.write('Input Your Text.')
plaintext = st.text_area('Plaintext', placeholder="Input Text...")

generate_submit = st.button('Generate Key Pair')
if generate_submit:
    # Generate ECC key pair
    private_key, public_key = generate_key_pair()
    
    # Serialize keys to PEM format
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    st.write("Private Key:", private_pem.decode())
    st.write("Public Key:", public_pem.decode())

    sign_submit = st.button('Sign Message')
    if sign_submit:
        if plaintext:  # Check if plaintext is not empty
            # Sign the message
            signature = sign_message(private_key, plaintext)

            st.write("Signature:", signature.hex())
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
