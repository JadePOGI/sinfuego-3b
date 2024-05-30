import streamlit as st
import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

# RSA Functions
def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def generate_rsa_keypair(p, q):
    n = p * q
    phi = (p - 1) * (q - 1)
    e = random.randrange(1, phi)

    g = gcd(e, phi)
    while g != 1:
        e = random.randrange(1, phi)
        g = gcd(e, phi)

    d = pow(e, -1, phi)
    return ((e, n), (d, n))

def rsa_encrypt(pk, plaintext):
    key, n = pk
    cipher = [(ord(char) ** key) % n for char in plaintext]
    return cipher

def rsa_decrypt(pk, ciphertext):
    key, n = pk
    plain = [chr((char ** key) % n) for char in ciphertext]
    return ''.join(plain)

# Diffie-Hellman and AES Functions
def generate_private_key(prime):
    return random.randint(2, prime - 2)

def generate_public_key(base, private_key, prime):
    return pow(base, private_key, prime)

def generate_shared_secret(public_key, private_key, prime):
    return pow(public_key, private_key, prime)

def aes_encrypt_message(shared_secret, plaintext):
    key = shared_secret.to_bytes(16, 'big')[:16]  # AES key must be either 16, 24, or 32 bytes long
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    return iv, ct

def aes_decrypt_message(shared_secret, iv, ciphertext):
    key = shared_secret.to_bytes(16, 'big')[:16]
    iv = base64.b64decode(iv)
    ct = base64.b64decode(ciphertext)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode('utf-8')

st.title("Cryptographic Algorithms: Diffie-Hellman & RSA")

algorithm = st.radio("Choose an algorithm", ("Diffie-Hellman", "RSA"))

if algorithm == "Diffie-Hellman":
    st.header("Diffie-Hellman Key Exchange with AES Encryption/Decryption")
    menu = ["Generate Keys", "Compute Shared Secret", "Encrypt Message", "Decrypt Message"]
    choice = st.sidebar.selectbox("Select an option", menu)

    if choice == "Generate Keys":
        st.subheader("Generate Public Keys")
        
        prime = st.number_input("Enter a prime number (p)", min_value=2, value=23)
        base = st.number_input("Enter a base number (g)", min_value=2, value=5)
        
        private_key_a = st.number_input("Enter private key for User A", min_value=1, value=generate_private_key(prime))
        private_key_b = st.number_input("Enter private key for User B", min_value=1, value=generate_private_key(prime))
        
        if st.button("Generate Public Keys"):
            public_key_a = generate_public_key(base, private_key_a, prime)
            public_key_b = generate_public_key(base, private_key_b, prime)
            
            st.write("User A's Public Key: ", public_key_a)
            st.write("User B's Public Key: ", public_key_b)

    elif choice == "Compute Shared Secret":
        st.subheader("Compute Shared Secret Key")
        
        prime = st.number_input("Enter the prime number (p)", min_value=2, value=23)
        private_key = st.number_input("Enter your private key", min_value=1, value=generate_private_key(prime))
        public_key_other = st.number_input("Enter the other party's public key", min_value=1)
        
        if st.button("Compute Shared Secret"):
            shared_secret = generate_shared_secret(public_key_other, private_key, prime)
            st.write("Shared Secret Key: ", shared_secret)

    elif choice == "Encrypt Message":
        st.subheader("Encrypt a Message")
        
        shared_secret = st.number_input("Enter the shared secret key", min_value=1)
        plaintext = st.text_area("Enter the message to encrypt")
        
        if st.button("Encrypt"):
            iv, ciphertext = aes_encrypt_message(shared_secret, plaintext)
            st.write("Initialization Vector (IV): ", iv)
            st.write("Ciphertext: ", ciphertext)

    elif choice == "Decrypt Message":
        st.subheader("Decrypt a Message")
        
        shared_secret = st.number_input("Enter the shared secret key", min_value=1)
        iv = st.text_input("Enter the initialization vector (IV)")
        ciphertext = st.text_area("Enter the ciphertext")
        
        if st.button("Decrypt"):
            try:
                decrypted_message = aes_decrypt_message(shared_secret, iv, ciphertext)
                st.write("Decrypted Message: ", decrypted_message)
            except Exception as e:
                st.write("Decryption failed: ", str(e))

elif algorithm == "RSA":
    st.header("RSA Encryption/Decryption")
    menu = ["Generate Keys", "Encrypt Message", "Decrypt Message"]
    choice = st.sidebar.selectbox("Select an option", menu)

    if choice == "Generate Keys":
        st.subheader("Generate RSA Keys")
        p = st.number_input("Enter a prime number p", min_value=2, value=11)
        q = st.number_input("Enter a prime number q", min_value=2, value=13)

        if st.button("Generate"):
            public, private = generate_rsa_keypair(p, q)
            st.write("Public Key: ", public)
            st.write("Private Key: ", private)

    elif choice == "Encrypt Message":
        st.subheader("Encrypt a Message")
        public_key = st.text_input("Enter the public key (e, n)", "(e, n)")
        message = st.text_area("Enter the message")

        if st.button("Encrypt"):
            try:
                public_key = eval(public_key)
                encrypted_msg = rsa_encrypt(public_key, message)
                st.write("Encrypted Message: ", encrypted_msg)
            except:
                st.write("Invalid public key")

    elif choice == "Decrypt Message":
        st.subheader("Decrypt a Message")
        private_key = st.text_input("Enter the private key (d, n)", "(d, n)")
        encrypted_msg = st.text_area("Enter the encrypted message (as a list)")

        if st.button("Decrypt"):
            try:
                private_key = eval(private_key)
                encrypted_msg = eval(encrypted_msg)
                decrypted_msg = rsa_decrypt(private_key, encrypted_msg)
                st.write("Decrypted Message: ", decrypted_msg)
            except:
                st.write("Invalid private key or encrypted message")
