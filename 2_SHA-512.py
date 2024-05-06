import hashlib
import streamlit as st

st.header("Welcome to SHA-512!🔐")

st.write('SHA-512, or Secure Hash Algorithm 512, is a hashing algorithm used to convert text of any length into a fixed-size string. Each output produces a SHA-512 length of 512 bits (64 bytes). This algorithm is commonly used for email addresses hashing, password hashing, and digital record verification. SHA-512 is also used in blockchain technology, with the most notable example being the BitShares network.')

def sha512_hash(input_string):
    # Encode the input string to bytes
    input_bytes = input_string.encode()

    # Create a new SHA-512 hash object
    sha512_hash_obj = hashlib.sha512()

    # Update the hash object with the input bytes
    sha512_hash_obj.update(input_bytes)

    # Get the hexadecimal representation of the hash value
    hash_hex = sha512_hash_obj.hexdigest()

    return hash_hex

# Example usage
input_string = "Hello, World!"
sha512_hash_value = sha512_hash(input_string)
print("SHA-512 Hash:", sha512_hash_value)

genre = st.radio(
    "Choose Input:",
    ["Text", "File"])

if genre == 'Text':
    st.write('Input Your Text.')
    input_string = st.text_area('Plaintext', placeholder="Input Text...")
    button = st.button("Submit", type="primary")

    if button:
        if input_string:  # Check if input_string is not empty
            st.write("Input Text:", input_string)
            sha512_hash = sha512_hash(input_string)
            st.write("SHA-512 hash of '{}' is: {}".format(input_string, sha512_hash))
        else:
            st.warning("Please input text for SHA-512 hash to work!")

elif genre == 'File':
    st.write('Enter Your Selected File.')
    uploaded_file = st.file_uploader("Choose a file")
    if uploaded_file is not None:
        # Read file contents as string
        file_contents = uploaded_file.getvalue().decode("utf-8")
        st.write("File contents:", file_contents)

        # Compute SHA-512 hash of file contents
        sha512_hash = sha512_hash(file_contents)
        st.write("SHA-512 hash of file contents:", sha512_hash)
        
else:
    st.write("Please choose.")