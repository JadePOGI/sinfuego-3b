import hashlib
import streamlit as st

st.header("Welcome to MD5!🔐")

st.write('MD5 is a cryptographic hash function algorithm that takes the message as input of any length and changes it into a fixed-length message of 16 bytes. MD5 algorithm stands for the message-digest algorithm. MD5 was developed as an improvement of MD4, with advanced security purposes. The output of MD5 (Digest size) is always 128 bits. MD5 was developed in 1991 by Ronald Rivest.')

def md5_hash(input_string):
    # Encode the input string to bytes
    input_bytes = input_string.encode()

    # Create a new MD5 hash object
    md5_hash_obj = hashlib.md5()

    # Update the hash object with the input bytes
    md5_hash_obj.update(input_bytes)

    # Get the hexadecimal representation of the hash value
    hash_hex = md5_hash_obj.hexdigest()

    return hash_hex

# Example usage
input_string = "Hello, World!"
md5_hash_value = md5_hash(input_string)
print("MD5 Hash:", md5_hash_value)

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
            md5_hash = md5_hash(input_string)
            st.write("MD5 hash of '{}' is: {}".format(input_string, md5_hash))
        else:
            st.warning("Please input text for MD5 hash to work!")

elif genre == 'File':
    st.write('Enter Your Selected File.')
    uploaded_file = st.file_uploader("Choose a file")
    if uploaded_file is not None:
        # Read file contents as string
        file_contents = uploaded_file.getvalue().decode("utf-8")
        st.write("File contents:", file_contents)

        # Compute MD5 hash of file contents
        md5_hash = md5_hash(file_contents)
        st.write("MD5 hash of file contents:", md5_hash)
        
else:
    st.write("Please choose.")