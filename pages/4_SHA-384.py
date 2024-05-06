import hashlib
import streamlit as st

st.header("Welcome to SHA-384!🔐")
st.write("SHA384 Encrypt/Decrypt is a free online tool for generating SHA384 hashes from strings and decrypting SHA384 hashes to strings.")
def sha384_hash(input_string):
    # Encode the input string to bytes
    input_bytes = input_string.encode()

    # Create a new SHA-384 hash object
    sha384_hash_obj = hashlib.sha384()

    # Update the hash object with the input bytes
    sha384_hash_obj.update(input_bytes)

    # Get the hexadecimal representation of the hash value
    hash_hex = sha384_hash_obj.hexdigest()

    return hash_hex

# Example usage
input_string = "Hello, World!"
sha384_hash_value = sha384_hash(input_string)
print("SHA-384 Hash:", sha384_hash_value)

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
            sha384_hash = sha384_hash(input_string)
            st.write("SHA384 hash of '{}' is: {}".format(input_string, sha384_hash))
        else:
            st.warning("Please input text for SHA-384 hash to work!")

elif genre == 'File':
    st.write('Enter Your Selected File.')
    uploaded_file = st.file_uploader("Choose a file")
    if uploaded_file is not None:
        # Read file contents as string
        file_contents = uploaded_file.getvalue().decode("utf-8")
        st.write("File contents:", file_contents)

        # Compute SHA-384 hash of file contents
        sha384_hash = sha384_hash(file_contents)
        st.write("SHA-384 hash of file contents:", sha384_hash)
        
else:
    st.write("Please choose.")