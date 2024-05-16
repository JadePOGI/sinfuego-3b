import streamlit as st
from PyPDF2 import PdfReader, PdfWriter
from docx import Document
import io

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

def read_text(file):
    return file.getvalue().decode("utf-8")

def read_pdf(file):
    try:
        pdf_reader = PdfReader(file)
        text = ""
        for page_num in range(len(pdf_reader.pages)):
            page = pdf_reader.pages[page_num]
            text += page.extract_text()
        return text
    except Exception as e:
        st.error("Error reading PDF file: " + str(e))
        return None

def read_docx(file):
    doc = Document(file)
    text = ""
    for para in doc.paragraphs:
        text += para.text + "\n"
    return text

def write_pdf(text, original_pdf_buffer):
    pdf_buffer = io.BytesIO()
    pdf_writer = PdfWriter()

    # Get the number of pages in the original PDF
    original_pdf = PdfReader(original_pdf_buffer)
    num_pages = len(original_pdf.pages)

    # Iterate through each page and add it to the new PDF
    for page_num in range(num_pages):
        # Create a new page in the output PDF
        pdf_writer.add_blank_page(width=original_pdf.pages[page_num].mediaBox.getWidth(), height=original_pdf.pages[page_num].mediaBox.getHeight())

        # Decrypt the text for this page
        page_text = text[page_num] if page_num < len(text) else ""

        # Write the decrypted text to the current page
        pdf_writer.add_page(PdfReader(io.BytesIO(page_text.encode())).pages[0])

    pdf_writer.write(pdf_buffer)
    pdf_buffer.seek(0)
    return pdf_buffer


def file_uploader(label, type):
    uploaded_file = st.file_uploader(label, type=type)
    if uploaded_file is not None:
        if uploaded_file.type == "application/pdf":
            file_contents = read_pdf(uploaded_file)
            file_extension = ".pdf"
        elif uploaded_file.type == "text/plain":
            file_contents = read_text(uploaded_file)
            file_extension = ".txt"
        elif uploaded_file.type == "application/vnd.openxmlformats-officedocument.wordprocessingml.document":
            file_contents = read_docx(uploaded_file)
            file_extension = ".txt"  # Use .txt extension for docx files
        return file_contents, uploaded_file.name, file_extension
    return None, None, None

genre = st.radio(
    "Choose Input:",
    ["Text", "File"])

if genre == 'Text':
    plaintext = st.text_area('Enter your text to Encrypt')
    shift = 5

    encrypt_submit = st.button('Submit')
    if encrypt_submit:
        encrypted_text = caesar_cipher(plaintext, shift)
        st.write("Encrypted:", encrypted_text)

        # Decrypting the ciphertext
        decrypted_text = caesar_decipher(encrypted_text, shift)
        st.write("Decrypted:", decrypted_text)

elif genre == 'File':
    st.write('Enter Your Selected File.')
    uploaded_file, file_name, file_extension = file_uploader("Choose a file", type=["pdf", "txt", "docx"])
    if uploaded_file is not None:

        encrypt_decrypt_choice = st.radio('Choose one', options=('Encrypt', 'Decrypt'))

        if encrypt_decrypt_choice == 'Encrypt':
            shift = 5
            encrypted_text = caesar_cipher(uploaded_file, shift)
            st.write("Encrypted file contents:")
            if file_extension == ".pdf":
                encrypted_pdf = write_pdf(encrypted_text, uploaded_file)
                st.download_button(
                    label="Download Encrypted File",
                    data=encrypted_pdf.getvalue(),
                    file_name=f"encrypted_{file_name}",
                    mime="application/pdf"
                )
            else:
                st.download_button(
                    label="Download Encrypted File",
                    data=encrypted_text.encode(),
                    file_name=f"encrypted_{file_name}{file_extension}",
                    mime="text/plain"
                )

        elif encrypt_decrypt_choice == 'Decrypt':
            encrypted_file, _, _ = file_uploader("Upload the encrypted file", type=["txt", "pdf"])
            if encrypted_file is not None:
                shift = 5
                decrypted_text = caesar_decipher(encrypted_file, shift)
                st.write("Decryption completed successfully.")
                if file_extension == ".pdf":
                    decrypted_pdf = write_pdf(decrypted_text, encrypted_file)
                    st.download_button(
                        label="Download Decrypted File",
                        data=decrypted_pdf.getvalue(),
                        file_name=f"decrypted_{file_name}",
                        mime="application/pdf"
                    )
                else:
                    st.download_button(
                        label="Download Decrypted File",
                        data=decrypted_text.encode(),
                        file_name=f"decrypted_{file_name}{file_extension}",
                        mime="text/plain"
                    )
