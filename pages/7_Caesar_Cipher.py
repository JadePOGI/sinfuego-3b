import streamlit as st
from PyPDF2 import PdfReader, PdfWriter
import io
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter

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

def read_pdf(file):
    pdf_reader = PdfReader(file)
    text = ""
    for page_num in range(len(pdf_reader.pages)):
        page = pdf_reader.pages[page_num]
        text += page.extract_text()
    return text

def create_pdf_from_text(text):
    pdf_buffer = io.BytesIO()
    c = canvas.Canvas(pdf_buffer, pagesize=letter)
    text_object = c.beginText(40, 750)
    text_object.setFont("Helvetica", 12)

    lines = text.split('\n')
    for line in lines:
        text_object.textLine(line)
    
    c.drawText(text_object)
    c.showPage()
    c.save()
    pdf_buffer.seek(0)
    return pdf_buffer

def write_pdf_from_text(text, original_pdf):
    pdf_reader = PdfReader(original_pdf)
    pdf_writer = PdfWriter()
    
    # Add the original pages
    for page in pdf_reader.pages:
        pdf_writer.add_page(page)

    # Create a new page with the decrypted text
    pdf_buffer = io.BytesIO()
    c = canvas.Canvas(pdf_buffer, pagesize=letter)
    text_object = c.beginText(40, 750)
    text_object.setFont("Helvetica", 12)

    lines = text.split('\n')
    for line in lines:
        text_object.textLine(line)
    
    c.drawText(text_object)
    c.showPage()
    c.save()
    pdf_buffer.seek(0)

    new_pdf_reader = PdfReader(pdf_buffer)
    pdf_writer.add_page(new_pdf_reader.pages[0])

    pdf_output = io.BytesIO()
    pdf_writer.write(pdf_output)
    pdf_output.seek(0)
    return pdf_output

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
    uploaded_file = st.file_uploader("Choose a file", type=["pdf"])
    if uploaded_file is not None:
        file_contents = read_pdf(uploaded_file)
        st.write("File contents extracted successfully.")

        encrypt_decrypt_choice = st.radio('Choose one', options=('Encrypt', 'Decrypt'))

        if encrypt_decrypt_choice == 'Encrypt':
            shift = 5
            encrypted_text = caesar_cipher(file_contents, shift)
            encrypted_pdf = create_pdf_from_text(encrypted_text)
            st.download_button(
                label="Download Encrypted File",
                data=encrypted_pdf.getvalue(),
                file_name="encrypted_file.pdf",
                mime="application/pdf"
            )

        elif encrypt_decrypt_choice == 'Decrypt':
            encrypted_file = st.file_uploader("Upload the encrypted file", type=["pdf"])
            if encrypted_file is not None:
                encrypted_contents = read_pdf(encrypted_file)
                shift = 5
                decrypted_text = caesar_decipher(encrypted_contents, shift)
                decrypted_pdf = write_pdf_from_text(decrypted_text, uploaded_file)
                st.download_button(
                    label="Download Decrypted File",
                    data=decrypted_pdf.getvalue(),
                    file_name="decrypted_file.pdf",
                    mime="application/pdf"
                )
