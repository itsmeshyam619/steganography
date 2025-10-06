# Streamlit Web Application for Image Steganography with Cryptography

import streamlit as st
import os
from PIL import Image
import io
import base64

# Local module imports
from encryption import encrypt, encode
from decryption import decode, decrypt

# Constants
MAX_IMAGE_SIZE = 10 * 1024 * 1024  # 10MB
SUPPORTED_FORMATS = ('.png', '.jpg', '.jpeg')

# Set page configuration
st.set_page_config(
    page_title="Image Steganography with Cryptography",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
st.markdown("""
    <style>
    .stApp {
        max-width: 1200px;
        margin: 0 auto;
    }
    .stButton > button {
        width: 100%;
    }
    .upload-box {
        border: 2px dashed #cccccc;
        padding: 20px;
        text-align: center;
        margin: 10px 0;
    }
    </style>
    """, unsafe_allow_html=True)

# Helper functions
def validate_image(uploaded_file):
    if uploaded_file is None:
        return False, "No image selected"
    if uploaded_file.size > MAX_IMAGE_SIZE:
        return False, f"Image size exceeds {MAX_IMAGE_SIZE//1024//1024}MB limit"
    try:
        image = Image.open(uploaded_file)
        image.verify()
        return True, "Image is valid"
    except Exception as e:
        return False, f"Invalid image file: {str(e)}"

def save_uploaded_file(uploaded_file):
    if uploaded_file is not None:
        file_details = {"FileName": uploaded_file.name, "FileType": uploaded_file.type}
        with open(os.path.join("temp", uploaded_file.name), "wb") as f:
            f.write(uploaded_file.getbuffer())
        return os.path.join("temp", uploaded_file.name)
    return None

def main():
    # Create temp directory if it doesn't exist
    os.makedirs("temp", exist_ok=True)

    # Title and description
    st.title("Image Steganography with Cryptography")
    st.markdown("""
    This application allows you to:
    * Hide secret messages in images using steganography
    * Encrypt messages for additional security
    * Extract and decrypt hidden messages from images
    """)

    # Tabs for Encrypt and Decrypt
    tab1, tab2 = st.tabs(["💌 Encrypt & Hide", "🔍 Decrypt & Extract"])

    # Encryption Tab
    with tab1:
        st.header("Encrypt and Hide Message")
        
        # Message input
        message = st.text_area("Enter your secret message", height=100, 
                             help="Type the message you want to hide in the image")
        
        # Password input
        password = st.text_input("Enter password", type="password",
                               help="Choose a strong password to encrypt your message")
        
        # File uploader
        uploaded_file = st.file_uploader("Choose a cover image", 
                                       type=['png', 'jpg', 'jpeg'],
                                       help="Select an image to hide your message in")
        
        # Show image preview
        if uploaded_file is not None:
            valid, message_1 = validate_image(uploaded_file)
            if valid:
                col1, col2 = st.columns(2)
                with col1:
                    st.image(uploaded_file, caption="Preview of cover image", 
                            use_container_width=True)
            else:
                st.error(message_1)
                uploaded_file = None

        # Process button
        if st.button("Encrypt and Hide Message", type="primary"):
            if not uploaded_file:
                st.error("Please select an image first")
            elif not message:
                st.error("Please enter a message to hide")
            elif not password:
                st.error("Please enter a password")
            else:
                try:
                    with st.spinner("Processing..."):
                        # Save uploaded file temporarily
                        temp_path = save_uploaded_file(uploaded_file)
                        
                        # Encrypt message
                        encrypted = encrypt(message, password)
                        
                        # Create output filename
                        output_path = os.path.join("temp", "output_image.png")
                        
                        # Encode message in image
                        encode(temp_path, encrypted, output_path)
                        
                        # Show success message and download button
                        st.success("Message hidden successfully!")
                        
                        # Show preview and download button
                        col1, col2 = st.columns(2)
                        with col1:
                            st.image(output_path, caption="Output image with hidden message",
                                   use_container_width=True)
                        with col2:
                            with open(output_path, "rb") as file:
                                btn = st.download_button(
                                    label="Download Image",
                                    data=file,
                                    file_name="stego_image.png",
                                    mime="image/png"
                                )
                        
                        # Cleanup
                        if temp_path and os.path.exists(temp_path):
                            os.remove(temp_path)
                
                except Exception as e:
                    st.error(f"An error occurred: {str(e)}")

    # Decryption Tab
    with tab2:
        st.header("Extract and Decrypt Message")
        
        # Password input
        decrypt_password = st.text_input("Enter password", type="password",
                                       help="Enter the password used for encryption",
                                       key="decrypt_password").strip()
        
        # File uploader
        stego_file = st.file_uploader("Choose image with hidden message", 
                                     type=['png'],
                                     help="Select the image containing the hidden message",
                                     key="decrypt_file")
        
        # Show image preview
        if stego_file is not None:
            valid, message = validate_image(stego_file)
            if valid:
                col1, col2 = st.columns(2)
                with col1:
                    st.image(stego_file, caption="Image with hidden message", 
                            use_container_width=True)
            else:
                st.error(message)
                stego_file = None
        
        # Process button
        if st.button("Extract and Decrypt Message", type="primary"):
            if not stego_file:
                st.error("Please select an image first")
            elif not decrypt_password:
                st.error("Please enter the password")
            else:
                try:
                    with st.spinner("Processing..."):
                        # Save uploaded file temporarily
                        temp_path = save_uploaded_file(stego_file)
                        
                        # Add debug information
                        st.write("### Debug Information")
                        
                        # Extract message
                        extracted_message = decode(temp_path)
                        st.write("Raw extracted message:", extracted_message)
                        
                        # Extract the message before ||
                        lsb_extraction = ''
                        for char in extracted_message:
                            if char == '|':
                                break
                            lsb_extraction += char
                        
                        st.write("Processed extraction:", lsb_extraction)
                        
                        try:
                            # Decrypt message
                            decrypted_message = decrypt(lsb_extraction, decrypt_password)
                            
                            # Show results
                            st.success("Message extracted and decrypted successfully!")
                            
                            # Display message in a text area
                            st.text_area("Decrypted Message", 
                                       value=decrypted_message,
                                       height=200,
                                       disabled=True)
                            
                            # Add download button for the message
                            st.download_button(
                                label="Download Message as Text File",
                                data=decrypted_message,
                                file_name="decrypted_message.txt",
                                mime="text/plain"
                            )
                        except Exception as decrypt_error:
                            st.error(f"Decryption error: {str(decrypt_error)}")
                            st.write("Decryption debug info:")
                            #st.write("- Length of extracted message:", len(lsb_extraction))
                            # Try to show base64 decoded length
                            try:
                                padded = lsb_extraction + '=' * (4 - len(lsb_extraction) % 4)
                                decoded = base64.b64decode(padded)
                                st.write("- Length of decoded data:", len(decoded))
                                st.write("- Decoded data (hex):", decoded.hex())
                            except Exception as e:
                                st.write("- Base64 decode error:", str(e))
                        
                        # Cleanup
                        if temp_path and os.path.exists(temp_path):
                            os.remove(temp_path)
                            
                except Exception as e:
                    st.error(f"An error occurred: {str(e)}")
                    st.write("Full error details:", str(e))
    
    # Cleanup temp directory on session end
    if st.session_state.get('cleanup_done') != True:
        for file in os.listdir("temp"):
            file_path = os.path.join("temp", file)
            try:
                if os.path.isfile(file_path):
                    os.remove(file_path)
            except Exception:
                pass
        st.session_state['cleanup_done'] = True

if __name__ == "__main__":
    main()
