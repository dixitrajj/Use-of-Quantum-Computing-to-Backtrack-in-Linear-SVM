import streamlit as st
from PIL import Image
import numpy as np
import csv
import os
import qrcode
import io
import cv2
import base64
import time

# ------------------------------------------
# Authentication and Credential Management
# ------------------------------------------
CREDENTIALS_FILE = "user_credentials.csv"
EXPECTED_HEADERS = ["email", "name", "password"]

def create_credentials_file():
    # If the credentials file does not exist, create one with the expected headers.
    if not os.path.exists(CREDENTIALS_FILE):
        with open(CREDENTIALS_FILE, "w", newline="") as file:
            writer = csv.writer(file)
            writer.writerow(EXPECTED_HEADERS)
    else:
        # File exists: check if headers match.
        with open(CREDENTIALS_FILE, "r", newline="") as file:
            reader = csv.reader(file)
            try:
                header = next(reader)
            except StopIteration:
                header = []
        if header != EXPECTED_HEADERS:
            st.warning("The credentials file is outdated. Updating the file...")
            # Remove the outdated credentials file.
            os.remove(CREDENTIALS_FILE)
            # Create a new file with the correct headers.
            with open(CREDENTIALS_FILE, "w", newline="") as file:
                writer = csv.writer(file)
                writer.writerow(EXPECTED_HEADERS)

def register_user(email, name, password):
    # Append the new user's details into the CSV file.
    with open(CREDENTIALS_FILE, "a", newline="") as file:
        writer = csv.writer(file)
        writer.writerow([email, name, password])
    st.success("Registration successful. Please log in.")

def login_user(email, password):
    # Read CSV file and check provided email and password.
    with open(CREDENTIALS_FILE, "r", newline="") as file:
        reader = csv.DictReader(file)
        for row in reader:
            if row.get("email") == email and row.get("password") == password:
                st.session_state.logged_in = True
                st.session_state.email = email
                st.session_state.name = row.get("name")
                st.success(f"Welcome, {row.get('name')}! You are now logged in.")
                return True
    st.error("Invalid email or password. Please try again.")
    return False

# ------------------------------------------
# Quantum Key Distribution Simulation (BB84)
# ------------------------------------------
def bb84_key_exchange(length):
    alice_bits = np.random.randint(2, size=length)
    alice_bases = np.random.randint(2, size=length)
    bob_bases = np.random.randint(2, size=length)
    bob_results = [alice_bits[i] if alice_bases[i] == bob_bases[i] 
                   else np.random.randint(2) for i in range(length)]
    return bob_results

# ------------------------------------------
# Message Encryption/Decryption (XOR)
# ------------------------------------------
def encrypt_message(message, key):
    return ''.join(chr(ord(c) ^ key[i % len(key)]) for i, c in enumerate(message))

def decrypt_message(encrypted_message, key):
    return ''.join(chr(ord(c) ^ key[i % len(key)]) for i, c in enumerate(encrypted_message))

# ------------------------------------------
# Helper Function for Chunked XOR Processing
# ------------------------------------------
def xor_chunk_process(flat_data, key_array, chunk_size=1024 * 1024):
    key_len = len(key_array)
    result = np.zeros_like(flat_data)
    for i in range(0, len(flat_data), chunk_size):
        chunk = flat_data[i:i + chunk_size]
        key_indices = np.arange(i, i + len(chunk)) % key_len
        chunk_key = key_array[key_indices]
        result[i:i + len(chunk)] = chunk ^ chunk_key
    return result

# ------------------------------------------
# Image Encryption/Decryption Functions
# ------------------------------------------
def encrypt_image(image_array, key):
    flattened = image_array.flatten()
    key_array = np.array(key, dtype=np.uint8)
    processed = xor_chunk_process(flattened, key_array)
    encoded = base64.b64encode(processed.tobytes()).decode("utf-8")
    return encoded

def decrypt_image(encrypted_data, key, shape):
    decoded = base64.b64decode(encrypted_data)
    flattened = np.frombuffer(decoded, dtype=np.uint8)
    key_array = np.array(key, dtype=np.uint8)
    processed = xor_chunk_process(flattened, key_array)
    return processed.reshape(shape)

# ------------------------------------------
# Key Generation and QR Code
# ------------------------------------------
def generate_image_key(max_length=100):
    key = np.random.randint(0, 256, size=max_length, dtype=np.uint8)
    return key

def generate_qr_code(shared_key):
    qr = qrcode.QRCode(
        version=3,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=5,
        border=2,
    )
    qr.add_data(shared_key)
    qr.make(fit=True)
    img = qr.make_image(fill_color="green", back_color="white")
    return img

# ------------------------------------------
# Image Compression for Fast Processing
# ------------------------------------------
def compress_image(image, quality=75):
    img = Image.fromarray(image)
    buffer = io.BytesIO()
    img.save(buffer, format="JPEG", quality=quality)
    buffer.seek(0)
    return np.array(Image.open(buffer))

# ------------------------------------------
# Main Streamlit Interface
# ------------------------------------------
def main():
    st.set_page_config(page_title="Lock Chat", layout="centered")
    create_credentials_file()

    # Initialize session state for login if not set.
    if "logged_in" not in st.session_state:
        st.session_state.logged_in = False
        st.session_state.message_sent = False
    
    # Custom CSS for better UI
    st.markdown("""
    <style>
    .main-header {
        color: #1E88E5;
        text-align: center;
    }
    .subheader {
        color: #424242;
        text-align: center;
        margin-bottom: 20px;
    }
    .stButton>button {
        background-color: #1E88E5;
        color: white;
        width: 100%;
    }
    .info-box {
        padding: 15px;
        border-radius: 5px;
        background-color: #E8F5E9;
        border-left: 5px solid #4CAF50;
        margin-bottom: 20px;
        font-size: 16px;
        color: #2E7D32;
    }
    .welcome-message {
        padding: 15px;
        border-radius: 8px;
        background-color: #BBDEFB;
        border: 1px solid #64B5F6;
        margin-bottom: 20px;
        font-size: 18px;
        color: #0D47A1;
        text-align: center;
        font-weight: 500;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    </style>
    """, unsafe_allow_html=True)

    if not st.session_state.logged_in:
        st.markdown("<h1 class='main-header'>🔒 Lock Chat</h1>", unsafe_allow_html=True)
        st.markdown("<h3 class='subheader'>Encrypt your messages and images using simulated Quantum Key Distribution</h3>", unsafe_allow_html=True)
        
        # Use a placeholder for the image
        st.image("https://image.binance.vision/editor-uploads/bd1d649021654f8f9a9059e02a7c1278.gif", width=700)

        st.sidebar.title("Authentication")
        auth_option = st.sidebar.radio("Choose an option", ("Login", "Register"))

        if auth_option == "Register":
            # Registration page: email, name, password, and re-enter password.
            with st.sidebar.form("registration_form"):
                st.subheader("Create Account")
                email = st.text_input("Email")
                name = st.text_input("Name")
                password = st.text_input("Password", type="password")
                re_password = st.text_input("Re-enter Password", type="password")
                submit_button = st.form_submit_button("Register")
                
                if submit_button:
                    if not (email and name and password and re_password):
                        st.error("Please fill in all fields.")
                    elif len(password) < 8:
                        st.error("Password must be at least 8 characters long.")
                    elif password != re_password:
                        st.error("Passwords do not match. Please re-enter.")
                    else:
                        register_user(email, name, password)
        else:
            # Login page using email and password.
            with st.sidebar.form("login_form"):
                st.subheader("Login")
                email = st.text_input("Email")
                password = st.text_input("Password", type="password")
                submit_button = st.form_submit_button("Login")
                
                if submit_button:
                    login_user(email, password)
    else:
        if st.sidebar.button("Logout"):
            st.session_state.logged_in = False
            st.experimental_rerun()

        st.sidebar.title("Navigation")
        nav_option = st.sidebar.radio("Go to:", ("Secure Chat Interface", "Image Encryption and Decryption"))

        if nav_option == "Secure Chat Interface":
            st.markdown("<h2 class='main-header'>Secure Chat Interface</h2>", unsafe_allow_html=True)
            
            # Updated welcome message with new styling
            st.markdown(f"<div class='welcome-message'>Welcome {st.session_state.name}! This secure messaging system uses quantum key distribution simulation for end-to-end encryption.</div>", unsafe_allow_html=True)

            with st.form("message_form"):
                message = st.text_area("Type your message:", height=150)
                submit_button = st.form_submit_button("Send Message")
                
                if submit_button and message:
                    shared_key = bb84_key_exchange(len(message))
                    encrypted_msg = encrypt_message(message, shared_key)
                    qr_image = generate_qr_code(''.join(map(str, shared_key)))
                    with io.BytesIO() as buffer:
                        qr_image.save(buffer, format="PNG")
                        qr_code_data = buffer.getvalue()
                    
                    st.session_state.update({
                        "original_message": message,
                        "shared_key": shared_key,
                        "encrypted_message": encrypted_msg,
                        "qr_code": qr_code_data,
                        "message_sent": True
                    })

            if st.session_state.get("message_sent"):
                col1, col2 = st.columns([2, 1])
                with col1:
                    st.subheader("Message Details")
                    st.text_area("Original Message", st.session_state.original_message, height=100)
                    st.text_area("Encrypted Message", st.session_state.encrypted_message, height=100)
                    st.text_input("Shared Key", ''.join(map(str, st.session_state.shared_key)))
                with col2:
                    st.subheader("Key QR Code")
                    st.image(st.session_state.qr_code, caption="Scan to share key")
                    
            st.markdown("<hr>", unsafe_allow_html=True)
            st.subheader("Decrypt a Message")
            
            with st.form("decrypt_form"):
                enc_input = st.text_area("Enter encrypted message:", height=100)
                key_input = st.text_input("Enter shared key (binary digits):")
                submit_button = st.form_submit_button("Decrypt Message")
                
                if submit_button and enc_input and key_input:
                    try:
                        key = list(map(int, key_input.strip()))
                        decrypted = decrypt_message(enc_input, key)
                        st.success("Decryption successful!")
                        st.text_area("Decrypted Message", decrypted, height=150)
                    except Exception as e:
                        st.error(f"Invalid key format: {e}")

        elif nav_option == "Image Encryption and Decryption":
            st.markdown("<h2 class='main-header'>Image Encryption and Decryption</h2>", unsafe_allow_html=True)
            
            # Updated info box with new styling
            st.markdown("<div class='info-box'>For best performance, please use images smaller than 5MB. Larger images will be automatically compressed.</div>", unsafe_allow_html=True)
            
            progress_placeholder = st.empty()
            
            tab1, tab2 = st.tabs(["Encrypt an Image", "Decrypt an Image"])
            
            with tab1:
                uploaded = st.file_uploader("Upload an image to encrypt", type=["png", "jpg", "jpeg"], key="encrypt_uploader")
                if uploaded:
                    try:
                        img = Image.open(uploaded)
                        img_array = np.array(img)
                        file_size_mb = uploaded.size / (1024 * 1024)
                        
                        col1, col2 = st.columns(2)
                        with col1:
                            st.image(img_array, caption="Original Image", use_column_width=True)
                        with col2:
                            st.write(f"Image dimensions: {img_array.shape[1]}x{img_array.shape[0]}")
                            st.write(f"File size: {file_size_mb:.2f} MB")
                            
                            if file_size_mb > 5:
                                st.warning(f"Large image detected. It will be compressed for better performance.")
                                img_array = compress_image(img_array, quality=70)
                                st.write(f"Compressed size: {img_array.size/(1024*1024):.2f} MB")
                        
                        if st.button("Encrypt Image", key="encrypt_btn"):
                            with st.spinner("Encrypting image..."):
                                progress_bar = st.progress(0)
                                
                                # Step 1: Generate key
                                progress_bar.progress(25)
                                qkd_key = generate_image_key(100)
                                
                                # Step 2: Encrypt image
                                progress_bar.progress(50)
                                start_time = time.time()
                                encrypted_data = encrypt_image(img_array, qkd_key)
                                encryption_time = time.time() - start_time
                                
                                # Step 3: Store in session state
                                progress_bar.progress(75)
                                st.session_state["enc_img"] = encrypted_data
                                st.session_state["img_shape"] = img_array.shape
                                st.session_state["key"] = qkd_key.tolist()
                                
                                # Complete
                                progress_bar.progress(100)
                                st.success(f"Image encrypted successfully in {encryption_time:.2f} seconds!")
                                
                                # Display key and encrypted data
                                key_str = ", ".join(map(str, qkd_key))
                                st.subheader("Encryption Key")
                                st.info("Copy and save this key to decrypt your image later")
                                st.code(key_str, language="text")
                                
                                st.download_button(
                                    label="Download Encryption Key",
                                    data=key_str,
                                    file_name="encryption_key.txt",
                                    mime="text/plain"
                                )
                                
                                st.subheader("Encrypted Image Data")
                                st.text_area("Base64 Encoded Data", encrypted_data[:1000] + "...", height=100)
                                
                                st.download_button(
                                    label="Download Encrypted Image Data",
                                    data=encrypted_data,
                                    file_name="encrypted_image.txt",
                                    mime="text/plain"
                                )
                    except Exception as e:
                        st.error(f"Error processing image: {e}")
            
            with tab2:
                st.subheader("Decrypt an Image")
                
                # Option to use previously encrypted image
                if "enc_img" in st.session_state and "img_shape" in st.session_state:
                    st.success("Previously encrypted image found in session")
                    use_previous = st.checkbox("Use previously encrypted image", value=True)
                else:
                    use_previous = False
                    st.file_uploader("Upload encrypted image data (text file)", type=["txt"], key="encrypted_data_uploader")
                
                key_input = st.text_area("Enter Decryption Key (comma-separated numbers)", height=100)
                
                if st.button("Decrypt Image"):
                    try:
                        with st.spinner("Decrypting image..."):
                            key_list = [int(k.strip()) for k in key_input.split(",")]
                            
                            if use_previous and "enc_img" in st.session_state and "img_shape" in st.session_state:
                                start_time = time.time()
                                dec_img = decrypt_image(st.session_state.enc_img, key_list, st.session_state.img_shape)
                                decryption_time = time.time() - start_time
                                
                                st.success(f"Image decrypted successfully in {decryption_time:.2f} seconds!")
                                st.image(dec_img, caption="Decrypted Image")
                                
                                # Option to download the decrypted image
                                pil_img = Image.fromarray(dec_img)
                                buf = io.BytesIO()
                                pil_img.save(buf, format="PNG")
                                byte_im = buf.getvalue()
                                
                                st.download_button(
                                    label="Download Decrypted Image",
                                    data=byte_im,
                                    file_name="decrypted_image.png",
                                    mime="image/png"
                                )
                            else:
                                st.error("No encrypted image data found. Please encrypt an image first or upload encrypted data.")
                    except Exception as e:
                        st.error(f"Decryption failed: {e}")

if __name__ == "__main__":
    main()