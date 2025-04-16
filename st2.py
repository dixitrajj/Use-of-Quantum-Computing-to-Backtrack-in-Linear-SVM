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

    if not st.session_state.logged_in:
        st.title("\U0001F512 Lock Chat")
        st.subheader("Encrypt your messages and images using simulated Quantum Key Distribution")
        st.image("https://image.binance.vision/editor-uploads/bd1d649021654f8f9a9059e02a7c1278.gif", width=700)

        st.sidebar.title("Authentication")
        auth_option = st.sidebar.radio("Choose an option", ("Login", "Register"))

        if auth_option == "Register":
            # Registration page: email, name, password, and re-enter password.
            email = st.sidebar.text_input("Email")
            name = st.sidebar.text_input("Name")
            password = st.sidebar.text_input("Password", type="password")
            re_password = st.sidebar.text_input("Re-enter Password", type="password")
            if st.sidebar.button("Register"):
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
            email = st.sidebar.text_input("Email")
            password = st.sidebar.text_input("Password", type="password")
            if st.sidebar.button("Login"):
                login_user(email, password)
    else:
        if st.sidebar.button("Logout"):
            st.session_state.logged_in = False
            st.experimental_rerun()

        st.sidebar.title("Navigation")
        nav_option = st.sidebar.radio("Go to:", ("Secure Chat Interface", "Image Encryption and Decryption"))

        if nav_option == "Secure Chat Interface":
            st.subheader("Secure Chat Interface")
            st.write(f"Welcome {st.session_state.name}!")

            message = st.text_area("Type your message:")
            if st.button("Send Message") and message:
                shared_key = bb84_key_exchange(len(message))
                encrypted_msg = encrypt_message(message, shared_key)
                qr_image = generate_qr_code(''.join(map(str, shared_key)))
                with io.BytesIO() as buffer:
                    qr_image.save(buffer, format="PNG")
                    st.image(buffer.getvalue(), caption="QR Code for Shared Key")
                st.session_state.update({
                    "original_message": message,
                    "shared_key": shared_key,
                    "encrypted_message": encrypted_msg,
                    "message_sent": True
                })

            if st.session_state.get("message_sent"):
                st.write("*Encrypted Message:*", st.session_state.encrypted_message)
                st.write("*Shared Key:*", ''.join(map(str, st.session_state.shared_key)))

            enc_input = st.text_input("Enter encrypted message:")
            key_input = st.text_input("Enter shared key:")
            if st.button("Decrypt Message") and enc_input and key_input:
                try:
                    key = list(map(int, key_input.strip()))
                    decrypted = decrypt_message(enc_input, key)
                    st.success("Decrypted Message: " + decrypted)
                except Exception as e:
                    st.error(f"Invalid key format: {e}")

        elif nav_option == "Image Encryption and Decryption":
            st.subheader("Image Encryption and Decryption")
            st.info("For best performance, please use images smaller than 5MB. Larger images will be automatically compressed.")
            progress_placeholder = st.empty()

            uploaded = st.file_uploader("Upload an image", type=["png", "jpg", "jpeg"])
            if uploaded:
                try:
                    img = Image.open(uploaded)
                    img_array = np.array(img)
                    file_size_mb = uploaded.size / (1024 * 1024)
                    if file_size_mb > 5:
                        progress_placeholder.warning(f"Image size: {file_size_mb:.1f}MB. Compressing for better performance...")
                        img_array = compress_image(img_array, quality=70)
                        progress_placeholder.success("Image compressed successfully")
                    st.image(img_array, caption="Original Image")

                    col1, col2 = st.columns(2)
                    with col1:
                        if st.button("Encrypt Image"):
                            try:
                                progress_placeholder.info("Generating encryption key...")
                                qkd_key = generate_image_key(100)
                                progress_placeholder.info("Encrypting image... This may take a moment")
                                start_time = time.time()
                                encrypted_data = encrypt_image(img_array, qkd_key)
                                encryption_time = time.time() - start_time
                                progress_placeholder.success(f"Image Encrypted Successfully in {encryption_time:.2f} seconds!")

                                st.session_state["enc_img"] = encrypted_data
                                st.session_state["img_shape"] = img_array.shape
                                st.session_state["key"] = qkd_key.tolist()

                                st.text_area("Encryption Key (Copy this for decryption)",
                                             ", ".join(map(str, qkd_key)),
                                             height=100)
                                st.text_area("Encrypted Image", encrypted_data, height=100)
                            except Exception as e:
                                progress_placeholder.error(f"Encryption failed: {e}")
                    with col2:
                        key_input = st.text_input("Enter Decryption Key (comma-separated):")
                        if st.button("Decrypt Image") and key_input:
                            try:
                                progress_placeholder.info("Decrypting image... This may take a moment")
                                key_list = [int(k.strip()) for k in key_input.split(",")]
                                if "enc_img" in st.session_state and "img_shape" in st.session_state:
                                    start_time = time.time()
                                    dec_img = decrypt_image(st.session_state.enc_img, key_list, st.session_state.img_shape)
                                    decryption_time = time.time() - start_time
                                    progress_placeholder.success(f"Image Decrypted Successfully in {decryption_time:.2f} seconds!")
                                    st.image(dec_img, caption="Decrypted Image")
                                else:
                                    progress_placeholder.error("No encrypted image found. Please encrypt an image first.")
                            except Exception as e:
                                progress_placeholder.error(f"Decryption failed: {e}")
                except Exception as e:
                    st.error(f"Error processing image: {e}")

if __name__ == "__main__":
    main()