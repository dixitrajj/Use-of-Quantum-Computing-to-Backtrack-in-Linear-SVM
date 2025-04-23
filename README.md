# 🔒 Lock Chat

**Lock Chat** is a secure messaging and image encryption web application built with Streamlit that simulates Quantum Key Distribution (QKD) using the BB84 protocol and encrypts data using XOR logic. It also supports QR code sharing of keys and image-based encryption/decryption using generated quantum keys.

---

## 🚀 Features

### ✅ User Authentication
- Register and log in securely.
- Stores credentials in a local CSV file.

### 🔐 Secure Chat Interface
- Compose and encrypt messages using a simulated BB84 key exchange.
- Share keys via generated QR codes.
- Decrypt encrypted messages using the shared key.

### 🖼️ Image Encryption & Decryption
- Upload images (JPG, JPEG, PNG) and encrypt them using quantum-generated keys.
- Download base64-encoded encrypted data and keys.
- Decrypt previously encrypted images using the shared key.
- Image compression applied to optimize performance for large files.

---

## 📷 Preview

![Lock Chat Preview](https://image.binance.vision/editor-uploads/bd1d649021654f8f9a9059e02a7c1278.gif)

---

## 🛠️ Technologies Used

- **Python**
- **Streamlit** – For interactive UI
- **NumPy** – Efficient array operations
- **Pillow** – Image handling
- **OpenCV** – Image processing
- **QRCode** – QR code generation
- **Base64** – Encoding encrypted images

---

## 📁 Project Structure

```
lock_chat/
│
├── user_credentials.csv       # User login data
├── lock_chat_app.py           # Main Streamlit application
├── README.md                  # Project documentation
└── requirements.txt           # Python dependencies
```

---

## 🧪 Simulated Quantum Features

### BB84 Key Exchange (Simulated)
- Random generation of Alice's and Bob's bits/bases.
- Secure key derived from matching bases.

### XOR Encryption
- Applied on messages and image byte data.
- Efficient, lightweight encryption method.

---

## 🔧 How to Run the App

1. **Clone this repo**
   ```bash
   git clone https://github.com/yourusername/lock-chat.git
   cd lock-chat
   ```

2. **Create a virtual environment (optional but recommended)**
   ```bash
   python -m venv venv
   source venv/bin/activate  # or `venv\Scripts\activate` on Windows
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Run the app**
   ```bash
   streamlit run lock_chat_app.py
   ```

---

## 📦 Requirements

Add this to your `requirements.txt`:

```
streamlit
pillow
numpy
opencv-python
qrcode
```

---

## 👨‍💻 Developer Notes

- The app is intended for educational purposes only and simulates quantum encryption concepts.
- Image encryption is done via XOR and is not quantum-secure in practice.
- Simulated QKD (BB84) does not involve actual quantum communication.

---
