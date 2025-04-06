# 🔐 Secure Data Handling using RSA Cryptography

## 📌 Overview

This project implements a comprehensive system for secure data handling using **RSA encryption and digital signatures**. It ensures secure storage, secure data transmission, and verification of authenticity and integrity — making it ideal for real-world use in digital communication.

---

## 🎯 Objectives

- 🔒 Securely store and transmit messages using RSA.
- ✍️ Implement digital signatures to verify the sender’s identity.
- 📁 Save encrypted messages and signatures in binary files.
- 🔑 Generate, save, and reuse RSA public-private key pairs.

---

## ⚙️ Technologies Used

- **Language**: Python 3
- **Library**: `cryptography`
- **File Formats**:
  - `.pem` for RSA keys
  - `.bin` for encrypted message and signature

---

## 🛠️ Features

- RSA key pair generation (2048-bit)
- Public key encryption using OAEP padding (SHA-256)
- Digital signing using PSS padding and SHA-256
- Secure binary file storage for ciphertext and signature
- Signature verification to ensure data integrity

---

## 📁 Files

| Filename               | Description                               |
|------------------------|-------------------------------------------|
| `private_key.pem`      | User’s RSA private key                    |
| `public_key.pem`       | User’s RSA public key                     |
| `encrypted_message.bin`| Encrypted version of user message         |
| `signature.bin`        | Digital signature of the original message |

---

## ▶️ How to Run

1. Clone the repository:
   ```bash
   git clone https://github.com/maithilikp/securedatahandling
   cd securedatahandling
   ```

2. Install dependencies:
   ```bash
   pip install cryptography
   ```

3. Run the script:
   ```bash
   python secure_data_handling.py
   ```

---

## 🎬 Demo

🔗 **Watch the demo screen recording**  
[Click here to view demo video](https://github.com/maithilikp/securedatahandling/blob/main/Screen%20Recording%202025-04-06%20230920.mp4)

---

## 🚀 Future Improvements

- Add a **Graphical User Interface (GUI)** for easier interaction.
- Support **file-based encryption** in addition to text messages.
- Implement **hybrid encryption** using AES for better performance.



