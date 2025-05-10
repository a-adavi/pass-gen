# 🔐 Secure Password Generator & Decryptor  
### *By Alireza Adavi*

A simple yet secure CLI-based password generator and decryptor using **SHA-512 hashing** and **AES-256-CBC encryption**. This tool generates strong, unique passwords based on personal data and supports optional encryption for secure storage.

---

## 📝 Description

This project allows users to:

- Generate strong passwords with customizable length (8–27 characters)
- Ensure all password requirements are met: lowercase, uppercase, digits, and special characters
- Encrypt generated passwords using AES-256-CBC and save them in a JSON file
- Decrypt stored passwords using a user-defined key

The password generation is deterministic — the same input always produces the same password — making it ideal for recovery without storing secrets in plain text.

---

## ⚙️ Features

- ✅ SHA-512 hashing for secure password derivation  
- ✅ AES-256-CBC encryption/decryption with PKCS#7 padding  
- ✅ Interactive menu system for easy terminal use  
- ✅ Encrypted password storage in JSON format  
- ✅ Input validation and error handling  
- ✅ No passwords stored unless explicitly encrypted  

---

## 🛠️ Requirements

You need Python 3 and `pip` installed. Then install the required library:

```bash
pip install pycryptodome
