import hashlib
import string
import random
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad, pad
from Crypto.Random import get_random_bytes
import base64
import os

# تنظیمات
SPECIAL_CHARS = "!@#$%^&*"
SALT = "SecurePasswordGeneratorSalt"

# --- توابع اعتبارسنجی ---
def contains_lower(password):
    return any(c in string.ascii_lowercase for c in password)

def contains_upper(password):
    return any(c in string.ascii_uppercase for c in password)

def contains_digit(password):
    return any(c in string.digits for c in password)

def contains_special(password):
    return any(c in SPECIAL_CHARS for c in password)

def ensure_requirements(password, favorite_char, all_chars, length):
    password = list(password)
    if not contains_lower(password):
        password[random.randint(0, len(password)-1)] = random.choice(string.ascii_lowercase)
    if not contains_upper(password):
        password[random.randint(0, len(password)-1)] = random.choice(string.ascii_uppercase)
    if not contains_digit(password):
        password[random.randint(0, len(password)-1)] = random.choice(string.digits)
    if not contains_special(password):
        password[random.randint(0, len(password)-1)] = random.choice(SPECIAL_CHARS)

    while len(password) < length:
        password.append(random.choice(all_chars))

    random.shuffle(password)
    return ''.join(password)

# --- رمزنگاری ---
def encrypt_data(data, key):
    try:
        key = key.encode('utf-8')
        key = key.ljust(32)[:32]  # کلید را به 32 بایت محدود کن
        cipher = AES.new(key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(data.encode(), AES.block_size))
        iv = base64.b64encode(cipher.iv).decode('utf-8')
        ct = base64.b64encode(ct_bytes).decode('utf-8')
        return json.dumps({'iv': iv, 'ciphertext': ct})
    except Exception as e:
        print(f"❌ Encryption error: {e}")
        return None

# --- رمزگشایی ---
def decrypt_data(json_data, key):
    try:
        data = json.loads(json_data)
        key = key.encode('utf-8').ljust(32)[:32]
        iv = base64.b64decode(data['iv'])
        ct = base64.b64decode(data['ciphertext'])
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return pt.decode('utf-8')
    except Exception as e:
        print(f"❌ Decryption failed: {e}")
        return None

# --- تولید پسورد ---
def generate_password(data):
    combined_data = ''.join([data[key] for key in data if key != "password_length"])
    full_data = combined_data + SALT
    hash_hex = hashlib.sha512(full_data.encode()).hexdigest()

    all_chars = string.ascii_letters + string.digits + SPECIAL_CHARS + data["favorite_char"]

    password = []
    for i in range(data["password_length"]):
        index = int(hash_hex[(i * 3) % len(hash_hex)], 16) % len(all_chars)
        password.append(all_chars[index])

    final_password = ''.join(password)
    final_password = ensure_requirements(final_password, data["favorite_char"], all_chars, data["password_length"])

    return final_password

# --- منوی اصلی ---
def main():
    while True:
        print("\n" + "="*50)
        print("🔐 Secure Password Generator & Decryptor 🔐")
        print("Designed by Alireza Adavi\n")
        print("1. Generate a new secure password")
        print("2. Decrypt an encrypted file")
        print("3. Exit")
        print("="*50)

        choice = input("Choose an option (1-3): ").strip()

        if choice == "1":
            try:
                first_name = input("Enter First Name: ").strip()
                last_name = input("Enter Last Name: ").strip()
                birth_date = input("Enter Date of Birth (YYYYMMDD): ").strip()
                pet_name = input("Enter Pet Name: ").strip()
                favorite_char = input(f"Enter Favorite Special Character ({SPECIAL_CHARS}): ").strip()
                service = input("Enter Service Name: ").strip()
                password_length = int(input("Enter Password Length (8-27): ").strip())

                if not (8 <= password_length <= 27):
                    raise ValueError("Password length must be between 8 and 27.")
                if not favorite_char or favorite_char not in SPECIAL_CHARS:
                    raise ValueError(f"Please choose a valid special character from: {SPECIAL_CHARS}")

                data = {
                    "first_name": first_name,
                    "last_name": last_name,
                    "birth_date": birth_date,
                    "pet_name": pet_name,
                    "favorite_char": favorite_char,
                    "service": service,
                    "password_length": password_length
                }

                password = generate_password(data)
                print(f"\n✅ Generated Password: {password}")

                encrypt_choice = input("Do you want to encrypt and save it? (y/n): ").strip().lower()
                if encrypt_choice == 'y':
                    key = input("Enter encryption key: ")
                    encrypted = encrypt_data(password, key)
                    if encrypted:
                        with open("encrypted_password.json", "w") as f:
                            f.write(encrypted)
                        print("🔒 Encrypted data saved to encrypted_password.json")
                    else:
                        print("⚠️ Encryption failed.")

                input("\nPress Enter to return to menu...")

            except ValueError as ve:
                print(f"❌ Error: {ve}")
                input("\nPress Enter to return to menu...")

        elif choice == "2":
            file_path = input("Enter the path to the encrypted JSON file: ").strip()
            if not os.path.exists(file_path):
                print("❌ File not found.")
                input("\nPress Enter to return to menu...")
                continue

            with open(file_path, "r") as f:
                encrypted_data = f.read()

            key = input("Enter decryption key: ")
            decrypted = decrypt_data(encrypted_data, key)
            if decrypted:
                print(f"\n🔓 Decrypted Password: {decrypted}")
            else:
                print("❌ Failed to decrypt the file.")

            input("\nPress Enter to return to menu...")

        elif choice == "3":
            print("👋 Goodbye!")
            break

        else:
            print("❌ Invalid option selected.")
            input("\nPress Enter to return to menu...")

if __name__ == "__main__":
    main()