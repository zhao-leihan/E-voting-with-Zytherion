import os
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

def generate_aes_key():
    """
    Generate a random 256-bit (32-byte) AES key.
    Returns the key as bytes.
    """
    return get_random_bytes(32)

def encrypt_data_aes(key, plaintext):
    """
    Encrypt data using AES encryption in CBC mode.
    Args:
        key (bytes): The AES key (must be 32 bytes for AES-256).
        plaintext (str): The plaintext data to encrypt.
    Returns:
        dict: A dictionary containing the IV and ciphertext (both Base64-encoded).
    """
    # Ensure the plaintext is bytes
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = pad(plaintext, AES.block_size)
    ciphertext = cipher.encrypt(padded_plaintext)
    return {
        "iv": b64encode(iv).decode('utf-8'),
        "ciphertext": b64encode(ciphertext).decode('utf-8')
    }

def decrypt_data_aes(key, encrypted_data):
    """
    Decrypt data using AES decryption in CBC mode.
    Args:
        key (bytes): The AES key (must be 32 bytes for AES-256).
        encrypted_data (dict): A dictionary containing the IV and ciphertext (Base64-encoded).
    Returns:
        str: The decrypted plaintext.
    """
    iv = b64decode(encrypted_data["iv"])
    ciphertext = b64decode(encrypted_data["ciphertext"])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = cipher.decrypt(ciphertext)
    plaintext = unpad(padded_plaintext, AES.block_size)
    return plaintext.decode('utf-8')

def decrypt_admin_data(admin, block_index):
    """
    Decrypt admin data from the blockchain.
    Returns a dictionary with decrypted fields.
    """
    try:
        aes_key = base64.b64decode(admin["aes_key"])
        decrypted_data = {
            "block_index": block_index,
            "tx_hash": admin.get("tx_hash", "Unknown"),
            "username": decrypt_data_aes(
                aes_key,
                {
                    "iv": admin["encrypted_username"]["iv"],
                    "ciphertext": admin["encrypted_username"]["ciphertext"]
                }
            ),
            "password": decrypt_data_aes(
                aes_key,
                {
                    "iv": admin["encrypted_password"]["iv"],
                    "ciphertext": admin["encrypted_password"]["ciphertext"]
                }
            ),
            "ip_address": decrypt_data_aes(
                aes_key,
                {
                    "iv": admin["encrypted_ip"]["iv"],
                    "ciphertext": admin["encrypted_ip"]["ciphertext"]
                }
            ) if "encrypted_ip" in admin else "Unknown"
        }
        return decrypted_data
    except Exception as e:
        print(f"Error decrypting admin data: {e}")
        return None