from phe import paillier
import hashlib

# Generate public and private keys for Paillier encryption
public_key, private_key = paillier.generate_paillier_keypair()

def get_public_key():
    """Return the public key."""
    return public_key

def get_private_key():
    """Return the private key."""
    return private_key

def encrypt_data_phe(public_key, plaintext):
    """
    Encrypt data using Paillier homomorphic encryption.
    Args:
        public_key: The public key for encryption.
        plaintext (int, float, or str): The data to encrypt.
    Returns:
        EncryptedNumber: The encrypted data.
    """
    if isinstance(plaintext, str):
        # Convert string to numeric representation using hash
        numeric_value = int(hashlib.sha256(plaintext.encode()).hexdigest(), 16) % 10**8
    else:
        numeric_value = plaintext
    return public_key.encrypt(numeric_value)

def decrypt_data_phe(private_key, encrypted_data):
    """
    Decrypt data using Paillier homomorphic encryption.
    Args:
        private_key: The private key for decryption.
        encrypted_data (EncryptedNumber): The encrypted data.
    Returns:
        int or float: The decrypted numeric value.
    """
    return private_key.decrypt(encrypted_data)


def reconstruct_encrypted_number(public_key, ciphertext):
    return paillier.EncryptedNumber(public_key, int(ciphertext))
