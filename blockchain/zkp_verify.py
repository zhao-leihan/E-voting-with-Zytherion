from py_ecc.secp256k1 import privtopub, ecdsa_raw_sign, ecdsa_raw_recover
from eth_utils import keccak, int_to_big_endian

def generate_keys():
    """
    Generate private and public keys for the voter.
    :return: A tuple of (private_key, public_key).
    - private_key: 32-byte big-endian byte string.
    - public_key: Tuple of two integers representing the public key.
    """
    from random import randint
    # Generate a random private key as an integer
    private_key_int = randint(1, 2**256 - 1)
    
    # Convert the private key to a 32-byte big-endian representation
    private_key_bytes = int_to_big_endian(private_key_int).rjust(32, b'\x00')
    
    # Generate the public key from the private key
    public_key = privtopub(private_key_bytes)
    return private_key_bytes, public_key


def sign_message(private_key, message):
    """
    Sign a message using the private key.
    :param private_key: The private key of the voter (32-byte big-endian).
    :param message: The message to sign (e.g., Voter ID).
    :return: The signature (v, r, s).
    """
    # Hash the message using keccak256
    message_hash = keccak(text=message)
    
    # Sign the hash using the private key
    v, r, s = ecdsa_raw_sign(message_hash, private_key)
    return v, r, s


def verify_signature(public_key, message, signature):
    """
    Verify a signature using the public key.
    :param public_key: The public key of the voter (tuple of two integers).
    :param message: The message to verify (e.g., Voter ID).
    :param signature: The signature (v, r, s).
    :return: True if the signature is valid, False otherwise.
    """
    # Hash the message using keccak256
    message_hash = keccak(text=message)
    
    # Extract v, r, s from the signature
    v, r, s = signature
    
    # Recover the public key from the signature
    recovered_public_key = ecdsa_raw_recover(message_hash, (v, r, s))
    
    # Compare the recovered public key with the provided public key
    return recovered_public_key == public_key