import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import numpy as np
import time

def generate_ecc_keypair():
    """Generate an ECC private key using SECP256R1"""
    try:
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
        return private_key, public_key
    except Exception as e:
        raise RuntimeError(f"Key generation failed: {e}")

def aes_encrypt(key, plaintext):
    """Enhanced encryption with authentication"""
    if not isinstance(plaintext, bytes):
        plaintext = plaintext.encode('utf-8')
    
    iv = secrets.token_bytes(16)
    # Using GCM mode instead of CBC for authenticated encryption
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return iv, ciphertext, encryptor.tag

def aes_decrypt(key, iv, ciphertext, tag):
    """Enhanced decryption with authentication"""
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

# Add message authentication
def create_message_signature(private_key, message):
    """Create a digital signature for a message"""
    if not isinstance(message, bytes):
        message = message.encode('utf-8')
    
    signature = private_key.sign(
        message,
        ec.ECDSA(hashes.SHA256())
    )
    return signature

def verify_message_signature(public_key, message, signature):
    """Verify a message's digital signature"""
    if not isinstance(message, bytes):
        message = message.encode('utf-8')
    
    try:
        public_key.verify(
            signature,
            message,
            ec.ECDSA(hashes.SHA256())
        )
        return True
    except:
        return False

def serialize_public_key(public_key):
    """Serialize a public key to bytes format"""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def deserialize_public_key(key_bytes):
    """Deserialize bytes back to a public key object"""
    return serialization.load_pem_public_key(
        key_bytes,
        backend=default_backend()
    )

def derive_shared_key(private_key, peer_public_key):
    """Derive a shared key using ECDH"""
    shared_key = private_key.exchange(
        ec.ECDH(),
        peer_public_key
    )
    
    # Use SHA256 to derive a 32-byte key suitable for AES-256
    digest = hashes.Hash(hashes.SHA256())
    digest.update(shared_key)
    return digest.finalize()

def constant_time_compare(val1, val2):
    """Implement constant-time comparison"""
    if len(val1) != len(val2):
        return False
    result = 0
    for x, y in zip(val1, val2):
        result |= x ^ y
    return result == 0

def add_timing_noise():
    """Add random timing noise to mask operations"""
    noise = np.random.normal(0, 0.001)  # 1μs standard deviation
    time.sleep(max(0, noise)) 