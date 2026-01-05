"""
AES Encryption Module
=====================

This module provides symmetric encryption using AES-GCM mode.
It is used after ECDH key exchange to encrypt actual message data.

ECC/RSA are not used to encrypt data directly due to:
    1. Performance: Asymmetric encryption is slow for large data
    2. Size limits: RSA can only encrypt data smaller than key size
    3. Standard practice: Use asymmetric crypto for key exchange,
       symmetric crypto for bulk encryption

Supported modes:
    - AES-GCM (recommended): Authenticated encryption with associated data
    - Simple XOR (demo only): For educational purposes
"""

import os
import hashlib
from typing import Tuple


# ============ AES-GCM Implementation (using cryptography library) ============

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    print("Warning: 'cryptography' library not installed.")
    print("Install with: pip install cryptography")
    print("Falling back to XOR cipher for demonstration.")


class AESEncryption:
    """
    AES-GCM encryption for secure message encryption.
    
    AES-GCM provides:
        - Confidentiality: Data is encrypted
        - Integrity: Any tampering is detected
        - Authentication: Verifies the sender
    
    Usage:
        key = derive_key_from_ecdh(...)  # 32 bytes for AES-256
        aes = AESEncryption(key)
        
        ciphertext, nonce, tag = aes.encrypt(b"Hello, World!")
        plaintext = aes.decrypt(ciphertext, nonce, tag)
    """
    
    def __init__(self, key: bytes):
        """
        Initialize AES encryption with a key.
        
        Args:
            key: 16, 24, or 32 bytes for AES-128, AES-192, or AES-256
        """
        if len(key) not in (16, 24, 32):
            raise ValueError(f"Key must be 16, 24, or 32 bytes, got {len(key)}")
        
        self.key = key
        
        if CRYPTO_AVAILABLE:
            self.aesgcm = AESGCM(key)
        else:
            self.aesgcm = None
    
    def encrypt(self, plaintext: bytes, 
                associated_data: bytes = None) -> Tuple[bytes, bytes]:
        """
        Encrypt plaintext using AES-GCM.
        
        Args:
            plaintext: Data to encrypt
            associated_data: Additional authenticated data (not encrypted)
        
        Returns:
            Tuple of (ciphertext_with_tag, nonce)
        """
        if not CRYPTO_AVAILABLE:
            return self._xor_encrypt(plaintext)
        
        # Generate random 96-bit nonce (recommended for GCM)
        nonce = os.urandom(12)
        
        # Encrypt (ciphertext includes authentication tag)
        ciphertext = self.aesgcm.encrypt(nonce, plaintext, associated_data)
        
        return ciphertext, nonce
    
    def decrypt(self, ciphertext: bytes, nonce: bytes,
                associated_data: bytes = None) -> bytes:
        """
        Decrypt ciphertext using AES-GCM.
        
        Args:
            ciphertext: Encrypted data with authentication tag
            nonce: The nonce used during encryption
            associated_data: Additional authenticated data
        
        Returns:
            Decrypted plaintext
        
        Raises:
            InvalidTag: If authentication fails (data was tampered)
        """
        if not CRYPTO_AVAILABLE:
            return self._xor_decrypt(ciphertext, nonce)
        
        plaintext = self.aesgcm.decrypt(nonce, ciphertext, associated_data)
        return plaintext
    
    def _xor_encrypt(self, plaintext: bytes) -> Tuple[bytes, bytes]:
        """
        Simple XOR encryption (DEMO ONLY - NOT SECURE).
        
        This is only for demonstration when cryptography library is unavailable.
        """
        # Use key hash as keystream seed
        nonce = os.urandom(16)
        keystream = self._generate_keystream(len(plaintext), nonce)
        
        ciphertext = bytes(p ^ k for p, k in zip(plaintext, keystream))
        return ciphertext, nonce
    
    def _xor_decrypt(self, ciphertext: bytes, nonce: bytes) -> bytes:
        """XOR decryption (DEMO ONLY)."""
        keystream = self._generate_keystream(len(ciphertext), nonce)
        plaintext = bytes(c ^ k for c, k in zip(ciphertext, keystream))
        return plaintext
    
    def _generate_keystream(self, length: int, nonce: bytes) -> bytes:
        """Generate keystream for XOR cipher using SHA-256 in counter mode."""
        keystream = b''
        counter = 0
        
        while len(keystream) < length:
            hasher = hashlib.sha256()
            hasher.update(self.key)
            hasher.update(nonce)
            hasher.update(counter.to_bytes(4, 'big'))
            keystream += hasher.digest()
            counter += 1
        
        return keystream[:length]


def encrypt_message(key: bytes, message: str) -> dict:
    """
    High-level function to encrypt a string message.
    
    Args:
        key: 32-byte AES key (from ECDH)
        message: String message to encrypt
    
    Returns:
        Dictionary with ciphertext and nonce (hex encoded)
    """
    aes = AESEncryption(key)
    plaintext = message.encode('utf-8')
    ciphertext, nonce = aes.encrypt(plaintext)
    
    return {
        'ciphertext': ciphertext.hex(),
        'nonce': nonce.hex(),
        'algorithm': 'AES-256-GCM' if CRYPTO_AVAILABLE else 'XOR-SHA256'
    }


def decrypt_message(key: bytes, encrypted_data: dict) -> str:
    """
    High-level function to decrypt a message.
    
    Args:
        key: 32-byte AES key (from ECDH)
        encrypted_data: Dictionary from encrypt_message()
    
    Returns:
        Decrypted string message
    """
    aes = AESEncryption(key)
    ciphertext = bytes.fromhex(encrypted_data['ciphertext'])
    nonce = bytes.fromhex(encrypted_data['nonce'])
    
    plaintext = aes.decrypt(ciphertext, nonce)
    return plaintext.decode('utf-8')


def derive_key_from_password(password: str, salt: bytes = None) -> Tuple[bytes, bytes]:
    """
    Derive an AES key from a password using PBKDF2.
    
    This is useful for testing without ECDH.
    
    Args:
        password: User password
        salt: Random salt (generated if not provided)
    
    Returns:
        Tuple of (key, salt)
    """
    if salt is None:
        salt = os.urandom(16)
    
    if CRYPTO_AVAILABLE:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = kdf.derive(password.encode())
    else:
        # Simple fallback
        hasher = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        key = hasher
    
    return key, salt


# ============ Tests ============
if __name__ == "__main__":
    print("Testing AES Encryption Module")
    print("=" * 60)
    print(f"Cryptography library available: {CRYPTO_AVAILABLE}")
    
    # Test 1: Basic encryption/decryption
    print("\n1. Basic Encryption/Decryption Test:")
    key = os.urandom(32)  # AES-256 key
    message = "Hello, this is a secret message!"
    
    print(f"   Original message: {message}")
    print(f"   Key: {key.hex()[:32]}...")
    
    encrypted = encrypt_message(key, message)
    print(f"   Algorithm: {encrypted['algorithm']}")
    print(f"   Ciphertext: {encrypted['ciphertext'][:32]}...")
    print(f"   Nonce: {encrypted['nonce']}")
    
    decrypted = decrypt_message(key, encrypted)
    print(f"   Decrypted message: {decrypted}")
    print(f"   Match: {message == decrypted}")
    
    # Test 2: Password-based key derivation
    print("\n2. Password-Based Key Derivation:")
    password = "MySecretPassword123"
    key1, salt = derive_key_from_password(password)
    key2, _ = derive_key_from_password(password, salt)
    
    print(f"   Password: {password}")
    print(f"   Salt: {salt.hex()}")
    print(f"   Derived key: {key1.hex()}")
    print(f"   Same key from same password+salt: {key1 == key2}")
    
    # Test 3: Different messages
    print("\n3. Multiple Message Test:")
    messages = [
        "Short",
        "A longer message with more content to encrypt.",
        "Unicode test: Hello 世界 🌍 مرحبا",
        "Binary-like: \x00\x01\x02\x03"
    ]
    
    for msg in messages:
        enc = encrypt_message(key, msg)
        dec = decrypt_message(key, enc)
        status = "✓" if msg == dec else "✗"
        print(f"   {status} '{msg[:30]}...' - Encrypted length: {len(enc['ciphertext'])//2} bytes")
    
    # Test 4: Simulate ECDH + AES flow
    print("\n4. Simulated ECDH + AES Flow:")
    
    # Simulate ECDH key (in practice, this comes from ecdh.py)
    simulated_ecdh_key = hashlib.sha256(b"shared_secret_point_x_coordinate").digest()
    
    alice_message = "Hello Bob, this is Alice!"
    print(f"   Alice's message: {alice_message}")
    
    # Alice encrypts with shared key
    encrypted = encrypt_message(simulated_ecdh_key, alice_message)
    print(f"   Encrypted (sent to Bob): {encrypted['ciphertext'][:40]}...")
    
    # Bob decrypts with same shared key
    bob_received = decrypt_message(simulated_ecdh_key, encrypted)
    print(f"   Bob decrypts: {bob_received}")
    
    print("\n" + "=" * 60)
    print("All AES tests completed!")
