"""
RSA Implementation for Comparison
=================================

This module implements RSA encryption for comparison with ECC.
RSA is implemented from scratch to demonstrate the key size and
performance differences with ECC.

RSA Algorithm:
    Key Generation:
        1. Choose two large primes p and q
        2. Compute n = p * q (modulus)
        3. Compute φ(n) = (p-1)(q-1) (Euler's totient)
        4. Choose e such that 1 < e < φ(n) and gcd(e, φ(n)) = 1
        5. Compute d = e^(-1) mod φ(n) (private exponent)
        
    Public key: (n, e)
    Private key: (n, d)
    
    Encryption: c = m^e mod n
    Decryption: m = c^d mod n
"""

import os
import hashlib
from dataclasses import dataclass
from typing import Tuple, Optional
from math_utils import mod_inverse, mod_exp, is_prime, generate_prime, extended_gcd


@dataclass
class RSAPublicKey:
    """RSA Public Key."""
    n: int  # Modulus
    e: int  # Public exponent
    
    def bit_length(self) -> int:
        """Get the key size in bits."""
        return self.n.bit_length()
    
    def to_bytes(self) -> bytes:
        """Convert public key to bytes."""
        n_bytes = self.n.to_bytes((self.n.bit_length() + 7) // 8, 'big')
        e_bytes = self.e.to_bytes((self.e.bit_length() + 7) // 8, 'big')
        return n_bytes + e_bytes


@dataclass
class RSAPrivateKey:
    """RSA Private Key with optional CRT parameters for faster decryption."""
    n: int  # Modulus
    d: int  # Private exponent
    p: Optional[int] = None  # First prime (for CRT optimization)
    q: Optional[int] = None  # Second prime (for CRT optimization)
    dp: Optional[int] = None  # d mod (p-1) (CRT parameter)
    dq: Optional[int] = None  # d mod (q-1) (CRT parameter)
    qinv: Optional[int] = None  # q^(-1) mod p (CRT parameter)
    
    def bit_length(self) -> int:
        """Get the key size in bits."""
        return self.n.bit_length()
    
    def has_crt_params(self) -> bool:
        """Check if CRT parameters are available for fast decryption."""
        return all(x is not None for x in [self.p, self.q, self.dp, self.dq, self.qinv])


@dataclass 
class RSAKeyPair:
    """RSA Key Pair."""
    public_key: RSAPublicKey
    private_key: RSAPrivateKey


def generate_rsa_keypair(bits: int = 2048, e: int = 65537) -> RSAKeyPair:
    """
    Generate an RSA key pair.
    
    Args:
        bits: Key size in bits (1024, 2048, 3072, or 4096 recommended)
        e: Public exponent (65537 is standard)
    
    Returns:
        RSAKeyPair containing public and private keys
    
    Note:
        2048-bit RSA ≈ 112-bit security (comparable to ECC-224)
        3072-bit RSA ≈ 128-bit security (comparable to ECC-256)
    """
    # Generate two large primes of half the key size
    prime_bits = bits // 2
    
    # Ensure p and q are different and their product has correct bit length
    while True:
        p = generate_prime(prime_bits)
        q = generate_prime(prime_bits)
        
        if p != q:
            n = p * q
            if n.bit_length() == bits:
                break
    
    # Compute Euler's totient φ(n) = (p-1)(q-1)
    phi_n = (p - 1) * (q - 1)
    
    # Verify e is coprime to φ(n)
    gcd, _, _ = extended_gcd(e, phi_n)
    if gcd != 1:
        raise ValueError(f"e={e} is not coprime to φ(n)")
    
    # Compute private exponent d = e^(-1) mod φ(n)
    d = mod_inverse(e, phi_n)
    
    # Compute CRT parameters for faster decryption (~4x speedup)
    dp = d % (p - 1)  # d mod (p-1)
    dq = d % (q - 1)  # d mod (q-1)
    qinv = mod_inverse(q, p)  # q^(-1) mod p
    
    public_key = RSAPublicKey(n=n, e=e)
    private_key = RSAPrivateKey(n=n, d=d, p=p, q=q, dp=dp, dq=dq, qinv=qinv)
    
    return RSAKeyPair(public_key=public_key, private_key=private_key)


def rsa_encrypt(message: int, public_key: RSAPublicKey) -> int:
    """
    Encrypt a message using RSA.
    
    Args:
        message: Integer message (must be < n)
        public_key: RSA public key
    
    Returns:
        Ciphertext as integer
    
    Note:
        message must be less than n. For real usage, apply padding (OAEP).
    """
    if message >= public_key.n:
        raise ValueError("Message must be less than modulus n")
    
    # c = m^e mod n
    ciphertext = mod_exp(message, public_key.e, public_key.n)
    return ciphertext


def rsa_decrypt(ciphertext: int, private_key: RSAPrivateKey) -> int:
    """
    Decrypt a ciphertext using RSA.
    
    Uses CRT optimization if parameters available (~4x faster):
        m1 = c^dp mod p
        m2 = c^dq mod q  
        h = qinv * (m1 - m2) mod p
        m = m2 + h * q
    
    Falls back to: m = c^d mod n
    
    Args:
        ciphertext: Encrypted integer
        private_key: RSA private key
    
    Returns:
        Decrypted message as integer
    """
    # Use CRT optimization if available (approximately 4x faster)
    if private_key.has_crt_params():
        m1 = mod_exp(ciphertext, private_key.dp, private_key.p)
        m2 = mod_exp(ciphertext, private_key.dq, private_key.q)
        h = (private_key.qinv * (m1 - m2)) % private_key.p
        message = m2 + h * private_key.q
        return message
    
    # Standard decryption (slower)
    message = mod_exp(ciphertext, private_key.d, private_key.n)
    return message


def rsa_encrypt_bytes(message: bytes, public_key: RSAPublicKey) -> bytes:
    """
    Encrypt bytes using RSA with simple padding.
    
    WARNING: This uses simple padding for demonstration.
    Production systems should use OAEP padding.
    
    Args:
        message: Bytes to encrypt (must fit in key size - 11 bytes)
        public_key: RSA public key
    
    Returns:
        Encrypted bytes
    """
    max_msg_len = (public_key.n.bit_length() // 8) - 11
    
    if len(message) > max_msg_len:
        raise ValueError(f"Message too long. Max {max_msg_len} bytes for this key size.")
    
    # Simple PKCS#1 v1.5 style padding (0x00 0x02 [random] 0x00 [message])
    # PKCS#1 v1.5 requires minimum 8 bytes of random padding
    MIN_PADDING_LEN = 8
    padding_len = (public_key.n.bit_length() // 8) - len(message) - 3
    
    if padding_len < MIN_PADDING_LEN:
        raise ValueError(f"Padding too short ({padding_len} bytes). PKCS#1 requires minimum {MIN_PADDING_LEN} bytes.")
    
    padding = bytes(os.urandom(padding_len).replace(b'\x00', b'\x01'))  # No zero bytes in padding
    
    padded = b'\x00\x02' + padding + b'\x00' + message
    
    # Convert to integer and encrypt
    m = int.from_bytes(padded, 'big')
    c = rsa_encrypt(m, public_key)
    
    # Convert back to bytes
    key_bytes = (public_key.n.bit_length() + 7) // 8
    return c.to_bytes(key_bytes, 'big')


def rsa_decrypt_bytes(ciphertext: bytes, private_key: RSAPrivateKey) -> bytes:
    """
    Decrypt bytes using RSA.
    
    Args:
        ciphertext: Encrypted bytes
        private_key: RSA private key
    
    Returns:
        Decrypted message bytes
    """
    # Convert to integer and decrypt
    c = int.from_bytes(ciphertext, 'big')
    m = rsa_decrypt(c, private_key)
    
    # Convert back to bytes
    key_bytes = (private_key.n.bit_length() + 7) // 8
    padded = m.to_bytes(key_bytes, 'big')
    
    # Remove PKCS#1 padding
    if padded[0:2] != b'\x00\x02':
        raise ValueError("Invalid padding")
    
    # Find the 0x00 separator after padding
    sep_idx = padded.index(b'\x00', 2)
    message = padded[sep_idx + 1:]
    
    return message


class RSAEncryption:
    """
    High-level RSA encryption class for comparison with ECC.
    
    Usage:
        rsa = RSAEncryption(bits=2048)
        
        # Encrypt for someone (using their public key)
        ciphertext = rsa.encrypt(b"Hello!")
        
        # Decrypt with private key
        plaintext = rsa.decrypt(ciphertext)
    """
    
    def __init__(self, bits: int = 2048, keypair: RSAKeyPair = None):
        """
        Initialize RSA encryption.
        
        Args:
            bits: Key size in bits
            keypair: Pre-existing keypair (generates new if None)
        """
        if keypair:
            self.keypair = keypair
        else:
            self.keypair = generate_rsa_keypair(bits)
        
        self.public_key = self.keypair.public_key
        self.private_key = self.keypair.private_key
    
    def encrypt(self, message: bytes) -> bytes:
        """Encrypt message with public key."""
        return rsa_encrypt_bytes(message, self.public_key)
    
    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt ciphertext with private key."""
        return rsa_decrypt_bytes(ciphertext, self.private_key)
    
    def get_public_key(self) -> RSAPublicKey:
        """Get the public key for sharing."""
        return self.public_key
    
    def encrypt_with_key(self, message: bytes, public_key: RSAPublicKey) -> bytes:
        """Encrypt message with a specific public key."""
        return rsa_encrypt_bytes(message, public_key)


def rsa_key_exchange_simulation(bits: int = 2048) -> Tuple[bytes, bytes]:
    """
    Simulate RSA-based key exchange for comparison with ECDH.
    
    In RSA key exchange:
        1. Bob generates RSA keypair, shares public key
        2. Alice generates random symmetric key
        3. Alice encrypts symmetric key with Bob's public key
        4. Bob decrypts to get the symmetric key
    
    Note: This is simpler than ECDH but requires one party to
    generate and transmit the encrypted key.
    
    Returns:
        Tuple of (alice_key, bob_key) - should be identical
    """
    # Bob generates RSA keypair
    bob = RSAEncryption(bits)
    bob_public = bob.get_public_key()
    
    # Alice generates random AES key
    alice_aes_key = os.urandom(32)  # AES-256 key
    
    # Alice encrypts the key with Bob's public key
    encrypted_key = rsa_encrypt_bytes(alice_aes_key, bob_public)
    
    # Bob decrypts to get the same key
    bob_aes_key = rsa_decrypt_bytes(encrypted_key, bob.private_key)
    
    return alice_aes_key, bob_aes_key


# ============ Tests ============
if __name__ == "__main__":
    import time
    
    print("Testing RSA Module")
    print("=" * 60)
    
    # Test 1: Key generation with small key (fast for testing)
    print("\n1. RSA Key Generation (1024-bit for testing):")
    start = time.time()
    keypair = generate_rsa_keypair(bits=1024)
    elapsed = time.time() - start
    
    print(f"   Key size: {keypair.public_key.bit_length()} bits")
    print(f"   Generation time: {elapsed:.3f} seconds")
    print(f"   n: {hex(keypair.public_key.n)[:50]}...")
    print(f"   e: {keypair.public_key.e}")
    
    # Test 2: Basic encryption/decryption (integer)
    print("\n2. Basic RSA Encryption/Decryption:")
    message = 12345678901234567890
    
    ciphertext = rsa_encrypt(message, keypair.public_key)
    decrypted = rsa_decrypt(ciphertext, keypair.private_key)
    
    print(f"   Original: {message}")
    print(f"   Ciphertext: {ciphertext}")
    print(f"   Decrypted: {decrypted}")
    print(f"   Match: {message == decrypted}")
    
    # Test 3: Byte encryption/decryption
    print("\n3. RSA Byte Encryption/Decryption:")
    message = b"Hello, RSA!"
    
    ciphertext = rsa_encrypt_bytes(message, keypair.public_key)
    decrypted = rsa_decrypt_bytes(ciphertext, keypair.private_key)
    
    print(f"   Original: {message}")
    print(f"   Ciphertext length: {len(ciphertext)} bytes")
    print(f"   Decrypted: {decrypted}")
    print(f"   Match: {message == decrypted}")
    
    # Test 4: High-level API
    print("\n4. High-Level RSA API:")
    rsa = RSAEncryption(bits=1024)
    
    message = b"Secret message for RSA test!"
    ciphertext = rsa.encrypt(message)
    decrypted = rsa.decrypt(ciphertext)
    
    print(f"   Original: {message}")
    print(f"   Encrypted length: {len(ciphertext)} bytes")
    print(f"   Decrypted: {decrypted}")
    print(f"   Match: {message == decrypted}")
    
    # Test 5: RSA key exchange simulation
    print("\n5. RSA Key Exchange Simulation:")
    alice_key, bob_key = rsa_key_exchange_simulation(bits=1024)
    
    print(f"   Alice's AES key: {alice_key.hex()}")
    print(f"   Bob's AES key:   {bob_key.hex()}")
    print(f"   Keys match: {alice_key == bob_key}")
    
    # Test 6: Key size comparison prep
    print("\n6. Key Size Comparison Info:")
    security_levels = {
        "80-bit":  {"RSA": 1024, "ECC": 160},
        "112-bit": {"RSA": 2048, "ECC": 224},
        "128-bit": {"RSA": 3072, "ECC": 256},
        "192-bit": {"RSA": 7680, "ECC": 384},
        "256-bit": {"RSA": 15360, "ECC": 521},
    }
    
    print("   Security Level | RSA Key Size | ECC Key Size | RSA/ECC Ratio")
    print("   " + "-" * 60)
    for level, sizes in security_levels.items():
        ratio = sizes["RSA"] / sizes["ECC"]
        print(f"   {level:13} | {sizes['RSA']:12} | {sizes['ECC']:12} | {ratio:.1f}x")
    
    print("\n" + "=" * 60)
    print("All RSA tests completed!")
