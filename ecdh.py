"""
Elliptic Curve Diffie-Hellman (ECDH) Key Exchange
=================================================

This module implements the ECDH key exchange protocol, which allows
two parties to establish a shared secret over an insecure channel.

Protocol:
    1. Alice generates keypair: (dA, QA = dA·G)
    2. Bob generates keypair: (dB, QB = dB·G)
    3. Alice and Bob exchange public keys (QA, QB)
    4. Alice computes: S = dA · QB
    5. Bob computes: S = dB · QA
    6. Both arrive at the same shared secret S (since dA·QB = dA·dB·G = dB·dA·G = dB·QA)

Security: Based on the Elliptic Curve Discrete Logarithm Problem (ECDLP)
"""

import hashlib
from ecc import (
    Point, CurveParams, SECP256K1, P256, TEST_CURVE,
    generate_keypair, scalar_multiply, get_generator
)


class ECDHKeyExchange:
    """
    ECDH Key Exchange handler for one party.
    
    Usage:
        # Alice's side
        alice = ECDHKeyExchange()
        alice_public = alice.get_public_key()
        
        # Bob's side
        bob = ECDHKeyExchange()
        bob_public = bob.get_public_key()
        
        # Exchange public keys and compute shared secret
        alice_shared = alice.compute_shared_secret(bob_public)
        bob_shared = bob.compute_shared_secret(alice_public)
        
        # alice_shared == bob_shared
    """
    
    def __init__(self, curve: CurveParams = SECP256K1, private_key: int = None):
        """
        Initialize ECDH key exchange.
        
        Args:
            curve: The elliptic curve to use
            private_key: Optional pre-existing private key (generates new if None)
        """
        self.curve = curve
        
        if private_key is not None:
            self.private_key = private_key
            G = get_generator(curve)
            self.public_key = scalar_multiply(private_key, G)
        else:
            self.private_key, self.public_key = generate_keypair(curve)
    
    def get_public_key(self) -> Point:
        """Get the public key to share with the other party."""
        return self.public_key
    
    def get_public_key_bytes(self) -> bytes:
        """
        Get the public key as bytes (uncompressed format).
        
        Format: 0x04 || X || Y (65 bytes for 256-bit curves)
        """
        # Determine byte length based on curve
        byte_len = (self.curve.p.bit_length() + 7) // 8
        
        x_bytes = self.public_key.x.to_bytes(byte_len, 'big')
        y_bytes = self.public_key.y.to_bytes(byte_len, 'big')
        
        return b'\x04' + x_bytes + y_bytes
    
    def compute_shared_secret(self, other_public_key: Point) -> Point:
        """
        Compute the shared secret using the other party's public key.
        
        Args:
            other_public_key: The other party's public key Q
        
        Returns:
            The shared secret point S = d · Q
        
        Raises:
            ValueError: If the public key is not on the curve
        """
        if not other_public_key.is_on_curve():
            raise ValueError("Invalid public key: not on curve")
        
        # S = d · Q_other
        shared_secret = scalar_multiply(self.private_key, other_public_key)
        
        return shared_secret
    
    def derive_symmetric_key(self, other_public_key: Point, 
                              key_length: int = 32,
                              info: bytes = b"ECDH") -> bytes:
        """
        Derive a symmetric key from the shared secret.
        
        Uses SHA-256 to hash the x-coordinate of the shared secret.
        This is a simplified key derivation - production systems should
        use proper KDFs like HKDF.
        
        Args:
            other_public_key: The other party's public key
            key_length: Desired key length in bytes (default 32 for AES-256)
            info: Additional context info for key derivation
        
        Returns:
            Derived symmetric key as bytes
        """
        shared_secret = self.compute_shared_secret(other_public_key)
        
        # Use x-coordinate for key derivation
        byte_len = (self.curve.p.bit_length() + 7) // 8
        x_bytes = shared_secret.x.to_bytes(byte_len, 'big')
        
        # Simple KDF: SHA-256(info || x)
        # For production, use HKDF from cryptography library
        hasher = hashlib.sha256()
        hasher.update(info)
        hasher.update(x_bytes)
        derived_key = hasher.digest()
        
        return derived_key[:key_length]


def perform_ecdh_exchange(curve: CurveParams = SECP256K1) -> tuple[bytes, bytes]:
    """
    Demonstrate a complete ECDH key exchange between two parties.
    
    Args:
        curve: The elliptic curve to use
    
    Returns:
        Tuple of (alice_key, bob_key) - should be identical
    """
    # Alice generates her keypair
    alice = ECDHKeyExchange(curve)
    alice_public = alice.get_public_key()
    
    # Bob generates his keypair
    bob = ECDHKeyExchange(curve)
    bob_public = bob.get_public_key()
    
    # They exchange public keys (simulated here)
    # In reality, this happens over an insecure channel
    
    # Each computes the shared secret
    alice_shared = alice.compute_shared_secret(bob_public)
    bob_shared = bob.compute_shared_secret(alice_public)
    
    # Verify they computed the same secret
    assert alice_shared == bob_shared, "ECDH failed: secrets don't match!"
    
    # Derive symmetric keys
    alice_key = alice.derive_symmetric_key(bob_public)
    bob_key = bob.derive_symmetric_key(alice_public)
    
    return alice_key, bob_key


def demonstrate_ecdh():
    """
    Visual demonstration of ECDH key exchange.
    """
    print("=" * 70)
    print("ECDH Key Exchange Demonstration")
    print("=" * 70)
    
    # Use test curve for readable numbers
    curve = TEST_CURVE
    print(f"\nUsing curve: {curve.name}")
    print(f"Curve equation: y² = x³ + {curve.a}x + {curve.b} (mod {curve.p})")
    
    # Alice's side
    print("\n" + "-" * 35)
    print("ALICE (User A)")
    print("-" * 35)
    alice = ECDHKeyExchange(curve)
    print(f"Private key dA: {alice.private_key}")
    print(f"Public key QA = dA·G: {alice.public_key}")
    
    # Bob's side
    print("\n" + "-" * 35)
    print("BOB (User B)")
    print("-" * 35)
    bob = ECDHKeyExchange(curve)
    print(f"Private key dB: {bob.private_key}")
    print(f"Public key QB = dB·G: {bob.public_key}")
    
    # Key exchange
    print("\n" + "-" * 35)
    print("KEY EXCHANGE")
    print("-" * 35)
    print("Alice sends QA to Bob")
    print("Bob sends QB to Alice")
    
    # Shared secret computation
    print("\n" + "-" * 35)
    print("SHARED SECRET COMPUTATION")
    print("-" * 35)
    
    alice_shared = alice.compute_shared_secret(bob.public_key)
    print(f"Alice computes: S = dA · QB = {alice.private_key} · {bob.public_key}")
    print(f"Alice's shared secret: {alice_shared}")
    
    bob_shared = bob.compute_shared_secret(alice.public_key)
    print(f"\nBob computes: S = dB · QA = {bob.private_key} · {alice.public_key}")
    print(f"Bob's shared secret: {bob_shared}")
    
    # Verify
    print("\n" + "-" * 35)
    print("VERIFICATION")
    print("-" * 35)
    if alice_shared == bob_shared:
        print("✓ SUCCESS: Both parties computed the same shared secret!")
    else:
        print("✗ FAILURE: Shared secrets don't match!")
    
    # Now with secp256k1 for real-world demo
    print("\n" + "=" * 70)
    print("ECDH with secp256k1 (Production Curve)")
    print("=" * 70)
    
    alice_key, bob_key = perform_ecdh_exchange(SECP256K1)
    
    print(f"\nAlice's derived AES key: {alice_key.hex()}")
    print(f"Bob's derived AES key:   {bob_key.hex()}")
    print(f"\nKeys match: {alice_key == bob_key}")
    
    return alice_key == bob_key


# ============ Tests ============
if __name__ == "__main__":
    print("\nTesting ECDH Module")
    print("=" * 70)
    
    # Test 1: Basic ECDH with test curve
    print("\n1. Basic ECDH Test (Test Curve):")
    alice = ECDHKeyExchange(TEST_CURVE)
    bob = ECDHKeyExchange(TEST_CURVE)
    
    alice_shared = alice.compute_shared_secret(bob.get_public_key())
    bob_shared = bob.compute_shared_secret(alice.get_public_key())
    
    print(f"   Alice's shared secret: {alice_shared}")
    print(f"   Bob's shared secret:   {bob_shared}")
    print(f"   Secrets match: {alice_shared == bob_shared}")
    
    # Test 2: Key derivation
    print("\n2. Key Derivation Test:")
    alice_key = alice.derive_symmetric_key(bob.get_public_key())
    bob_key = bob.derive_symmetric_key(alice.get_public_key())
    
    print(f"   Alice's key: {alice_key.hex()}")
    print(f"   Bob's key:   {bob_key.hex()}")
    print(f"   Keys match: {alice_key == bob_key}")
    
    # Test 3: Full demonstration
    print("\n3. Full ECDH Demonstration:")
    demonstrate_ecdh()
    
    print("\n" + "=" * 70)
    print("All ECDH tests completed!")
