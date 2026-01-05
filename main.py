"""
Main Demo: Comparative Study of ECC and RSA for Secure Communication
====================================================================

This script demonstrates the complete workflow:
    1. ECC key generation
    2. ECDH key exchange
    3. Symmetric key derivation
    4. AES message encryption/decryption
    5. RSA comparison

Run this script to see ECC and RSA in action.
"""

import time
import os


def print_header(text: str):
    """Print a formatted header."""
    print("\n" + "=" * 70)
    print(f" {text}")
    print("=" * 70)


def print_section(text: str):
    """Print a formatted section."""
    print("\n" + "-" * 50)
    print(f" {text}")
    print("-" * 50)


def demo_ecc_math():
    """Demonstrate ECC mathematics."""
    from ecc import (
        TEST_CURVE, SECP256K1, get_generator, 
        point_add, point_double, scalar_multiply
    )
    
    print_header("PHASE 1: ECC Mathematics")
    
    # Show curve parameters
    print_section("1.1 Elliptic Curve Parameters")
    curve = TEST_CURVE
    print(f"Using test curve: {curve.name}")
    print(f"Curve equation: y² = x³ + {curve.a}x + {curve.b} (mod {curve.p})")
    print(f"Generator point G: ({curve.Gx}, {curve.Gy})")
    print(f"Order n: {curve.n}")
    
    # Point operations
    print_section("1.2 Point Operations")
    G = get_generator(curve)
    
    # Point doubling
    P2 = point_double(G)
    print(f"2G = G + G = {P2}")
    print(f"   Verification: 2G is on curve = {P2.is_on_curve()}")
    
    # Point addition
    P3 = point_add(P2, G)
    print(f"3G = 2G + G = {P3}")
    print(f"   Verification: 3G is on curve = {P3.is_on_curve()}")
    
    # Scalar multiplication
    print_section("1.3 Scalar Multiplication (Double-and-Add)")
    print("Computing k·G for k = 1 to 5:")
    for k in range(1, 6):
        kG = scalar_multiply(k, G)
        print(f"   {k}·G = {kG}")


def demo_key_generation():
    """Demonstrate ECC key generation."""
    from ecc import SECP256K1, generate_keypair, verify_keypair
    
    print_header("PHASE 2: ECC Key Generation")
    
    print_section("2.1 Generate Key Pair")
    print("Using secp256k1 curve (Bitcoin's curve)")
    
    start = time.time()
    private_key, public_key = generate_keypair(SECP256K1)
    elapsed = time.time() - start
    
    print(f"\nPrivate key (d):")
    print(f"   {hex(private_key)}")
    print(f"\nPublic key (Q = d·G):")
    print(f"   X: {hex(public_key.x)}")
    print(f"   Y: {hex(public_key.y)}")
    print(f"\nKey generation time: {elapsed*1000:.2f} ms")
    
    # Verify
    print_section("2.2 Key Verification")
    is_valid = verify_keypair(private_key, public_key)
    print(f"Public key is on curve: {public_key.is_on_curve()}")
    print(f"Q = d·G verification: {is_valid}")
    
    return private_key, public_key


def demo_ecdh():
    """Demonstrate ECDH key exchange."""
    from ecdh import ECDHKeyExchange
    from ecc import SECP256K1
    
    print_header("PHASE 3: ECDH Key Exchange")
    
    print_section("3.1 Alice and Bob Generate Keys")
    
    # Alice
    alice = ECDHKeyExchange(SECP256K1)
    print("Alice:")
    print(f"   Private key dA: {hex(alice.private_key)[:30]}...")
    print(f"   Public key QA: ({hex(alice.public_key.x)[:20]}..., ...)")
    
    # Bob
    bob = ECDHKeyExchange(SECP256K1)
    print("\nBob:")
    print(f"   Private key dB: {hex(bob.private_key)[:30]}...")
    print(f"   Public key QB: ({hex(bob.public_key.x)[:20]}..., ...)")
    
    print_section("3.2 Public Key Exchange")
    print("Alice sends QA to Bob over insecure channel")
    print("Bob sends QB to Alice over insecure channel")
    print("\n⚠️  Private keys (dA, dB) are NEVER transmitted!")
    
    print_section("3.3 Shared Secret Computation")
    
    # Alice computes shared secret
    alice_shared = alice.compute_shared_secret(bob.public_key)
    print(f"Alice computes: S = dA · QB")
    print(f"   S = {alice_shared}")
    
    # Bob computes shared secret
    bob_shared = bob.compute_shared_secret(alice.public_key)
    print(f"\nBob computes: S = dB · QA")
    print(f"   S = {bob_shared}")
    
    # Verify they match
    print(f"\n✓ Shared secrets match: {alice_shared == bob_shared}")
    
    print_section("3.4 Security Analysis")
    print("""
The security of ECDH relies on the Elliptic Curve Discrete Logarithm Problem (ECDLP):

Given points G and Q = d·G, it is computationally infeasible to find d.

For secp256k1:
    - 256-bit security level
    - Approximately 2^128 operations to break
    - Equivalent to RSA-3072 in security strength
    """)
    
    return alice, bob


def demo_symmetric_encryption(alice, bob):
    """Demonstrate AES encryption using ECDH-derived key."""
    from aes_encryption import encrypt_message, decrypt_message, CRYPTO_AVAILABLE
    
    print_header("PHASE 4: Symmetric Encryption (AES)")
    
    print_section("4.1 Key Derivation")
    print("ECC is NOT used to encrypt data directly.")
    print("Instead, we derive a symmetric key from the shared secret.")
    
    # Derive symmetric keys
    alice_key = alice.derive_symmetric_key(bob.public_key)
    bob_key = bob.derive_symmetric_key(alice.public_key)
    
    print(f"\nAlice derives AES key: {alice_key.hex()}")
    print(f"Bob derives AES key:   {bob_key.hex()}")
    print(f"Keys match: {alice_key == bob_key}")
    
    print_section("4.2 Message Encryption")
    print(f"Using: {'AES-256-GCM' if CRYPTO_AVAILABLE else 'XOR cipher (demo)'}")
    
    message = "Hello Bob! This is a secret message from Alice. 🔐"
    print(f"\nAlice's message: {message}")
    
    # Alice encrypts
    encrypted = encrypt_message(alice_key, message)
    print(f"\nEncrypted (ciphertext): {encrypted['ciphertext'][:50]}...")
    print(f"Nonce: {encrypted['nonce']}")
    print(f"Algorithm: {encrypted['algorithm']}")
    
    print_section("4.3 Message Decryption")
    
    # Bob decrypts using his derived key (same as Alice's)
    decrypted = decrypt_message(bob_key, encrypted)
    print(f"Bob decrypts: {decrypted}")
    print(f"\n✓ Message integrity verified: {message == decrypted}")


def demo_rsa_comparison():
    """Demonstrate RSA and compare with ECC."""
    from rsa import generate_rsa_keypair, rsa_encrypt_bytes, rsa_decrypt_bytes
    
    print_header("PHASE 5: RSA Comparison")
    
    print_section("5.1 RSA Key Generation")
    
    # Generate RSA keys (smaller for demo speed)
    print("Generating RSA-1024 key pair (for demo speed)...")
    start = time.time()
    rsa_keypair = generate_rsa_keypair(1024)
    rsa_time = time.time() - start
    
    print(f"RSA key generation time: {rsa_time*1000:.2f} ms")
    print(f"Public key (n): {hex(rsa_keypair.public_key.n)[:50]}...")
    print(f"Public exponent (e): {rsa_keypair.public_key.e}")
    
    print_section("5.2 RSA Encryption/Decryption")
    
    message = b"Hello RSA!"
    ciphertext = rsa_encrypt_bytes(message, rsa_keypair.public_key)
    decrypted = rsa_decrypt_bytes(ciphertext, rsa_keypair.private_key)
    
    print(f"Original: {message}")
    print(f"Ciphertext: {ciphertext[:30]}...")
    print(f"Decrypted: {decrypted}")
    
    print_section("5.3 ECC vs RSA Comparison")
    
    from ecc import SECP256K1, generate_keypair
    
    # Time ECC key generation
    start = time.time()
    ecc_priv, ecc_pub = generate_keypair(SECP256K1)
    ecc_time = time.time() - start
    
    # Calculate key sizes
    ecc_priv_bits = ecc_priv.bit_length()
    ecc_pub_bits = ecc_pub.x.bit_length() + ecc_pub.y.bit_length()
    rsa_pub_bits = rsa_keypair.public_key.n.bit_length()
    
    print(f"""
┌─────────────────────────┬──────────────────┬──────────────────┐
│        Metric           │    RSA-1024      │    ECC-256       │
├─────────────────────────┼──────────────────┼──────────────────┤
│ Key Gen Time            │  {rsa_time*1000:>10.2f} ms │  {ecc_time*1000:>10.2f} ms │
│ Private Key Size        │  {rsa_keypair.private_key.d.bit_length():>10} bits │  {ecc_priv_bits:>10} bits │
│ Public Key Size         │  {rsa_pub_bits:>10} bits │  {ecc_pub_bits:>10} bits │
│ Security Level          │      ~80-bit     │     ~128-bit     │
└─────────────────────────┴──────────────────┴──────────────────┘

Key Observations:
    1. ECC provides MORE security with SMALLER keys
    2. ECC key generation is significantly faster
    3. ECC is ideal for resource-constrained devices (IoT, smart cards)
    4. RSA-3072 would be needed to match ECC-256 security
    """)


def demo_complete_workflow():
    """Show complete secure communication workflow."""
    from ecdh import ECDHKeyExchange
    from ecc import SECP256K1
    from aes_encryption import encrypt_message, decrypt_message
    
    print_header("COMPLETE SECURE COMMUNICATION DEMO")
    
    print("""
    ┌──────────────────────────────────────────────────────────────┐
    │                    SYSTEM ARCHITECTURE                        │
    │                                                               │
    │    User A                              User B                 │
    │    ------                              ------                 │
    │    Private key (dA)                    Private key (dB)       │
    │    Public key (QA = dA·G)              Public key (QB = dB·G) │
    │           │                                  │                │
    │           └───────── Public Keys ────────────┘                │
    │                                                               │
    │                    Shared Secret:                             │
    │               S = dA · QB = dB · QA                           │
    │                          ↓                                    │
    │                   Key Derivation                              │
    │                          ↓                                    │
    │               AES Encryption / Decryption                     │
    └──────────────────────────────────────────────────────────────┘
    """)
    
    print_section("Step 1: Key Generation")
    alice = ECDHKeyExchange(SECP256K1)
    bob = ECDHKeyExchange(SECP256K1)
    print("✓ Alice generated keypair")
    print("✓ Bob generated keypair")
    
    print_section("Step 2: Key Exchange (over insecure channel)")
    print("✓ Alice → Bob: Public key QA")
    print("✓ Bob → Alice: Public key QB")
    
    print_section("Step 3: Shared Secret & Key Derivation")
    alice_key = alice.derive_symmetric_key(bob.public_key)
    bob_key = bob.derive_symmetric_key(alice.public_key)
    print(f"✓ Both derived same AES key: {alice_key == bob_key}")
    
    print_section("Step 4: Secure Communication")
    
    # Alice sends to Bob
    alice_msg = "Hi Bob, let's meet at 5pm. - Alice"
    encrypted = encrypt_message(alice_key, alice_msg)
    print(f"Alice → Bob (encrypted): {encrypted['ciphertext'][:40]}...")
    
    bob_received = decrypt_message(bob_key, encrypted)
    print(f"Bob receives: {bob_received}")
    
    # Bob replies to Alice
    bob_msg = "Sounds good! See you there. - Bob"
    encrypted = encrypt_message(bob_key, bob_msg)
    print(f"\nBob → Alice (encrypted): {encrypted['ciphertext'][:40]}...")
    
    alice_received = decrypt_message(alice_key, encrypted)
    print(f"Alice receives: {alice_received}")
    
    print("\n✓ Secure communication established!")


def main():
    """Run the complete demonstration."""
    print("""
╔══════════════════════════════════════════════════════════════════════╗
║                                                                       ║
║   COMPARATIVE STUDY OF ECC AND RSA FOR SECURE COMMUNICATION          ║
║                                                                       ║
║   Implementation from Scratch                                         ║
║   - Elliptic Curve Mathematics                                        ║
║   - ECDH Key Exchange                                                 ║
║   - AES Symmetric Encryption                                          ║
║   - RSA Comparison                                                    ║
║                                                                       ║
╚══════════════════════════════════════════════════════════════════════╝
    """)
    
    input("Press Enter to begin the demonstration...\n")
    
    # Phase 1: ECC Mathematics
    demo_ecc_math()
    input("\nPress Enter to continue to Phase 2...")
    
    # Phase 2: Key Generation
    private_key, public_key = demo_key_generation()
    input("\nPress Enter to continue to Phase 3...")
    
    # Phase 3: ECDH Key Exchange
    alice, bob = demo_ecdh()
    input("\nPress Enter to continue to Phase 4...")
    
    # Phase 4: Symmetric Encryption
    demo_symmetric_encryption(alice, bob)
    input("\nPress Enter to continue to Phase 5...")
    
    # Phase 5: RSA Comparison
    demo_rsa_comparison()
    input("\nPress Enter to see complete workflow demo...")
    
    # Complete Workflow
    demo_complete_workflow()
    
    print_header("DEMONSTRATION COMPLETE")
    print("""
To run benchmarks and generate graphs:
    python benchmark.py --full --plot --csv

To run individual module tests:
    python math_utils.py
    python ecc.py
    python ecdh.py
    python aes_encryption.py
    python rsa.py

Thank you for watching!
    """)


if __name__ == "__main__":
    main()
