# Plan: Implement ECC vs RSA Comparative Study from Scratch

A full implementation of ECC mathematics, ECDH key exchange, AES encryption, and RSA comparison—all in Python, with performance benchmarking and visualization.

## Steps

1. **Create `math_utils.py`** — Implement modular arithmetic: extended GCD, modular inverse (`mod_inverse`), modular exponentiation for RSA.

2. **Create `ecc.py`** — Implement ECC from scratch:
   - Define curve parameters (p, a, b, G, n) using secp256k1 or a smaller test curve
   - `point_add()`, `point_double()`, `scalar_multiply()` (double-and-add algorithm)
   - Key generation: `generate_keypair()` returning (private_key `d`, public_key `Q = d·G`)

3. **Create `ecdh.py`** — Implement ECDH key exchange:
   - Compute shared secret `S = dA · QB`
   - Derive symmetric key using SHA-256 hash of shared secret x-coordinate

4. **Create `aes_encryption.py`** — Implement symmetric encryption:
   - Use Python's `cryptography` library for AES-GCM (acceptable for symmetric part)
   - Or implement simple XOR cipher for demo purposes

5. **Create `rsa.py`** — Implement basic RSA (or use library for comparison):
   - Key generation (2048-bit), encrypt, decrypt
   - This can use `rsa` library since focus is ECC from scratch

6. **Create `benchmark.py`** — Performance comparison:
   - Measure key generation time, encryption/decryption time, memory usage
   - Compare ECC-256 vs RSA-2048 (equivalent security levels)
   - Generate matplotlib graphs for visualization

## Further Considerations

1. **Curve choice for Phase 1 testing?** Use small test curve (p=97) initially for debugging, then switch to secp256k1 for production benchmarks.

2. **AES approach?** Recommend using `cryptography` library for AES (industry standard) since focus is ECC math—pure XOR is too weak for meaningful comparison.

3. **RSA implementation depth?** Suggest using `rsa` library for RSA since paper's focus is demonstrating ECC efficiency, not RSA internals—this keeps scope manageable.

## Additional Notes
- Ensure proper documentation and comments in each module for clarity.
- Keep code modular for easy testing and benchmarking.
- Keep code simple and focused on educational purposes.