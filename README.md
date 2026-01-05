# Comparative Study of ECC and RSA for Secure Communication

A comprehensive implementation and comparison of Elliptic Curve Cryptography (ECC) and RSA for secure communication, built from scratch in Python.

## Project Structure

```
ECCRSA/
├── math_utils.py        # Modular arithmetic utilities
├── ecc.py               # ECC implementation from scratch
├── ecdh.py              # ECDH key exchange protocol
├── aes_encryption.py    # AES-GCM symmetric encryption
├── rsa.py               # RSA implementation for comparison
├── benchmark.py         # Performance benchmarking & visualization
├── main.py              # Complete demonstration script
└── README.md            # This file
```

## Features

### ECC Implementation (from scratch)
- **Modular arithmetic**: Extended GCD, modular inverse, fast exponentiation
- **Point operations**: Point addition, doubling, scalar multiplication
- **Key generation**: Private/public key pair generation
- **Curves supported**: secp256k1 (Bitcoin), P-256, custom test curves

### ECDH Key Exchange
- Complete Diffie-Hellman key exchange over elliptic curves
- Shared secret computation
- Key derivation using SHA-256

### AES Encryption
- AES-256-GCM for authenticated encryption
- Integration with ECDH-derived keys

### RSA Comparison
- RSA implementation from scratch
- Key generation, encryption, decryption
- Performance benchmarking against ECC

## Requirements

```bash
# Core functionality (no external dependencies for ECC/RSA)
pip install cryptography  # For AES-GCM (optional, fallback available)
pip install matplotlib    # For benchmark graphs (optional)
```

## Usage

### Run Complete Demo
```bash
python main.py
```

### Run Individual Modules
```bash
# Test math utilities
python math_utils.py

# Test ECC implementation
python ecc.py

# Test ECDH key exchange
python ecdh.py

# Test AES encryption
python aes_encryption.py

# Test RSA implementation
python rsa.py
```

### Run Benchmarks
```bash
# Quick benchmark
python benchmark.py --quick

# Full benchmark with plots
python benchmark.py --full --plot --csv

# Show comparison table only
python benchmark.py --table
```

## System Architecture

```
User A                     User B
------                     ------
Private key (dA)           Private key (dB)
Public key (QA = dA·G)     Public key (QB = dB·G)
        |                        |
        |---- Public Keys -------|
        |                        |
Shared Secret:
S = dA · QB = dB · QA

        ↓
Key Derivation (SHA-256)
        ↓
AES-256-GCM Encryption/Decryption
```

## Key Comparison: ECC vs RSA

| Metric | RSA-2048 | ECC-256 | Advantage |
|--------|----------|---------|-----------|
| Security Level | ~112-bit | ~128-bit | ECC |
| Private Key Size | ~2048 bits | ~256 bits | 8x smaller |
| Public Key Size | ~2048 bits | ~512 bits | 4x smaller |
| Key Generation | Slow | Fast | ECC |
| Computation | Heavy | Efficient | ECC |
| Smart Card Suitable | Limited | Excellent | ECC |

### Security Level Equivalences

| Security | RSA | ECC | Ratio |
|----------|-----|-----|-------|
| 80-bit | 1024 | 160 | 6.4x |
| 112-bit | 2048 | 224 | 9.1x |
| 128-bit | 3072 | 256 | 12x |
| 192-bit | 7680 | 384 | 20x |
| 256-bit | 15360 | 521 | 29.5x |

## Mathematical Background

### Elliptic Curve Equation
```
y² = x³ + ax + b (mod p)
```

### Point Addition
For points P(x₁, y₁) and Q(x₂, y₂):
```
λ = (y₂ - y₁) / (x₂ - x₁)
x₃ = λ² - x₁ - x₂
y₃ = λ(x₁ - x₃) - y₁
```

### Point Doubling
For point P(x, y):
```
λ = (3x² + a) / (2y)
x₃ = λ² - 2x
y₃ = λ(x - x₃) - y
```

### ECDH Security
Based on the Elliptic Curve Discrete Logarithm Problem (ECDLP):
> Given G and Q = d·G, it is computationally infeasible to find d.

## Sample Output

```
BENCHMARK SUMMARY
================================================================
  Operation                     Algorithm             Time (ms)
  ----------------------------------------------------------------
  Key Generation               ECC-secp256k1             45.23
  Key Generation               RSA-2048                 892.15
  Key Exchange                 ECDH-secp256k1            91.45
  Key Exchange                 RSA-2048                 934.82
  Scalar Multiplication        ECC-secp256k1             43.21
```

## References

- [SEC 2: Recommended Elliptic Curve Domain Parameters](https://www.secg.org/sec2-v2.pdf)
- [NIST SP 800-186: Recommendations for Discrete Logarithm-based Cryptography](https://csrc.nist.gov/publications/detail/sp/800-186/final)
- [RFC 6090: Fundamental Elliptic Curve Cryptography Algorithms](https://tools.ietf.org/html/rfc6090)

## License

This project is for educational purposes as part of a Computer Security course.

## Author

Computer Security Course Project - Semester VI
