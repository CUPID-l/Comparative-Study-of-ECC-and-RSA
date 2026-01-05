"""
Elliptic Curve Cryptography (ECC) Implementation from Scratch
=============================================================

This module implements the core mathematics of Elliptic Curve Cryptography:
    - Point representation on elliptic curves
    - Point addition and doubling
    - Scalar multiplication (double-and-add algorithm)
    - Key generation

Curve equation: y² = x³ + ax + b (mod p)

The implementation includes:
    - A small test curve for debugging (p=97)
    - secp256k1 curve for production use (Bitcoin's curve)
"""

import secrets
from dataclasses import dataclass
from typing import Optional
from math_utils import mod_inverse


@dataclass
class CurveParams:
    """
    Parameters defining an elliptic curve over a finite field.
    
    Curve equation: y² = x³ + ax + b (mod p)
    
    Attributes:
        name: Name of the curve
        p: Prime modulus (defines the finite field GF(p))
        a: Coefficient a in the curve equation
        b: Coefficient b in the curve equation
        Gx: x-coordinate of the generator point G
        Gy: y-coordinate of the generator point G
        n: Order of the generator point (number of points in subgroup)
        h: Cofactor
    """
    name: str
    p: int      # Prime modulus
    a: int      # Curve coefficient a
    b: int      # Curve coefficient b
    Gx: int     # Generator point x-coordinate
    Gy: int     # Generator point y-coordinate
    n: int      # Order of G
    h: int      # Cofactor


# ============ Curve Definitions ============

# Small test curve for debugging and educational purposes
# y² = x³ + 2x + 3 (mod 97)
TEST_CURVE = CurveParams(
    name="TestCurve-97",
    p=97,
    a=2,
    b=3,
    Gx=3,
    Gy=6,
    n=5,  # Small order for testing
    h=1
)

# secp256k1 - The curve used by Bitcoin
# y² = x³ + 7 (mod p)
SECP256K1 = CurveParams(
    name="secp256k1",
    p=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
    a=0,
    b=7,
    Gx=0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    Gy=0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
    n=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
    h=1
)

# NIST P-256 curve (also known as secp256r1 or prime256v1)
# Used in TLS, ECDSA, and many other applications
P256 = CurveParams(
    name="P-256",
    p=0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
    a=0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC,
    b=0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
    Gx=0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    Gy=0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
    n=0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
    h=1
)


@dataclass
class Point:
    """
    A point on an elliptic curve.
    
    The point at infinity (identity element) is represented by x=None, y=None.
    
    Attributes:
        x: x-coordinate (None for point at infinity)
        y: y-coordinate (None for point at infinity)
        curve: The curve this point belongs to
    """
    x: Optional[int]
    y: Optional[int]
    curve: CurveParams
    
    def is_infinity(self) -> bool:
        """Check if this is the point at infinity."""
        return self.x is None and self.y is None
    
    def __eq__(self, other) -> bool:
        if not isinstance(other, Point):
            return False
        return self.x == other.x and self.y == other.y
    
    def __repr__(self) -> str:
        if self.is_infinity():
            return "Point(∞)"
        return f"Point({self.x}, {self.y})"
    
    def is_on_curve(self) -> bool:
        """Verify that this point lies on the curve."""
        if self.is_infinity():
            return True
        
        p = self.curve.p
        a = self.curve.a
        b = self.curve.b
        
        # Check: y² ≡ x³ + ax + b (mod p)
        left = (self.y * self.y) % p
        right = (pow(self.x, 3, p) + a * self.x + b) % p
        
        return left == right


def point_at_infinity(curve: CurveParams) -> Point:
    """Create the point at infinity for a given curve."""
    return Point(None, None, curve)


def get_generator(curve: CurveParams) -> Point:
    """Get the generator point G for a curve."""
    return Point(curve.Gx, curve.Gy, curve)


def point_add(P: Point, Q: Point) -> Point:
    """
    Add two points on an elliptic curve.
    
    This implements the group operation on elliptic curves:
        - P + O = P (adding identity)
        - P + (-P) = O (adding inverse)
        - P + Q for distinct points
        - P + P = 2P (point doubling, delegated to point_double)
    
    Args:
        P: First point
        Q: Second point
    
    Returns:
        The sum P + Q as a point on the curve
    
    Raises:
        ValueError: If points are on different curves
    """
    if P.curve != Q.curve:
        raise ValueError("Points must be on the same curve")
    
    curve = P.curve
    p = curve.p
    
    # Handle identity cases
    if P.is_infinity():
        return Q
    if Q.is_infinity():
        return P
    
    # Handle P + (-P) = O case
    if P.x == Q.x and (P.y + Q.y) % p == 0:
        return point_at_infinity(curve)
    
    # Handle P == Q case (point doubling)
    if P.x == Q.x and P.y == Q.y:
        return point_double(P)
    
    # General case: P ≠ Q
    # Slope: λ = (y_Q - y_P) / (x_Q - x_P)
    dy = (Q.y - P.y) % p
    dx = (Q.x - P.x) % p
    
    # λ = dy * dx^(-1) mod p
    lam = (dy * mod_inverse(dx, p)) % p
    
    # x_R = λ² - x_P - x_Q
    x_r = (lam * lam - P.x - Q.x) % p
    
    # y_R = λ(x_P - x_R) - y_P
    y_r = (lam * (P.x - x_r) - P.y) % p
    
    return Point(x_r, y_r, curve)


def point_double(P: Point) -> Point:
    """
    Double a point on an elliptic curve (compute P + P = 2P).
    
    Uses the tangent line at P to find the intersection with the curve.
    
    Args:
        P: The point to double
    
    Returns:
        2P as a point on the curve
    """
    if P.is_infinity():
        return P
    
    curve = P.curve
    p = curve.p
    a = curve.a
    
    # Handle case where tangent is vertical (y = 0)
    if P.y == 0:
        return point_at_infinity(curve)
    
    # Slope of tangent: λ = (3x² + a) / (2y)
    numerator = (3 * P.x * P.x + a) % p
    denominator = (2 * P.y) % p
    
    lam = (numerator * mod_inverse(denominator, p)) % p
    
    # x_R = λ² - 2x_P
    x_r = (lam * lam - 2 * P.x) % p
    
    # y_R = λ(x_P - x_R) - y_P
    y_r = (lam * (P.x - x_r) - P.y) % p
    
    return Point(x_r, y_r, curve)


def scalar_multiply(k: int, P: Point) -> Point:
    """
    Scalar multiplication: compute k·P = P + P + ... + P (k times).
    
    Uses the double-and-add algorithm for efficiency:
        - O(log k) point operations instead of O(k)
        - Essential for cryptographic operations with large k
    
    Algorithm:
        1. Start with result = O (point at infinity)
        2. For each bit of k from LSB to MSB:
            - If bit is 1: result = result + P
            - P = 2P (double P for next iteration)
    
    Args:
        k: The scalar multiplier
        P: The point to multiply
    
    Returns:
        k·P as a point on the curve
    
    Example:
        >>> G = get_generator(SECP256K1)
        >>> Q = scalar_multiply(12345, G)  # Compute 12345·G
    """
    if k == 0 or P.is_infinity():
        return point_at_infinity(P.curve)
    
    if k < 0:
        # For negative k: k·P = |k|·(-P)
        k = -k
        P = Point(P.x, (-P.y) % P.curve.p, P.curve)
    
    result = point_at_infinity(P.curve)
    addend = P
    
    while k:
        if k & 1:  # If current bit is 1
            result = point_add(result, addend)
        
        addend = point_double(addend)  # Double for next bit
        k >>= 1  # Move to next bit
    
    return result


def generate_keypair(curve: CurveParams = SECP256K1) -> tuple[int, Point]:
    """
    Generate an ECC key pair.
    
    Private key: Random integer d in range [1, n-1]
    Public key: Q = d·G where G is the generator point
    
    Args:
        curve: The elliptic curve to use (default: secp256k1)
    
    Returns:
        Tuple (private_key, public_key) where:
            - private_key is an integer d
            - public_key is a Point Q = d·G
    
    Example:
        >>> private_key, public_key = generate_keypair()
        >>> print(f"Private key: {private_key}")
        >>> print(f"Public key: {public_key}")
    """
    G = get_generator(curve)
    
    # Generate random private key in range [1, n-1]
    private_key = secrets.randbelow(curve.n - 1) + 1
    
    # Compute public key Q = d·G
    public_key = scalar_multiply(private_key, G)
    
    return private_key, public_key


def verify_keypair(private_key: int, public_key: Point) -> bool:
    """
    Verify that a public key matches a private key.
    
    Args:
        private_key: The private key d
        public_key: The public key Q
    
    Returns:
        True if Q = d·G, False otherwise
    """
    curve = public_key.curve
    G = get_generator(curve)
    expected = scalar_multiply(private_key, G)
    return expected == public_key and public_key.is_on_curve()


# ============ Tests ============
if __name__ == "__main__":
    print("Testing ECC Module")
    print("=" * 60)
    
    # Test 1: Point on curve verification
    print("\n1. Point on Curve Verification (Test Curve):")
    G_test = get_generator(TEST_CURVE)
    print(f"   Generator G = {G_test}")
    print(f"   G is on curve: {G_test.is_on_curve()}")
    
    # Test 2: Point addition on test curve
    print("\n2. Point Addition (Test Curve):")
    P2 = point_double(G_test)
    print(f"   2G = {P2}")
    print(f"   2G is on curve: {P2.is_on_curve()}")
    
    P3 = point_add(P2, G_test)
    print(f"   3G = {P3}")
    print(f"   3G is on curve: {P3.is_on_curve()}")
    
    # Test 3: Scalar multiplication
    print("\n3. Scalar Multiplication (Test Curve):")
    for k in range(1, 6):
        kG = scalar_multiply(k, G_test)
        print(f"   {k}G = {kG}, on curve: {kG.is_on_curve()}")
    
    # Test 4: Key generation with secp256k1
    print("\n4. Key Generation (secp256k1):")
    private_key, public_key = generate_keypair(SECP256K1)
    print(f"   Private key: {hex(private_key)}")
    print(f"   Public key X: {hex(public_key.x)}")
    print(f"   Public key Y: {hex(public_key.y)}")
    print(f"   Public key on curve: {public_key.is_on_curve()}")
    
    # Test 5: Verify keypair
    print("\n5. Keypair Verification:")
    is_valid = verify_keypair(private_key, public_key)
    print(f"   Keypair is valid: {is_valid}")
    
    # Test 6: secp256k1 generator point verification
    print("\n6. secp256k1 Generator Point Verification:")
    G_secp = get_generator(SECP256K1)
    print(f"   G is on curve: {G_secp.is_on_curve()}")
    
    # Verify n·G = O (generator order)
    print("   Computing n·G (should be point at infinity)...")
    nG = scalar_multiply(SECP256K1.n, G_secp)
    print(f"   n·G = {nG}")
    print(f"   n·G is infinity: {nG.is_infinity()}")
    
    print("\n" + "=" * 60)
    print("All ECC tests completed!")
