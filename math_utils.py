"""
Modular Arithmetic Utilities for ECC and RSA
============================================
This module provides fundamental mathematical operations needed for
cryptographic implementations.

Functions:
    - extended_gcd: Extended Euclidean Algorithm
    - mod_inverse: Modular multiplicative inverse
    - mod_exp: Fast modular exponentiation
"""


def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """
    Extended Euclidean Algorithm.
    
    Computes gcd(a, b) and finds x, y such that:
        a * x + b * y = gcd(a, b)
    
    Args:
        a: First integer
        b: Second integer
    
    Returns:
        Tuple (gcd, x, y) where gcd is the greatest common divisor
        and x, y are the Bézout coefficients
    
    Example:
        >>> extended_gcd(35, 15)
        (5, 1, -2)  # 35*1 + 15*(-2) = 5
    """
    if a == 0:
        return b, 0, 1
    
    gcd, x1, y1 = extended_gcd(b % a, a)
    
    # Update x and y using results from recursive call
    x = y1 - (b // a) * x1
    y = x1
    
    return gcd, x, y


def mod_inverse(a: int, m: int) -> int:
    """
    Compute the modular multiplicative inverse of a modulo m.
    
    Finds x such that: (a * x) ≡ 1 (mod m)
    
    Args:
        a: The number to find inverse of
        m: The modulus
    
    Returns:
        The modular inverse of a modulo m
    
    Raises:
        ValueError: If the inverse doesn't exist (gcd(a, m) != 1)
    
    Example:
        >>> mod_inverse(3, 7)
        5  # because 3 * 5 = 15 ≡ 1 (mod 7)
    """
    gcd, x, _ = extended_gcd(a % m, m)
    
    if gcd != 1:
        raise ValueError(f"Modular inverse doesn't exist for {a} mod {m}")
    
    return (x % m + m) % m  # Ensure positive result


def mod_exp(base: int, exp: int, mod: int) -> int:
    """
    Fast modular exponentiation using square-and-multiply algorithm.
    
    Computes: base^exp mod mod
    
    This is much faster than computing base^exp first and then taking mod,
    especially for large numbers used in cryptography.
    
    Args:
        base: The base number
        exp: The exponent
        mod: The modulus
    
    Returns:
        base^exp mod mod
    
    Example:
        >>> mod_exp(2, 10, 1000)
        24  # 2^10 = 1024, 1024 mod 1000 = 24
    """
    if mod == 1:
        return 0
    
    result = 1
    base = base % mod
    
    while exp > 0:
        # If exp is odd, multiply base with result
        if exp & 1:
            result = (result * base) % mod
        
        # exp must be even now
        exp = exp >> 1  # Divide by 2
        base = (base * base) % mod
    
    return result


def is_prime(n: int, k: int = 10) -> bool:
    """
    Miller-Rabin primality test.
    
    Probabilistic test to check if n is prime.
    
    Args:
        n: Number to test for primality
        k: Number of rounds (higher = more accurate)
    
    Returns:
        True if n is probably prime, False if definitely composite
    """
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False
    
    # Write n-1 as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    
    # Witness loop
    import random
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = mod_exp(a, d, n)
        
        if x == 1 or x == n - 1:
            continue
        
        for _ in range(r - 1):
            x = mod_exp(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    
    return True


def generate_prime(bits: int) -> int:
    """
    Generate a random prime number with specified bit length.
    
    Args:
        bits: Desired bit length of the prime
    
    Returns:
        A prime number with the specified bit length
    """
    import random
    
    while True:
        # Generate random odd number with correct bit length
        n = random.getrandbits(bits)
        n |= (1 << bits - 1) | 1  # Set MSB and LSB
        
        if is_prime(n):
            return n


# ============ Tests ============
if __name__ == "__main__":
    print("Testing math_utils module...")
    print("=" * 50)
    
    # Test extended_gcd
    print("\n1. Extended GCD Test:")
    gcd, x, y = extended_gcd(35, 15)
    print(f"   extended_gcd(35, 15) = ({gcd}, {x}, {y})")
    print(f"   Verification: 35*{x} + 15*{y} = {35*x + 15*y}")
    
    # Test mod_inverse
    print("\n2. Modular Inverse Test:")
    inv = mod_inverse(3, 7)
    print(f"   mod_inverse(3, 7) = {inv}")
    print(f"   Verification: 3 * {inv} mod 7 = {(3 * inv) % 7}")
    
    # Test mod_exp
    print("\n3. Modular Exponentiation Test:")
    result = mod_exp(2, 10, 1000)
    print(f"   mod_exp(2, 10, 1000) = {result}")
    print(f"   Verification: 2^10 = 1024, 1024 mod 1000 = {pow(2, 10) % 1000}")
    
    # Test is_prime
    print("\n4. Primality Test:")
    test_numbers = [17, 18, 97, 100, 104729]
    for n in test_numbers:
        print(f"   is_prime({n}) = {is_prime(n)}")
    
    # Test generate_prime
    print("\n5. Prime Generation Test:")
    for bits in [16, 32, 64]:
        p = generate_prime(bits)
        print(f"   {bits}-bit prime: {p}")
    
    print("\n" + "=" * 50)
    print("All tests completed!")
