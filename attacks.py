"""
Cryptographic Attack Implementations
====================================

This module implements attacks against weak RSA and ECC keys to demonstrate
the security differences between the two cryptosystems.

RSA Attacks:
    - Trial Division: Simple factorization for very small n
    - Pollard's Rho: Efficient factorization for larger n
    - Fermat's Factorization: For n where p and q are close

ECC Attacks:
    - Brute Force: Try all possible private keys
    - Baby-step Giant-step (BSGS): O(√n) discrete log algorithm
    - Pollard's Rho for ECDLP: Probabilistic discrete log

WARNING: These attacks are for EDUCATIONAL PURPOSES ONLY.
         They demonstrate why small key sizes are insecure.
"""

import time
import math
from typing import Optional, Tuple
from dataclasses import dataclass
from math_utils import mod_inverse, mod_exp

# Algorithm safety limits
MAX_BSGS_TABLE_SIZE = 100000  # Maximum entries in baby-step table to prevent memory exhaustion
MAX_POLLARD_RESTARTS = 10  # Maximum restarts for Pollard's Rho before giving up


# ============ Attack Result Structures ============

@dataclass
class RSAAttackResult:
    """Result of an RSA attack."""
    success: bool
    p: Optional[int]          # First prime factor
    q: Optional[int]          # Second prime factor
    private_key_d: Optional[int]  # Recovered private exponent
    time_taken: float         # Time in seconds
    method: str               # Attack method used
    iterations: int           # Number of iterations/operations
    
    def __str__(self) -> str:
        if self.success:
            return (f"RSA Attack SUCCESS ({self.method})\n"
                    f"  Factors: p={self.p}, q={self.q}\n"
                    f"  Private key d: {self.private_key_d}\n"
                    f"  Time: {self.time_taken:.4f}s\n"
                    f"  Iterations: {self.iterations}")
        return f"RSA Attack FAILED ({self.method}) after {self.time_taken:.4f}s"


@dataclass
class ECCAttackResult:
    """Result of an ECC discrete log attack."""
    success: bool
    private_key: Optional[int]  # Recovered private key d
    time_taken: float           # Time in seconds
    method: str                 # Attack method used
    iterations: int             # Number of iterations/operations
    
    def __str__(self) -> str:
        if self.success:
            return (f"ECC Attack SUCCESS ({self.method})\n"
                    f"  Private key: {self.private_key}\n"
                    f"  Time: {self.time_taken:.4f}s\n"
                    f"  Iterations: {self.iterations}")
        return f"ECC Attack FAILED ({self.method}) after {self.time_taken:.4f}s"


# ============ RSA Attacks ============

def gcd(a: int, b: int) -> int:
    """Compute greatest common divisor."""
    while b:
        a, b = b, a % b
    return a


def trial_division(n: int, limit: int = 1000000) -> RSAAttackResult:
    """
    Factor n using trial division.
    
    Simple but effective for small factors.
    Complexity: O(√n) in worst case
    
    Args:
        n: The number to factor (RSA modulus)
        limit: Maximum number to try
    
    Returns:
        RSAAttackResult with factors if found
    """
    start_time = time.time()
    iterations = 0
    
    # Check small primes first
    if n % 2 == 0:
        p = 2
        q = n // 2
        elapsed = time.time() - start_time
        return RSAAttackResult(True, p, q, None, elapsed, "Trial Division", 1)
    
    # Try odd numbers up to √n or limit
    max_check = min(int(math.isqrt(n)) + 1, limit)
    
    for i in range(3, max_check, 2):
        iterations += 1
        if n % i == 0:
            p = i
            q = n // i
            elapsed = time.time() - start_time
            return RSAAttackResult(True, p, q, None, elapsed, "Trial Division", iterations)
    
    elapsed = time.time() - start_time
    return RSAAttackResult(False, None, None, None, elapsed, "Trial Division", iterations)


def pollard_rho(n: int, max_iterations: int = 10000000) -> RSAAttackResult:
    """
    Factor n using Pollard's Rho algorithm.
    
    Uses cycle detection to find factors probabilistically.
    Complexity: O(n^(1/4)) expected
    
    This is much faster than trial division for semi-prime numbers
    like RSA moduli. Includes restart mechanism for robustness.
    
    Args:
        n: The number to factor (RSA modulus)
        max_iterations: Maximum iterations before giving up
    
    Returns:
        RSAAttackResult with factors if found
    """
    start_time = time.time()
    total_iterations = 0
    
    # Handle trivial cases
    if n % 2 == 0:
        elapsed = time.time() - start_time
        return RSAAttackResult(True, 2, n // 2, None, elapsed, "Pollard's Rho", 1)
    
    # Polynomial function: f(x) = x² + c mod n
    def f(x: int, c: int) -> int:
        return (x * x + c) % n
    
    # Try different starting values with bounded restarts
    iterations_per_c = max(max_iterations // MAX_POLLARD_RESTARTS, 1000)
    
    for c in range(1, MAX_POLLARD_RESTARTS + 1):
        x = 2
        y = 2
        d = 1
        
        for _ in range(iterations_per_c):
            total_iterations += 1
            
            x = f(x, c)           # Tortoise moves one step
            y = f(f(y, c), c)     # Hare moves two steps
            
            # Early exit if cycle detected without finding factor
            if x == y:
                break
                
            d = gcd(abs(x - y), n)
            
            if d != 1 and d != n:
                p = d
                q = n // d
                elapsed = time.time() - start_time
                return RSAAttackResult(True, p, q, None, elapsed, "Pollard's Rho", total_iterations)
        
        if total_iterations >= max_iterations:
            break
    
    elapsed = time.time() - start_time
    return RSAAttackResult(False, None, None, None, elapsed, "Pollard's Rho", total_iterations)


def fermat_factorization(n: int, max_iterations: int = 1000000) -> RSAAttackResult:
    """
    Factor n using Fermat's factorization method.
    
    Works well when p and q are close together.
    Based on: n = a² - b² = (a+b)(a-b)
    
    Args:
        n: The number to factor
        max_iterations: Maximum iterations
    
    Returns:
        RSAAttackResult with factors if found
    """
    start_time = time.time()
    
    # Start with a = ceil(√n)
    a = math.isqrt(n)
    if a * a < n:
        a += 1
    
    b2 = a * a - n
    iterations = 0
    
    while iterations < max_iterations:
        iterations += 1
        b = math.isqrt(b2)
        
        if b * b == b2:
            # Found it! n = (a+b)(a-b)
            p = a + b
            q = a - b
            if p * q == n and p > 1 and q > 1:
                elapsed = time.time() - start_time
                return RSAAttackResult(True, p, q, None, elapsed, "Fermat's Method", iterations)
        
        a += 1
        b2 = a * a - n
    
    elapsed = time.time() - start_time
    return RSAAttackResult(False, None, None, None, elapsed, "Fermat's Method", iterations)


def crack_rsa(n: int, e: int = 65537, timeout: float = 60.0) -> RSAAttackResult:
    """
    Attempt to crack RSA by factoring n and recovering private key.
    
    Tries multiple methods in order of efficiency.
    
    Args:
        n: RSA modulus
        e: Public exponent
        timeout: Maximum time in seconds
    
    Returns:
        RSAAttackResult with complete attack results
    """
    start_time = time.time()
    
    # Try trial division first (fast for small factors)
    result = trial_division(n, limit=100000)
    if result.success:
        # Compute private key
        p, q = result.p, result.q
        phi_n = (p - 1) * (q - 1)
        d = mod_inverse(e, phi_n)
        result.private_key_d = d
        return result
    
    # Check timeout
    if time.time() - start_time > timeout:
        return RSAAttackResult(False, None, None, None, time.time() - start_time, "Timeout", 0)
    
    # Try Pollard's Rho
    remaining_time = timeout - (time.time() - start_time)
    max_iter = int(remaining_time * 100000)  # Rough estimate
    result = pollard_rho(n, max_iterations=max_iter)
    
    if result.success:
        p, q = result.p, result.q
        phi_n = (p - 1) * (q - 1)
        d = mod_inverse(e, phi_n)
        result.private_key_d = d
        return result
    
    # Try Fermat's method
    if time.time() - start_time < timeout:
        result = fermat_factorization(n, max_iterations=100000)
        if result.success:
            p, q = result.p, result.q
            phi_n = (p - 1) * (q - 1)
            d = mod_inverse(e, phi_n)
            result.private_key_d = d
            return result
    
    elapsed = time.time() - start_time
    return RSAAttackResult(False, None, None, None, elapsed, "All Methods", 0)


def mod_inverse(a: int, m: int) -> int:
    """Compute modular inverse using extended Euclidean algorithm."""
    def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
        if a == 0:
            return b, 0, 1
        gcd_val, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd_val, x, y
    
    _, x, _ = extended_gcd(a % m, m)
    return (x % m + m) % m


# ============ ECC Attacks ============

def brute_force_ecdlp(public_key, generator, curve, max_iterations: int = 1000000) -> ECCAttackResult:
    """
    Solve ECDLP using brute force.
    
    Given Q (public key) and G (generator), find d such that Q = d·G
    
    Simply computes G, 2G, 3G, ... until we find Q.
    Complexity: O(n) where n is the private key
    
    Args:
        public_key: The public key point Q
        generator: The generator point G
        curve: The elliptic curve
        max_iterations: Maximum iterations
    
    Returns:
        ECCAttackResult with private key if found
    """
    from ecc import point_add, point_at_infinity, Point
    
    start_time = time.time()
    
    # Start with G
    current = generator
    
    for d in range(1, max_iterations + 1):
        if current.x == public_key.x and current.y == public_key.y:
            elapsed = time.time() - start_time
            return ECCAttackResult(True, d, elapsed, "Brute Force", d)
        
        # Move to next multiple: current = (d+1)·G
        current = point_add(current, generator)
    
    elapsed = time.time() - start_time
    return ECCAttackResult(False, None, elapsed, "Brute Force", max_iterations)


def baby_step_giant_step(public_key, generator, curve, order: int = None) -> ECCAttackResult:
    """
    Solve ECDLP using Baby-step Giant-step algorithm.
    
    This is a time-memory tradeoff:
    - Time: O(√n)
    - Space: O(√n)
    
    Algorithm:
    1. Choose m = ceil(√n)
    2. Baby step: Compute and store j·G for j = 0, 1, ..., m-1
    3. Giant step: Compute Q - i·(m·G) for i = 0, 1, ..., m-1
    4. If match found: d = i·m + j
    
    Args:
        public_key: The public key point Q
        generator: The generator point G  
        curve: The elliptic curve
        order: Order of the generator (if known)
    
    Returns:
        ECCAttackResult with private key if found
    """
    from ecc import point_add, scalar_multiply, Point
    
    start_time = time.time()
    iterations = 0
    
    # Use curve order or estimate
    if order is None:
        order = curve.n if hasattr(curve, 'n') else 10000000
    
    # m = ceil(√order)
    m = math.isqrt(order) + 1
    
    # Limit m for memory constraints (prevents excessive memory usage)
    m = min(m, MAX_BSGS_TABLE_SIZE)
    
    # Baby step: Store j·G for j = 0, 1, ..., m-1
    # We store as {x_coordinate: j} for fast lookup
    baby_steps = {}
    current = Point(None, None, curve)  # Point at infinity (0·G)
    
    # Handle 0·G = infinity specially
    baby_steps[None] = 0
    
    current = generator  # 1·G
    for j in range(1, m):
        iterations += 1
        # Use x-coordinate as key (with y to handle edge cases)
        key = (current.x, current.y)
        baby_steps[key] = j
        current = point_add(current, generator)
    
    # Compute -m·G (for giant steps)
    mG = scalar_multiply(m, generator)
    # Negate: -mG has same x, negated y
    neg_mG = Point(mG.x, (-mG.y) % curve.p, curve)
    
    # Giant step: Check Q - i·(m·G) for i = 0, 1, ..., m-1
    gamma = public_key  # Start with Q
    
    for i in range(m):
        iterations += 1
        
        # Check if gamma is in baby_steps
        if gamma.is_infinity():
            key = None
        else:
            key = (gamma.x, gamma.y)
        
        if key in baby_steps:
            j = baby_steps[key]
            d = (i * m + j) % order
            
            # Verify
            elapsed = time.time() - start_time
            return ECCAttackResult(True, d, elapsed, "Baby-step Giant-step", iterations)
        
        # gamma = gamma - m·G = gamma + (-m·G)
        gamma = point_add(gamma, neg_mG)
    
    elapsed = time.time() - start_time
    return ECCAttackResult(False, None, elapsed, "Baby-step Giant-step", iterations)


def pollard_rho_ecdlp(public_key, generator, curve, order: int, max_iterations: int = 1000000) -> ECCAttackResult:
    """
    Solve ECDLP using Pollard's Rho algorithm.
    
    Probabilistic algorithm with O(√n) expected time and O(1) space.
    Uses cycle detection similar to the factoring version.
    
    Args:
        public_key: The public key point Q
        generator: The generator point G
        curve: The elliptic curve  
        order: Order of the generator point
        max_iterations: Maximum iterations
    
    Returns:
        ECCAttackResult with private key if found
    """
    from ecc import point_add, Point
    import random
    
    start_time = time.time()
    
    def partition(P):
        """Partition point into one of 3 sets based on x-coordinate."""
        if P.is_infinity():
            return 0
        return P.x % 3
    
    def step(P, a, b):
        """
        Iteration function for Pollard's rho.
        Depending on partition, compute:
            Set 0: P + Q, a, b+1
            Set 1: 2P, 2a, 2b
            Set 2: P + G, a+1, b
        """
        s = partition(P)
        
        if s == 0:
            # P = P + Q
            return point_add(P, public_key), a, (b + 1) % order
        elif s == 1:
            # P = 2P
            return point_add(P, P), (2 * a) % order, (2 * b) % order
        else:
            # P = P + G
            return point_add(P, generator), (a + 1) % order, b
    
    # Initialize: X = a·G + b·Q
    a1, b1 = random.randint(1, order - 1), random.randint(1, order - 1)
    
    from ecc import scalar_multiply
    X = point_add(scalar_multiply(a1, generator), scalar_multiply(b1, public_key))
    
    a2, b2 = a1, b1
    Y = X
    
    restarts = 0
    total_iterations = 0
    
    while total_iterations < max_iterations and restarts < MAX_POLLARD_RESTARTS:
        for _ in range(max_iterations // MAX_POLLARD_RESTARTS):
            total_iterations += 1
            
            # Tortoise: one step
            X, a1, b1 = step(X, a1, b1)
            
            # Hare: two steps
            Y, a2, b2 = step(Y, a2, b2)
            Y, a2, b2 = step(Y, a2, b2)
            
            # Check for collision
            if X.x == Y.x and X.y == Y.y:
                # Found collision: a1·G + b1·Q = a2·G + b2·Q
                # (a1 - a2)·G = (b2 - b1)·Q = (b2 - b1)·d·G
                # d = (a1 - a2) / (b2 - b1) mod order
                
                numerator = (a1 - a2) % order
                denominator = (b2 - b1) % order
                
                if denominator == 0:
                    # Bad collision, restart with different values
                    restarts += 1
                    a1 = random.randint(1, order - 1)
                    b1 = random.randint(1, order - 1)
                    X = point_add(scalar_multiply(a1, generator), scalar_multiply(b1, public_key))
                    a2, b2 = a1, b1
                    Y = X
                    break  # Exit inner loop, continue outer
                
                try:
                    d = (numerator * mod_inverse(denominator, order)) % order
                    
                    # Verify
                    test = scalar_multiply(d, generator)
                    if test.x == public_key.x and test.y == public_key.y:
                        elapsed = time.time() - start_time
                        return ECCAttackResult(True, d, elapsed, "Pollard's Rho ECDLP", total_iterations)
                except:
                    pass
                
                # If verification failed, restart
                restarts += 1
                a1 = random.randint(1, order - 1)
                b1 = random.randint(1, order - 1)
                X = point_add(scalar_multiply(a1, generator), scalar_multiply(b1, public_key))
                a2, b2 = a1, b1
                Y = X
                break  # Exit inner loop, continue outer
        else:
            # Inner loop completed without break - all iterations used
            break
    
    elapsed = time.time() - start_time
    return ECCAttackResult(False, None, elapsed, "Pollard's Rho ECDLP", total_iterations)


def crack_ecc(public_key, generator, curve, order: int = None, timeout: float = 60.0) -> ECCAttackResult:
    """
    Attempt to crack ECC by solving the discrete log problem.
    
    Tries multiple methods based on the order size.
    
    Args:
        public_key: The public key point Q
        generator: The generator point G
        curve: The elliptic curve
        order: Order of the generator (optional)
        timeout: Maximum time in seconds
    
    Returns:
        ECCAttackResult with complete attack results
    """
    start_time = time.time()
    
    if order is None:
        order = curve.n if hasattr(curve, 'n') else 1000000
    
    # For very small orders, use brute force
    if order < 10000:
        result = brute_force_ecdlp(public_key, generator, curve, max_iterations=order)
        if result.success:
            return result
    
    # Check timeout
    if time.time() - start_time > timeout:
        return ECCAttackResult(False, None, time.time() - start_time, "Timeout", 0)
    
    # Try Baby-step Giant-step
    result = baby_step_giant_step(public_key, generator, curve, order)
    if result.success:
        return result
    
    # Check timeout
    if time.time() - start_time > timeout:
        return ECCAttackResult(False, None, time.time() - start_time, "Timeout", 0)
    
    # Try Pollard's Rho
    remaining_time = timeout - (time.time() - start_time)
    max_iter = int(remaining_time * 10000)
    result = pollard_rho_ecdlp(public_key, generator, curve, order, max_iterations=max_iter)
    
    return result


# ============ Tests ============

if __name__ == "__main__":
    print("Testing Attack Implementations")
    print("=" * 60)
    
    # Test 1: RSA factorization (small numbers)
    print("\n1. RSA Factorization Tests:")
    
    test_cases = [
        (15, "3 × 5"),           # Trivial
        (143, "11 × 13"),        # Small
        (9991, "97 × 103"),      # Medium
        (1000003 * 1000033, "1000003 × 1000033"),  # Larger
    ]
    
    for n, expected in test_cases:
        print(f"\n   Factoring n = {n} ({expected}):")
        result = crack_rsa(n, timeout=10.0)
        print(f"   {result}")
    
    # Test 2: ECC Discrete Log (using test curve)
    print("\n" + "=" * 60)
    print("2. ECC Discrete Log Tests:")
    
    from ecc import TEST_CURVE, get_generator, scalar_multiply, generate_keypair
    
    # Test with small private key on test curve
    G = get_generator(TEST_CURVE)
    
    for d in [2, 3, 4]:
        Q = scalar_multiply(d, G)
        print(f"\n   Finding d where Q = {d}·G:")
        print(f"   Q = {Q}")
        result = crack_ecc(Q, G, TEST_CURVE, order=TEST_CURVE.n, timeout=5.0)
        print(f"   {result}")
        print(f"   Correct: {result.private_key == d}")
    
    # Test with a custom small curve for better demonstration
    print("\n" + "=" * 60)
    print("3. Attack on Custom Small Curve:")
    
    from ecc import CurveParams, Point
    
    # Create a small curve with known order
    # y² = x³ + x + 1 (mod 23)
    SMALL_CURVE = CurveParams(
        name="SmallCurve-23",
        p=23,
        a=1,
        b=1,
        Gx=0,
        Gy=1,
        n=28,  # Order of this curve
        h=1
    )
    
    G_small = Point(SMALL_CURVE.Gx, SMALL_CURVE.Gy, SMALL_CURVE)
    
    # Test various private keys
    for d in [5, 10, 15, 20]:
        Q = scalar_multiply(d, G_small)
        print(f"\n   Target: d = {d}")
        result = crack_ecc(Q, G_small, SMALL_CURVE, order=SMALL_CURVE.n, timeout=5.0)
        print(f"   {result}")
    
    print("\n" + "=" * 60)
    print("All attack tests completed!")
