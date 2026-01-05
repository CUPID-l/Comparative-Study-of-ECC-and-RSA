"""
Benchmark: ECC vs RSA Performance Comparison
============================================

This module benchmarks and compares ECC and RSA across multiple metrics:
    - Key generation time
    - Key sizes
    - Encryption/decryption time
    - Memory usage
    - Key exchange time (ECDH vs RSA key transport)

Security Level Equivalences:
    - ECC-256 ≈ RSA-3072 ≈ 128-bit security
    - ECC-384 ≈ RSA-7680 ≈ 192-bit security
"""

import time
import sys
import os
import statistics
from dataclasses import dataclass
from typing import List, Dict, Callable
import tracemalloc

# Import our implementations
from ecc import SECP256K1, P256, generate_keypair, scalar_multiply, get_generator
from ecdh import ECDHKeyExchange, perform_ecdh_exchange
from rsa import generate_rsa_keypair, rsa_key_exchange_simulation, RSAEncryption
from aes_encryption import AESEncryption, encrypt_message, decrypt_message


@dataclass
class BenchmarkResult:
    """Store benchmark results for a single operation."""
    name: str
    algorithm: str
    iterations: int
    times: List[float]  # List of execution times
    memory_peak: int    # Peak memory usage in bytes
    
    @property
    def mean_time(self) -> float:
        return statistics.mean(self.times)
    
    @property
    def std_dev(self) -> float:
        return statistics.stdev(self.times) if len(self.times) > 1 else 0
    
    @property
    def min_time(self) -> float:
        return min(self.times)
    
    @property
    def max_time(self) -> float:
        return max(self.times)
    
    def __str__(self) -> str:
        return (f"{self.name} ({self.algorithm}): "
                f"{self.mean_time*1000:.2f}ms ± {self.std_dev*1000:.2f}ms "
                f"(n={self.iterations})")


def benchmark(func: Callable, iterations: int = 10, warmup: int = 1) -> BenchmarkResult:
    """
    Benchmark a function.
    
    Args:
        func: Callable that returns (result, name, algorithm)
        iterations: Number of iterations to run
        warmup: Number of warmup iterations (not counted)
    
    Returns:
        BenchmarkResult with timing and memory statistics
    """
    # Warmup runs
    for _ in range(warmup):
        func()
    
    times = []
    
    # Measure memory for one run
    tracemalloc.start()
    func()
    _, memory_peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    
    # Timing runs
    for _ in range(iterations):
        start = time.perf_counter()
        result, name, algorithm = func()
        elapsed = time.perf_counter() - start
        times.append(elapsed)
    
    return BenchmarkResult(
        name=name,
        algorithm=algorithm,
        iterations=iterations,
        times=times,
        memory_peak=memory_peak
    )


def benchmark_ecc_keygen(curve=SECP256K1, iterations=10) -> BenchmarkResult:
    """Benchmark ECC key generation."""
    def keygen():
        private_key, public_key = generate_keypair(curve)
        return (private_key, public_key), "Key Generation", f"ECC-{curve.name}"
    
    return benchmark(keygen, iterations)


def benchmark_rsa_keygen(bits=2048, iterations=5) -> BenchmarkResult:
    """Benchmark RSA key generation."""
    def keygen():
        keypair = generate_rsa_keypair(bits)
        return keypair, "Key Generation", f"RSA-{bits}"
    
    return benchmark(keygen, iterations)


def benchmark_ecdh_exchange(curve=SECP256K1, iterations=10) -> BenchmarkResult:
    """Benchmark ECDH key exchange."""
    def exchange():
        alice_key, bob_key = perform_ecdh_exchange(curve)
        return (alice_key, bob_key), "Key Exchange", f"ECDH-{curve.name}"
    
    return benchmark(exchange, iterations)


def benchmark_rsa_exchange(bits=1024, iterations=3) -> BenchmarkResult:
    """Benchmark RSA key exchange (using 1024-bit for reasonable speed)."""
    def exchange():
        alice_key, bob_key = rsa_key_exchange_simulation(bits)
        return (alice_key, bob_key), "Key Exchange", f"RSA-{bits}"
    
    return benchmark(exchange, iterations)


def benchmark_scalar_multiply(curve=SECP256K1, iterations=20) -> BenchmarkResult:
    """Benchmark scalar multiplication (core ECC operation)."""
    import secrets
    G = get_generator(curve)
    k = secrets.randbelow(curve.n - 1) + 1
    
    def scalar_mult():
        result = scalar_multiply(k, G)
        return result, "Scalar Multiplication", f"ECC-{curve.name}"
    
    return benchmark(scalar_mult, iterations)


def run_full_benchmark(quick_mode=True):
    """
    Run comprehensive ECC vs RSA benchmark.
    
    Args:
        quick_mode: If True, use fewer iterations for faster results
    """
    print("=" * 70)
    print("ECC vs RSA Performance Benchmark")
    print("=" * 70)
    print(f"Quick mode: {quick_mode}")
    print(f"Python version: {sys.version}")
    print()
    
    # Adjust iterations based on mode
    if quick_mode:
        ecc_iter = 5
        rsa_iter = 2
        scalar_iter = 10
    else:
        ecc_iter = 20
        rsa_iter = 5
        scalar_iter = 50
    
    results = []
    
    # ============ Key Generation Benchmarks ============
    print("-" * 70)
    print("KEY GENERATION")
    print("-" * 70)
    
    # ECC Key Generation (256-bit curve)
    print("Benchmarking ECC-256 key generation...")
    ecc_keygen = benchmark_ecc_keygen(SECP256K1, ecc_iter)
    results.append(ecc_keygen)
    print(f"  {ecc_keygen}")
    
    # RSA Key Generation (for equivalent security, need RSA-3072)
    # But RSA-2048 is more commonly used, so we test both
    print("Benchmarking RSA-1024 key generation...")
    rsa_keygen_1024 = benchmark_rsa_keygen(1024, rsa_iter)
    results.append(rsa_keygen_1024)
    print(f"  {rsa_keygen_1024}")
    
    # Skip RSA-2048 in quick mode - too slow for pure Python
    if not quick_mode:
        print("Benchmarking RSA-2048 key generation...")
        rsa_keygen_2048 = benchmark_rsa_keygen(2048, 1)  # Only 1 iteration
        results.append(rsa_keygen_2048)
        print(f"  {rsa_keygen_2048}")
    else:
        print("Skipping RSA-2048 keygen in quick mode (too slow for pure Python)")
        # Create placeholder result for comparison
        rsa_keygen_2048 = BenchmarkResult("Key Generation", "RSA-2048", 0, [0], 0)
    
    # ============ Key Exchange Benchmarks ============
    print("\n" + "-" * 70)
    print("KEY EXCHANGE")
    print("-" * 70)
    
    print("Benchmarking ECDH key exchange...")
    ecdh_exchange = benchmark_ecdh_exchange(SECP256K1, ecc_iter)
    results.append(ecdh_exchange)
    print(f"  {ecdh_exchange}")
    
    print("Benchmarking RSA-1024 key exchange (2048 too slow for pure Python)...")
    rsa_exchange = benchmark_rsa_exchange(1024, rsa_iter)
    results.append(rsa_exchange)
    print(f"  {rsa_exchange}")
    
    # ============ Core Operation Benchmarks ============
    print("\n" + "-" * 70)
    print("CORE OPERATIONS")
    print("-" * 70)
    
    print("Benchmarking ECC scalar multiplication...")
    scalar_mult = benchmark_scalar_multiply(SECP256K1, scalar_iter)
    results.append(scalar_mult)
    print(f"  {scalar_mult}")
    
    # ============ Key Size Comparison ============
    print("\n" + "-" * 70)
    print("KEY SIZE COMPARISON")
    print("-" * 70)
    
    # Generate sample keys for size comparison
    ecc_priv, ecc_pub = generate_keypair(SECP256K1)
    rsa_keypair = generate_rsa_keypair(2048)
    
    ecc_priv_size = (ecc_priv.bit_length() + 7) // 8
    ecc_pub_size = ((ecc_pub.x.bit_length() + 7) // 8) + ((ecc_pub.y.bit_length() + 7) // 8)
    rsa_pub_size = (rsa_keypair.public_key.n.bit_length() + 7) // 8
    rsa_priv_size = (rsa_keypair.private_key.d.bit_length() + 7) // 8
    
    print(f"\n  {'Metric':<25} {'ECC-256':>15} {'RSA-2048':>15} {'Ratio':>10}")
    print(f"  {'-'*65}")
    print(f"  {'Private Key Size':<25} {ecc_priv_size:>12} B {rsa_priv_size:>12} B {rsa_priv_size/ecc_priv_size:>9.1f}x")
    print(f"  {'Public Key Size':<25} {ecc_pub_size:>12} B {rsa_pub_size:>12} B {rsa_pub_size/ecc_pub_size:>9.1f}x")
    print(f"  {'Security Level':<25} {'~128-bit':>15} {'~112-bit':>15} {'':>10}")
    
    # ============ Summary Table ============
    print("\n" + "=" * 70)
    print("BENCHMARK SUMMARY")
    print("=" * 70)
    
    print(f"\n  {'Operation':<30} {'Algorithm':<20} {'Time (ms)':>12} {'Memory (KB)':>12}")
    print(f"  {'-'*74}")
    
    for r in results:
        mem_kb = r.memory_peak / 1024
        print(f"  {r.name:<30} {r.algorithm:<20} {r.mean_time*1000:>12.2f} {mem_kb:>12.1f}")
    
    # ============ Speedup Analysis ============
    print("\n" + "-" * 70)
    print("SPEEDUP ANALYSIS")
    print("-" * 70)
    
    # Key generation speedup
    if ecc_keygen.mean_time > 0:
        keygen_speedup = rsa_keygen_2048.mean_time / ecc_keygen.mean_time
        print(f"\n  ECC-256 vs RSA-2048 Key Generation: ECC is {keygen_speedup:.1f}x faster")
    
    # Key exchange speedup
    if ecdh_exchange.mean_time > 0:
        exchange_speedup = rsa_exchange.mean_time / ecdh_exchange.mean_time
        print(f"  ECDH vs RSA Key Exchange: ECDH is {exchange_speedup:.1f}x faster")
    
    return results


def create_comparison_table():
    """Create a formatted comparison table for the paper."""
    
    print("\n" + "=" * 70)
    print("COMPARISON TABLE (for paper/presentation)")
    print("=" * 70)
    
    table = """
┌─────────────────────────┬──────────────────┬──────────────────┐
│        Metric           │       RSA        │       ECC        │
├─────────────────────────┼──────────────────┼──────────────────┤
│ Key Size (128-bit sec)  │    3072 bits     │     256 bits     │
│ Key Generation Speed    │      Slow        │      Fast        │
│ Computation Complexity  │     Heavy        │    Efficient     │
│ Bandwidth Usage         │      High        │       Low        │
│ Smart Card Suitability  │       ❌         │        ✅        │
│ Mobile Device Fit       │    Limited       │    Excellent     │
│ Power Consumption       │      High        │       Low        │
│ Mathematical Basis      │ Integer Factor.  │      ECDLP       │
│ Standardization         │   Well-estab.    │   Well-estab.    │
│ Quantum Resistance      │       ❌         │        ❌        │
└─────────────────────────┴──────────────────┴──────────────────┘
"""
    print(table)
    
    print("\nKey Size Equivalences (Comparable Security Levels):")
    print("┌────────────────┬───────────┬───────────┬───────────┐")
    print("│ Security Level │    RSA    │    ECC    │   Ratio   │")
    print("├────────────────┼───────────┼───────────┼───────────┤")
    print("│    80-bit      │   1024    │    160    │    6.4x   │")
    print("│   112-bit      │   2048    │    224    │    9.1x   │")
    print("│   128-bit      │   3072    │    256    │   12.0x   │")
    print("│   192-bit      │   7680    │    384    │   20.0x   │")
    print("│   256-bit      │  15360    │    521    │   29.5x   │")
    print("└────────────────┴───────────┴───────────┴───────────┘")


def export_results_csv(results: List[BenchmarkResult], filename: str = "benchmark_results.csv"):
    """Export benchmark results to CSV file."""
    import csv
    
    with open(filename, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Operation', 'Algorithm', 'Mean Time (ms)', 'Std Dev (ms)', 
                        'Min Time (ms)', 'Max Time (ms)', 'Memory (KB)', 'Iterations'])
        
        for r in results:
            writer.writerow([
                r.name,
                r.algorithm,
                f"{r.mean_time * 1000:.4f}",
                f"{r.std_dev * 1000:.4f}",
                f"{r.min_time * 1000:.4f}",
                f"{r.max_time * 1000:.4f}",
                f"{r.memory_peak / 1024:.2f}",
                r.iterations
            ])
    
    print(f"\nResults exported to {filename}")


def plot_results(results: List[BenchmarkResult]):
    """
    Generate plots for benchmark results.
    
    Requires matplotlib: pip install matplotlib
    """
    try:
        import matplotlib.pyplot as plt
        import numpy as np
    except ImportError:
        print("\nMatplotlib not installed. Install with: pip install matplotlib")
        print("Skipping plot generation.")
        return
    
    # Prepare data
    keygen_results = [r for r in results if "Key Generation" in r.name]
    exchange_results = [r for r in results if "Key Exchange" in r.name]
    
    # Create figure with subplots
    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    fig.suptitle('ECC vs RSA Performance Comparison', fontsize=14, fontweight='bold')
    
    # Plot 1: Key Generation Time
    ax1 = axes[0, 0]
    algorithms = [r.algorithm for r in keygen_results]
    times = [r.mean_time * 1000 for r in keygen_results]
    errors = [r.std_dev * 1000 for r in keygen_results]
    colors = ['green' if 'ECC' in alg else 'blue' for alg in algorithms]
    
    bars = ax1.bar(algorithms, times, yerr=errors, capsize=5, color=colors, alpha=0.7)
    ax1.set_ylabel('Time (ms)')
    ax1.set_title('Key Generation Time')
    ax1.tick_params(axis='x', rotation=45)
    
    # Plot 2: Key Exchange Time
    ax2 = axes[0, 1]
    if exchange_results:
        algorithms = [r.algorithm for r in exchange_results]
        times = [r.mean_time * 1000 for r in exchange_results]
        errors = [r.std_dev * 1000 for r in exchange_results]
        colors = ['green' if 'ECDH' in alg else 'blue' for alg in algorithms]
        
        ax2.bar(algorithms, times, yerr=errors, capsize=5, color=colors, alpha=0.7)
        ax2.set_ylabel('Time (ms)')
        ax2.set_title('Key Exchange Time')
        ax2.tick_params(axis='x', rotation=45)
    
    # Plot 3: Key Size Comparison
    ax3 = axes[1, 0]
    security_levels = ['80-bit', '112-bit', '128-bit', '192-bit', '256-bit']
    rsa_sizes = [1024, 2048, 3072, 7680, 15360]
    ecc_sizes = [160, 224, 256, 384, 521]
    
    x = np.arange(len(security_levels))
    width = 0.35
    
    ax3.bar(x - width/2, rsa_sizes, width, label='RSA', color='blue', alpha=0.7)
    ax3.bar(x + width/2, ecc_sizes, width, label='ECC', color='green', alpha=0.7)
    ax3.set_xlabel('Security Level')
    ax3.set_ylabel('Key Size (bits)')
    ax3.set_title('Key Size at Equivalent Security Levels')
    ax3.set_xticks(x)
    ax3.set_xticklabels(security_levels)
    ax3.legend()
    ax3.set_yscale('log')
    
    # Plot 4: Memory Usage
    ax4 = axes[1, 1]
    all_results = results[:5]  # Limit to avoid clutter
    algorithms = [r.algorithm for r in all_results]
    memory = [r.memory_peak / 1024 for r in all_results]
    colors = ['green' if 'ECC' in alg or 'ECDH' in alg else 'blue' for alg in algorithms]
    
    ax4.barh(algorithms, memory, color=colors, alpha=0.7)
    ax4.set_xlabel('Memory (KB)')
    ax4.set_title('Peak Memory Usage')
    
    plt.tight_layout()
    plt.savefig('benchmark_comparison.png', dpi=150, bbox_inches='tight')
    print("\nPlot saved to benchmark_comparison.png")
    plt.show()


# ============ Main ============
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='ECC vs RSA Benchmark')
    parser.add_argument('--quick', action='store_true', help='Run quick benchmark')
    parser.add_argument('--full', action='store_true', help='Run full benchmark')
    parser.add_argument('--plot', action='store_true', help='Generate plots')
    parser.add_argument('--csv', action='store_true', help='Export to CSV')
    parser.add_argument('--table', action='store_true', help='Show comparison table only')
    
    args = parser.parse_args()
    
    if args.table:
        create_comparison_table()
    else:
        # Default to quick mode
        quick_mode = not args.full
        
        results = run_full_benchmark(quick_mode=quick_mode)
        create_comparison_table()
        
        if args.csv:
            export_results_csv(results)
        
        if args.plot:
            plot_results(results)
