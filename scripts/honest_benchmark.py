#!/usr/bin/env python3
"""HONEST comparison: PQC vs Modern Classical Crypto."""

import sys
import time
from pathlib import Path

# Добавить src в PYTHONPATH
project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(project_root / "src"))

from security.crypto.pqc import KyberKEM, DilithiumSigner
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519, ec
from cryptography.hazmat.primitives import hashes


def benchmark_ed25519() -> dict:
    """Benchmark Ed25519 (modern, fast signatures)."""
    print("⏱️  Benchmarking Ed25519 (modern signatures)...")

    # Keygen
    times = []
    for _ in range(100):
        start = time.time()
        private_key = ed25519.Ed25519PrivateKey.generate()
        times.append((time.time() - start) * 1000)
    ed_keygen = sum(times) / len(times)

    # Sign
    message = b"Test message"
    times = []
    for _ in range(100):
        start = time.time()
        signature = private_key.sign(message)
        times.append((time.time() - start) * 1000)
    ed_sign = sum(times) / len(times)

    # Verify
    public_key = private_key.public_key()
    times = []
    for _ in range(100):
        start = time.time()
        public_key.verify(signature, message)
        times.append((time.time() - start) * 1000)
    ed_verify = sum(times) / len(times)

    return {
        "keygen": ed_keygen,
        "sign": ed_sign,
        "verify": ed_verify,
        "pk_size": 32,
        "sig_size": 64,
    }


def benchmark_x25519() -> dict:
    """Benchmark X25519 (modern key exchange)."""
    print("⏱️  Benchmarking X25519 (modern key exchange)...")

    # Keygen
    times = []
    for _ in range(100):
        start = time.time()
        private_key = x25519.X25519PrivateKey.generate()
        times.append((time.time() - start) * 1000)
    x_keygen = sum(times) / len(times)

    # Exchange
    peer_private = x25519.X25519PrivateKey.generate()
    peer_public = peer_private.public_key()
    times = []
    for _ in range(100):
        start = time.time()
        shared = private_key.exchange(peer_public)
        times.append((time.time() - start) * 1000)
    x_exchange = sum(times) / len(times)

    return {
        "keygen": x_keygen,
        "exchange": x_exchange,
        "pk_size": 32,
        "shared_size": 32,
    }


def benchmark_ecdsa_p256() -> dict:
    """Benchmark ECDSA P-256 (NIST standard)."""
    print("⏱️  Benchmarking ECDSA P-256 (NIST curve)...")

    # Keygen
    times = []
    for _ in range(100):
        start = time.time()
        private_key = ec.generate_private_key(ec.SECP256R1())
        times.append((time.time() - start) * 1000)
    ec_keygen = sum(times) / len(times)

    # Sign
    message = b"Test message"
    times = []
    for _ in range(100):
        start = time.time()
        signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
        times.append((time.time() - start) * 1000)
    ec_sign = sum(times) / len(times)

    return {
        "keygen": ec_keygen,
        "sign": ec_sign,
        "sig_size": 64,
    }


def benchmark_dilithium() -> dict:
    """Benchmark Dilithium-3 (PQC)."""
    print("⏱️  Benchmarking Dilithium-3 (post-quantum)...")

    # Keygen
    times = []
    for _ in range(100):
        start = time.time()
        signer = DilithiumSigner.generate()
        times.append((time.time() - start) * 1000)
    dil_keygen = sum(times) / len(times)

    # Sign
    message = b"Test message"
    times = []
    for _ in range(100):
        start = time.time()
        signature = signer.sign(message)
        times.append((time.time() - start) * 1000)
    dil_sign = sum(times) / len(times)

    # Verify
    public_key = signer.export_public_key()
    verifier = DilithiumSigner.from_public_key(public_key)
    times = []
    for _ in range(100):
        start = time.time()
        verifier.verify(message, signature)
        times.append((time.time() - start) * 1000)
    dil_verify = sum(times) / len(times)

    return {
        "keygen": dil_keygen,
        "sign": dil_sign,
        "verify": dil_verify,
        "pk_size": 1952,
        "sig_size": 3309,
    }


def benchmark_kyber() -> dict:
    """Benchmark Kyber-768 (PQC)."""
    print("⏱️  Benchmarking Kyber-768 (post-quantum)...")

    # Keygen
    times = []
    for _ in range(100):
        start = time.time()
        kem = KyberKEM.generate()
        times.append((time.time() - start) * 1000)
    kyber_keygen = sum(times) / len(times)

    # Encapsulate
    pk = kem.export_public_key()
    kem_sender = KyberKEM.from_public_key(pk)
    times = []
    for _ in range(100):
        start = time.time()
        ct, ss = kem_sender.encapsulate()
        times.append((time.time() - start) * 1000)
    kyber_encap = sum(times) / len(times)

    # Decapsulate
    times = []
    for _ in range(100):
        start = time.time()
        shared = kem.decapsulate(ct)
        times.append((time.time() - start) * 1000)
    kyber_decap = sum(times) / len(times)

    return {
        "keygen": kyber_keygen,
        "encap": kyber_encap,
        "decap": kyber_decap,
        "pk_size": 1184,
        "ct_size": 1088,
    }


def print_honest_comparison() -> None:
    """Print honest comparison."""
    print()
    print("╔" + "═" * 68 + "╗")
    print("║" + " " * 10 + "⚔️  HONEST CRYPTO SHOWDOWN ⚔️" + " " * 20 + "║")
    print("║" + " " * 15 + "PQC vs Modern Classical" + " " * 21 + "║")
    print("╚" + "═" * 68 + "╝")
    print()

    ed = benchmark_ed25519()
    x25519_data = benchmark_x25519()
    ecdsa = benchmark_ecdsa_p256()
    dilithium = benchmark_dilithium()
    kyber = benchmark_kyber()

    print()
    print("=" * 70)
    print("🔑 KEY GENERATION SPEED")
    print("=" * 70)
    print()
    print(f"   Ed25519:      {ed['keygen']:6.3f} ms  {'█' * 50}")
    print(
        f"   X25519:       {x25519_data['keygen']:6.3f} ms  {'█' * int(x25519_data['keygen']/ed['keygen']*50)}"
    )
    print(
        f"   ECDSA P-256:  {ecdsa['keygen']:6.3f} ms  {'█' * int(ecdsa['keygen']/ed['keygen']*50)}"
    )
    print(
        f"   Dilithium-3:  {dilithium['keygen']:6.3f} ms  {'█' * int(dilithium['keygen']/ed['keygen']*50)}"
    )
    print(
        f"   Kyber-768:    {kyber['keygen']:6.3f} ms  {'█' * int(kyber['keygen']/ed['keygen']*50) if kyber['keygen'] > 0.001 else 1}"
    )
    print()

    print("=" * 70)
    print("✍️  SIGNATURE GENERATION SPEED")
    print("=" * 70)
    print()
    print(f"   Ed25519:      {ed['sign']:6.3f} ms  {'█' * 50}")
    print(
        f"   ECDSA P-256:  {ecdsa['sign']:6.3f} ms  {'█' * int(ecdsa['sign']/ed['sign']*50)}"
    )
    print(
        f"   Dilithium-3:  {dilithium['sign']:6.3f} ms  {'█' * int(dilithium['sign']/ed['sign']*50)}"
    )
    print()
    ratio = ed["sign"] / dilithium["sign"]
    if ratio > 1:
        print(f"   ⚡ Dilithium is {ratio:.1f}x FASTER than Ed25519!")
    else:
        print(f"   ⚠️  Dilithium is {1/ratio:.1f}x SLOWER than Ed25519")
    print()

    print("=" * 70)
    print("🔍 VERIFICATION SPEED")
    print("=" * 70)
    print()
    print(f"   Ed25519:      {ed['verify']:6.3f} ms  {'█' * 50}")
    print(
        f"   Dilithium-3:  {dilithium['verify']:6.3f} ms  {'█' * int(dilithium['verify']/ed['verify']*50)}"
    )
    print()

    print("=" * 70)
    print("🔀 KEY EXCHANGE / KEM SPEED")
    print("=" * 70)
    print()
    print(f"   X25519 exchange:     {x25519_data['exchange']:6.3f} ms  {'█' * 50}")
    print(
        f"   Kyber encapsulate:   {kyber['encap']:6.3f} ms  {'█' * int(kyber['encap']/x25519_data['exchange']*50)}"
    )
    print(
        f"   Kyber decapsulate:   {kyber['decap']:6.3f} ms  {'█' * int(kyber['decap']/x25519_data['exchange']*50)}"
    )
    print()

    print("=" * 70)
    print("📦 DATA SIZES (bytes)")
    print("=" * 70)
    print()
    print("SIGNATURES:")
    print(f"   Ed25519:      {ed['sig_size']:5d} bytes  {'▓' * 10}")
    print(f"   ECDSA P-256:  {ecdsa['sig_size']:5d} bytes  {'▓' * 10}")
    print(
        f"   Dilithium-3:  {dilithium['sig_size']:5d} bytes  {'▓' * int(dilithium['sig_size']/ed['sig_size']*10)}"
    )
    print()
    print("PUBLIC KEYS:")
    print(f"   Ed25519:      {ed['pk_size']:5d} bytes  {'▓' * 10}")
    print(
        f"   Dilithium-3:  {dilithium['pk_size']:5d} bytes  {'▓' * int(dilithium['pk_size']/ed['pk_size']*10)}"
    )
    print(
        f"   Kyber-768:    {kyber['pk_size']:5d} bytes  {'▓' * int(kyber['pk_size']/ed['pk_size']*10)}"
    )
    print()

    print("=" * 70)
    print("🎯 HONEST VERDICT")
    print("=" * 70)
    print()

    print("SPEED:")
    ed_total = ed["keygen"] + ed["sign"] + ed["verify"]
    dil_total = dilithium["keygen"] + dilithium["sign"] + dilithium["verify"]

    if dil_total < ed_total:
        print(f"   ✅ PQC is FASTER overall ({ed_total/dil_total:.1f}x)")
    else:
        print(f"   ⚠️  PQC is {dil_total/ed_total:.1f}x slower than modern classical")
    print()

    print("SIZE:")
    print(
        f"   ⚠️  PQC signatures are {dilithium['sig_size']/ed['sig_size']:.0f}x larger"
    )
    print(f"   ⚠️  PQC public keys are {dilithium['pk_size']/ed['pk_size']:.0f}x larger")
    print()

    print("SECURITY:")
    print("   ✅ Ed25519: 128-bit classical security")
    print("   ❌ Ed25519: 0-bit quantum security (broken by Shor's algorithm)")
    print()
    print("   ✅ Dilithium-3: 128-bit classical security")
    print("   ✅ Dilithium-3: 192-bit quantum security")
    print()

    print("=" * 70)
    print("💡 THE REAL TRADEOFF")
    print("=" * 70)
    print()
    print("Classical (Ed25519, X25519):")
    print("   ✅ Ultra-fast")
    print("   ✅ Tiny keys/signatures")
    print("   ❌ Vulnerable to quantum computers")
    print("   ❌ 'Harvest now, decrypt later' risk")
    print()
    print("Post-Quantum (Kyber, Dilithium):")
    if dil_total < ed_total:
        print("   ✅ Still very fast (competitive with classical!)")
    else:
        print(f"   ⚠️  ~{dil_total/ed_total:.0f}x slower than classical")
    print("   ⚠️  Larger keys/signatures")
    print("   ✅ Quantum-resistant")
    print("   ✅ Future-proof security")
    print()
    print("HYBRID APPROACH (X25519 + Kyber):")
    print("   ✅ Best of both worlds")
    print("   ✅ Protected if either is broken")
    print("   ⚠️  Small performance overhead")
    print("   ✅ Recommended for production")
    print()


if __name__ == "__main__":
    print_honest_comparison()
