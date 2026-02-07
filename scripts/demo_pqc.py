#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Demo script for Post-Quantum Cryptography.

Usage:
    python demo_pqc.py
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

# Add src to path
project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(project_root / "src"))

from security.crypto.pqc import (
    KYBER_AVAILABLE,
    DILITHIUM_AVAILABLE,
    KyberKEM,
    DilithiumSigner,
    hybrid_kem_x25519_kyber,
)


def print_banner(text: str) -> None:
    """Print section banner."""
    print()
    print("=" * 70)
    print(f"  {text}")
    print("=" * 70)


def print_success(text: str) -> None:
    """Print success message."""
    print(f"✅ {text}")


def print_info(text: str) -> None:
    """Print info message."""
    print(f"ℹ️  {text}")


def print_data(label: str, data: bytes, max_len: int = 64) -> None:
    """Print data preview."""
    hex_data = data.hex()
    if len(hex_data) > max_len:
        preview = f"{hex_data[:max_len]}... ({len(data)} bytes)"
    else:
        preview = f"{hex_data} ({len(data)} bytes)"
    print(f"   {label}: {preview}")


def check_availability() -> None:
    """Check PQC availability."""
    print_banner("🔍 Checking PQC Availability")

    print_info(f"Kyber available: {KYBER_AVAILABLE}")
    print_info(f"Dilithium available: {DILITHIUM_AVAILABLE}")

    if not (KYBER_AVAILABLE and DILITHIUM_AVAILABLE):
        print()
        print("❌ PQC not available!")
        print("   Install: pip install liboqs-python")
        sys.exit(1)

    print_success("All PQC algorithms available!")


def demo_kyber() -> None:
    """Demonstrate Kyber KEM."""
    print_banner("📦 Demo: Kyber-768 Key Encapsulation")

    # Step 1: Generate keypair
    print()
    print("Step 1: Generating Kyber-768 keypair...")
    start = time.time()
    kem = KyberKEM.generate()
    duration = (time.time() - start) * 1000
    print_success(f"Keypair generated in {duration:.2f}ms")

    public_key = kem.export_public_key()
    secret_key = kem.export_secret_key()

    print_data("Public key", public_key)
    print_data("Secret key", secret_key)

    # Step 2: Encapsulate
    print()
    print("Step 2: Encapsulating shared secret...")
    kem_sender = KyberKEM.from_public_key(public_key)
    start = time.time()
    ciphertext, shared_secret_sender = kem_sender.encapsulate()
    duration = (time.time() - start) * 1000
    print_success(f"Encapsulation completed in {duration:.2f}ms")

    print_data("Ciphertext", ciphertext)
    print_data("Shared secret", shared_secret_sender)

    # Step 3: Decapsulate
    print()
    print("Step 3: Decapsulating shared secret...")
    start = time.time()
    shared_secret_receiver = kem.decapsulate(ciphertext)
    duration = (time.time() - start) * 1000
    print_success(f"Decapsulation completed in {duration:.2f}ms")

    print_data("Recovered secret", shared_secret_receiver)

    # Step 4: Verify
    print()
    if shared_secret_sender == shared_secret_receiver:
        print_success("✨ Secrets match! KEM successful!")
    else:
        print("❌ Secrets don't match!")


def demo_dilithium() -> None:
    """Demonstrate Dilithium signatures."""
    print_banner("✍️  Demo: Dilithium-3 Digital Signatures")

    # Step 1: Generate keypair
    print()
    print("Step 1: Generating Dilithium-3 keypair...")
    start = time.time()
    signer = DilithiumSigner.generate()
    duration = (time.time() - start) * 1000
    print_success(f"Keypair generated in {duration:.2f}ms")

    public_key = signer.export_public_key()
    secret_key = signer.export_secret_key()

    print_data("Public key", public_key)
    print_data("Secret key", secret_key)

    # Step 2: Sign message
    print()
    message = "This is a quantum-resistant signed message!".encode("utf-8")  # FIXED
    print(f"Step 2: Signing message: {message.decode()}")
    start = time.time()
    signature = signer.sign(message)
    duration = (time.time() - start) * 1000
    print_success(f"Signature created in {duration:.2f}ms")

    print_data("Signature", signature)

    # Step 3: Verify signature (valid)
    print()
    print("Step 3: Verifying signature with correct message...")
    verifier = DilithiumSigner.from_public_key(public_key)
    start = time.time()
    is_valid = verifier.verify(message, signature)
    duration = (time.time() - start) * 1000

    if is_valid:
        print_success(
            f"Signature valid! Verified in {duration:.2f}ms"
        )  # FIXED - убрал emoji
    else:
        print("❌ Signature invalid!")

    # Step 4: Verify signature (invalid)
    print()
    wrong_message = b"This is a MODIFIED message!"
    print(f"Step 4: Verifying signature with wrong message: {wrong_message.decode()}")
    is_valid = verifier.verify(wrong_message, signature)

    if not is_valid:
        print_success("Signature correctly rejected!")  # FIXED - убрал emoji
    else:
        print("❌ Signature should be invalid!")


def demo_hybrid_kem() -> None:
    """Demonstrate hybrid X25519 + Kyber KEM."""
    print_banner("🔀 Demo: Hybrid KEM (X25519 + Kyber-768)")

    from cryptography.hazmat.primitives.asymmetric import x25519

    # Step 1: Generate recipient keys
    print()
    print("Step 1: Generating recipient keys (X25519 + Kyber)...")

    # X25519 keypair
    x25519_private = x25519.X25519PrivateKey.generate()
    x25519_public = x25519_private.public_key().public_bytes_raw()

    # Kyber keypair
    kyber_kem = KyberKEM.generate()
    kyber_public = kyber_kem.export_public_key()

    print_success("Recipient keys generated")
    print_data("X25519 public", x25519_public)
    print_data("Kyber public", kyber_public)

    # Step 2: Hybrid encapsulation
    print()
    print("Step 2: Performing hybrid key exchange...")
    start = time.time()
    kyber_ct, x25519_ephemeral, combined_secret = hybrid_kem_x25519_kyber(
        x25519_public, kyber_public
    )
    duration = (time.time() - start) * 1000
    print_success(f"Hybrid KEM completed in {duration:.2f}ms")

    print_data("Kyber ciphertext", kyber_ct)
    print_data("X25519 ephemeral", x25519_ephemeral)
    print_data("Combined secret", combined_secret)

    # Step 3: Explain security
    print()
    print_info("Security properties:")
    print("   • Protected against quantum attacks (Kyber)")
    print("   • Protected against classical attacks (X25519)")
    print("   • Defense-in-depth: breaking one doesn't break the system")
    print("   • Combined via HKDF-SHA256")


def demo_performance() -> None:
    """Show performance comparison."""
    print_banner("⚡ Performance Benchmark")

    print()
    print("Running benchmarks (10 iterations each)...")

    # Kyber keygen
    times = []
    for _ in range(10):
        start = time.time()
        KyberKEM.generate()
        times.append((time.time() - start) * 1000)
    avg_kyber_keygen = sum(times) / len(times)

    # Kyber encap
    kem = KyberKEM.generate()
    public_key = kem.export_public_key()
    kem_sender = KyberKEM.from_public_key(public_key)
    times = []
    for _ in range(10):
        start = time.time()
        kem_sender.encapsulate()
        times.append((time.time() - start) * 1000)
    avg_kyber_encap = sum(times) / len(times)

    # Dilithium keygen
    times = []
    for _ in range(10):
        start = time.time()
        DilithiumSigner.generate()
        times.append((time.time() - start) * 1000)
    avg_dilithium_keygen = sum(times) / len(times)

    # Dilithium sign
    signer = DilithiumSigner.generate()
    message = b"Test message"
    times = []
    for _ in range(10):
        start = time.time()
        signer.sign(message)
        times.append((time.time() - start) * 1000)
    avg_dilithium_sign = sum(times) / len(times)

    print()
    print("Results:")
    print(f"   Kyber-768 keygen:     {avg_kyber_keygen:6.2f} ms")
    print(f"   Kyber-768 encap:      {avg_kyber_encap:6.2f} ms")
    print(f"   Dilithium-3 keygen:   {avg_dilithium_keygen:6.2f} ms")
    print(f"   Dilithium-3 sign:     {avg_dilithium_sign:6.2f} ms")

    print()
    print_info("Note: PQC is slower than classical crypto, but still practical!")


def main() -> None:
    """Main demo function."""
    print()
    print("╔════════════════════════════════════════════════════════════════════╗")
    print("║                                                                    ║")
    print("║        🔐 POST-QUANTUM CRYPTOGRAPHY DEMONSTRATION 🔐              ║")
    print("║                                                                    ║")
    print("║     NIST-Standardized Quantum-Resistant Algorithms                ║")
    print("║                                                                    ║")
    print("╚════════════════════════════════════════════════════════════════════╝")

    try:
        # Check availability
        check_availability()

        # Run demos
        demo_kyber()
        demo_dilithium()
        demo_hybrid_kem()
        demo_performance()

        # Final message
        print()
        print_banner("🎉 All Demos Completed Successfully!")
        print()
        print("Summary:")
        print("  ✅ Kyber-768 (ML-KEM-768) - Key Encapsulation")
        print("  ✅ Dilithium-3 (ML-DSA-65) - Digital Signatures")
        print("  ✅ Hybrid KEM (X25519 + Kyber) - Defense-in-depth")
        print()
        print("🔐 Your application is protected against quantum computers!")
        print()

    except KeyboardInterrupt:
        print()
        print()
        print("❌ Demo interrupted by user")
        sys.exit(1)
    except Exception as e:
        print()
        print()
        print(f"❌ Error: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
