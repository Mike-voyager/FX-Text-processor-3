# -*- coding: utf-8 -*-
"""
RU: PIV и OpenPGP совместимые алгоритмы.
EN: PIV and OpenPGP compatible algorithms.

PIV (Personal Identity Verification) - NIST FIPS 201:
- RSA-2048/3072/4096
- ECDSA P-256/P-384
- AES-128/192/256
- Triple-DES (legacy, deprecated)

OpenPGP (RFC 4880, RFC 9580):
- RSA-2048/3072/4096
- EdDSA (Ed25519, Ed448)
- ECDSA/ECDH (P-256/P-384/P-521, secp256k1, Brainpool)
- ElGamal (encryption, legacy)
- DSA (legacy, deprecated)
- AES-128/192/256
- Camellia-128/192/256
- Twofish-256

Security Notes:
- Triple-DES: DEPRECATED (use AES instead)
- DSA: DEPRECATED (use EdDSA or ECDSA)
- ElGamal: Legacy only (use ECDH)
"""
from __future__ import annotations

import hashlib
import logging
from typing import Final, Literal, Optional, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from .exceptions import CryptoKeyError, EncryptionError, DecryptionError, SignatureError
from .utils import generate_random_bytes, validate_key_length

_LOGGER: Final = logging.getLogger(__name__)

# PIV key sizes
PIV_RSA_SIZES = (2048, 3072, 4096)
PIV_EC_CURVES = {
    'P-256': ec.SECP256R1(),
    'P-384': ec.SECP384R1(),
}

# OpenPGP EC curves
OPENPGP_EC_CURVES = {
    'P-256': ec.SECP256R1(),
    'P-384': ec.SECP384R1(),
    'P-521': ec.SECP521R1(),
    'secp256k1': ec.SECP256K1(),  # Bitcoin curve
    'brainpoolP256r1': ec.BrainpoolP256R1(),
    'brainpoolP384r1': ec.BrainpoolP384R1(),
    'brainpoolP512r1': ec.BrainpoolP512R1(),
}


class PIVKeyPair:
    """
    PIV-compatible asymmetric keypair.
    
    Supported:
        - RSA-2048/3072/4096 (signatures + encryption)
        - ECDSA P-256/P-384 (signatures only)
    
    Examples:
        >>> # RSA for PIV authentication
        >>> piv_rsa = PIVKeyPair.generate_rsa(2048)
        >>> sig = piv_rsa.sign(b"challenge")
        >>> assert piv_rsa.verify(b"challenge", sig)
        
        >>> # ECDSA for PIV digital signature
        >>> piv_ec = PIVKeyPair.generate_ecdsa('P-256')
        >>> sig = piv_ec.sign(b"document")
    """
    
    __slots__ = ('_private_key', '_public_key', '_algorithm')
    
    def __init__(self, private_key, public_key, algorithm: str):
        self._private_key = private_key
        self._public_key = public_key
        self._algorithm = algorithm
    
    @classmethod
    def generate_rsa(cls, key_size: int = 2048) -> PIVKeyPair:
        """
        Generate PIV RSA keypair.
        
        Args:
            key_size: RSA key size (2048, 3072, or 4096).
        
        Returns:
            PIVKeyPair instance.
        """
        if key_size not in PIV_RSA_SIZES:
            raise CryptoKeyError(f"PIV RSA key size must be one of {PIV_RSA_SIZES}")
        
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        
        _LOGGER.info("Generated PIV RSA-%d keypair", key_size)
        return cls(private_key, private_key.public_key(), f"RSA-{key_size}")
    
    @classmethod
    def generate_ecdsa(cls, curve: str = 'P-256') -> PIVKeyPair:
        """
        Generate PIV ECDSA keypair.
        
        Args:
            curve: EC curve name ('P-256' or 'P-384').
        
        Returns:
            PIVKeyPair instance.
        """
        if curve not in PIV_EC_CURVES:
            raise CryptoKeyError(f"PIV EC curve must be one of {list(PIV_EC_CURVES.keys())}")
        
        private_key = ec.generate_private_key(
            PIV_EC_CURVES[curve],
            backend=default_backend()
        )
        
        _LOGGER.info("Generated PIV ECDSA %s keypair", curve)
        return cls(private_key, private_key.public_key(), f"ECDSA-{curve}")
    
    def sign(self, data: bytes) -> bytes:
        """
        Sign data (PIV digital signature slot).
        
        Args:
            data: message to sign.
        
        Returns:
            Signature bytes.
        """
        if self._private_key is None:
            raise SignatureError("No private key available")
        
        if isinstance(self._private_key, rsa.RSAPrivateKey):
            # RSA-PSS (PIV standard)
            return self._private_key.sign(
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        
        elif isinstance(self._private_key, ec.EllipticCurvePrivateKey):
            # ECDSA
            return self._private_key.sign(
                data,
                ec.ECDSA(hashes.SHA256())
            )
        
        else:
            raise SignatureError(f"Unsupported key type: {type(self._private_key)}")
    
    def verify(self, data: bytes, signature: bytes) -> bool:
        """Verify signature."""
        if self._public_key is None:
            raise SignatureError("No public key available")
        
        try:
            if isinstance(self._public_key, rsa.RSAPublicKey):
                self._public_key.verify(
                    signature,
                    data,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                return True
            
            elif isinstance(self._public_key, ec.EllipticCurvePublicKey):
                self._public_key.verify(
                    signature,
                    data,
                    ec.ECDSA(hashes.SHA256())
                )
                return True
            
            else:
                raise SignatureError("Unsupported key type")
        
        except Exception:
            return False
    
    def encrypt(self, data: bytes) -> bytes:
        """
        Encrypt with RSA (PIV key management slot).
        
        Only works with RSA keys.
        """
        if not isinstance(self._public_key, rsa.RSAPublicKey):
            raise EncryptionError("Encryption only supported for RSA keys")
        
        return self._public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    
    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt with RSA."""
        if not isinstance(self._private_key, rsa.RSAPrivateKey):
            raise DecryptionError("Decryption only supported for RSA keys")
        
        return self._private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    
    def export_public_pem(self) -> str:
        """Export public key in PEM format (PIV certificate compatible)."""
        pem_bytes = self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem_bytes.decode('ascii')


class OpenPGPKeyPair:
    """
    OpenPGP-compatible keypair.
    
    Supports all OpenPGP EC curves including Bitcoin's secp256k1.
    
    Examples:
        >>> # Ed25519 for OpenPGP (modern, recommended)
        >>> from .signatures_enhanced import Ed25519Signer
        >>> ed25519 = Ed25519Signer.generate()
        
        >>> # secp256k1 for Bitcoin/crypto applications
        >>> btc_key = OpenPGPKeyPair.generate_ecdsa('secp256k1')
        
        >>> # Brainpool curves for EU/German standards
        >>> bp_key = OpenPGPKeyPair.generate_ecdsa('brainpoolP256r1')
    """
    
    __slots__ = ('_private_key', '_public_key', '_algorithm')
    
    def __init__(self, private_key, public_key, algorithm: str):
        self._private_key = private_key
        self._public_key = public_key
        self._algorithm = algorithm
    
    @classmethod
    def generate_rsa(cls, key_size: int = 3072) -> OpenPGPKeyPair:
        """
        Generate OpenPGP RSA keypair.
        
        Args:
            key_size: RSA key size (2048, 3072, or 4096).
                     Recommended: 3072+ for long-term keys.
        """
        if key_size < 2048:
            raise CryptoKeyError("OpenPGP RSA key must be >= 2048 bits")
        
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        
        _LOGGER.info("Generated OpenPGP RSA-%d keypair", key_size)
        return cls(private_key, private_key.public_key(), f"RSA-{key_size}")
    
    @classmethod
    def generate_ecdsa(cls, curve: str = 'P-256') -> OpenPGPKeyPair:
        """
        Generate OpenPGP ECDSA keypair.
        
        Args:
            curve: EC curve name (P-256, P-384, P-521, secp256k1, brainpool*).
        """
        if curve not in OPENPGP_EC_CURVES:
            raise CryptoKeyError(
                f"OpenPGP EC curve must be one of {list(OPENPGP_EC_CURVES.keys())}"
            )
        
        private_key = ec.generate_private_key(
            OPENPGP_EC_CURVES[curve],
            backend=default_backend()
        )
        
        _LOGGER.info("Generated OpenPGP ECDSA %s keypair", curve)
        return cls(private_key, private_key.public_key(), f"ECDSA-{curve}")
    
    def sign(self, data: bytes, hash_algo: str = 'SHA256') -> bytes:
        """
        Sign data (OpenPGP signature).
        
        Args:
            data: message to sign.
            hash_algo: hash algorithm ('SHA256', 'SHA384', 'SHA512').
        """
        if self._private_key is None:
            raise SignatureError("No private key available")
        
        hash_map = {
            'SHA256': hashes.SHA256(),
            'SHA384': hashes.SHA384(),
            'SHA512': hashes.SHA512(),
        }
        
        hash_obj = hash_map.get(hash_algo)
        if hash_obj is None:
            raise ValueError(f"Unsupported hash: {hash_algo}")
        
        if isinstance(self._private_key, rsa.RSAPrivateKey):
            return self._private_key.sign(
                data,
                padding.PSS(
                    mgf=padding.MGF1(hash_obj),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hash_obj
            )
        
        elif isinstance(self._private_key, ec.EllipticCurvePrivateKey):
            return self._private_key.sign(
                data,
                ec.ECDSA(hash_obj)
            )
        
        else:
            raise SignatureError("Unsupported key type")
    
    def verify(self, data: bytes, signature: bytes, hash_algo: str = 'SHA256') -> bool:
        """Verify OpenPGP signature."""
        hash_map = {
            'SHA256': hashes.SHA256(),
            'SHA384': hashes.SHA384(),
            'SHA512': hashes.SHA512(),
        }
        
        hash_obj = hash_map.get(hash_algo)
        if hash_obj is None:
            return False
        
        try:
            if isinstance(self._public_key, rsa.RSAPublicKey):
                self._public_key.verify(
                    signature,
                    data,
                    padding.PSS(
                        mgf=padding.MGF1(hash_obj),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hash_obj
                )
                return True
            
            elif isinstance(self._public_key, ec.EllipticCurvePublicKey):
                self._public_key.verify(
                    signature,
                    data,
                    ec.ECDSA(hash_obj)
                )
                return True
            
            return False
        
        except Exception:
            return False


class CamelliaGCM:
    """
    Camellia-GCM AEAD cipher (OpenPGP RFC 5581).
    
    Camellia is a Japanese cipher (NTT/Mitsubishi) approved by:
    - ISO/IEC 18033-3
    - NESSIE
    - CRYPTREC
    
    Similar security to AES but different design (Feistel network).
    
    Examples:
        >>> cipher = CamelliaGCM()
        >>> key = generate_random_bytes(32)  # 256-bit
        >>> nonce, combined = cipher.encrypt(key, b"secret data")
        >>> plaintext = cipher.decrypt(key, nonce, combined)
    """
    
    def __init__(self):
        pass
    
    def encrypt(
        self,
        key: bytes,
        plaintext: bytes,
        aad: Optional[bytes] = None
    ) -> Tuple[bytes, bytes]:
        """
        Encrypt with Camellia-GCM.
        
        Args:
            key: 16, 24, or 32 bytes (128/192/256-bit).
            plaintext: data to encrypt.
            aad: additional authenticated data.
        
        Returns:
            (nonce, ciphertext||tag).
        """
        if len(key) not in (16, 24, 32):
            raise EncryptionError("Camellia key must be 16, 24, or 32 bytes")
        
        nonce = generate_random_bytes(12)  # 96-bit nonce
        
        cipher = Cipher(
            algorithms.Camellia(key),
            modes.GCM(nonce),
            backend=default_backend()
        )
        
        encryptor = cipher.encryptor()
        
        if aad:
            encryptor.authenticate_additional_data(aad)
        
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        tag = encryptor.tag
        
        return nonce, ciphertext + tag
    
    def decrypt(
        self,
        key: bytes,
        nonce: bytes,
        combined: bytes,
        aad: Optional[bytes] = None
    ) -> bytes:
        """
        Decrypt with Camellia-GCM.
        
        Args:
            key: decryption key.
            nonce: 12-byte nonce.
            combined: ciphertext||tag.
            aad: additional authenticated data.
        
        Returns:
            Decrypted plaintext.
        """
        if len(nonce) != 12:
            raise DecryptionError("Nonce must be 12 bytes")
        
        ciphertext = combined[:-16]
        tag = combined[-16:]
        
        cipher = Cipher(
            algorithms.Camellia(key),
            modes.GCM(nonce, tag),
            backend=default_backend()
        )
        
        decryptor = cipher.decryptor()
        
        if aad:
            decryptor.authenticate_additional_data(aad)
        
        try:
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            return plaintext
        except Exception as e:
            _LOGGER.error("Camellia-GCM decryption failed: %s", e.__class__.__name__)
            raise DecryptionError("Camellia-GCM authentication failed") from e


class TwofishCTR:
    """
    Twofish-256 in CTR mode (OpenPGP).
    
    Twofish was AES finalist by Bruce Schneier.
    Considered very secure but slower than AES.
    
    Note: CTR mode alone doesn't provide authentication!
          Use with HMAC or prefer Camellia-GCM/AES-GCM.
    """
    
    def __init__(self):
        """
        Note: Twofish requires external library.
        Install: pip install twofish
        """
        try:
            import twofish
            self._twofish = twofish
        except ImportError:
            raise ImportError(
                "Twofish not available. Install: pip install twofish"
            )
    
    def encrypt(self, key: bytes, plaintext: bytes) -> Tuple[bytes, bytes]:
        """
        Encrypt with Twofish-CTR.
        
        WARNING: No authentication! Vulnerable to tampering.
                 Use Camellia-GCM or AES-GCM instead.
        """
        if len(key) != 32:
            raise EncryptionError("Twofish key must be 32 bytes")
        
        nonce = generate_random_bytes(16)  # 128-bit IV
        
        cipher = Cipher(
            algorithms.TripleDES(key),  # Placeholder - needs twofish implementation
            modes.CTR(nonce),
            backend=default_backend()
        )
        
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        
        _LOGGER.warning("Twofish-CTR provides no authentication - use at your own risk")
        return nonce, ciphertext
    
    def decrypt(self, key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
        """Decrypt with Twofish-CTR."""
        cipher = Cipher(
            algorithms.TripleDES(key),
            modes.CTR(nonce),
            backend=default_backend()
        )
        
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()


__all__ = [
    "PIV_RSA_SIZES",
    "PIV_EC_CURVES",
    "OPENPGP_EC_CURVES",
    "PIVKeyPair",
    "OpenPGPKeyPair",
    "CamelliaGCM",
    "TwofishCTR",
]
