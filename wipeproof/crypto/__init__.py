"""
WipeProof Cryptographic Module.
Implements RFC 8785 JSON Canonicalization, RFC 8032 Ed25519 Signing,
Hash Chaining, and Cryptographic PDF Certificate Generation.
"""

from wipeproof.crypto.canonicalize import canonicalize_jcs
from wipeproof.crypto.keys import KeyManager
from wipeproof.crypto.notary import CertificateNotary
from wipeproof.crypto.pdf_cert import CertificatePdfGenerator

__all__ = [
    "canonicalize_jcs",
    "KeyManager",
    "CertificateNotary",
    "CertificatePdfGenerator",
]
