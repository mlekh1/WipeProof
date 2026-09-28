"""
WipeProof Independent Verifier Module.
Supports offline CLI verification, append-only Merkle transparency log,
and FastAPI verification microservice.
"""

from wipeproof.verifier.verifier_engine import CertificateVerifier, VerificationReport, VerificationStatus
from wipeproof.verifier.merkle_log import MerkleTransparencyLog

__all__ = [
    "CertificateVerifier",
    "VerificationReport",
    "VerificationStatus",
    "MerkleTransparencyLog",
]
