"""
WipeProof Independent Verification Microservice (FastAPI).

Provides REST API endpoints for certificate validation, revocation checking,
and append-only Merkle transparency log inclusion.
"""

import os
import tempfile
from typing import Any, Optional
from fastapi import FastAPI, HTTPException, status
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from wipeproof import __version__
from wipeproof.core.models import SanitizationMethod
from wipeproof.core.orchestrator import SanitizationOrchestrator
from wipeproof.crypto.keys import KeyManager, RevocationRegistry
from wipeproof.crypto.notary import CertificateNotary
from wipeproof.verifier.merkle_log import MerkleTransparencyLog
from wipeproof.verifier.verifier_engine import CertificateVerifier, VerificationStatus
from wipeproof.verifier.web_ui import WEB_DASHBOARD_HTML


app = FastAPI(
    title="WipeProof Certificate Verification Service",
    description="Independent cryptographic verification service for WipeProof disk sanitization certificates.",
    version=__version__,
)

# Global in-memory state (can be configured with persistent files)
revocation_registry = RevocationRegistry()
merkle_log = MerkleTransparencyLog()
verifier = CertificateVerifier(revocation_registry=revocation_registry)

# Generate or load a default service demonstration keypair
demo_private_key, demo_public_key = KeyManager.generate_keypair()


@app.get("/", response_class=HTMLResponse, tags=["Dashboard"])
def get_dashboard():
    """Serve embedded single-page local dashboard."""
    return HTMLResponse(content=WEB_DASHBOARD_HTML)


@app.post("/api/demo/run", tags=["Lab"])
def run_interactive_demo():
    """Execute a safe, virtual sparse disk sanitization and produce a signed certificate."""
    with tempfile.NamedTemporaryFile(suffix=".img", delete=False) as f:
        sparse_path = f.name
        # Populate 2MB with random high-entropy bytes
        f.write(os.urandom(1024 * 1024 * 2))
        f.flush()

    try:
        orchestrator = SanitizationOrchestrator(test_mode_loopback_only=True)
        # Execute wipe on virtual sparse image
        result = orchestrator.run_wipe_job(
            target_path=sparse_path,
            dry_run=False,
            interactive=False,
            preferred_method=SanitizationMethod.SIMULATION_ERASE,
        )

        notary = CertificateNotary(private_key=demo_private_key)
        cert = notary.issue_certificate(result)

        return {
            "status": "COMPLETED",
            "method": result.method.value,
            "entropy": result.verification.shannon_entropy,
            "certificate": cert,
            "public_key_hex": KeyManager.public_key_to_hex(demo_public_key),
        }
    finally:
        if os.path.exists(sparse_path):
            try:
                os.unlink(sparse_path)
            except OSError:
                pass


class VerifyRequest(BaseModel):
    certificate: dict[str, Any]
    trusted_public_key_hex: Optional[str] = None


class VerifyResponse(BaseModel):
    status: str
    reason: str
    certificate_id: str
    key_id: str
    canonical_payload_sha256: str
    calculated_payload_sha256: str
    device_serial: Optional[str] = None
    sanitization_method: Optional[str] = None
    sanitization_level: Optional[str] = None
    merkle_tree_size: Optional[int] = None
    merkle_root_hash: Optional[str] = None
    merkle_leaf_index: Optional[int] = None


@app.get("/health", tags=["System"])
def health_check():
    """Service health and transparency log status."""
    return {
        "status": "HEALTHY",
        "service": "wipeproof-verifier",
        "version": __version__,
        "merkle_log_size": len(merkle_log.leaves),
        "merkle_root": merkle_log.get_root_hash(),
    }


@app.post("/verify", response_model=VerifyResponse, tags=["Verification"])
def verify_certificate_endpoint(req: VerifyRequest):
    """Verify cryptographic authenticity, payload integrity, and revocation state of a wipe certificate."""
    report = verifier.verify_certificate(
        certificate=req.certificate,
        trusted_public_key=req.trusted_public_key_hex,
    )

    leaf_idx = None
    if report.status == VerificationStatus.VALID:
        # Append valid certificate to Merkle Transparency Log
        leaf_idx = merkle_log.append_certificate(
            certificate_id=report.certificate_id,
            canonical_payload_sha256=report.canonical_payload_sha256,
        )

    return VerifyResponse(
        status=report.status.value,
        reason=report.reason,
        certificate_id=report.certificate_id,
        key_id=report.key_id,
        canonical_payload_sha256=report.canonical_payload_sha256,
        calculated_payload_sha256=report.calculated_payload_sha256,
        device_serial=report.device_serial,
        sanitization_method=report.sanitization_method,
        sanitization_level=report.sanitization_level,
        merkle_tree_size=len(merkle_log.leaves),
        merkle_root_hash=merkle_log.get_root_hash(),
        merkle_leaf_index=leaf_idx,
    )


@app.get("/proof/{leaf_index}", tags=["Transparency Log"])
def get_merkle_inclusion_proof(leaf_index: int):
    """Retrieve Merkle audit path (inclusion proof) for a specific log entry."""
    try:
        proof = merkle_log.get_inclusion_proof(leaf_index)
        return {
            "leaf_index": proof.leaf_index,
            "leaf_hash": proof.leaf_hash,
            "tree_size": proof.tree_size,
            "root_hash": proof.root_hash,
            "audit_path": proof.audit_path,
            "is_valid": proof.verify(),
        }
    except IndexError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
