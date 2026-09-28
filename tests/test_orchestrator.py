"""
Integration tests for SanitizationOrchestrator.
Tests end-to-end flow: Discovery -> Safety -> Wipe -> Verification -> Audit Hash.
"""

from pathlib import Path
from wipeproof.core.models import SanitizationMethod, SanitizationLevel
from wipeproof.core.orchestrator import SanitizationOrchestrator


def test_orchestrator_full_wipe_pipeline(temp_sparse_image: Path):
    """Verify that full pipeline wipes the sparse virtual image and produces valid WipeResult."""
    orchestrator = SanitizationOrchestrator(test_mode_loopback_only=True)

    result = orchestrator.run_wipe_job(
        target_path=str(temp_sparse_image),
        dry_run=False,
        interactive=True,
        confirmation_override=f"SIM-{abs(hash(str(temp_sparse_image))) % 1000000000:09d}",
        preferred_method=SanitizationMethod.OVERWRITE_ZERO,
    )

    assert result.success is True
    assert result.job_id.startswith("urn:uuid:")
    assert result.verification.verification_passed is True
    assert result.verification.shannon_entropy == 0.0
    assert result.verification.zero_fill_ratio == 1.0
    assert len(result.audit_log_sha256) == 64
    assert result.duration_seconds >= 0.0


def test_orchestrator_dry_run(temp_sparse_image: Path):
    """Verify that dry-run mode runs cleanly without touching bytes."""
    orchestrator = SanitizationOrchestrator(test_mode_loopback_only=True)

    result = orchestrator.run_wipe_job(
        target_path=str(temp_sparse_image),
        dry_run=True,
        interactive=False,
    )

    assert result.success is True
    assert result.firmware_reported_status in ("DRY_RUN_SUCCESS", "SIMULATION_DRY_RUN_SUCCESS")
    assert result.verification.verification_passed is True
