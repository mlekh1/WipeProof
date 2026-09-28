"""
Tests for StructuredAuditLogger.
"""

from wipeproof.core.audit import StructuredAuditLogger


def test_audit_logger_tracks_commands_and_monotonic_time():
    """Verify that audit entries capture monotonic timestamps, exit codes, and action names."""
    logger = StructuredAuditLogger(job_id="test-job-001")
    logger.log("COMMAND_RUN", command="lsblk -J", exit_code=0, stdout="{}", duration_ms=12.5)
    logger.log("WIPE_PASS", notes="Pass 1 completed.")

    d = logger.to_dict()
    assert d["entries_count"] == 2
    assert d["entries"][0]["action"] == "COMMAND_RUN"
    assert d["entries"][0]["exit_code"] == 0
    assert d["entries"][0]["monotonic_ns"] > 0
    assert d["entries"][1]["action"] == "WIPE_PASS"

    # Verify SHA-256 calculation is deterministic
    hash1 = logger.compute_sha256()
    hash2 = logger.compute_sha256()
    assert hash1 == hash2
    assert len(hash1) == 64
