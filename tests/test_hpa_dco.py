"""
Tests for HPA and DCO detection, unhiding, and sector logging.
"""

from wipeproof.core.hpa_dco import HpaDcoAuditor


def test_hpa_detected_and_logged():
    """Verify that when native_max exceeds visible sectors, HPA is detected."""
    auditor = HpaDcoAuditor()
    # Simulate a drive with 1,000,000 visible sectors and 2,000,000 native max sectors
    state = auditor.audit_and_unhide(
        device_path="/dev/sda",
        is_ata=True,
        simulate_hpa_sectors=(1000000, 2000000),
    )

    assert state.hpa_detected is True
    assert state.hpa_removed is True
    assert state.native_max_sectors_before == 1000000
    assert state.native_max_sectors_after == 2000000
    assert "unhidden 1000000 hidden sectors" in state.details


def test_hpa_clean_drive():
    """When visible equals native max, HPA is reported as clean."""
    auditor = HpaDcoAuditor()
    state = auditor.audit_and_unhide(
        device_path="/dev/sda",
        is_ata=True,
        simulate_hpa_sectors=(2000000, 2000000),
    )

    assert state.hpa_detected is False
    assert state.native_max_sectors_before == 2000000
    assert state.native_max_sectors_after == 2000000
