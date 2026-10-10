"""
Tests for Sanitization Drivers and Post-Wipe Verification.
Validates:
- OverwriteDriver zeroing on a virtual sparse image
- Shannon entropy before and after overwrite
- PostWipeVerifier detection of un-wiped residual data
- SimulationDriver execution and error injection
"""

from pathlib import Path
import pytest

from wipeproof.core.drivers.overwrite import OverwriteDriver
from wipeproof.core.drivers.simulation import SimulationDriver
from wipeproof.core.exceptions import VerificationFailedError
from wipeproof.core.models import (
    DeviceProfile,
    SanitizationLevel,
    SanitizationMethod,
)
from wipeproof.core.verifier import PostWipeVerifier


def test_overwrite_driver_clears_virtual_disk(temp_sparse_image: Path, mock_device_profile: DeviceProfile):
    """Test that OverwriteDriver zeroes out random data and passes verification."""
    verifier = PostWipeVerifier(sample_blocks_count=64, block_size_bytes=4096)

    # 1. Before wipe: image has random data, verification should FAIL
    with pytest.raises(VerificationFailedError):
        verifier.verify(mock_device_profile, expected_entropy_max=0.05, min_zero_ratio=0.99, raise_on_failure=True)

    # 2. Execute OverwriteDriver
    driver = OverwriteDriver()
    exec_result = driver.execute(mock_device_profile, dry_run=False)

    assert exec_result.success is True
    assert exec_result.method == SanitizationMethod.OVERWRITE_ZERO
    assert exec_result.level == SanitizationLevel.CLEAR
    assert exec_result.bytes_written == mock_device_profile.size_bytes

    # 3. After wipe: image should have 0.0 entropy and 100% zero fill ratio
    verif_result = verifier.verify(mock_device_profile, expected_entropy_max=0.05, min_zero_ratio=0.99)

    assert verif_result.verification_passed is True
    assert verif_result.shannon_entropy == 0.0
    assert verif_result.zero_fill_ratio == 1.0
    assert verif_result.partition_table_cleared is True


def test_overwrite_driver_dry_run_leaves_data_untouched(temp_sparse_image: Path, mock_device_profile: DeviceProfile):
    """Dry-run must report success without modifying physical file bytes."""
    with open(temp_sparse_image, "rb") as f:
        bytes_before = f.read(1024)

    driver = OverwriteDriver()
    exec_result = driver.execute(mock_device_profile, dry_run=True)

    assert exec_result.success is True
    assert exec_result.bytes_written == 0

    with open(temp_sparse_image, "rb") as f:
        bytes_after = f.read(1024)

    assert bytes_before == bytes_after


def test_simulation_driver_success(mock_device_profile: DeviceProfile):
    """Simulation driver should execute cleanly on virtual loopback devices."""
    driver = SimulationDriver()
    assert driver.can_sanitize(mock_device_profile) is True

    result = driver.execute(mock_device_profile, dry_run=False)
    assert result.success is True
    assert result.level == SanitizationLevel.PURGE


def test_simulation_driver_injected_failure(mock_device_profile: DeviceProfile):
    """Simulation driver properly returns failure when error injection is enabled."""
    driver = SimulationDriver(fail_simulation=True)
    result = driver.execute(mock_device_profile, dry_run=False)
    assert result.success is False
    assert "injected" in result.notes.lower()
