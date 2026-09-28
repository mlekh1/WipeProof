"""
Tests for WipeProof SafetyGatekeeper.
Validates defense-in-depth safety invariants:
- Rejection of root/boot/swap mounts
- Rejection of active filesystems
- Loopback isolation in test mode
- Typed confirmation challenges
"""

import pytest
from wipeproof.core.exceptions import SafetyViolationError
from wipeproof.core.models import DeviceProfile, MediaType
from wipeproof.core.safety import SafetyGatekeeper


def test_safety_refuses_root_boot_mounts():
    """Verify that targeting any device hosting / or /boot raises SafetyViolationError."""
    gatekeeper = SafetyGatekeeper()

    # Device with root mount
    root_dev = DeviceProfile(
        path="/dev/sda",
        model="Host Root Drive",
        serial="SN-ROOT-001",
        size_bytes=512000000000,
        media_type=MediaType.SATA_SSD,
        mountpoints=["/"],
    )

    with pytest.raises(SafetyViolationError, match="hosting critical system mount point '/'"):
        gatekeeper.evaluate_target_safety(root_dev)

    # Device with /boot mount
    boot_dev = DeviceProfile(
        path="/dev/nvme0n1",
        model="Host NVMe",
        serial="SN-BOOT-001",
        size_bytes=1000000000000,
        media_type=MediaType.NVME_SSD,
        mountpoints=["/boot"],
    )

    with pytest.raises(SafetyViolationError, match="hosting critical system mount point '/boot'"):
        gatekeeper.evaluate_target_safety(boot_dev)


def test_safety_refuses_active_mounts():
    """Verify that any active mountpoint on the device aborts sanitization."""
    gatekeeper = SafetyGatekeeper()

    data_dev = DeviceProfile(
        path="/dev/sdb",
        model="Data Drive",
        serial="SN-DATA-001",
        size_bytes=500000000000,
        media_type=MediaType.ROTATIONAL_HDD,
        mountpoints=["/mnt/data"],
    )

    with pytest.raises(SafetyViolationError, match="active mount points: \\[/mnt/data\\]"):
        gatekeeper.evaluate_target_safety(data_dev)


def test_safety_enforces_loopback_isolation_in_test_mode():
    """Verify that when test_mode_loopback_only is True, real disk paths are rejected."""
    test_gatekeeper = SafetyGatekeeper(test_mode_loopback_only=True)

    real_disk = DeviceProfile(
        path="/dev/sda",
        model="Physical Drive",
        serial="SN-REAL-001",
        size_bytes=500000000000,
        media_type=MediaType.SATA_SSD,
        mountpoints=[],
    )

    with pytest.raises(SafetyViolationError, match="CRITICAL SAFETY ABORT: Test suite attempted to target real disk"):
        test_gatekeeper.evaluate_target_safety(real_disk)


def test_safety_allows_virtual_loopback():
    """Verify that virtual loopback devices pass safety checks when unmounted."""
    gatekeeper = SafetyGatekeeper(test_mode_loopback_only=True)

    loop_dev = DeviceProfile(
        path="/tmp/test_disk.img",
        model="Virtual Loopback",
        serial="SN-VIRT-001",
        size_bytes=10485760,
        media_type=MediaType.VIRTUAL_LOOPBACK,
        mountpoints=[],
    )

    # Should not raise
    gatekeeper.evaluate_target_safety(loop_dev)


def test_typed_confirmation_matching_serial():
    """Typed confirmation succeeds when serial matches exactly."""
    dev = DeviceProfile(
        path="/dev/loop0",
        model="Mock Drive",
        serial="CONFIRM-ME-123",
        size_bytes=1000000,
        media_type=MediaType.VIRTUAL_LOOPBACK,
    )

    res = SafetyGatekeeper.request_typed_confirmation(dev, override_input="CONFIRM-ME-123")
    assert res is True


def test_typed_confirmation_mismatched_serial():
    """Typed confirmation raises SafetyViolationError on mismatch."""
    dev = DeviceProfile(
        path="/dev/loop0",
        model="Mock Drive",
        serial="CONFIRM-ME-123",
        size_bytes=1000000,
        media_type=MediaType.VIRTUAL_LOOPBACK,
    )

    with pytest.raises(SafetyViolationError, match="Confirmation failed: Expected serial 'CONFIRM-ME-123'"):
        SafetyGatekeeper.request_typed_confirmation(dev, override_input="WRONG-SERIAL")
