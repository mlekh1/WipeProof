"""
WipeProof Core Data Models & Standards Enums.
Strictly maps to NIST SP 800-88 Rev. 2 and IEEE 2883:2022.
"""

from __future__ import annotations
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Optional


class MediaType(str, Enum):
    ROTATIONAL_HDD = "ROTATIONAL_HDD"
    SATA_SSD = "SATA_SSD"
    NVME_SSD = "NVME_SSD"
    USB_REMOVABLE = "USB_REMOVABLE"
    VIRTUAL_LOOPBACK = "VIRTUAL_LOOPBACK"
    UNKNOWN = "UNKNOWN"


class SanitizationLevel(str, Enum):
    """NIST SP 800-88 Rev. 2 & IEEE 2883:2022 Sanitization Categories."""
    CLEAR = "Clear"
    PURGE = "Purge"
    DESTROY = "Destroy"


class SanitizationMethod(str, Enum):
    """Concrete sanitization method executed."""
    OVERWRITE_ZERO = "OVERWRITE_ZERO"
    OVERWRITE_RANDOM = "OVERWRITE_RANDOM"
    ATA_SECURE_ERASE = "ATA_SECURE_ERASE"
    ATA_SANITIZE_BLOCK_ERASE = "ATA_SANITIZE_BLOCK_ERASE"
    ATA_SANITIZE_CRYPTO = "ATA_SANITIZE_CRYPTO"
    ATA_SANITIZE_OVERWRITE = "ATA_SANITIZE_OVERWRITE"
    NVME_FORMAT_USER_ERASE = "NVME_FORMAT_USER_ERASE"
    NVME_FORMAT_CRYPTO = "NVME_FORMAT_CRYPTO"
    NVME_SANITIZE_BLOCK_ERASE = "NVME_SANITIZE_BLOCK_ERASE"
    NVME_SANITIZE_CRYPTO = "NVME_SANITIZE_CRYPTO"
    SIMULATION_ERASE = "SIMULATION_ERASE"


class VerificationStatus(str, Enum):
    PASSED = "PASSED"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"


@dataclass
class HpaDcoState:
    """Audit record for Host Protected Area and Device Configuration Overlay."""
    hpa_detected: bool = False
    dco_detected: bool = False
    native_max_sectors_before: int = 0
    native_max_sectors_after: int = 0
    hpa_removed: bool = False
    dco_restored: bool = False
    details: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class DeviceProfile:
    """Discovered physical or virtual storage device profile."""
    path: str
    model: str
    serial: str
    size_bytes: int
    media_type: MediaType
    sector_size_logical: int = 512
    sector_size_physical: int = 512
    wwn: Optional[str] = None
    firmware_revision: Optional[str] = None
    bus_type: str = "unknown"
    is_rotational: bool = False
    is_removable: bool = False
    is_read_only: bool = False
    is_encrypted: bool = False
    encryption_type: Optional[str] = None
    mountpoints: list[str] = field(default_factory=list)
    hpa_dco: Optional[HpaDcoState] = None

    @property
    def capacity_gb(self) -> float:
        return round(self.size_bytes / (1024 ** 3), 2)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["media_type"] = self.media_type.value
        if self.hpa_dco:
            d["hpa_dco"] = self.hpa_dco.to_dict()
        return d


@dataclass
class VerificationResult:
    """Results of the post-wipe verification sampling and entropy check."""
    sampling_method: str
    sampled_blocks_count: int
    sample_block_size_bytes: int
    total_bytes_sampled: int
    read_errors: int
    shannon_entropy: float
    zero_fill_ratio: float
    partition_table_cleared: bool
    firmware_status_verified: bool
    verification_passed: bool
    details: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AuditEntry:
    """Single execution step in the structured audit log."""
    timestamp_utc: str
    monotonic_ns: int
    action: str
    command: Optional[str] = None
    exit_code: Optional[int] = None
    stdout_snippet: Optional[str] = None
    stderr_snippet: Optional[str] = None
    duration_ms: Optional[float] = None
    notes: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class WipeResult:
    """Summary record of an entire sanitization job."""
    job_id: str
    device: DeviceProfile
    method: SanitizationMethod
    level: SanitizationLevel
    standard_reference: str
    started_at: str
    completed_at: str
    duration_seconds: float
    firmware_reported_status: str
    verification: VerificationResult
    audit_log_sha256: str
    success: bool
    disclaimer: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["device"] = self.device.to_dict()
        d["method"] = self.method.value
        d["level"] = self.level.value
        d["verification"] = self.verification.to_dict()
        return d
