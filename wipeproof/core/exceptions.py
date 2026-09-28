"""
WipeProof Core Exceptions.
Enforces fail-safe and defense-in-depth safety invariants.
"""


class WipeProofError(Exception):
    """Base exception for all WipeProof errors."""
    pass


class SafetyViolationError(WipeProofError):
    """Raised when an operation would violate safety invariants.
    
    Examples:
    - Target drive contains root filesystem (/), /boot, or active swap
    - Target drive has active mounts
    - Test runner attempts to touch non-loopback devices
    - Serial number confirmation mismatch
    """
    pass


class DeviceNotFoundError(WipeProofError):
    """Raised when the specified device path or node cannot be found."""
    pass


class DeviceLockedError(WipeProofError):
    """Raised when an ATA or NVMe device is in a frozen or locked security state."""
    pass


class SanitizationFailedError(WipeProofError):
    """Raised when a sanitization command or write pass fails."""
    pass


class VerificationFailedError(WipeProofError):
    """Raised when post-wipe verification fails (e.g. non-zero bytes or unexpected entropy)."""
    pass


class HpaDcoError(WipeProofError):
    """Raised when HPA/DCO detection or removal fails."""
    pass
