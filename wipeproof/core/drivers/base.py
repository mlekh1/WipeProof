"""
WipeProof Sanitization Driver Base Interface.
"""

from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Callable, Optional

from wipeproof.core.models import DeviceProfile, SanitizationLevel, SanitizationMethod


@dataclass
class DriverExecutionResult:
    """Outcome of a driver's execution."""
    success: bool
    method: SanitizationMethod
    level: SanitizationLevel
    standard_reference: str
    command_executed: str
    firmware_status: str
    bytes_written: int
    duration_seconds: float
    notes: str
    disclaimer: Optional[str] = None


class SanitizerDriver(ABC):
    """Abstract base class for all storage sanitization drivers."""

    def __init__(self, name: str):
        self.name = name

    @abstractmethod
    def can_sanitize(self, device: DeviceProfile) -> bool:
        """Check whether this driver can operate on the specified device."""
        pass

    @abstractmethod
    def execute(
        self,
        device: DeviceProfile,
        dry_run: bool = False,
        progress_callback: Optional[Callable[[float, int, int], None]] = None,
    ) -> DriverExecutionResult:
        """Execute the sanitization routine.
        
        Args:
            device: Target device profile.
            dry_run: If True, simulate execution without writing data.
            progress_callback: Optional callback receiving (fraction_complete, bytes_done, total_bytes).
            
        Returns:
            DriverExecutionResult with status and command details.
        """
        pass
