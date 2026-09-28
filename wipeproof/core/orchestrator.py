"""
WipeProof Sanitization Orchestrator.

Orchestrates the entire sanitization workflow:
1. Safety Interlocks & Gatekeeper evaluation.
2. Device profiling and HPA/DCO audit & restoration.
3. Intelligent strategy selection (ATA vs NVMe vs Overwrite vs Simulation).
4. Post-wipe sampling and Shannon entropy verification.
5. Structured audit logging and SHA-256 log hash calculation.
"""

from __future__ import annotations
import time
import uuid
from datetime import datetime, timezone
from typing import Callable, Optional

from wipeproof.core.audit import StructuredAuditLogger
from wipeproof.core.discovery import DeviceDiscovery
from wipeproof.core.drivers.base import SanitizerDriver, DriverExecutionResult
from wipeproof.core.drivers.overwrite import OverwriteDriver
from wipeproof.core.drivers.ata import AtaSanitizerDriver
from wipeproof.core.drivers.nvme import NvmeSanitizerDriver
from wipeproof.core.drivers.simulation import SimulationDriver
from wipeproof.core.exceptions import SanitizationFailedError
from wipeproof.core.hpa_dco import HpaDcoAuditor
from wipeproof.core.models import (
    DeviceProfile,
    MediaType,
    SanitizationLevel,
    SanitizationMethod,
    WipeResult,
)
from wipeproof.core.safety import SafetyGatekeeper
from wipeproof.core.verifier import PostWipeVerifier


class SanitizationOrchestrator:
    """End-to-end sanitization workflow coordinator."""

    def __init__(
        self,
        test_mode_loopback_only: bool = False,
        discovery: Optional[DeviceDiscovery] = None,
        safety_gatekeeper: Optional[SafetyGatekeeper] = None,
        hpa_auditor: Optional[HpaDcoAuditor] = None,
        verifier: Optional[PostWipeVerifier] = None,
    ):
        self.test_mode = test_mode_loopback_only
        self.discovery = discovery or DeviceDiscovery()
        self.safety = safety_gatekeeper or SafetyGatekeeper(test_mode_loopback_only=test_mode_loopback_only)
        self.hpa_auditor = hpa_auditor or HpaDcoAuditor()
        self.verifier = verifier or PostWipeVerifier()

    def select_driver(
        self,
        device: DeviceProfile,
        preferred_method: Optional[SanitizationMethod] = None,
    ) -> SanitizerDriver:
        """Select the appropriate sanitization driver for the media type."""
        # Test & Simulation mode
        if device.media_type == MediaType.VIRTUAL_LOOPBACK or self.test_mode:
            return SimulationDriver()

        # Specific user override if requested
        if preferred_method == SanitizationMethod.OVERWRITE_ZERO:
            return OverwriteDriver()

        # NVMe SSDs
        if device.media_type == MediaType.NVME_SSD:
            nvme_driver = NvmeSanitizerDriver()
            if nvme_driver.can_sanitize(device):
                return nvme_driver
            return OverwriteDriver()

        # SATA SSDs and Rotational HDDs
        if device.media_type in (MediaType.SATA_SSD, MediaType.ROTATIONAL_HDD):
            ata_driver = AtaSanitizerDriver()
            if ata_driver.can_sanitize(device):
                return ata_driver
            return OverwriteDriver()

        # Default fallback: Sequential Overwrite (honest Clear)
        return OverwriteDriver()

    def run_wipe_job(
        self,
        target_path: str,
        dry_run: bool = False,
        interactive: bool = True,
        confirmation_override: Optional[str] = None,
        preferred_method: Optional[SanitizationMethod] = None,
        progress_callback: Optional[Callable[[float, int, int], None]] = None,
    ) -> WipeResult:
        """Execute a full sanitization pipeline on the specified target.
        
        Args:
            target_path: Device node or virtual disk path.
            dry_run: If True, execute dry run without writing bytes.
            interactive: Whether to prompt for typed confirmation.
            confirmation_override: Serial string for programmatic/test validation.
            preferred_method: Optional override for sanitization method.
            progress_callback: Progress monitor callback.
            
        Returns:
            WipeResult containing verification, audit hash, and device metadata.
        """
        job_id = f"urn:uuid:{uuid.uuid4()}"
        audit = StructuredAuditLogger(job_id)
        start_mono = time.monotonic()
        start_utc = datetime.now(timezone.utc).isoformat()

        audit.log("JOB_STARTED", notes=f"Starting sanitization for {target_path}, dry_run={dry_run}")

        # Step 1: Discover Device
        device = self.discovery.get_device_profile(target_path)
        audit.log(
            "DEVICE_DISCOVERED",
            notes=f"Model: {device.model}, Serial: {device.serial}, Size: {device.size_bytes} bytes, Type: {device.media_type.value}",
        )

        # Step 2: Evaluate Safety Invariants
        self.safety.evaluate_target_safety(device)
        audit.log("SAFETY_CHECKS_PASSED", notes="Root disk and active mountpoint checks passed.")

        # Step 3: Typed Confirmation (if not dry run)
        if not dry_run and interactive:
            self.safety.request_typed_confirmation(device, override_input=confirmation_override)
            audit.log("OPERATOR_CONFIRMED", notes=f"Operator verified serial {device.serial}")

        # Step 4: Audit & Unhide HPA/DCO
        is_ata = device.media_type in (MediaType.SATA_SSD, MediaType.ROTATIONAL_HDD)
        hpa_state = self.hpa_auditor.audit_and_unhide(device.path, is_ata=is_ata)
        device.hpa_dco = hpa_state
        audit.log("HPA_DCO_AUDITED", notes=hpa_state.details)

        # Step 5: Select Driver and Execute Sanitization
        driver = self.select_driver(device, preferred_method=preferred_method)
        audit.log("DRIVER_SELECTED", notes=f"Selected driver: {driver.name}")

        exec_result: DriverExecutionResult = driver.execute(
            device=device,
            dry_run=dry_run,
            progress_callback=progress_callback,
        )

        audit.log(
            "SANITIZATION_EXECUTED",
            command=exec_result.command_executed,
            exit_code=0 if exec_result.success else 1,
            duration_ms=exec_result.duration_seconds * 1000,
            notes=f"Status: {exec_result.firmware_status}, Bytes: {exec_result.bytes_written}",
        )

        if not exec_result.success:
            raise SanitizationFailedError(f"Sanitization failed: {exec_result.notes}")

        # Step 6: Post-Wipe Verification
        audit.log("VERIFICATION_STARTED", notes="Beginning LBA sampling and Shannon entropy check.")
        if dry_run:
            from wipeproof.core.models import VerificationResult
            verification = VerificationResult(
                sampling_method="DRY_RUN_SIMULATION",
                sampled_blocks_count=0,
                sample_block_size_bytes=0,
                total_bytes_sampled=0,
                read_errors=0,
                shannon_entropy=0.0,
                zero_fill_ratio=1.0,
                partition_table_cleared=True,
                firmware_status_verified=True,
                verification_passed=True,
                details="Dry-run: verification skipped.",
            )
        else:
            verification = self.verifier.verify(device)

        audit.log("VERIFICATION_COMPLETED", notes=verification.details)

        completed_utc = datetime.now(timezone.utc).isoformat()
        duration_total = round(time.monotonic() - start_mono, 3)
        audit_hash = audit.compute_sha256()

        return WipeResult(
            job_id=job_id,
            device=device,
            method=exec_result.method,
            level=exec_result.level,
            standard_reference=exec_result.standard_reference,
            started_at=start_utc,
            completed_at=completed_utc,
            duration_seconds=duration_total,
            firmware_reported_status=exec_result.firmware_status,
            verification=verification,
            audit_log_sha256=audit_hash,
            success=verification.verification_passed,
            disclaimer=exec_result.disclaimer,
        )
