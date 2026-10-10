"""
WipeProof Command-Line Interface (CLI).
Provides enterprise storage discovery, safety-gated wiping, and certificate issuance.
"""

from __future__ import annotations
import os
import sys
import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeRemainingColumn

import json
from pathlib import Path

from wipeproof import __version__
from wipeproof.core.discovery import DeviceDiscovery
from wipeproof.core.exceptions import WipeProofError
from wipeproof.core.models import SanitizationMethod
from wipeproof.core.orchestrator import SanitizationOrchestrator
from wipeproof.crypto.keys import KeyManager, RevocationRegistry
from wipeproof.crypto.notary import CertificateNotary
from wipeproof.crypto.pdf_cert import CertificatePdfGenerator
from wipeproof.verifier.verifier_engine import CertificateVerifier, VerificationStatus

console = Console()


@click.group()
@click.version_option(version=__version__, prog_name="wipeproof")
def cli():
    """WipeProof: Enterprise disk sanitization with cryptographically signed certificates."""
    pass


@cli.command(name="scan")
def scan_devices():
    """Scan and list all detected storage devices with safety annotations."""
    discovery = DeviceDiscovery()
    table = Table(title="Detected Storage Media", border_style="cyan", show_lines=True)

    table.add_column("Path", style="bold cyan")
    table.add_column("Type", style="magenta")
    table.add_column("Model", style="white")
    table.add_column("Serial", style="yellow")
    table.add_column("Capacity", style="green", justify="right")
    table.add_column("Status / Mounts", style="red")

    # On Linux check /sys/block; on Windows/dev list sample or virtual
    target_dirs = ["/dev/sda", "/dev/sdb", "/dev/nvme0n1", "/dev/loop0"] if os.name != "nt" else []

    # If no physical devices visible, inform user
    if not target_dirs:
        console.print("[yellow]Host is non-Linux or has no exposed raw block devices in PATH.[/yellow]")
        console.print("[green]Use virtual image files (e.g. disk.img) or loopback devices for wiping and testing.[/green]")
        return

    for dev_path in target_dirs:
        try:
            profile = discovery.get_device_profile(dev_path)
            mps = ", ".join(profile.mountpoints) if profile.mountpoints else "[dim]Unmounted[/dim]"
            if any(m in ("/", "/boot") for m in profile.mountpoints):
                mps = f"[bold red]PROTECTED (OS Root: {mps})[/bold red]"

            table.add_row(
                profile.path,
                profile.media_type.value,
                profile.model,
                profile.serial,
                f"{profile.capacity_gb} GB",
                mps,
            )
        except Exception:
            continue

    console.print(table)


@cli.command(name="info")
@click.argument("target", type=click.Path(exists=True))
def device_info(target: str):
    """Inspect low-level hardware attributes, HPA/DCO, and encryption status."""
    discovery = DeviceDiscovery()
    try:
        profile = discovery.get_device_profile(target)
    except Exception as e:
        console.print(f"[bold red]Error reading device {target}: {e}[/bold red]")
        sys.exit(1)

    info_table = Table(title=f"Device Details: {target}", border_style="green")
    info_table.add_column("Attribute", style="cyan")
    info_table.add_column("Value", style="white")

    info_table.add_row("Device Path", profile.path)
    info_table.add_row("Model", profile.model)
    info_table.add_row("Serial Number", profile.serial)
    info_table.add_row("Capacity", f"{profile.capacity_gb} GB ({profile.size_bytes} bytes)")
    info_table.add_row("Media Type", profile.media_type.value)
    info_table.add_row("Bus Transport", profile.bus_type)
    info_table.add_row("Rotational", "Yes (Magnetic HDD)" if profile.is_rotational else "No (Flash / Virtual)")
    info_table.add_row("Logical Sector Size", f"{profile.sector_size_logical} bytes")
    info_table.add_row("Physical Sector Size", f"{profile.sector_size_physical} bytes")
    info_table.add_row("Encrypted Volume", "Yes" if profile.is_encrypted else "No")
    info_table.add_row("Active Mountpoints", ", ".join(profile.mountpoints) or "None (Clean)")

    console.print(info_table)


@cli.command(name="wipe")
@click.argument("target", type=click.Path(exists=True))
@click.option("--dry-run", is_flag=True, help="Simulate sanitization without writing data.")
@click.option(
    "--method",
    type=click.Choice(["auto", "overwrite", "ata-sanitize", "nvme-sanitize"]),
    default="auto",
    help="Sanitization strategy to invoke.",
)
@click.option(
    "--force-yes-i-understand-data-loss",
    is_flag=True,
    help="Non-interactive bypass for automated scripts.",
)
@click.option("--expected-serial", type=str, help="Expected serial number guard for automation.")
@click.option("--test-mode-loopback", is_flag=True, help="Restrict destruction strictly to loopback/virtual images.")
@click.option("--output-cert", type=click.Path(), help="Output path for JSON wipe certificate.")
def wipe_device(
    target: str,
    dry_run: bool,
    method: str,
    force_yes_i_understand_data_loss: bool,
    expected_serial: str | None,
    test_mode_loopback: bool,
    output_cert: str | None,
):
    """Execute certified secure sanitization on the specified storage target."""
    interactive = not force_yes_i_understand_data_loss

    # Method mapping
    pref_method = None
    if method == "overwrite":
        pref_method = SanitizationMethod.OVERWRITE_ZERO
    elif method == "ata-sanitize":
        pref_method = SanitizationMethod.ATA_SANITIZE_BLOCK_ERASE
    elif method == "nvme-sanitize":
        pref_method = SanitizationMethod.NVME_SANITIZE_BLOCK_ERASE

    orchestrator = SanitizationOrchestrator(test_mode_loopback_only=test_mode_loopback)

    console.print(
        Panel.fit(
            f"[bold red]WipeProof Sanitization Initiated[/bold red]\n"
            f"Target: [cyan]{target}[/cyan] | Dry Run: [yellow]{dry_run}[/yellow] | Strategy: [magenta]{method}[/magenta]",
            border_style="red",
        )
    )

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeRemainingColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("[cyan]Sanitizing...", total=100)

            def progress_cb(fraction: float, done_bytes: int, total_bytes: int):
                progress.update(task, completed=fraction * 100)

            result = orchestrator.run_wipe_job(
                target_path=target,
                dry_run=dry_run,
                interactive=interactive,
                confirmation_override=expected_serial,
                preferred_method=pref_method,
                progress_callback=progress_cb,
            )

        # Output Summary
        console.print("\n[bold green] Sanitization Complete & Verified![/bold green]")
        summary_table = Table(border_style="green")
        summary_table.add_column("Field", style="cyan")
        summary_table.add_column("Result", style="white")

        summary_table.add_row("Job ID", result.job_id)
        summary_table.add_row("Standard Mapping", result.standard_reference)
        summary_table.add_row("NIST Level", result.level.value)
        summary_table.add_row("Sanitization Method", result.method.value)
        summary_table.add_row("Shannon Entropy", f"{result.verification.shannon_entropy:.6f} bits/byte")
        summary_table.add_row("Zero-Fill Ratio", f"{result.verification.zero_fill_ratio * 100:.4f}%")
        summary_table.add_row("Duration", f"{result.duration_seconds}s")
        summary_table.add_row("Audit Log SHA-256", result.audit_log_sha256[:32] + "...")

        if result.disclaimer:
            summary_table.add_row("[yellow]Standards Advisory[/yellow]", f"[yellow]{result.disclaimer}[/yellow]")

        console.print(summary_table)

        # Generate signed certificate if requested
        if output_cert and result.success:
            cert_path = Path(output_cert).resolve()
            key_path = cert_path.parent / "station_signing_key.pem"
            if key_path.exists():
                priv = KeyManager.load_private_key(key_path)
            else:
                priv, pub = KeyManager.generate_keypair()
                KeyManager.save_private_key(priv, key_path)
                KeyManager.save_public_key(pub, cert_path.parent / "station_public_key.pem")

            notary = CertificateNotary(private_key=priv)
            cert = notary.issue_certificate(result)

            # Save JSON certificate
            cert_path.write_text(json.dumps(cert, indent=2), encoding="utf-8")
            console.print(f"[bold green] Signed JSON certificate saved to:[/bold green] {cert_path}")

            # Also generate PDF certificate
            pdf_path = cert_path.with_suffix(".pdf")
            pdf_gen = CertificatePdfGenerator()
            pdf_gen.generate_pdf(cert, pdf_path)
            console.print(f"[bold green] Cryptographic PDF certificate saved to:[/bold green] {pdf_path}")

    except WipeProofError as e:
        console.print(f"\n[bold red] OPERATION ABORTED BY SAFETY GATEKEEPER: {e}[/bold red]")
        sys.exit(77)
    except Exception as e:
        console.print(f"\n[bold red] UNEXPECTED SYSTEM ERROR: {e}[/bold red]")
        sys.exit(1)


@cli.command(name="verify")
@click.argument("cert_file", type=click.Path(exists=True))
@click.option("--public-key", type=click.Path(exists=True), help="Optional path to trusted Ed25519 public key PEM.")
@click.option("--revocations", type=click.Path(), help="Optional path to revocation registry JSON.")
def verify_certificate_cli(cert_file: str, public_key: str | None, revocations: str | None):
    """Verify cryptographic authenticity, payload integrity, and revocation of a certificate."""
    try:
        data = json.loads(Path(cert_file).read_text(encoding="utf-8"))
    except Exception as e:
        console.print(f"[bold red]Failed to parse certificate JSON: {e}[/bold red]")
        sys.exit(1)

    reg = RevocationRegistry(Path(revocations)) if revocations else None
    verifier = CertificateVerifier(revocation_registry=reg)

    report = verifier.verify_certificate(certificate=data, trusted_public_key=public_key)

    color = "green" if report.status == VerificationStatus.VALID else ("yellow" if report.status == VerificationStatus.REVOKED else "red")

    table = Table(title="Certificate Verification Outcome", border_style=color)
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="white")

    status_str = f"[bold {color}]{report.status.value}[/bold {color}]"
    table.add_row("Status", status_str)
    table.add_row("Reason", report.reason)
    table.add_row("Certificate ID", report.certificate_id)
    table.add_row("Signing Key ID", report.key_id)
    table.add_row("Device Serial", report.device_serial or "N/A")
    table.add_row("Sanitization Level", report.sanitization_level or "N/A")
    table.add_row("Reported Canonical Hash", report.canonical_payload_sha256)
    table.add_row("Calculated Canonical Hash", report.calculated_payload_sha256 or "N/A")

    console.print(table)

    if report.status != VerificationStatus.VALID:
        sys.exit(1)


if __name__ == "__main__":
    cli()
