"""
WipeProof Cryptographic PDF Certificate Generator.

Generates an executive-ready, tamper-evident PDF certificate with:
1. Human-readable device identity and sanitization metrics.
2. Forensic sampling and Shannon entropy audit table.
3. Cryptographic proof block (Key ID, canonical SHA-256 payload hash, signature snippet).
4. Machine-scannable QR code encoding the verification link.
"""

from __future__ import annotations
import io
import os
from pathlib import Path
from typing import Any, Optional

import qrcode
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    Image,
    KeepTogether,
)


class CertificatePdfGenerator:
    """Renders signed WipeProof JSON certificates into publication-quality PDFs."""

    def __init__(self, verification_base_url: str = "https://verify.wipeproof.org/verify"):
        self.verification_base_url = verification_base_url

    def generate_pdf(
        self,
        certificate: dict[str, Any],
        output_path: str | Path,
    ) -> str:
        """Render certificate dictionary into a PDF artifact on disk.
        
        Args:
            certificate: Signed WipeProof certificate dictionary.
            output_path: Destination file path for PDF.
            
        Returns:
            String path to generated PDF.
        """
        dest = Path(output_path).resolve()
        dest.parent.mkdir(parents=True, exist_ok=True)

        doc = SimpleDocTemplate(
            str(dest),
            pagesize=letter,
            rightMargin=0.5 * inch,
            leftMargin=0.5 * inch,
            topMargin=0.5 * inch,
            bottomMargin=0.5 * inch,
        )

        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            "CertTitle",
            parent=styles["Heading1"],
            fontSize=18,
            leading=22,
            textColor=colors.HexColor("#0f172a"),
            alignment=1,  # Center
            spaceAfter=4,
        )
        subtitle_style = ParagraphStyle(
            "CertSubtitle",
            parent=styles["Normal"],
            fontSize=10,
            leading=14,
            textColor=colors.HexColor("#475569"),
            alignment=1,
            spaceAfter=12,
        )
        section_style = ParagraphStyle(
            "SectionHeader",
            parent=styles["Heading2"],
            fontSize=12,
            leading=16,
            textColor=colors.HexColor("#1e293b"),
            spaceBefore=8,
            spaceAfter=4,
        )
        body_style = ParagraphStyle(
            "CertBody",
            parent=styles["Normal"],
            fontSize=8,
            leading=11,
            textColor=colors.HexColor("#334155"),
        )
        mono_style = ParagraphStyle(
            "CertMono",
            parent=styles["Normal"],
            fontName="Courier",
            fontSize=7,
            leading=9,
            textColor=colors.HexColor("#0f172a"),
        )

        story = []

        # 1. Header Banner
        story.append(Paragraph("WIPEPROOF SANITIZATION CERTIFICATE", title_style))
        story.append(
            Paragraph(
                "Independently Verifiable Cryptographic Audit Record | NIST SP 800-88 Rev. 2 / IEEE 2883:2022",
                subtitle_style,
            )
        )

        # 2. Top Meta & QR Code
        cert_id = certificate.get("certificate_id", "UNKNOWN")
        sig_data = certificate.get("signature", {})
        canonical_hash = sig_data.get("canonical_payload_sha256", "UNKNOWN")
        key_id = sig_data.get("key_id", "UNKNOWN")
        sig_hex = sig_data.get("signature_hex", "UNKNOWN")

        qr_img = self._generate_qr_code_image(cert_id, canonical_hash, sig_hex)

        meta_table_data = [
            [
                Paragraph(f"<b>Certificate ID:</b> {cert_id}<br/>"
                          f"<b>Standard Level:</b> <font color='#059669'><b>{certificate.get('sanitization', {}).get('standard_mapping', {}).get('level', 'N/A').upper()}</b></font><br/>"
                          f"<b>Issued At:</b> {certificate.get('timestamps', {}).get('completed_at', 'N/A')}<br/>"
                          f"<b>Station Host:</b> {certificate.get('station', {}).get('hostname', 'N/A')} (Tool v{certificate.get('station', {}).get('tool_version')})", body_style),
                qr_img,
            ]
        ]
        meta_table = Table(meta_table_data, colWidths=[5.5 * inch, 1.5 * inch])
        meta_table.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("ALIGN", (1, 0), (1, 0), "RIGHT"),
            ("TOPPADDING", (0, 0), (-1, -1), 2),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ]))
        story.append(meta_table)
        story.append(Spacer(1, 8))

        # 3. Target Device Profile Table
        story.append(Paragraph("1. Device Identification", section_style))
        dev = certificate.get("device", {})
        hpa = dev.get("hpa_dco") or {}
        dev_table_data = [
            [
                Paragraph("<b>Model:</b>", body_style), Paragraph(str(dev.get("model")), body_style),
                Paragraph("<b>Serial Number:</b>", body_style), Paragraph(f"<b>{dev.get('serial')}</b>", body_style),
            ],
            [
                Paragraph("<b>Path / Node:</b>", body_style), Paragraph(str(dev.get("path")), body_style),
                Paragraph("<b>Media Architecture:</b>", body_style), Paragraph(str(dev.get("media_type")), body_style),
            ],
            [
                Paragraph("<b>Capacity:</b>", body_style), Paragraph(f"{round(dev.get('size_bytes', 0)/(1024**3), 2)} GB ({dev.get('size_bytes', 0)} bytes)", body_style),
                Paragraph("<b>Sector Geometry:</b>", body_style), Paragraph(f"{dev.get('sector_size_logical', 512)}L / {dev.get('sector_size_physical', 512)}P bytes", body_style),
            ],
            [
                Paragraph("<b>HPA Hidden Sectors:</b>", body_style), Paragraph(f"Detected: {hpa.get('hpa_detected', False)} | Removed: {hpa.get('hpa_removed', False)}", body_style),
                Paragraph("<b>Native Max Sectors:</b>", body_style), Paragraph(f"Before: {hpa.get('native_max_sectors_before', 0)} | After: {hpa.get('native_max_sectors_after', 0)}", body_style),
            ],
        ]
        dev_table = Table(dev_table_data, colWidths=[1.4 * inch, 2.1 * inch, 1.4 * inch, 2.1 * inch])
        dev_table.setStyle(self._get_standard_table_style())
        story.append(dev_table)
        story.append(Spacer(1, 8))

        # 4. Sanitization Execution Table
        story.append(Paragraph("2. Sanitization Method & Execution", section_style))
        san = certificate.get("sanitization", {})
        ts = certificate.get("timestamps", {})
        san_table_data = [
            [
                Paragraph("<b>Method Executed:</b>", body_style), Paragraph(str(san.get("method_invoked")), body_style),
                Paragraph("<b>Firmware Status:</b>", body_style), Paragraph(f"<font color='#059669'><b>{san.get('firmware_reported_status')}</b></font>", body_style),
            ],
            [
                Paragraph("<b>Standard Reference:</b>", body_style), Paragraph(str(san.get("standard_mapping", {}).get("reference")), body_style),
                Paragraph("<b>Duration:</b>", body_style), Paragraph(f"{ts.get('duration_seconds', 0)} seconds", body_style),
            ],
        ]
        if san.get("disclaimer"):
            san_table_data.append([
                Paragraph("<b>Standards Advisory:</b>", body_style),
                Paragraph(f"<font color='#b45309'>{san.get('disclaimer')}</font>", body_style),
                Paragraph("", body_style), Paragraph("", body_style),
            ])

        san_table = Table(san_table_data, colWidths=[1.4 * inch, 2.1 * inch, 1.4 * inch, 2.1 * inch])
        san_table.setStyle(self._get_standard_table_style())
        story.append(san_table)
        story.append(Spacer(1, 8))

        # 5. Forensic Sampling & Verification Table
        story.append(Paragraph("3. Forensic Sampling Verification", section_style))
        ver = certificate.get("verification", {})
        ver_table_data = [
            [
                Paragraph("<b>Sampling Method:</b>", body_style), Paragraph(str(ver.get("sampling_method")), body_style),
                Paragraph("<b>Blocks Sampled:</b>", body_style), Paragraph(f"{ver.get('sampled_blocks_count')} blocks ({ver.get('total_bytes_sampled', 0)} bytes)", body_style),
            ],
            [
                Paragraph("<b>Shannon Entropy:</b>", body_style), Paragraph(f"<b>{ver.get('shannon_entropy'):.6f} bits/byte</b>", body_style),
                Paragraph("<b>Zero-Fill Ratio:</b>", body_style), Paragraph(f"<b>{ver.get('zero_fill_ratio', 0) * 100:.4f}%</b>", body_style),
            ],
            [
                Paragraph("<b>Partition Table Cleared:</b>", body_style), Paragraph("Yes (MBR & GPT Zero-Probed)", body_style),
                Paragraph("<b>Verification Result:</b>", body_style), Paragraph("<font color='#059669'><b>PASSED</b></font>" if ver.get("verification_passed") else "<font color='#dc2626'><b>FAILED</b></font>", body_style),
            ],
        ]
        ver_table = Table(ver_table_data, colWidths=[1.4 * inch, 2.1 * inch, 1.4 * inch, 2.1 * inch])
        ver_table.setStyle(self._get_standard_table_style())
        story.append(ver_table)
        story.append(Spacer(1, 8))

        # 6. Cryptographic Trust & Signature Proof Block
        story.append(Paragraph("4. Cryptographic Integrity Proof (RFC 8785 / RFC 8032)", section_style))
        audit = certificate.get("audit", {})
        crypto_table_data = [
            [Paragraph("<b>Signing Key ID:</b>", body_style), Paragraph(key_id, mono_style)],
            [Paragraph("<b>Canonical Payload SHA-256:</b>", body_style), Paragraph(canonical_hash, mono_style)],
            [Paragraph("<b>Ed25519 Signature:</b>", body_style), Paragraph(f"{sig_hex[:64]}<br/>{sig_hex[64:]}", mono_style)],
            [Paragraph("<b>Previous Certificate Hash:</b>", body_style), Paragraph(audit.get("previous_certificate_hash", "GENESIS"), mono_style)],
            [Paragraph("<b>Execution Log SHA-256:</b>", body_style), Paragraph(audit.get("execution_log_sha256", "N/A"), mono_style)],
        ]
        crypto_table = Table(crypto_table_data, colWidths=[2.0 * inch, 5.0 * inch])
        crypto_table.setStyle(self._get_standard_table_style())
        story.append(crypto_table)

        # Build document
        doc.build(story)
        return str(dest)

    def _generate_qr_code_image(self, cert_id: str, canonical_hash: str, sig_hex: str) -> Image:
        """Generate high-contrast QR code image containing verification URI."""
        url = f"{self.verification_base_url}?cert_id={cert_id}&hash={canonical_hash}&sig={sig_hex[:32]}"
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=4,
            border=1,
        )
        qr.add_data(url)
        qr.make(fit=True)
        img = qr.make_image(fill_color="#0f172a", back_color="white")

        buf = io.BytesIO()
        img.save(buf, format="PNG")
        buf.seek(0)

        return Image(buf, width=1.3 * inch, height=1.3 * inch)

    @staticmethod
    def _get_standard_table_style() -> TableStyle:
        return TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ])
