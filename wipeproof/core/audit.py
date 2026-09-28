"""
WipeProof Structured Audit Logger.

Records every command, exit code, monotonic timestamp, and tool execution state.
Computes a SHA-256 integrity hash over the canonical serialized execution trace
to bind the audit log to the cryptographic certificate.
"""

from __future__ import annotations
import hashlib
import json
import time
from datetime import datetime, timezone
from typing import Any, Optional

from wipeproof import __version__
from wipeproof.core.models import AuditEntry


class StructuredAuditLogger:
    """Thread-safe in-memory and on-disk audit logger for sanitization jobs."""

    def __init__(self, job_id: str):
        self.job_id = job_id
        self.entries: list[AuditEntry] = []
        self.metadata: dict[str, Any] = {
            "job_id": job_id,
            "tool_name": "wipeproof",
            "tool_version": __version__,
            "started_at_utc": datetime.now(timezone.utc).isoformat(),
        }

    def log(
        self,
        action: str,
        command: Optional[str] = None,
        exit_code: Optional[int] = None,
        stdout: Optional[str] = None,
        stderr: Optional[str] = None,
        duration_ms: Optional[float] = None,
        notes: Optional[str] = None,
    ) -> None:
        """Record an execution step in the audit log."""
        entry = AuditEntry(
            timestamp_utc=datetime.now(timezone.utc).isoformat(),
            monotonic_ns=time.monotonic_ns(),
            action=action,
            command=command,
            exit_code=exit_code,
            stdout_snippet=stdout[:200] if stdout else None,
            stderr_snippet=stderr[:200] if stderr else None,
            duration_ms=round(duration_ms, 2) if duration_ms is not None else None,
            notes=notes,
        )
        self.entries.append(entry)

    def compute_sha256(self) -> str:
        """Calculate deterministic SHA-256 digest of the entire audit sequence."""
        serialized = self.to_json(compact=True)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "metadata": self.metadata,
            "entries_count": len(self.entries),
            "entries": [e.to_dict() for e in self.entries],
        }

    def to_json(self, compact: bool = False) -> str:
        """Serialize audit log to JSON."""
        data = self.to_dict()
        if compact:
            return json.dumps(data, sort_keys=True, separators=(",", ":"))
        return json.dumps(data, indent=2)

    def write_to_file(self, output_path: str) -> str:
        """Write human-readable JSON audit log to disk and return path."""
        content = self.to_json(compact=False)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(content)
        return output_path
