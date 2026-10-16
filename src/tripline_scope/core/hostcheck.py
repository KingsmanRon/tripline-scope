"""Host checks reported by ``tscope doctor`` and before data-processing commands. Read-only, no network."""

from __future__ import annotations

import os
from pathlib import Path


def active_swap() -> list[str]:
    try:
        lines = Path("/proc/swaps").read_text().splitlines()[1:]
    except OSError:
        return []
    return [ln.split()[0] for ln in lines if ln.strip()]


def warnings(home) -> list[str]:
    out = []
    swaps = active_swap()
    if swaps and not home.config.get("swap_encrypted_attested"):
        out.append(
            f"{len(swaps)} swap device(s) active and not attested as encrypted: working data in RAM could be paged "
            "to disk in plaintext. Disable swap or use encrypted swap, then set swap_encrypted_attested: true."
        )
    d = home.config.get("duckdb") or {}
    if d.get("spill_dir") and not d.get("spill_dir_encrypted"):
        out.append("duckdb.spill_dir is set but not attested as an encrypted volume; spilling is disabled.")
    kek = Path(home.config["kek_path"])
    try:
        if kek.exists() and kek.stat().st_mode & 0o077:
            out.append("KEK file is readable by group/other; restrict it to the service account (chmod 600).")
    except OSError:
        pass
    if os.environ.get("TSCOPE_KEK_PASSPHRASE"):
        out.append("KEK passphrase supplied via environment (acceptable for drills and demos only).")
    return out
