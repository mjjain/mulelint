from __future__ import annotations

import os
import shutil
import tempfile
import zipfile
from pathlib import Path

MAX_UPLOAD_SIZE = 50 * 1024 * 1024  # 50 MB
ALLOWED_EXTENSIONS = {".zip", ".jar"}


class ExtractionError(Exception):
    pass


def validate_upload(filename: str, size: int) -> None:
    ext = Path(filename).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise ExtractionError(
            f"Unsupported file type '{ext}'. Please upload a .zip or .jar file."
        )
    if size > MAX_UPLOAD_SIZE:
        raise ExtractionError(
            f"File size ({size / 1024 / 1024:.1f} MB) exceeds the "
            f"{MAX_UPLOAD_SIZE / 1024 / 1024:.0f} MB limit."
        )


def extract_zip(zip_path: str, dest_dir: str) -> str:
    """Extract a ZIP/JAR and return the path to the Mule project root.

    Handles the common case where the ZIP contains a single top-level
    directory wrapping the actual project.
    """
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            # Safety: reject path traversal entries
            for entry in zf.namelist():
                if entry.startswith("/") or ".." in entry:
                    raise ExtractionError(
                        "ZIP contains unsafe path entries (absolute or traversal)."
                    )
            zf.extractall(dest_dir)
    except zipfile.BadZipFile:
        raise ExtractionError("The uploaded file is not a valid ZIP archive.")

    return _find_project_root(dest_dir)


def _find_project_root(dest_dir: str) -> str:
    """Walk the extraction directory to locate the Mule project root.

    Heuristic: look for pom.xml or mule-artifact.json as markers.
    If the ZIP wraps everything in one subdirectory, descend into it.
    """
    dest = Path(dest_dir)

    # Skip __MACOSX and hidden directories
    children = [
        c for c in dest.iterdir()
        if c.is_dir() and not c.name.startswith((".", "__"))
    ]

    # If extraction produced a single wrapper directory, descend
    if len(children) == 1 and children[0].is_dir():
        candidate = children[0]
        if _is_mule_project(candidate):
            return str(candidate)
        # Try one more level
        inner = [
            c for c in candidate.iterdir()
            if c.is_dir() and not c.name.startswith((".", "__"))
        ]
        if len(inner) == 1 and _is_mule_project(inner[0]):
            return str(inner[0])
        return str(candidate)

    if _is_mule_project(dest):
        return str(dest)

    raise ExtractionError(
        "Could not detect a Mule project in the uploaded archive. "
        "Ensure it contains a pom.xml or mule-artifact.json."
    )


def _is_mule_project(path: Path) -> bool:
    return (path / "pom.xml").exists() or (path / "mule-artifact.json").exists()


def create_temp_dir() -> str:
    return tempfile.mkdtemp(prefix="mule_compliance_")


def cleanup_temp_dir(path: str) -> None:
    if os.path.isdir(path):
        shutil.rmtree(path, ignore_errors=True)
