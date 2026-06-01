"""Create a test ZIP from the sample Mule project for manual testing."""
import os
import zipfile
from pathlib import Path

SAMPLE_DIR = Path(__file__).parent / "sample_mule_project"
OUTPUT_ZIP = Path(__file__).parent / "sample-mule-app.zip"


def create_zip():
    with zipfile.ZipFile(OUTPUT_ZIP, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(SAMPLE_DIR):
            for file in files:
                filepath = Path(root) / file
                arcname = str(filepath.relative_to(SAMPLE_DIR.parent))
                zf.write(filepath, arcname)
    print(f"Created {OUTPUT_ZIP} ({OUTPUT_ZIP.stat().st_size} bytes)")


if __name__ == "__main__":
    create_zip()
