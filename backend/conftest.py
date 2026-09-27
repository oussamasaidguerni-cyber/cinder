"""Root conftest: put the backend package on the path so `app` imports work.

Run tests from the backend directory: `python -m pytest`.
"""

import os
import sys
from pathlib import Path

# Tests are in backend/tests; imports like `from app...` resolve from backend.
BACKEND = Path(__file__).resolve().parent
sys.path.insert(0, str(BACKEND))

# Reproducible provider: always start with a clean environment slot for keys.
os.environ.pop("NVIDIA_API_KEY", None)
os.environ.pop("NVIDIA_MODEL", None)
os.environ.pop("GEMINI_API_KEY", None)
os.environ.pop("GEMINI_MODEL", None)