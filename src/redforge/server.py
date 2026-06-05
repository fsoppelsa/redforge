"""Launch the Streamlit dashboard for RedForge."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def serve(
    config_path: str = "redforge.toml",
    host: str = "127.0.0.1",
    port: int = 8501,
) -> None:
    """Run the Streamlit process pointing to app.py."""
    root_dir = str(Path(__file__).parents[2])   # project root
    app      = Path(root_dir) / "app.py"
    src_dir  = str(Path(__file__).parents[1])   # .../src  (redforge package)

    env = os.environ.copy()
    env["REDFORGE_CONFIG"] = str(Path(config_path).resolve())
    existing = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = f"{src_dir}{os.pathsep}{root_dir}" + (
        f"{os.pathsep}{existing}" if existing else ""
    )

    subprocess.run(
        [
            sys.executable, "-m", "streamlit", "run", str(app),
            "--server.address", host,
            "--server.port", str(port),
            "--server.headless", "true",
        ],
        env=env,
    )
