from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from django.conf import settings


class Ti14VisionError(RuntimeError):
    pass


def ti14_dir() -> Path:
    return Path(settings.BASE_DIR) / "vendor" / "ti14-vision"


def html_dir() -> Path:
    return ti14_dir() / "data"


def output_dir() -> Path:
    out = ti14_dir() / "output"
    out.mkdir(parents=True, exist_ok=True)
    return out


def script_path() -> Path:
    return ti14_dir() / "single_game_vision.py"


def html_path(match_id: str) -> Path:
    return html_dir() / f"Match {match_id} - Vision - DOTABUFF - Dota 2 Stats.html"


def events_csv_path(match_id: str) -> Path:
    return output_dir() / f"events_{match_id}.csv"


def normalize_side(side: str) -> str:
    s = (side or "").strip().lower()
    if s in ("dire", "d"):
        return "Dire"
    if s in ("radiant", "r"):
        return "Radiant"
    raise Ti14VisionError(f"Invalid side: {side!r}. Expected Dire/Radiant.")


def find_vision_jpg(match_id: str, enemy_side: str) -> Path:
    """
    Find the generated vision jpg for this match.
    Prefers the one matching enemy_side (Dire/Radiant).
    Falls back to any jpg containing match_id.
    """
    side = normalize_side(enemy_side)

    # First try: match both match_id and side (case-insensitive)
    side_key = side.lower()
    candidates = sorted(
        output_dir().glob(f"*{match_id}*.jpg"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )

    if not candidates:
        raise Ti14VisionError(f"No vision jpg found for match_id={match_id} in {output_dir()}")

    for p in candidates:
        if side_key in p.name.lower():
            return p

    # fallback: just return newest jpg for that match
    return candidates[0]



def vision_python() -> str:
    p = os.environ.get("VISION_PY") or getattr(settings, "VISION_PY", None) or sys.executable
    return str(p)


def _build_vision_env(py: str) -> dict:
    """
    Make subprocess env behave like 'conda activate visionenv' by ensuring
    the visionenv DLL directories are first in PATH.
    This prevents Windows native crash (0xC06D007F) when importing numpy/cv2.
    """
    env = os.environ.copy()

    # Infer env prefix from python.exe path: ...\envs\visionenv\python.exe
    py_path = Path(py)
    prefix = py_path.parent  # env root (contains python.exe, DLLs, Lib, Scripts)
    # If python.exe is in prefix, prefix is correct
    if not (prefix / "python.exe").exists():
        # fallback: use parent if someone passes ...\Scripts\python.exe style
        prefix = py_path.parent.parent

    candidates = [
        str(prefix),  # D:\anaconda3\envs\visionenv
        str(prefix / "Library" / "bin"),
        str(prefix / "Scripts"),
        str(prefix / "DLLs"),
    ]

    # Prepend (keep only existing dirs)
    prepend = [p for p in candidates if Path(p).exists()]
    env["PATH"] = os.pathsep.join(prepend) + os.pathsep + env.get("PATH", "")

    # Optional: these sometimes help some native libs behave correctly
    env["CONDA_PREFIX"] = str(prefix)
    env["PYTHONNOUSERSITE"] = "1"  # avoid user-site pollution

    return env


def run_single_game_vision(
    match_id: str,
    our_side: str = "Dire",
    timeout_sec: int = 180,
) -> str:
    sp = script_path()
    if not sp.exists():
        raise Ti14VisionError(f"single_game_vision.py not found at: {sp}")

    py = vision_python()
    env = _build_vision_env(py)

    cmd = [
        py,
        "-X", "faulthandler",  # helps when crashes happen
        str(sp),
        "--game_id", str(match_id),
        "--our_side", str(our_side),
    ]

    try:
        res = subprocess.run(
            cmd,
            cwd=str(ti14_dir()),
            env=env,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout_sec,
        )

        csv_ok = events_csv_path(match_id).exists()
        jpg_ok = any(output_dir().glob(f"*{match_id}*.jpg"))

        if not (csv_ok or jpg_ok):
            stderr = (res.stderr or "").strip()
            stdout = (res.stdout or "").strip()
            raise Ti14VisionError(
                f"ti14-vision did not produce outputs (returncode={res.returncode}).\n"
                f"CMD: {' '.join(cmd)}\n"
                f"STDOUT:\n{stdout}\n"
                f"STDERR:\n{stderr}"
            )

        return res.stdout or ""

    except subprocess.TimeoutExpired as e:
        raise Ti14VisionError(f"ti14-vision script timed out after {timeout_sec}s") from e
