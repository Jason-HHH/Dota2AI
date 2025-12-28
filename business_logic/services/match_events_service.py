from __future__ import annotations

import csv
from typing import List, Dict

from .runner import (
    Ti14VisionError,
    html_path,
    events_csv_path,
    run_single_game_vision,
)
from .vision_graph_service import download_html_if_needed  # reuse the same downloader


def get_match_events(match_id: str, our_side: str = "Dire") -> List[Dict]:
    """
    Ensure events CSV exists (generate if missing), then read it into list[dict].
    """
    if not match_id:
        raise ValueError("match_id is required")

    # 1) make sure html exists (script depends on it)
    download_html_if_needed(match_id)

    # 2) make sure CSV exists
    csv_file = events_csv_path(match_id)
    if not csv_file.exists():
        # run third-party tool to generate csv/jpg
        run_single_game_vision(match_id, our_side=our_side)

    if not csv_file.exists():
        # still missing => tool didn't produce expected file
        raise Ti14VisionError(f"events csv not generated: {csv_file}")

    # 3) read csv
    with open(csv_file, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))
