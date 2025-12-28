from __future__ import annotations

from pathlib import Path

from selenium import webdriver
from selenium.webdriver.chrome.options import Options

from django.conf import settings

from business_logic.models import VisionGraph
from .runner import (
    Ti14VisionError,
    html_path,
    find_vision_jpg,
    run_single_game_vision,
)
from .cloudinary_service import upload_private_image, CloudinaryUploadError


class HtmlDownloadError(RuntimeError):
    pass


def download_html_if_needed(match_id: str) -> Path:
    """
    Ensure the DOTABUFF vision html exists under vendor/ti14-vision/data.
    Uses headless selenium to download if missing.
    """
    hp = html_path(match_id)
    hp.parent.mkdir(parents=True, exist_ok=True)

    if hp.exists():
        return hp

    # Headless chrome
    chrome_options = Options()
    chrome_options.add_argument("--headless=new")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    user_agent = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/121.0.6167.140 Safari/537.36"
    )
    chrome_options.add_argument(f"user-agent={user_agent}")

    url = f"https://www.dotabuff.com/matches/{match_id}/vision"

    try:
        driver = webdriver.Chrome(options=chrome_options)
        driver.get(url)
        page = driver.page_source
    except Exception as e:
        raise HtmlDownloadError(f"Failed to download html via selenium for match {match_id}: {e}") from e
    finally:
        try:
            driver.quit()
        except Exception:
            pass

    with open(hp, "w", encoding="utf-8") as f:
        f.write(page)

    return hp


def get_or_create_vision_graph_url(match_id: str, enemy_side: str) -> str:
    """
    Returns Cloudinary URL for the generated vision graph image.
    Cache priority:
      1) DB VisionGraph (uploaded URL)
      2) Local jpg file (vendor/ti14-vision/output)
      3) Generate via script -> upload -> save DB
    """
    if not match_id:
        raise ValueError("match_id is required")
    if enemy_side not in ("Radiant", "Dire"):
        raise ValueError("enemy_side must be 'Radiant' or 'Dire'")

    vision_graph_id = f"enemy_{enemy_side}_{match_id}"

    # 1) DB cache
    obj = VisionGraph.objects.filter(vision_graph_id=vision_graph_id).first()
    if obj:
        return obj.url

    # 2) ensure html exists
    download_html_if_needed(match_id)

    # 3) local jpg cache
    jpg = find_vision_jpg(match_id, enemy_side)
    if not jpg.exists():
        our_side = "Radiant" if enemy_side == "Dire" else "Dire"
        run_single_game_vision(match_id, our_side=our_side)

    if not jpg.exists():
        raise Ti14VisionError(f"vision jpg not generated: {jpg}")

    # 4) upload cloudinary
    url, created_at = upload_private_image(jpg, public_id=vision_graph_id)

    # 5) save DB cache
    VisionGraph.objects.create(
        vision_graph_id=vision_graph_id,
        url=url,
        date_created=created_at,
    )
    return url
