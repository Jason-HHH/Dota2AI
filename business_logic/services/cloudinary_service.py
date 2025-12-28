from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Tuple

import cloudinary
import cloudinary.uploader

from django.conf import settings


class CloudinaryUploadError(RuntimeError):
    pass


def _cloudinary_config_path() -> Path:
    return Path(settings.BASE_DIR) / "cloudinary_config.json"


def _load_cloudinary_config() -> dict:
    cfg_path = _cloudinary_config_path()
    if not cfg_path.exists():
        raise CloudinaryUploadError(f"Cloudinary config not found: {cfg_path}")
    with open(cfg_path, "r", encoding="utf-8") as f:
        return json.load(f)


def upload_private_image(local_file: Path, public_id: str) -> Tuple[str, str]:
    if not local_file.exists():
        raise CloudinaryUploadError(f"Image file not found: {local_file}")

    cfg = _load_cloudinary_config()

    try:
        cloudinary.config(
            cloud_name=cfg["cloud_name"],
            api_key=cfg["api_key"],
            api_secret=cfg["api_secret"],
        )
    except KeyError as e:
        raise CloudinaryUploadError(f"Missing key in cloudinary_config.json: {e}") from e

    timestamp = int(time.time())
    params_to_sign = {"timestamp": timestamp, "public_id": public_id}
    signature = cloudinary.utils.api_sign_request(
        params_to_sign, cloudinary.config().api_secret
    )

    try:
        resp = cloudinary.uploader.upload(
            str(local_file),
            type="private",
            api_key=cloudinary.config().api_key,
            signature=signature,
            timestamp=timestamp,
            public_id=public_id,
        )
        return resp["secure_url"], resp.get("created_at", "")
    except Exception as e:
        raise CloudinaryUploadError(f"Cloudinary upload failed: {e}") from e
