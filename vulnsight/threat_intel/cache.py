import json
from datetime import datetime, timezone
from pathlib import Path

# Cache directory and files
CACHE_DIR = Path("cache")
CACHE_DIR.mkdir(exist_ok=True)

KEV_CACHE = CACHE_DIR / "kev.json"
NVD_CACHE = CACHE_DIR / "nvd_cache.json"
EPSS_CACHE = CACHE_DIR / "epss_cache.json"

# Cache TTLs (in seconds)
TTL_KEV_SECONDS = 24 * 3600      # 24 hours
TTL_EPSS_SECONDS = 24 * 3600     # 24 hours
TTL_NVD_SECONDS = 12 * 3600      # 12 hours



# JSON helpers

def load_json(path: Path):
    if path.exists():
        try:
            return json.loads(path.read_text())
        except Exception:
            return {}
    return {}


def save_json(path: Path, data):
    try:
        path.write_text(json.dumps(data, indent=2))
    except Exception:
        pass

# Cache helpers

def _now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _is_expired(timestamp_str: str, ttl_seconds: int) -> bool:
    try:
        ts = datetime.fromisoformat(timestamp_str)
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
    except Exception:
        return True

    age = datetime.now(timezone.utc) - ts
    return age.total_seconds() > ttl_seconds


def load_cache(path: Path, ttl_seconds: int | None = None):
    raw = load_json(path)
    if not raw:
        return None

    if isinstance(raw, dict) and "timestamp" in raw and "data" in raw:
        if ttl_seconds is None:
            return raw["data"]

        ts = raw.get("timestamp")
        if ts is None or _is_expired(ts, ttl_seconds):
            return None

        return raw["data"]

    return raw


def save_cache(path: Path, data):
    payload = {
        "timestamp": _now_utc_iso(),
        "data": data,
    }
    save_json(path, payload)
