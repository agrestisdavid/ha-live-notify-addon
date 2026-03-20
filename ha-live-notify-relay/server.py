"""
ha-live-notify Push Relay Server (HA Add-on)
Receives timer updates from Home Assistant and pushes them to iOS Live Activities via APNs.
"""

import hashlib
import hmac
import json
import logging
import os
import secrets
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx
import jwt
import uvicorn
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

# --- Configuration (read from HA Add-on options.json or env) ---

def _load_addon_options() -> dict:
    """Load options from HA Add-on options.json if available."""
    options_path = Path("/data/options.json")
    if options_path.exists():
        return json.loads(options_path.read_text())
    return {}

_opts = _load_addon_options()

APNS_KEY_PATH = os.getenv("APNS_KEY_PATH", "/config/AuthKey.p8")
APNS_KEY_ID = _opts.get("apns_key_id") or os.getenv("APNS_KEY_ID", "")
APNS_TEAM_ID = _opts.get("apns_team_id") or os.getenv("APNS_TEAM_ID", "")
APNS_BUNDLE_ID = _opts.get("apns_bundle_id") or os.getenv("APNS_BUNDLE_ID", "ios.ha-live-notify")
APNS_USE_SANDBOX = _opts.get("apns_use_sandbox", True) if "apns_use_sandbox" in _opts else os.getenv("APNS_USE_SANDBOX", "true").lower() == "true"

API_KEY_PATH = os.getenv("API_KEY_PATH", "/config/api_key.txt")
API_KEY = os.getenv("API_KEY", "")

MAX_PUSHES_PER_MINUTE = _opts.get("max_pushes_per_minute") or int(os.getenv("MAX_PUSHES_PER_MINUTE", "30"))

# --- Logging ---

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("push-relay")

# --- App ---

app = FastAPI(
    title="ha-live-notify Push Relay",
    version="1.0.0",
    docs_url=None,
    redoc_url=None,
)

# --- State ---

registered_devices: dict[str, dict] = {}
push_timestamps: dict[str, list[float]] = {}
_apns_jwt_cache: dict[str, str | float] = {"token": "", "expires": 0}


# --- Security ---


def _load_or_generate_api_key() -> str:
    global API_KEY

    if API_KEY:
        return API_KEY

    key_path = Path(API_KEY_PATH)
    if key_path.exists():
        API_KEY = key_path.read_text().strip()
        log.info("Loaded API key from %s", API_KEY_PATH)
        return API_KEY

    API_KEY = secrets.token_urlsafe(32)
    key_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.write_text(API_KEY)
    key_path.chmod(0o600)
    log.info("Generated new API key → %s", API_KEY_PATH)
    log.info("=" * 60)
    log.info("API KEY: %s", API_KEY)
    log.info("Copy this key to the iOS app settings!")
    log.info("=" * 60)
    return API_KEY


def _constant_time_compare(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


async def verify_api_key(authorization: str = Header(None)):
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization header")

    parts = authorization.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(status_code=401, detail="Invalid Authorization format")

    if not _constant_time_compare(parts[1], API_KEY):
        raise HTTPException(status_code=403, detail="Invalid API key")


def _check_rate_limit(push_token: str) -> bool:
    now = time.time()
    timestamps = push_timestamps.get(push_token, [])
    timestamps = [t for t in timestamps if now - t < 60]
    push_timestamps[push_token] = timestamps

    if len(timestamps) >= MAX_PUSHES_PER_MINUTE:
        return False
    timestamps.append(now)
    return True


# --- APNs ---


def _load_apns_key() -> str:
    key_path = Path(APNS_KEY_PATH)
    if not key_path.exists():
        raise RuntimeError(f"APNs key not found: {APNS_KEY_PATH}")
    return key_path.read_text()


def _get_apns_jwt() -> str:
    now = time.time()
    if _apns_jwt_cache["token"] and _apns_jwt_cache["expires"] > now:
        return _apns_jwt_cache["token"]

    private_key = _load_apns_key()
    payload = {"iss": APNS_TEAM_ID, "iat": int(now)}
    token = jwt.encode(payload, private_key, algorithm="ES256", headers={"kid": APNS_KEY_ID})

    _apns_jwt_cache["token"] = token
    _apns_jwt_cache["expires"] = now + 3000
    log.info("Generated new APNs JWT (expires in 50 min)")
    return token


def _apns_host() -> str:
    if APNS_USE_SANDBOX:
        return "https://api.sandbox.push.apple.com"
    return "https://api.push.apple.com"


async def _send_apns_push(push_token: str, payload: dict) -> tuple[bool, str]:
    url = f"{_apns_host()}/3/device/{push_token}"

    headers = {
        "authorization": f"bearer {_get_apns_jwt()}",
        "apns-topic": f"{APNS_BUNDLE_ID}.push-type.liveactivity",
        "apns-push-type": "liveactivity",
        "apns-priority": "10",
    }

    body = json.dumps(payload, separators=(",", ":"))

    if len(body.encode()) > 4096:
        return False, "Payload exceeds 4KB APNs limit"

    async with httpx.AsyncClient(http2=True) as client:
        try:
            resp = await client.post(url, content=body, headers=headers, timeout=10)

            if resp.status_code == 200:
                log.info("APNs push OK → %s...%s", push_token[:8], push_token[-4:])
                return True, "ok"

            error_body = resp.text
            log.error("APNs error %d: %s", resp.status_code, error_body)

            if resp.status_code == 410:
                for device_id, device in list(registered_devices.items()):
                    if device["push_token"] == push_token:
                        del registered_devices[device_id]
                        log.info("Removed expired device: %s", device_id)
                return False, "Token expired - device removed"

            return False, f"APNs error {resp.status_code}: {error_body}"

        except httpx.TimeoutException:
            return False, "APNs request timed out"
        except Exception as e:
            log.exception("APNs request failed")
            return False, str(e)


# --- Models ---


class EntityConfig(BaseModel):
    entity_id: str
    icon_name: str = "timer"
    color_hex: str = "#FF8C00"
    invert_progress: bool = False


class RegisterRequest(BaseModel):
    device_id: str
    push_token: str
    entity_ids: list[str]
    entity_configs: list[EntityConfig] | None = None


class UpdateRequest(BaseModel):
    entity_id: str
    state: str
    end_time: str | None = None
    total_duration: str | float | None = None
    device_name: str | None = None
    icon_name: str | None = None
    accent_color_hex: str | None = None
    invert_progress: bool = False


# --- Endpoints ---


@app.on_event("startup")
async def startup():
    _load_or_generate_api_key()
    try:
        _load_apns_key()
        log.info("APNs key loaded OK")
    except RuntimeError as e:
        log.warning("APNs key missing: %s", e)
    log.info("Push Relay started (sandbox=%s, port=8765)", APNS_USE_SANDBOX)


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "registered_devices": len(registered_devices),
        "apns_sandbox": APNS_USE_SANDBOX,
    }


@app.post("/register", dependencies=[Depends(verify_api_key)])
async def register_device(req: RegisterRequest):
    if not req.device_id or not req.push_token:
        raise HTTPException(status_code=400, detail="device_id and push_token required")
    if not req.entity_ids:
        raise HTTPException(status_code=400, detail="At least one entity_id required")

    clean_token = req.push_token.strip().replace(" ", "").replace("<", "").replace(">", "")
    if not all(c in "0123456789abcdefABCDEF" for c in clean_token):
        raise HTTPException(status_code=400, detail="Invalid push token format")

    # Build entity config lookup
    configs = {}
    if req.entity_configs:
        for ec in req.entity_configs:
            configs[ec.entity_id] = {
                "icon_name": ec.icon_name,
                "color_hex": ec.color_hex,
                "invert_progress": ec.invert_progress,
            }

    registered_devices[req.device_id] = {
        "push_token": clean_token,
        "entity_ids": req.entity_ids,
        "entity_configs": configs,
        "registered_at": datetime.now(timezone.utc).isoformat(),
    }

    log.info("Registered device %s for %s", req.device_id[:8], req.entity_ids)
    return {"status": "registered", "device_id": req.device_id}


@app.post("/unregister", dependencies=[Depends(verify_api_key)])
async def unregister_device(device_id: str):
    if device_id in registered_devices:
        del registered_devices[device_id]
        return {"status": "unregistered"}
    raise HTTPException(status_code=404, detail="Device not found")


@app.post("/update", dependencies=[Depends(verify_api_key)])
async def update_activity(req: UpdateRequest):
    targets = _find_devices_for_entity(req.entity_id)
    if not targets:
        return {"status": "no_targets", "message": "No devices registered for this entity"}

    is_start = req.state == "active"
    is_end = req.state in ("finished", "idle")

    APPLE_REFERENCE_OFFSET = 978307200  # seconds between 1970-01-01 and 2001-01-01

    content_state: dict = {"state": "finished" if req.state == "idle" else req.state}

    # Parse end_time (ISO8601 -> Apple reference date for Swift Codable)
    end_time_apple: float | None = None
    if req.end_time:
        try:
            from datetime import datetime as dt
            end_dt = dt.fromisoformat(req.end_time)
            unix_ts = end_dt.timestamp()
            end_time_apple = unix_ts - APPLE_REFERENCE_OFFSET
        except (ValueError, TypeError):
            log.warning("Could not parse end_time: %s", req.end_time)

    # Parse total_duration (H:MM:SS string or numeric seconds)
    total_duration_secs: float | None = None
    if req.total_duration is not None:
        if isinstance(req.total_duration, str):
            parts = str(req.total_duration).split(":")
            if len(parts) == 3:
                total_duration_secs = int(parts[0]) * 3600 + int(parts[1]) * 60 + int(parts[2])
            else:
                try:
                    total_duration_secs = float(req.total_duration)
                except ValueError:
                    log.warning("Could not parse total_duration: %s", req.total_duration)
        else:
            total_duration_secs = float(req.total_duration)

    if is_end:
        # For end events: endTime = now, totalDuration = 0 (timer is done)
        now_apple = time.time() - APPLE_REFERENCE_OFFSET
        content_state["endTime"] = now_apple
        content_state["totalDuration"] = total_duration_secs if total_duration_secs is not None else 0.0
        content_state["progress"] = 1.0
    else:
        # For active/paused: use provided values
        if end_time_apple is not None:
            content_state["endTime"] = end_time_apple
        if total_duration_secs is not None:
            content_state["totalDuration"] = total_duration_secs

    if is_start:
        # Look up entity config from registered device
        entity_config = _get_entity_config(req.entity_id)
        icon_name = entity_config.get("icon_name", "timer") if entity_config else "timer"
        color_hex = entity_config.get("color_hex", "#FF8C00") if entity_config else "#FF8C00"
        invert_progress = entity_config.get("invert_progress", False) if entity_config else False
        device_name = req.device_name or req.entity_id

        # Start a NEW Live Activity via push
        payload = {
            "aps": {
                "timestamp": int(time.time()),
                "event": "start",
                "content-state": content_state,
                "attributes-type": "TimerActivityAttributes",
                "attributes": {
                    "entityID": req.entity_id,
                    "deviceName": device_name,
                    "iconName": icon_name,
                    "accentColorHex": color_hex,
                    "invertProgress": invert_progress,
                },
                "alert": {
                    "title": device_name,
                    "body": "Timer gestartet",
                },
            },
        }
    elif is_end:
        payload = {
            "aps": {
                "timestamp": int(time.time()),
                "event": "end",
                "content-state": content_state,
                "dismissal-date": int(time.time()) + 10,
            },
        }
    else:
        # Pause or other update
        payload = {
            "aps": {
                "timestamp": int(time.time()),
                "event": "update",
                "content-state": content_state,
            },
        }

    results = []
    for device_id, device in targets:
        push_token = device["push_token"]

        if not _check_rate_limit(push_token):
            results.append({"device_id": device_id, "success": False, "error": "rate_limited"})
            continue

        log.info("Sending payload: %s", json.dumps(payload, indent=2))
        success, msg = await _send_apns_push(push_token, payload)
        results.append({"device_id": device_id, "success": success, "message": msg})

    return {"status": "sent", "results": results}


def _find_devices_for_entity(entity_id: str) -> list[tuple[str, dict]]:
    return [
        (device_id, device)
        for device_id, device in registered_devices.items()
        if entity_id in device["entity_ids"]
    ]


def _get_entity_config(entity_id: str) -> dict | None:
    """Look up entity config (icon, color, invertProgress) from any registered device."""
    for device in registered_devices.values():
        configs = device.get("entity_configs", {})
        if entity_id in configs:
            return configs[entity_id]
    return None


@app.exception_handler(Exception)
async def generic_error_handler(request: Request, exc: Exception):
    log.exception("Unhandled error: %s", exc)
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


# --- Run directly (for HA Add-on) ---

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8765, log_level="info", access_log=False)
