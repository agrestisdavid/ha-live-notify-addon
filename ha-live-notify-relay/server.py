import hashlib
import hmac
import json
import logging
import os
import re
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


def _load_addon_options() -> dict:
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

MAX_DEVICES = 50

GLOBAL_MAX_PUSHES_PER_MINUTE = 100

DEVICES_FILE_PATH = Path("/config/devices.json")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("push-relay")

app = FastAPI(
    title="ha-live-notify Push Relay",
    version="1.0.0",
    docs_url=None,
    redoc_url=None,
)

registered_devices: dict[str, dict] = {}
_active_entities: set[str] = set()
push_timestamps: dict[str, list[float]] = {}
_global_push_timestamps: list[float] = []
_apns_jwt_cache: dict[str, str | float] = {"token": "", "expires": 0}
_apns_key_content: str | None = None
_apns_client: httpx.AsyncClient | None = None
_registration_timestamps: dict[str, list[float]] = {}
MAX_REGISTRATIONS_PER_MINUTE = 10

ENTITY_ID_PATTERN = re.compile(r"^[a-z_]+\.[a-z0-9_]+$")


def _save_devices():
    try:
        DEVICES_FILE_PATH.parent.mkdir(parents=True, exist_ok=True)
        DEVICES_FILE_PATH.write_text(json.dumps(registered_devices, indent=2))
    except Exception:
        log.exception("Failed to save devices to %s", DEVICES_FILE_PATH)


def _load_devices():
    global registered_devices
    if DEVICES_FILE_PATH.exists():
        try:
            registered_devices = json.loads(DEVICES_FILE_PATH.read_text())
            log.info("Loaded %d devices from %s", len(registered_devices), DEVICES_FILE_PATH)
        except Exception:
            log.exception("Failed to load devices from %s", DEVICES_FILE_PATH)
            registered_devices = {}


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
    log.info("Generated new API key → saved to %s (read it there)", API_KEY_PATH)
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


def _check_global_rate_limit() -> bool:
    now = time.time()
    global _global_push_timestamps
    _global_push_timestamps = [t for t in _global_push_timestamps if now - t < 60]

    if len(_global_push_timestamps) >= GLOBAL_MAX_PUSHES_PER_MINUTE:
        return False
    _global_push_timestamps.append(now)
    return True


def _check_registration_rate_limit(client_ip: str) -> bool:
    now = time.time()
    timestamps = _registration_timestamps.get(client_ip, [])
    timestamps = [t for t in timestamps if now - t < 60]
    _registration_timestamps[client_ip] = timestamps

    if len(timestamps) >= MAX_REGISTRATIONS_PER_MINUTE:
        return False
    timestamps.append(now)
    return True


def _validate_entity_id(entity_id: str) -> bool:
    return bool(ENTITY_ID_PATTERN.match(entity_id))


def _load_apns_key() -> str:
    global _apns_key_content
    if _apns_key_content is not None:
        return _apns_key_content
    key_path = Path(APNS_KEY_PATH)
    if not key_path.exists():
        raise RuntimeError(f"APNs key not found: {APNS_KEY_PATH}")
    _apns_key_content = key_path.read_text()
    return _apns_key_content


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

    client = _apns_client
    if client is None:
        return False, "APNs client not initialized"

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
                    _save_devices()
                    log.info("Removed expired device: %s", device_id)
            return False, "Token expired - device removed"

        return False, f"APNs error {resp.status_code}: {error_body}"

    except httpx.TimeoutException:
        return False, "APNs request timed out"
    except Exception as e:
        log.exception("APNs request failed")
        return False, str(e)


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


@app.on_event("startup")
async def startup():
    global _apns_client
    _load_or_generate_api_key()
    _load_devices()
    try:
        _load_apns_key()
        log.info("APNs key loaded OK")
    except RuntimeError as e:
        log.warning("APNs key missing: %s", e)
    _apns_client = httpx.AsyncClient(http2=True)
    log.info("Push Relay started (sandbox=%s, port=8765)", APNS_USE_SANDBOX)


@app.on_event("shutdown")
async def shutdown():
    global _apns_client
    if _apns_client:
        await _apns_client.aclose()
        _apns_client = None
    log.info("Push Relay shut down")


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.post("/register", dependencies=[Depends(verify_api_key)])
async def register_device(req: RegisterRequest, request: Request):
    if not req.device_id or not req.push_token:
        raise HTTPException(status_code=400, detail="device_id and push_token required")
    if not req.entity_ids:
        raise HTTPException(status_code=400, detail="At least one entity_id required")

    for eid in req.entity_ids:
        if not _validate_entity_id(eid):
            raise HTTPException(status_code=400, detail=f"Invalid entity_id format: {eid}")

    client_ip = request.client.host if request.client else "unknown"
    if not _check_registration_rate_limit(client_ip):
        raise HTTPException(status_code=429, detail="Too many registrations, try again later")

    if req.device_id not in registered_devices and len(registered_devices) >= MAX_DEVICES:
        raise HTTPException(status_code=429, detail=f"Maximum device limit ({MAX_DEVICES}) reached")

    clean_token = req.push_token.strip().replace(" ", "").replace("<", "").replace(">", "")
    if not all(c in "0123456789abcdefABCDEF" for c in clean_token):
        raise HTTPException(status_code=400, detail="Invalid push token format")

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

    _save_devices()

    log.info("Registered device %s for %s", req.device_id[:8], req.entity_ids)
    return {"status": "registered", "device_id": req.device_id}


@app.post("/unregister", dependencies=[Depends(verify_api_key)])
async def unregister_device(device_id: str):
    if device_id in registered_devices:
        del registered_devices[device_id]
        _save_devices()
        return {"status": "unregistered"}
    raise HTTPException(status_code=404, detail="Device not found")


@app.post("/update", dependencies=[Depends(verify_api_key)])
async def update_activity(req: UpdateRequest):
    if not _validate_entity_id(req.entity_id):
        raise HTTPException(status_code=400, detail=f"Invalid entity_id format: {req.entity_id}")

    targets = _find_devices_for_entity(req.entity_id)
    if not targets:
        return {"status": "no_targets", "message": "No devices registered for this entity"}

    is_new_start = req.state == "active" and req.entity_id not in _active_entities
    is_resume = req.state == "active" and req.entity_id in _active_entities
    is_end = req.state in ("finished", "idle")

    if req.state == "active":
        _active_entities.add(req.entity_id)
    elif is_end:
        _active_entities.discard(req.entity_id)

    APPLE_REFERENCE_OFFSET = 978307200

    content_state: dict = {"state": "finished" if req.state == "idle" else req.state}

    end_time_apple: float | None = None
    if req.end_time:
        try:
            from datetime import datetime as dt
            end_dt = dt.fromisoformat(req.end_time)
            unix_ts = end_dt.timestamp()
            end_time_apple = unix_ts - APPLE_REFERENCE_OFFSET
        except (ValueError, TypeError):
            log.warning("Could not parse end_time: %s", req.end_time)

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
        now_apple = time.time() - APPLE_REFERENCE_OFFSET
        content_state["endTime"] = now_apple
        content_state["totalDuration"] = total_duration_secs if total_duration_secs is not None else 0.0
        content_state["progress"] = 1.0
    else:
        if end_time_apple is not None:
            content_state["endTime"] = end_time_apple
        if total_duration_secs is not None:
            content_state["totalDuration"] = total_duration_secs

    if is_new_start:
        entity_config = _get_entity_config(req.entity_id)
        icon_name = entity_config.get("icon_name", "timer") if entity_config else "timer"
        color_hex = entity_config.get("color_hex", "#FF8C00") if entity_config else "#FF8C00"
        invert_progress = entity_config.get("invert_progress", False) if entity_config else False
        device_name = req.device_name or req.entity_id

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
        log.info("New activity START for %s", req.entity_id)
    elif is_resume:
        payload = {
            "aps": {
                "timestamp": int(time.time()),
                "event": "update",
                "content-state": content_state,
            },
        }
        log.info("Resume UPDATE for %s", req.entity_id)
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

        if not _check_global_rate_limit():
            results.append({"device_id": device_id, "success": False, "error": "global_rate_limited"})
            continue

        log.debug("Sending payload: %s", json.dumps(payload, indent=2))
        success, msg = await _send_apns_push(push_token, payload)
        log.info("Push %s → entity=%s device=%s", "OK" if success else "FAIL", req.entity_id, device_id[:8])
        results.append({"device_id": device_id, "success": success, "message": msg})

    return {"status": "sent", "results": results}


def _find_devices_for_entity(entity_id: str) -> list[tuple[str, dict]]:
    return [
        (device_id, device)
        for device_id, device in registered_devices.items()
        if entity_id in device["entity_ids"]
    ]


def _get_entity_config(entity_id: str) -> dict | None:
    for device in registered_devices.values():
        configs = device.get("entity_configs", {})
        if entity_id in configs:
            return configs[entity_id]
    return None


@app.exception_handler(Exception)
async def generic_error_handler(request: Request, exc: Exception):
    log.exception("Unhandled error: %s", exc)
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8765, log_level="info", access_log=False)
