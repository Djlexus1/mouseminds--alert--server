#!/usr/bin/env python3
"""
MouseMinds remote wait alert server with APNs support.

This service:
- accepts device registration from the app
- accepts synced wait-alert thresholds
- polls Queue-Times on an interval
- sends real APNs pushes when a ride drops below the saved threshold

Required environment variables:
- APPLE_TEAM_ID
- APPLE_KEY_ID
- APPLE_AUTH_KEY_PATH
- APPLE_BUNDLE_ID

Optional environment variables:
- APNS_USE_SANDBOX=1
- HOST=0.0.0.0
- PORT=8787
- POLL_SECONDS=120

This script uses:
- `openssl` to sign the APNs JWT
- `curl --http2` to call the APNs API
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import threading
import time
import tempfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, List, Optional
from urllib.error import URLError
from urllib.request import urlopen


POLL_SECONDS = int(os.environ.get("POLL_SECONDS", "120"))
HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "8787"))

APPLE_TEAM_ID = os.environ.get("APPLE_TEAM_ID", "").strip()
APPLE_KEY_ID = os.environ.get("APPLE_KEY_ID", "").strip()
APPLE_AUTH_KEY_PATH = os.environ.get("APPLE_AUTH_KEY_PATH", "").strip()
APPLE_AUTH_KEY_P8 = os.environ.get("APPLE_AUTH_KEY_P8", "")
APPLE_BUNDLE_ID = os.environ.get("APPLE_BUNDLE_ID", "").strip()
APNS_USE_SANDBOX = os.environ.get("APNS_USE_SANDBOX", "").strip() == "1"

APNS_HOST = "api.sandbox.push.apple.com" if APNS_USE_SANDBOX else "api.push.apple.com"
APNS_PORT = 443
APNS_TOKEN_TTL_SECONDS = 50 * 60


@dataclass
class DeviceRecord:
    user_id: str
    device_token: str
    platform: str
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class AlertRecord:
    park_id: int
    ride_id: int
    ride_name: str
    threshold_minutes: int
    created_at: str
    is_enabled: bool
    expires_at: str

    def is_expired(self) -> bool:
        try:
            expiry = datetime.fromisoformat(self.expires_at.replace("Z", "+00:00"))
        except ValueError:
            return False
        return expiry <= datetime.now(timezone.utc)


DEVICES_BY_USER: Dict[str, DeviceRecord] = {}
ALERTS_BY_USER: Dict[str, List[AlertRecord]] = {}

_cached_apns_token: Optional[str] = None
_cached_apns_token_generated_at: float = 0
_generated_auth_key_path: Optional[str] = None


def base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def parse_der_length(der: bytes, index: int) -> tuple[int, int]:
    length = der[index]
    index += 1
    if length & 0x80 == 0:
        return length, index
    byte_count = length & 0x7F
    value = int.from_bytes(der[index:index + byte_count], "big")
    return value, index + byte_count


def der_signature_to_raw(der: bytes, part_size: int = 32) -> bytes:
    if not der or der[0] != 0x30:
        raise ValueError("Invalid DER signature")
    _, index = parse_der_length(der, 1)

    if der[index] != 0x02:
        raise ValueError("Invalid DER signature")
    r_length, index = parse_der_length(der, index + 1)
    r_bytes = der[index:index + r_length]
    index += r_length

    if der[index] != 0x02:
        raise ValueError("Invalid DER signature")
    s_length, index = parse_der_length(der, index + 1)
    s_bytes = der[index:index + s_length]

    r_bytes = r_bytes[-part_size:].rjust(part_size, b"\x00")
    s_bytes = s_bytes[-part_size:].rjust(part_size, b"\x00")
    return r_bytes + s_bytes


def sign_with_openssl(message: bytes, key_path: str) -> bytes:
    process = subprocess.run(
        ["openssl", "dgst", "-sha256", "-sign", key_path],
        input=message,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if process.returncode != 0:
        raise RuntimeError(process.stderr.decode("utf-8").strip() or "openssl signing failed")
    return process.stdout


def resolve_auth_key_path() -> str:
    global _generated_auth_key_path

    if APPLE_AUTH_KEY_PATH:
        return APPLE_AUTH_KEY_PATH

    if not APPLE_AUTH_KEY_P8.strip():
        raise RuntimeError("Neither APPLE_AUTH_KEY_PATH nor APPLE_AUTH_KEY_P8 is set")

    if _generated_auth_key_path:
        return _generated_auth_key_path

    key_material = APPLE_AUTH_KEY_P8.strip()
    if "\\n" in key_material:
        key_material = key_material.replace("\\n", "\n")
    if not key_material.endswith("\n"):
        key_material += "\n"

    temp_file = tempfile.NamedTemporaryFile(prefix="mouseminds_apns_", suffix=".p8", delete=False)
    temp_file.write(key_material.encode("utf-8"))
    temp_file.flush()
    temp_file.close()
    os.chmod(temp_file.name, 0o600)
    _generated_auth_key_path = temp_file.name
    return _generated_auth_key_path


def generate_apns_jwt() -> str:
    global _cached_apns_token, _cached_apns_token_generated_at

    now = int(time.time())
    if _cached_apns_token and (now - _cached_apns_token_generated_at) < APNS_TOKEN_TTL_SECONDS:
        return _cached_apns_token

    if not all([APPLE_TEAM_ID, APPLE_KEY_ID]) or not (APPLE_AUTH_KEY_PATH or APPLE_AUTH_KEY_P8.strip()):
        raise RuntimeError("APNs environment variables are missing")

    header = {"alg": "ES256", "kid": APPLE_KEY_ID}
    payload = {"iss": APPLE_TEAM_ID, "iat": now}
    signing_input = (
        f"{base64url_encode(json.dumps(header, separators=(',', ':')).encode('utf-8'))}."
        f"{base64url_encode(json.dumps(payload, separators=(',', ':')).encode('utf-8'))}"
    )
    der_signature = sign_with_openssl(signing_input.encode("utf-8"), resolve_auth_key_path())
    raw_signature = der_signature_to_raw(der_signature)
    token = f"{signing_input}.{base64url_encode(raw_signature)}"

    _cached_apns_token = token
    _cached_apns_token_generated_at = now
    return token


def fetch_queue_times(park_id: int) -> Optional[dict]:
    url = f"https://queue-times.com/parks/{park_id}/queue_times.json"
    try:
        with urlopen(url, timeout=10) as response:
            return json.loads(response.read().decode("utf-8"))
    except URLError as exc:
        print(f"[poller] failed park {park_id}: {exc}")
        return None


def flatten_rides(payload: Optional[dict]) -> List[dict]:
    if not payload:
        return []
    rides = list(payload.get("rides") or [])
    for land in payload.get("lands") or []:
        rides.extend(land.get("rides") or [])
    return rides


def send_apns_push(device_token: str, title: str, body: str) -> None:
    if not APPLE_BUNDLE_ID:
        raise RuntimeError("APPLE_BUNDLE_ID is missing")

    bearer_token = generate_apns_jwt()
    payload = {
        "aps": {
            "alert": {
                "title": title,
                "body": body,
            },
            "sound": "default",
        }
    }

    url = f"https://{APNS_HOST}:{APNS_PORT}/3/device/{device_token}"
    process = subprocess.run(
        [
            "curl",
            "--silent",
            "--show-error",
            "--http2",
            "--write-out",
            "\n%{http_code}",
            "--header",
            f"authorization: bearer {bearer_token}",
            "--header",
            f"apns-topic: {APPLE_BUNDLE_ID}",
            "--header",
            "apns-push-type: alert",
            "--header",
            "content-type: application/json",
            "--data",
            json.dumps(payload, separators=(",", ":")),
            url,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        text=True,
    )

    if process.returncode != 0:
        raise RuntimeError(process.stderr.strip() or "curl failed")

    response_text, _, status_code = process.stdout.rpartition("\n")
    if status_code.strip() != "200":
        raise RuntimeError(f"APNs {status_code.strip()}: {response_text.strip()}")

    print(f"[push] sent token={device_token[:12]}... title={title}")


def prune_expired_alerts() -> None:
    for user_id, alerts in list(ALERTS_BY_USER.items()):
        remaining = [alert for alert in alerts if not alert.is_expired()]
        if remaining:
            ALERTS_BY_USER[user_id] = remaining
        else:
            ALERTS_BY_USER.pop(user_id, None)


def poll_alerts_forever() -> None:
    while True:
        prune_expired_alerts()
        park_cache: Dict[int, List[dict]] = {}

        for user_id, alerts in list(ALERTS_BY_USER.items()):
            device = DEVICES_BY_USER.get(user_id)
            if not device:
                continue

            active_alerts = [alert for alert in alerts if alert.is_enabled and not alert.is_expired()]
            for alert in active_alerts:
                if alert.park_id not in park_cache:
                    payload = fetch_queue_times(alert.park_id)
                    park_cache[alert.park_id] = flatten_rides(payload)

                ride = next((item for item in park_cache[alert.park_id] if item.get("id") == alert.ride_id), None)
                if not ride or not ride.get("is_open"):
                    continue

                wait_time = ride.get("wait_time")
                if wait_time is None or wait_time > alert.threshold_minutes:
                    continue

                try:
                    send_apns_push(
                        device.device_token,
                        f"{alert.ride_name} is down to {wait_time} min",
                        f"Your MouseMinds alert was set for {alert.threshold_minutes} minutes or less.",
                    )
                    alert.is_enabled = False
                except Exception as exc:
                    print(f"[push] failed for {alert.ride_name}: {exc}")

        time.sleep(POLL_SECONDS)


class MouseMindsAlertsHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/health":
            self.respond_json(
                {
                    "ok": True,
                    "devices": len(DEVICES_BY_USER),
                    "usersWithAlerts": len(ALERTS_BY_USER),
                    "apnsHost": APNS_HOST,
                    "apnsConfigured": bool(
                        APPLE_TEAM_ID and APPLE_KEY_ID and APPLE_AUTH_KEY_PATH and APPLE_BUNDLE_ID
                    ),
                }
            )
            return
        self.respond_json({"error": "Not found"}, status=HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        if self.path == "/devices/register":
            self.handle_register_device()
            return
        if self.path == "/alerts/sync":
            self.handle_sync_alerts()
            return
        self.respond_json({"error": "Not found"}, status=HTTPStatus.NOT_FOUND)

    def handle_register_device(self) -> None:
        payload = self.read_json()
        if not payload:
            self.respond_json({"error": "Invalid JSON"}, status=HTTPStatus.BAD_REQUEST)
            return

        user_id = str(payload.get("userID") or "").strip()
        device_token = str(payload.get("deviceToken") or "").strip()
        platform = str(payload.get("platform") or "ios").strip()
        if not user_id or not device_token:
            self.respond_json({"error": "userID and deviceToken are required"}, status=HTTPStatus.BAD_REQUEST)
            return

        DEVICES_BY_USER[user_id] = DeviceRecord(user_id=user_id, device_token=device_token, platform=platform)
        self.respond_json({"ok": True, "device": asdict(DEVICES_BY_USER[user_id])})

    def handle_sync_alerts(self) -> None:
        payload = self.read_json()
        if not payload:
            self.respond_json({"error": "Invalid JSON"}, status=HTTPStatus.BAD_REQUEST)
            return

        user_id = str(payload.get("userID") or "").strip()
        device_token = str(payload.get("deviceToken") or "").strip()
        alerts = payload.get("alerts") or []
        if not user_id or not device_token:
            self.respond_json({"error": "userID and deviceToken are required"}, status=HTTPStatus.BAD_REQUEST)
            return

        existing_device = DEVICES_BY_USER.get(user_id)
        if existing_device:
            existing_device.device_token = device_token
            existing_device.updated_at = datetime.now(timezone.utc).isoformat()
        else:
            DEVICES_BY_USER[user_id] = DeviceRecord(user_id=user_id, device_token=device_token, platform="ios")

        ALERTS_BY_USER[user_id] = [
            AlertRecord(
                park_id=int(item["parkID"]),
                ride_id=int(item["rideID"]),
                ride_name=str(item["rideName"]),
                threshold_minutes=int(item["thresholdMinutes"]),
                created_at=str(item["createdAt"]),
                is_enabled=bool(item["isEnabled"]),
                expires_at=str(item["expiresAt"]),
            )
            for item in alerts
        ]
        self.respond_json({"ok": True, "alertCount": len(ALERTS_BY_USER[user_id])})

    def read_json(self) -> Optional[dict]:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return None
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError:
            return None

    def respond_json(self, payload: dict, status: HTTPStatus = HTTPStatus.OK) -> None:
        data = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format: str, *args) -> None:
        print(f"[http] {self.address_string()} - {format % args}")


def validate_environment() -> None:
    missing = [
        name
        for name, value in [
            ("APPLE_TEAM_ID", APPLE_TEAM_ID),
            ("APPLE_KEY_ID", APPLE_KEY_ID),
            ("APPLE_BUNDLE_ID", APPLE_BUNDLE_ID),
        ]
        if not value
    ]
    if not (APPLE_AUTH_KEY_PATH or APPLE_AUTH_KEY_P8.strip()):
        missing.append("APPLE_AUTH_KEY_PATH or APPLE_AUTH_KEY_P8")
    if missing:
        print("[startup] APNs is not fully configured.")
        print(f"[startup] Missing: {', '.join(missing)}")
        print("[startup] Queue-Times polling will still run, but pushes will fail until these are set.")
    else:
        print(f"[startup] APNs configured for topic {APPLE_BUNDLE_ID} via {APNS_HOST}")


def main() -> None:
    validate_environment()

    thread = threading.Thread(target=poll_alerts_forever, daemon=True)
    thread.start()

    server = ThreadingHTTPServer((HOST, PORT), MouseMindsAlertsHandler)
    print(f"MouseMinds alert server listening on http://{HOST}:{PORT}")
    server.serve_forever()


if __name__ == "__main__":
    main()
