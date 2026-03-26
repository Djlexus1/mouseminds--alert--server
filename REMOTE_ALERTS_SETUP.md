# Reliable Wait Alerts

MouseMinds now supports a server-backed wait alert flow.

## App Setup
1. Open `More > Reliable Alerts`
2. Enter your backend base URL
3. Enter a stable user ID
4. Tap `Request Notification Permission`
5. Confirm an APNs token appears
6. Tap `Sync Alerts Now`

After that, any ride alert you set in the app will sync to the backend.

## Backend Contract

### `POST /devices/register`
Request:
```json
{
  "userID": "user-123",
  "deviceToken": "abcd1234",
  "platform": "ios"
}
```

### `POST /alerts/sync`
Request:
```json
{
  "userID": "user-123",
  "deviceToken": "abcd1234",
  "alerts": [
    {
      "parkID": 5,
      "rideID": 160,
      "rideName": "Expedition Everest",
      "thresholdMinutes": 30,
      "createdAt": "2025-01-01T15:00:00Z",
      "isEnabled": true,
      "expiresAt": "2025-01-02T15:00:00Z"
    }
  ]
}
```

## APNs Requirements
- `APPLE_TEAM_ID`
- `APPLE_KEY_ID`
- `APPLE_AUTH_KEY_PATH` or `APPLE_AUTH_KEY_P8`
- `APPLE_BUNDLE_ID`

You get these from Apple Developer:
1. Create an APNs auth key in Certificates, Identifiers & Profiles
2. Download the `.p8` key file once
3. Copy the key ID
4. Copy your Apple Developer team ID
5. Use your iOS app bundle ID:
   - `com.mousemindspodcastversion2.MouseMinds-Podcast-Version-2`

## Server
- File: `tools/remote_wait_alerts_server.py`
- Run:
```bash
export APPLE_TEAM_ID="YOUR_TEAM_ID"
export APPLE_KEY_ID="YOUR_KEY_ID"
export APPLE_AUTH_KEY_PATH="/full/path/AuthKey_ABC123XYZ.p8"
export APPLE_BUNDLE_ID="com.mousemindspodcastversion2.MouseMinds-Podcast-Version-2"
python3 "MouseMinds Podcast Version 2/tools/remote_wait_alerts_server.py"
```

For Railway or other hosted platforms, use `APPLE_AUTH_KEY_P8` instead of a file path.
Paste the full `.p8` file contents into that variable.

Example:
```bash
export APPLE_TEAM_ID="YOUR_TEAM_ID"
export APPLE_KEY_ID="YOUR_KEY_ID"
export APPLE_BUNDLE_ID="com.mousemindspodcastversion2.MouseMinds-Podcast-Version-2"
export APPLE_AUTH_KEY_P8="-----BEGIN PRIVATE KEY-----\nYOUR_KEY_HERE\n-----END PRIVATE KEY-----"
python3 "MouseMinds Podcast Version 2/tools/remote_wait_alerts_server.py"
```

Optional:
```bash
export APNS_USE_SANDBOX=1
export HOST="0.0.0.0"
export PORT=8787
export POLL_SECONDS=120
```

This server now:
- accepts device registration
- accepts synced ride alerts
- polls Queue-Times every 2 minutes
- marks matching alerts as triggered
- sends real APNs pushes with Apple token auth
- exposes `GET /health`

## Local vs Real Device
- `http://127.0.0.1:8787` only makes sense for simulator-side local testing
- a real iPhone needs a reachable server URL on your network or internet
- for production, deploy this behind HTTPS and use that URL in `More > Reliable Alerts`

## Production Work Still Needed
- real database persistence
- auth for user/device ownership
- retry logic and monitoring
- background worker/process supervision
