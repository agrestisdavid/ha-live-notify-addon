# HA Live Notify - Push Relay Add-on

Home Assistant Add-on that relays push notifications for iOS Live Activities.

## Installation

1. Go to **Settings** → **Add-ons** → **Add-on Store**
2. Click **⋮** (three dots top right) → **Repositories**
3. Add this URL: `https://github.com/agrestisdavid/ha-live-notify-addon`
4. Search for **"HA Live Notify Relay"** and click **Install**
5. Start the add-on

## Configuration

| Field | Description |
|-------|-------------|
| `apns_key_id` | Your APNs Key ID (10 characters, e.g. `ABC1234DEF`) |
| `apns_team_id` | Your Apple Developer Team ID (10 characters) |
| `apns_bundle_id` | The iOS app bundle ID (default: `ios.ha-live-notify`) |
| `apns_use_sandbox` | `true` for development/debug builds, `false` for production/TestFlight |
| `max_pushes_per_minute` | Maximum push messages per minute per device (default: `30`) |

Additionally, the `AuthKey.p8` file (APNs key) must be copied to the add-on config directory:
- Path: `/addon_configs/ha-live-notify-relay/AuthKey.p8`
- Transfer via Samba share or SSH

## API Key

On first start, the add-on automatically generates an API key. You can find it:
- In the **Add-on Logs** (after first start)
- In the file `/addon_configs/ha-live-notify-relay/api_key.txt`

The API key is required for authentication of the iOS app and HA rest_commands.

## Endpoints

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/health` | GET | No | Health check |
| `/register` | POST | Yes | Register device for push notifications |
| `/unregister` | POST | Yes | Remove device registration |
| `/update` | POST | Yes | Send timer update to registered devices |

## Used with the iOS App

This add-on is the server component of **HA Live Notify**. Find the iOS app here:

[https://github.com/agrestisdavid/ha-live-notify](https://github.com/agrestisdavid/ha-live-notify)

The full setup guide (including APNs key, app installation, and HA configuration) can be found in the iOS app README.

## License

MIT
