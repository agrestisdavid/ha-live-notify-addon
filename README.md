# HA Live Notify - Push Relay Add-on

Home Assistant Add-on das Push-Benachrichtigungen für iOS Live Activities weiterleitet.

## Installation

1. Gehe zu **Settings** → **Add-ons** → **Add-on Store**
2. Klicke auf **⋮** (drei Punkte oben rechts) → **Repositories**
3. Füge diese URL hinzu: `https://github.com/agrestisdavid/ha-live-notify-addon`
4. Suche nach **"HA Live Notify Relay"** und klicke auf **Installieren**
5. Starte das Add-on

## Konfiguration

| Feld | Beschreibung |
|------|-------------|
| `apns_key_id` | Die Key ID deines APNs Keys (10-stellig, z.B. `ABC1234DEF`) |
| `apns_team_id` | Deine Apple Developer Team ID (10-stellig) |
| `apns_bundle_id` | Die Bundle ID der iOS App (Standard: `ios.ha-live-notify`) |
| `apns_use_sandbox` | `true` für Entwicklung/Debug-Builds, `false` für Production/TestFlight |
| `max_pushes_per_minute` | Maximale Push-Nachrichten pro Minute pro Gerät (Standard: `30`) |

Zusätzlich muss die Datei `AuthKey.p8` (APNs Schlüssel) in den Add-on Konfigurationsordner kopiert werden:
- Pfad: `/addon_configs/ha-live-notify-relay/AuthKey.p8`
- Übertragung via Samba Share oder SSH

## API Key

Beim ersten Start generiert das Add-on automatisch einen API Key. Diesen findest du:
- In den **Add-on Logs** (nach dem ersten Start)
- In der Datei `/addon_configs/ha-live-notify-relay/api_key.txt`

Der API Key wird für die Authentifizierung der iOS App und der HA rest_commands benötigt.

## Endpunkte

| Endpunkt | Methode | Auth | Beschreibung |
|----------|---------|------|-------------|
| `/health` | GET | Nein | Health-Check |
| `/register` | POST | Ja | Gerät für Push-Nachrichten registrieren |
| `/unregister` | POST | Ja | Geräteregistrierung entfernen |
| `/update` | POST | Ja | Timer-Update an registrierte Geräte senden |

## Zusammen mit der iOS App

Dieses Add-on ist der Server-Teil von **HA Live Notify**. Die iOS App findest du hier:

[https://github.com/agrestisdavid/ha-live-notify](https://github.com/agrestisdavid/ha-live-notify)

Die vollständige Setup-Anleitung (inkl. APNs Key, App-Installation und HA-Konfiguration) findest du im README der iOS App.

## Lizenz

MIT
