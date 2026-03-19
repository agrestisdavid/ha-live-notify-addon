#!/usr/bin/with-contenv bashio
# ==============================================================================
# ha-live-notify-relay startup script
# ==============================================================================

# Read config from HA Add-on options
export APNS_KEY_ID=$(bashio::config 'apns_key_id')
export APNS_TEAM_ID=$(bashio::config 'apns_team_id')
export APNS_BUNDLE_ID=$(bashio::config 'apns_bundle_id')
export APNS_USE_SANDBOX=$(bashio::config 'apns_use_sandbox')
export MAX_PUSHES_PER_MINUTE=$(bashio::config 'max_pushes_per_minute')

# APNs key and API key stored in addon_config
export APNS_KEY_PATH="/config/AuthKey.p8"
export API_KEY_PATH="/config/api_key.txt"

# Validate APNs key exists
if [ ! -f "$APNS_KEY_PATH" ]; then
    bashio::log.error "APNs key not found at $APNS_KEY_PATH"
    bashio::log.error "Please upload your AuthKey.p8 file to /addon_configs/ha-live-notify-relay/"
    bashio::exit.nok
fi

# Validate required config
if [ -z "$APNS_KEY_ID" ] || [ "$APNS_KEY_ID" = "null" ]; then
    bashio::log.error "apns_key_id is not configured"
    bashio::exit.nok
fi

if [ -z "$APNS_TEAM_ID" ] || [ "$APNS_TEAM_ID" = "null" ]; then
    bashio::log.error "apns_team_id is not configured"
    bashio::exit.nok
fi

bashio::log.info "Starting HA Live Notify Relay..."
bashio::log.info "APNs Key ID: ${APNS_KEY_ID}"
bashio::log.info "APNs Team ID: ${APNS_TEAM_ID}"
bashio::log.info "Bundle ID: ${APNS_BUNDLE_ID}"
bashio::log.info "Sandbox: ${APNS_USE_SANDBOX}"

# Start the server
exec python3 /app/server.py
