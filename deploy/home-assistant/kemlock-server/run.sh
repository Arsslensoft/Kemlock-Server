#!/usr/bin/with-contenv bashio
# Turns the add-on's options into Kemlock Server's settings and starts it.

domain="$(bashio::config 'domain')"
if [ -z "${domain}" ]; then
  bashio::log.fatal "Set the 'domain' option to the address clients use, such as https://vault.example.com."
  bashio::exit.nok
fi

export DOMAIN="${domain}"
export SIGNUPS_ALLOWED="$(bashio::config 'signups_allowed')"
export LOG_LEVEL="$(bashio::config 'log_level')"
export DATA_FOLDER=/data/kemlock
export ROCKET_PORT=8080
mkdir -p "${DATA_FOLDER}"

if bashio::config.has_value 'ip_header'; then
  export IP_HEADER="$(bashio::config 'ip_header')"
fi
if bashio::config.has_value 'trusted_proxies'; then
  export KEMLOCK_TRUSTED_PROXIES="$(bashio::config 'trusted_proxies')"
fi
if bashio::config.has_value 'database_url'; then
  export DATABASE_URL="$(bashio::config 'database_url')"
fi

bashio::log.info "Starting Kemlock Server for ${DOMAIN}"
exec /usr/local/bin/kemlock-server
