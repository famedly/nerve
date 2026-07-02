#!/usr/bin/env bash
#
# Entrypoint for a Synapse homeserver in the local federation testbed.
#
# Synapse serves plain HTTP on :8008 behind an nginx reverse proxy that
# terminates TLS on :8448. The Matrix server_name therefore carries the
# explicit TLS port (e.g. "hs1:8448"). Federation TLS verification is
# disabled because the testbed uses a throwaway self-signed CA.
#
# On first run we generate the base config + signing key, then on every
# run we (re)render an override config from the environment and start
# Synapse loading both config files (the override directory wins).

set -euo pipefail

echo "nameserver 127.0.0.11" > /etc/resolv.conf

DATA_DIR="/data"
BASE_CONFIG="${DATA_DIR}/homeserver.yaml"
CONF_D="${DATA_DIR}/conf.d"
OVERRIDE_CONFIG="${CONF_D}/override.yaml"

: "${SYNAPSE_SERVER_NAME:?SYNAPSE_SERVER_NAME must be set}"
: "${POSTGRES_HOST:?POSTGRES_HOST must be set}"
: "${POSTGRES_USER:?POSTGRES_USER must be set}"
: "${POSTGRES_PASSWORD:?POSTGRES_PASSWORD must be set}"
: "${POSTGRES_DB:?POSTGRES_DB must be set}"
: "${SHARED_REGISTRATION_SECRET:?SHARED_REGISTRATION_SECRET must be set}"

mkdir -p "${DATA_DIR}" "${CONF_D}"

# Write a log config that logs to stdout. Synapse's auto-generated log config
# points at a file in the working directory ('/'), which the non-root synapse
# user cannot write; logging to stdout avoids that and plays nicely with
# `docker compose logs`.
LOG_CONFIG="${DATA_DIR}/log.config"
cat > "${LOG_CONFIG}" <<'LOGEOF'
version: 1
formatters:
  precise:
    format: '%(asctime)s - %(name)s - %(lineno)d - %(levelname)s - %(request)s - %(message)s'
handlers:
  console:
    class: logging.StreamHandler
    formatter: precise
loggers:
  synapse.storage.SQL:
    level: WARNING
root:
  level: INFO
  handlers: [console]
disable_existing_loggers: false
LOGEOF

# First-run: generate the base config and signing key. The signing key
# file Synapse creates is named after the server_name; that's expected.
if [ ! -f "${BASE_CONFIG}" ]; then
  echo "entrypoint: generating base config at ${BASE_CONFIG}"
  python -m synapse.app.homeserver \
    --server-name "${SYNAPSE_SERVER_NAME}" \
    --config-path "${BASE_CONFIG}" \
    --generate-config \
    --report-stats=no \
    --data-directory "${DATA_DIR}"
fi

# Render the override config from the environment on every start so that
# config changes take effect without recreating the volume. We build it
# with python's YAML dumper so values are always safely quoted/escaped.
echo "entrypoint: rendering override config at ${OVERRIDE_CONFIG}"
python - "${OVERRIDE_CONFIG}" <<'PYEOF'
import os
import sys

import yaml

out_path = sys.argv[1]

config = {
    "server_name": os.environ["SYNAPSE_SERVER_NAME"],
    "public_baseurl": "http://%s/" % os.environ["SYNAPSE_SERVER_NAME"],
    "pid_file": "/data/homeserver.pid",
    "listeners": [
        {
            "type": "http",
            "port": 8008,
            "bind_addresses": ["0.0.0.0"],
            "x_forwarded": True,
            "tls": False,
            "resources": [
                {"names": ["client", "federation"], "compress": False},
            ],
        }
    ],
    "database": {
        "name": "psycopg2",
        "args": {
            "user": os.environ["POSTGRES_USER"],
            "password": os.environ["POSTGRES_PASSWORD"],
            "database": os.environ["POSTGRES_DB"],
            "host": os.environ["POSTGRES_HOST"],
            "port": 5432,
            "cp_min": 5,
            "cp_max": 10,
        },
    },
    "registration_shared_secret": os.environ["SHARED_REGISTRATION_SECRET"],
    "enable_registration": True,
    "enable_registration_without_verification": True,
    "report_stats": False,
    "federation_verify_certificates": False,
    "trusted_key_servers": [],
    "suppress_key_server_warning": True,
    "serve_server_wellknown": False,
    "log_config": "/data/log.config",
    "ip_range_blocklist": ["127.0.0.0/8"],
    "ip_range_blacklist": ["127.0.0.0/8"],
    "ip_range_whitelist": ["172.18.0.0/16"],
    "ip_range_allowlist": ["172.18.0.0/16"],
    "rc_message": {"per_second": 10000, "burst_count": 10000},
    "rc_registration": {"per_second": 10000, "burst_count": 10000},
    "rc_registration_token_validity": {"per_second": 10000, "burst_count": 10000},
    "rc_login": {
        "address": {"per_second": 10000, "burst_count": 10000},
        "account": {"per_second": 10000, "burst_count": 10000},
        "failed_attempts": {"per_second": 10000, "burst_count": 10000},
    },
    "rc_admin_redaction": {"per_second": 10000, "burst_count": 10000},
    "rc_joins": {
        "local": {"per_second": 10000, "burst_count": 10000},
        "remote": {"per_second": 10000, "burst_count": 10000},
    },
    "rc_joins_per_room": {"per_second": 10000, "burst_count": 10000},
    "rc_3pid_validation": {"per_second": 10000, "burst_count": 10000},
    "rc_invites": {
        "per_room": {"per_second": 10000, "burst_count": 10000},
        "per_user": {"per_second": 10000, "burst_count": 10000},
        "per_issuer": {"per_second": 10000, "burst_count": 10000},
    },
    "rc_third_party_invite": {"per_second": 10000, "burst_count": 10000},
    "rc_federation": {
        "window_size": 1,
        "sleep_limit": 10000,
        "sleep_delay": 0,
        "reject_limit": 10000,
        "concurrent": 10000,
    },
}

with open(out_path, "w") as f:
    yaml.safe_dump(config, f, default_flow_style=False, sort_keys=False)
PYEOF

# Start Synapse loading the base config first, then the override directory
# (a directory --config-path loads its *.yaml after the base file, so the
# override wins).
echo "entrypoint: starting synapse"
exec python -m synapse.app.homeserver \
  --config-path "${BASE_CONFIG}" \
  --config-path "${CONF_D}/"
