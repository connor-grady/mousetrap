"""Centralized environment-variable access for the backend.

Every read of ``os.environ`` lives here. Directory and path overrides are
exposed raw (as provided, or ``None`` when unset); ``backend.paths`` owns the
repo root and applies the filesystem defaults. Non-path settings are returned
final.
"""

from os import environ

# Directory overrides (raw; paths.py resolves and applies repo-root defaults)
CONFIG_DIR = environ.get("CONFIG_DIR")
FRONTEND_PUBLIC_DIR = environ.get("FRONTEND_PUBLIC_DIR")

# Individual config-file path overrides (raw; paths.py falls back to CONFIG_DIR)
NOTIFY_CONFIG_PATH = environ.get("NOTIFY_CONFIG_PATH")
PORT_MONITOR_CONFIG_PATH = environ.get("PORT_MONITOR_CONFIG_PATH")

# API tokens (None when unset)
IPDATA_API_KEY = environ.get("IPDATA_API_KEY")
IPINFO_TOKEN = environ.get("IPINFO_TOKEN")

# Scalar settings
APP_VERSION = environ.get("APP_VERSION", "dev")
DOCKER_HOST = environ.get("DOCKER_HOST")
LOGLEVEL = environ.get("LOGLEVEL", "INFO").upper()
TZ = environ.get("TZ") or "UTC"
