"""Filesystem paths for config-file and frontend locations.

Owns the repo layout: resolves the base directories from ``backend.env``
(applying repo-root defaults for any not overridden in the environment) and
derives every on-disk path from them, so the layout is governed in one place.
"""

from pathlib import Path

from backend import env

REPO_ROOT = Path(__file__).parent.parent

CONFIG_DIR = Path(env.CONFIG_DIR) if env.CONFIG_DIR else Path("/config")

FRONTEND_DIR = REPO_ROOT / "frontend"
# Public dir is env-overridable (e.g. a Docker-specific location); defaults to the repo's.
FRONTEND_PUBLIC_DIR = (
    Path(env.FRONTEND_PUBLIC_DIR) if env.FRONTEND_PUBLIC_DIR else FRONTEND_DIR / "public"
)
FRONTEND_BUILD_DIR = FRONTEND_DIR / "build"
ASSETS_DIR = FRONTEND_BUILD_DIR / "assets"

CONFIG_PATH = CONFIG_DIR / "config.yaml"
DB_PATH = CONFIG_DIR / "mousetrap.db"
LAST_SESSION_PATH = CONFIG_DIR / "last_session.yaml"
PROXIES_PATH = CONFIG_DIR / "proxies.yaml"

# These two accept a dedicated full-path override, else fall back under CONFIG_DIR.
NOTIFY_PATH = Path(env.NOTIFY_CONFIG_PATH) if env.NOTIFY_CONFIG_PATH else CONFIG_DIR / "notify.yaml"
PORT_MONITOR_PATH = (
    Path(env.PORT_MONITOR_CONFIG_PATH)
    if env.PORT_MONITOR_CONFIG_PATH
    else CONFIG_DIR / "port_monitoring_stacks.yaml"
)
