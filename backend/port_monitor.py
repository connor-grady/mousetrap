"""Port Monitor Stack Backend Module.

This module manages stack-based port checks and coordinated restarts.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import UTC, datetime
import logging
import socket
import threading
import time
from typing import Any

import docker
import yaml

from backend.env import DOCKER_HOST
from backend.event_log import append_ui_event_log
from backend.notifications_backend import notify_event
from backend.paths import PORT_MONITOR_PATH

_logger: logging.Logger = logging.getLogger(__name__)

# Marker substrings that indicate a container IP probe returned no usable address.
_INVALID_IP_MARKERS = ("not found", "OCI runtime exec", "command not found")


def _is_invalid_container_ip(ip: str) -> bool:
    """True if a container IP probe returned no usable address (empty or an error string)."""
    return not ip or any(marker in ip for marker in _INVALID_IP_MARKERS)


def _stack_event(
    stack: PortMonitorStack,
    *,
    event: str,
    status: str,
    status_message: str,
    level: str,
    details: dict[str, Any],
    timestamp: str | None = None,
) -> dict[str, Any]:
    """Build a UI event-log payload for a port-monitor stack runtime event.

    ``event`` doubles as ``event_type``; ``label`` and ``stack`` both carry the
    stack name. ``timestamp`` defaults to the current time.
    """
    return {
        "event": event,
        "event_type": event,
        "label": stack.name,
        "stack": stack.name,
        "primary_container": stack.primary_container,
        "primary_port": stack.primary_port,
        "timestamp": timestamp or datetime.now(tz=UTC).isoformat(),
        "status": status,
        "status_message": status_message,
        "details": details,
        "level": level,
    }


@dataclass(eq=False)
class PortMonitorStack:
    """A monitored port "stack": a primary container/port plus optional secondaries.

    Secondary containers are restarted if the primary's public port is
    unreachable. Instances also carry runtime state used by the manager.

    Attributes:
        name: Human-readable stack name.
        primary_container: Name of the primary docker container to monitor.
        primary_port: Public port on the primary container to check.
        secondary_containers: Secondary container names to restart if the primary fails.
        interval: Check interval in minutes.
        public_ip: Optional manual public IP override for the primary container.
        public_ip_detected: Whether the public IP was detected automatically.
    """

    name: str
    primary_container: str
    primary_port: int
    secondary_containers: list[str]
    interval: int = 60
    public_ip: str | None = None
    public_ip_detected: bool | None = None
    status: str = field(default="Unknown", init=False)
    last_checked: float = field(default=0.0, init=False)
    last_result: bool = field(default=False, init=False)
    # Track failures for manual IP and pause restarts once the threshold is reached
    consecutive_manual_ip_failures: int = field(default=0, init=False)
    manual_ip_paused: bool = field(default=False, init=False)

    def to_config_dict(self) -> dict[str, Any]:
        """Return the persisted-config representation (the constructor fields)."""
        return {
            "name": self.name,
            "primary_container": self.primary_container,
            "primary_port": self.primary_port,
            "secondary_containers": self.secondary_containers,
            "interval": self.interval,
            "public_ip": self.public_ip,
            "public_ip_detected": self.public_ip_detected,
        }


class PortMonitorStackManager:
    """Manager for PortMonitorStack instances and the background monitoring loop.

    This class is responsible for loading and saving configured PortMonitorStack
    objects, running a background thread that periodically checks stack ports,
    coordinating container restarts when failures are detected, caching a Docker
    client instance, and applying rate-limiting to warning logs and notifications.

    Attributes:
        stacks (list[PortMonitorStack]): Configured port-monitor stacks.
        running (bool): Whether the monitoring loop is active.
        thread (threading.Thread | None): Background monitoring thread.
        _docker_client: Cached Docker client or None if unavailable.
        _last_warning_times (dict): Timestamps used for rate-limiting warnings.
    """

    def __init__(self) -> None:
        """Initialize the PortMonitorStackManager and load configured stacks."""
        self.stacks: list[PortMonitorStack] = []
        self.running: bool = False
        self.thread: threading.Thread | None = None
        self._docker_client: Any = None  # docker.DockerClient when available
        self._last_warning_times: dict[str, Any] = {}  # Rate limiting for warnings
        self.load_stacks()

    def _should_log_warning(self, key: str, min_interval: int = 30) -> bool:
        """Rate limit warnings to prevent log spam."""
        now = time.time()
        last = self._last_warning_times.get(key)
        if last is None or now - last >= min_interval:
            self._last_warning_times[key] = now
            return True
        return False

    def load_stacks(self) -> None:
        """Load stacks from the configured YAML file.

        If the config file does not exist an empty stack list is used. Any
        parse or IO errors are caught and logged; in that case the stacks
        list will be empty.
        """
        if not PORT_MONITOR_PATH.exists():
            self.stacks = []
            _logger.info("[PortMonitor] No config found at %s", PORT_MONITOR_PATH)
            return
        try:
            with PORT_MONITOR_PATH.open(encoding="utf-8") as f:
                data = yaml.safe_load(f) or []
            seen = set()
            unique_stacks = []
            for d in data:
                name = d["name"]
                if name in seen:
                    _logger.warning(
                        "[PortMonitorStack] Duplicate stack name '%s' found in config, ignoring duplicate.",
                        name,
                    )
                    continue
                seen.add(name)
                unique_stacks.append(
                    PortMonitorStack(
                        d["name"],
                        d["primary_container"],
                        d["primary_port"],
                        d.get("secondary_containers", []),
                        d.get("interval", 60),
                        d.get("public_ip"),
                        d.get("public_ip_detected"),
                    )
                )
            self.stacks = unique_stacks
            _logger.info("[PortMonitorStack] Loaded stacks: %s", [s.name for s in self.stacks])
        except Exception as e:
            _logger.error("[PortMonitorStack] Failed to load stacks: %s", e)
            self.stacks = []

    def save_stacks(self) -> None:
        """Persist the current stack list to the configured YAML path.

        Errors during writing are logged but not raised to the caller.
        """
        try:
            with PORT_MONITOR_PATH.open("w", encoding="utf-8") as f:
                yaml.safe_dump([s.to_config_dict() for s in self.stacks], f)
        except Exception as e:
            _logger.error("[PortMonitorStack] Failed to save stacks: %s", e)

    def get_docker_client(self) -> Any:
        """Return a cached Docker client or create one from the environment.

        Supports both direct socket access and Docker Socket Proxy via DOCKER_HOST.
        When DOCKER_HOST is set (e.g., tcp://docker-proxy:2375), connects via HTTP.
        Otherwise, uses the default docker socket at /var/run/docker.sock.

        Returns None if client creation fails, otherwise a docker.DockerClient.
        """
        if self._docker_client is not None:
            return self._docker_client
        try:
            if DOCKER_HOST:
                # Connect via socket proxy (e.g., tcp://docker-proxy:2375)
                _logger.info(
                    "[PortMonitorStack] Connecting to Docker via DOCKER_HOST: %s", DOCKER_HOST
                )
                client = docker.DockerClient(base_url=DOCKER_HOST)
            else:
                # Use default socket at /var/run/docker.sock
                client = docker.from_env()
            self._docker_client = client
        except Exception as e:
            if self._should_log_warning("docker_from_env_failed", min_interval=60):
                _logger.error(
                    "[PortMonitorStack] Failed to create docker client (DOCKER_HOST=%s): %s",
                    DOCKER_HOST or "/var/run/docker.sock",
                    e,
                )
            return None
        else:
            return self._docker_client

    def check_port(self, container_name: str, port: int) -> bool:
        """Check if the container's public IP and port are reachable from the host (outside the container),
        matching the behavior of 'nc -zv <public_ip> <port>' from the host.
        Tries manual override, then curl, then wget.
        """
        # Find the stack object to check for manual public_ip override
        stack = next((s for s in self.stacks if s.primary_container == container_name), None)
        if stack and stack.public_ip:
            ip = stack.public_ip
            _logger.info(
                "[PortMonitorStack] Using manual public_ip override for %s: %s",
                container_name,
                ip,
            )
            public_ip_detected = True
        else:
            client = self.get_docker_client()
            if not client:
                if self._should_log_warning(f"docker_client_{container_name}", min_interval=60):
                    _logger.warning(
                        "[PortMonitorStack] Docker client not available for container %s",
                        container_name,
                    )
                if stack:
                    stack.public_ip_detected = False
                return False
            try:
                container = client.containers.get(container_name)
                # Try curl first
                exec_result = container.exec_run("curl -s https://ipinfo.io/ip")
                ip = exec_result.output.decode().strip()
                if _is_invalid_container_ip(ip):
                    # Try wget as fallback
                    exec_result = container.exec_run("wget -qO- https://ipinfo.io/ip")
                    ip = exec_result.output.decode().strip()
                _logger.debug("[PortMonitorStack] Fetched public IP for %s: %s", container_name, ip)
                if _is_invalid_container_ip(ip):
                    if self._should_log_warning(f"no_ip_{container_name}", min_interval=60):
                        _logger.warning(
                            "[PortMonitorStack] No valid public IP found for %s", container_name
                        )
                    if stack:
                        stack.public_ip_detected = False
                    return False
                public_ip_detected = True
            except Exception as e:
                _logger.error(
                    "[PortMonitorStack] Error fetching public IP for %s: %s", container_name, e
                )
                if stack:
                    stack.public_ip_detected = False
                return False
        # Try to connect from the host to the container's public IP and port
        try:
            with socket.create_connection((ip, port), timeout=3):
                _logger.debug(
                    "[PortMonitorStack] Port %s on %s (container %s) is reachable from host.",
                    port,
                    ip,
                    container_name,
                )
                if stack:
                    stack.public_ip_detected = public_ip_detected
                return True
        except Exception as e:
            if self._should_log_warning(f"port_check_{container_name}_{port}_{ip}", min_interval=30):
                _logger.warning(
                    "[PortMonitorStack] Port %s on %s (container %s) is NOT reachable from host: %s",
                    port,
                    ip,
                    container_name,
                    e,
                )
            if stack:
                stack.public_ip_detected = public_ip_detected
            return False

    def restart_container(self, container_name: str) -> bool:
        """Restart a container by name using the docker client.

        Returns True on success, False if the docker client is not
        available or the restart operation failed.
        """
        client = self.get_docker_client()
        if not client:
            return False
        try:
            client.containers.get(container_name).restart()
        except Exception:
            return False
        else:
            return True

    def _is_container_running(self, container_name: str) -> bool:
        """Return True if the named container reports a 'running' status."""
        client = self.get_docker_client()
        if not client:
            return False
        try:
            return client.containers.get(container_name).status == "running"
        except Exception:
            return False

    def _check_and_record(self, stack: PortMonitorStack) -> bool:
        """Check the stack's primary port, record the result on the stack, and return it."""
        result = self.check_port(stack.primary_container, stack.primary_port)
        stack.last_checked = time.time()
        stack.last_result = result
        stack.status = "OK" if result else "Failed"
        return result

    async def restart_stack(self, stack: PortMonitorStack) -> None:
        """Restart the primary and secondary containers for a stack.

        This method updates stack status, records an event in the UI event
        log, restarts the primary container and, if appropriate, restarts
        the secondary containers and rechecks the stack status.
        """
        stack.status = "Restarting..."
        self.save_stacks()
        append_ui_event_log(
            _stack_event(
                stack,
                event="port_monitor_restart",
                status="Restarting...",
                status_message=f"Restarting stack '{stack.name}' (primary: {stack.primary_container}:{stack.primary_port})...",
                level="warning",
                details={
                    "primary_container": stack.primary_container,
                    "primary_port": stack.primary_port,
                    "secondaries": stack.secondary_containers,
                },
            )
        )
        # Restart primary
        self.restart_container(stack.primary_container)
        # Wait for primary to be reachable (up to 60s), fallback to running status
        port_ok = False
        for _ in range(12):  # Wait up to 12*5=60s
            if self.check_port(stack.primary_container, stack.primary_port):
                port_ok = True
                break
            await asyncio.sleep(5)
        if not port_ok:
            if self._is_container_running(stack.primary_container):
                # Port unreachable, but container running, proceeding
                append_ui_event_log(
                    _stack_event(
                        stack,
                        event="port_monitor_port_timeout",
                        status="Port unreachable, container running",
                        status_message=f"Port {stack.primary_port} on {stack.primary_container} not reachable after 60s, but container is running. Proceeding to restart secondaries.",
                        level="warning",
                        details={},
                    )
                )
                await notify_event(
                    event_type="port_monitor_failure",
                    label=stack.name,
                    status="WARNING",
                    message=f"Port {stack.primary_port} on {stack.primary_container} not reachable after 60s, but container is running. Proceeding to restart secondaries.",
                    details={},
                )
            else:
                # Container not running
                append_ui_event_log(
                    _stack_event(
                        stack,
                        event="port_monitor_container_not_running",
                        status="Container not running",
                        status_message=f"Container {stack.primary_container} is not running after restart. Secondary containers not restarted.",
                        level="error",
                        details={},
                    )
                )
                await notify_event(
                    event_type="port_monitor_failure",
                    label=stack.name,
                    status="ERROR",
                    message=f"Container {stack.primary_container} is not running after restart. Secondary containers not restarted.",
                    details={},
                )
                return  # Do not restart secondaries
        # Restart all secondaries
        for sec in stack.secondary_containers:
            self.restart_container(sec)
        # Immediately recheck status after restart (this will update status and log result)
        self.recheck_stack(stack.name)

    def add_stack(
        self,
        name: str,
        primary_container: str,
        primary_port: int,
        secondary_containers: list[str],
        interval: int = 60,
        public_ip: str | None = None,
    ) -> None:
        """Add a new PortMonitorStack and perform an immediate status check.

        If a stack with the same name already exists the operation is
        ignored.
        """
        if any(s.name == name for s in self.stacks):
            _logger.warning(
                "[PortMonitorStack] Attempted to add duplicate stack '%s', ignoring.", name
            )
            return
        stack = PortMonitorStack(
            name, primary_container, primary_port, secondary_containers, interval, public_ip
        )
        result = self._check_and_record(stack)
        self.stacks.append(stack)
        self.save_stacks()
        _logger.info(
            "[PortMonitorStack] Added stack '%s' with initial status: %s",
            name,
            "OK" if result else "Failed",
        )

    def recheck_stack(self, name: str) -> bool:
        """Re-evaluate a single stack's primary port and update its state.

        Returns True if the stack exists and was rechecked, False otherwise.
        """
        stack = self.get_stack(name)
        if not stack:
            return False
        self._check_and_record(stack)
        self.save_stacks()
        return True

    def remove_stack(self, name: str) -> None:
        """Remove a stack by name and persist the updated stack list."""
        self.stacks = [s for s in self.stacks if s.name != name]
        self.save_stacks()

    def get_stack(self, name: str) -> PortMonitorStack | None:
        """Return the stack with the given name or None if not found."""
        return next((s for s in self.stacks if s.name == name), None)

    def list_stacks(self) -> list[PortMonitorStack]:
        """Return the list of configured PortMonitorStack objects."""
        return self.stacks

    async def monitor_loop(self) -> None:
        """Background monitoring loop.

        Periodically checks configured stacks and triggers restarts/notifications
        when a primary port is unreachable according to configured guardrails.
        """
        self.running = True

        # Perform initial status checks immediately at startup
        _logger.info("[PortMonitorStack] Starting port monitoring with immediate initial checks...")
        for stack in self.stacks:
            result = self._check_and_record(stack)
            _logger.info(
                "[PortMonitorStack] Initial check for %s:%s (stack '%s'): %s",
                stack.primary_container,
                stack.primary_port,
                stack.name,
                "OK" if result else "FAILED",
            )
        self.save_stacks()
        _logger.info(
            "[PortMonitorStack] Initial status checks complete, beginning periodic monitoring..."
        )

        while self.running:
            now = time.time()
            for stack in self.stacks:
                # Only check once enough time has passed since the last check
                if stack.last_checked and (now - stack.last_checked) < stack.interval * 60:
                    continue
                manual_ip = stack.public_ip
                result = self._check_and_record(stack)
                _logger.info(
                    "[PortMonitorStack] Port check for %s:%s (stack '%s'): %s",
                    stack.primary_container,
                    stack.primary_port,
                    stack.name,
                    "OK" if result else "FAILED",
                )
                append_ui_event_log(
                    _stack_event(
                        stack,
                        event="port_monitor_check",
                        status="OK" if result else "Failed",
                        status_message=f"Port check for {stack.primary_container}:{stack.primary_port} (stack '{stack.name}'): {'OK' if result else 'FAILED'}",
                        level="primary" if result else "warning",
                        details={
                            "primary_container": stack.primary_container,
                            "primary_port": stack.primary_port,
                            "result": result,
                            "interval": stack.interval,
                            "secondaries": stack.secondary_containers,
                        },
                        timestamp=datetime.fromtimestamp(stack.last_checked, tz=UTC).isoformat(),
                    )
                )
                if manual_ip:
                    if not result:
                        stack.consecutive_manual_ip_failures += 1
                        if stack.consecutive_manual_ip_failures >= 3:
                            stack.manual_ip_paused = True
                            append_ui_event_log(
                                _stack_event(
                                    stack,
                                    event="port_monitor_manual_ip_paused",
                                    status="Manual IP unreachable, auto-restart paused",
                                    status_message=f"Manual IP {manual_ip} unreachable for 3+ cycles. Auto-restart paused until user updates or disables manual IP.",
                                    level="error",
                                    details={},
                                )
                            )
                            await notify_event(
                                event_type="port_monitor_failure",
                                label=stack.name,
                                status="ERROR",
                                message=f"Manual IP {manual_ip} unreachable for 3+ cycles. Auto-restart paused until user updates or disables manual IP.",
                                details={},
                            )
                            self.save_stacks()
                            continue  # Skip restart
                    else:
                        stack.consecutive_manual_ip_failures = 0
                        stack.manual_ip_paused = False
                if not result:
                    if stack.manual_ip_paused:
                        continue  # Don't restart if paused
                    await notify_event(
                        event_type="port_monitor_failure",
                        label=stack.name,
                        status="FAILED",
                        message=f"Docker Port Monitor: {stack.primary_container}:{stack.primary_port} unreachable (stack '{stack.name}')",
                        details={
                            "primary_container": stack.primary_container,
                            "primary_port": stack.primary_port,
                            "stack": stack.name,
                            "secondaries": stack.secondary_containers,
                        },
                    )
                    await self.restart_stack(stack)
                self.save_stacks()
            await asyncio.sleep(5)

    def start(self) -> None:
        """Start background monitoring in a daemon thread.

        This initializes stack status and spawns the monitoring thread if it
        is not already running.
        """
        self.load_stacks()
        for stack in self.stacks:
            self._check_and_record(stack)
        self.save_stacks()
        if not self.running:
            self.thread = threading.Thread(
                target=lambda: asyncio.run(self.monitor_loop()), daemon=True
            )
            self.thread.start()

    def stop(self) -> None:
        """Stop the background monitoring loop and join the thread."""
        self.running = False
        if self.thread:
            self.thread.join()


# Singleton instance
port_monitor_manager = PortMonitorStackManager()
