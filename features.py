"""Turns each part of Privacy Protector on or off when its switch in Settings changes.

A switch that is off leaves no trace: its threads stop, and what it changed in
Windows (DNS servers, firewall rules, the watchdog task) is undone through its
own script, which Windows confirms once with its UAC prompt.
"""

from __future__ import annotations

import logging
import sys
import threading
from typing import Any, Callable

import ai_providers
import paths
import tracker_lists
from settings import CAPABILITY_KINDS, Settings


class Switch:
    """A background service that can stop and start again."""

    def __init__(self, name: str, service: Any, start: Callable[[Any], None] | None = None):
        self.name = name
        self.service = service
        self._start = start or (lambda s: s.start())
        self.running = False

    def set(self, on: bool) -> None:
        if on and not self.running:
            self.service.stop_event = threading.Event()
            if hasattr(self.service, "threads"):
                self.service.threads = []
            self._start(self.service)
            self.running = True
            logging.info("feature on: %s", self.name)
        elif not on and self.running:
            self.service.shutdown()
            self.running = False
            logging.info("feature off: %s", self.name)


class Features:
    def __init__(self, settings: Settings, *, dns: Callable[[str | None], None],
                 switches: dict[str, list[Switch]], capabilities: Any = None,
                 run_script: Callable[..., bool] | None = None):
        self.settings = settings
        self.dns = dns
        self.switches = switches
        self.capabilities = capabilities
        if run_script is None:
            import elevated

            run_script = elevated.run_script
        self.run_script = run_script
        self.lock = threading.Lock()
        self.last_error = ""
        if capabilities is not None:
            capabilities.kind_filter = lambda kind: kind not in CAPABILITY_KINDS or settings.enabled(kind)
        settings.listeners.append(self.changed)

    # -- what the engine listens on -------------------------------------
    @staticmethod
    def dns_host(data: dict[str, Any]) -> str | None:
        if data.get("phone"):
            return "0.0.0.0"
        if data.get("pc"):
            return "127.0.0.1"
        return None

    def start(self) -> None:
        """At startup: follow the saved switches without touching Windows settings again."""
        data = self.settings.snapshot()
        self.dns(self.dns_host(data))
        self._services(data)
        self._models(data)

    def _services(self, data: dict[str, Any]) -> None:
        wanted = {
            "phone": data["phone"],
            "pc": data["pc"],
            "trackerLists": data["trackerLists"],
            "capabilities": data["capabilities"]["enabled"],
            "outlook": data["outlook"],
            "defender": data["defender"],
            "tempCleanup": data["tempCleanup"],
            "any": data["phone"] or data["pc"],
        }
        for key, items in self.switches.items():
            for switch in items:
                try:
                    switch.set(bool(wanted.get(key)))
                except Exception as error:  # noqa: BLE001 - one service never stops the others
                    logging.warning("feature %s: %s", switch.name, error)

    @staticmethod
    def _models(data: dict[str, Any]) -> None:
        config = ai_providers.load_config()
        if bool(config.get("enabled")) != bool(data["models"]):
            config["enabled"] = bool(data["models"])
            config.setdefault("providers", [])
            ai_providers.save_config(config)

    # -- a switch changed in Settings -----------------------------------
    def changed(self, old: dict[str, Any], new: dict[str, Any]) -> None:
        with self.lock:
            self.last_error = ""
            # Listen first, so turning PC protection on finds the engine answering on 127.0.0.1:53.
            self.dns(self.dns_host(new))
            program = sys.executable if paths.FROZEN else ""
            data_dir = str(paths.DATA_ROOT)
            if new["phone"] != old["phone"]:
                script = "Enable-Phone-Protection.ps1" if new["phone"] else "Disable-Phone-Protection.ps1"
                args = (["-Program", program] if new["phone"] and program else []) + ["-DataDir", data_dir]
                if not self.run_script(script, *args):
                    self.last_error = "Windows did not allow the phone's firewall change"
            if new["pc"] != old["pc"]:
                script = "Enable-PC-Protection.ps1" if new["pc"] else "Disable-PC-Protection.ps1"
                if not self.run_script(script, "-DataDir", data_dir):
                    self.last_error = "Windows did not allow the PC's DNS change"
            if new["capabilities"]["enabled"] != old["capabilities"]["enabled"]:
                script = "Enable-Capability-History.ps1" if new["capabilities"]["enabled"] else "Disable-Capability-History.ps1"
                # Optional: the live monitor works without the Windows history copy.
                self.run_script(script, wait=False)
            self._services(new)
            self._models(new)
            if old["trackerLists"] and not new["trackerLists"]:
                tracker_lists.clear()
