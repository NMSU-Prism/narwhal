# Copyright(C) Facebook, Inc.
from __future__ import annotations
from collections import OrderedDict
import os
from fabric import Connection

from .settings import Settings, SettingsError
from .utils import Print

class BenchError(Exception):
    pass


class StaticInstanceManager:
    """Instance manager for fixed on-prem hosts (no AWS)."""

    def __init__(self, settings: Settings):
        self.settings = settings
        if not settings.hosts:
            raise BenchError("StaticInstanceManager requires 'hosts' in settings")
        self._default_user = settings.ssh_user or os.getenv("USER") or "ubuntu"
        self._key_path = settings.key_path

        self._hosts = []
        for i, h in enumerate(settings.hosts):
            if isinstance(h, str):
                self._hosts.append({"name": "h{}".format(i + 1), "ip": h, "user": self._default_user})
            else:
                hh = dict(h)
                hh.setdefault("user", self._default_user)
                self._hosts.append(hh)

        # For legacy code that expects region->ips
        self._by_region = OrderedDict([("static", [h["ip"] for h in self._hosts])])

    @property
    def key_path(self) -> str:
        return self._key_path

    @property
    def ssh_user(self) -> str:
        return self._default_user

    def hosts(self, flat: bool = False):
        """Return dict(region->[ips]) or a flat list of ips."""
        if flat:
            return [ip for ips in self._by_region.values() for ip in ips]
        return self._by_region

    def hosts_with_users(self):
        """Return list of host dicts with user + ip."""
        return list(self._hosts)

    # AWS-compatible no-ops
    def create_instances(self, *a, **k): pass
    def terminate_instances(self, *a, **k): pass
    def start_instances(self, *a, **k): pass
    def stop_instances(self, *a, **k): pass

    def print_info(self):
        for h in self._hosts:
            Print.info("static: {}@{} key={}".format(h["user"], h["ip"], self._key_path))


# Optional: if your repo still imports AWS manager paths, keep a tiny stub.
class AWSInstanceManager:
    def __init__(self, settings: Settings):
        raise BenchError("AWS mode not supported in this build. Provide 'hosts' in benchmarks/settings.json.")


class InstanceManager:
    @classmethod
    def make(cls, settings_file: str = None):
        try:
            settings = Settings.load(settings_file)
        except SettingsError as e:
            raise BenchError("Failed to load settings: {}".format(e))
        # Prefer static when hosts present
        if settings.hosts:
            return StaticInstanceManager(settings)
        # else fall back to AWS (stub above will explain)
        return AWSInstanceManager(settings)
