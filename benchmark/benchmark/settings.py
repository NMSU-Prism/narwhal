# Copyright(C) Facebook, Inc.
import json
import os
from dataclasses import dataclass
from typing import Optional, List

DEFAULT_SETTINGS_PATH = os.path.join("benchmarks", "settings.json")


class SettingsError(Exception):
    pass


@dataclass
class Settings:
    # Common
    key_name: str
    key_path: str
    base_port: int
    repo_name: str
    repo_url: str
    branch: str

    # Static hosts
    ssh_user: Optional[str] = None
    hosts: Optional[List[dict]] = None  # [{"name":"n1","ip":"10.0.0.1",["user":"..."]}, ...]

    # AWS (kept for compatibility; unused when hosts present)
    instance_type: Optional[str] = None
    aws_regions: Optional[List[str]] = None

    @classmethod
    def load(cls, path: Optional[str] = None) -> "Settings":
        path = path or os.getenv("NARWHAL_SETTINGS", DEFAULT_SETTINGS_PATH)
        try:
            with open(path, "r") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            raise SettingsError(str(e))

        try:
            key = data["key"]
            repo = data["repo"]
            key_name = key["name"]
            key_path = key["path"]
            base_port = int(data["port"])
            repo_name = repo["name"]
            repo_url = repo["url"]
            branch = repo["branch"]
        except KeyError as e:
            raise SettingsError("Malformed settings: missing key {}".format(e))

        hosts = data.get("hosts")
        ssh_user = data.get("ssh_user")

        instances = data.get("instances", {})
        instance_type = instances.get("type")
        aws_regions = instances.get("regions")

        # Normalize static hosts if present
        if hosts is not None:
            if not isinstance(hosts, list) or not hosts:
                raise SettingsError("For static mode, 'hosts' must be a non-empty list")
            norm: List[dict] = []
            for i, h in enumerate(hosts):
                if isinstance(h, str):
                    norm.append({"name": "h{}".format(i + 1), "ip": h})
                elif isinstance(h, dict) and "ip" in h:
                    norm.append(h)
                else:
                    raise SettingsError("Each host must be an IP string or an object with at least an 'ip' field")
            hosts = norm
            aws_regions = None  # ensure AWS not used
            instance_type = None
        else:
            # No hosts => expect AWS fields (kept for back-compat)
            if isinstance(aws_regions, str):
                aws_regions = [aws_regions]
            if not instance_type or not aws_regions:
                raise SettingsError("Missing 'instances.type' / 'instances.regions' for AWS mode")

        return cls(
            key_name=key_name,
            key_path=key_path,
            base_port=base_port,
            repo_name=repo_name,
            repo_url=repo_url,
            branch=branch,
            ssh_user=ssh_user,
            hosts=hosts,
            instance_type=instance_type,
            aws_regions=aws_regions,
        )
