"""Per-session virtual Linux filesystem.

This module intentionally never touches the host filesystem. It provides
just enough Linux-like behavior for interactive shells, FTP listings, and
future SFTP support while keeping every attacker session isolated.
"""

from __future__ import annotations

import posixpath
import time
from dataclasses import dataclass, field
from typing import Iterable


@dataclass
class VNode:
    """A virtual file or directory."""

    path: str
    node_type: str
    owner: str = "root"
    group: str = "root"
    mode: str = "drwxr-xr-x"
    content: str = ""
    created_at: float = field(default_factory=time.time)
    modified_at: float = field(default_factory=time.time)

    @property
    def size(self) -> int:
        if self.node_type == "dir":
            return 4096
        return len(self.content.encode("utf-8", "replace"))


@dataclass
class VirtualSessionState:
    """Mutable Linux-like state for one attacker session."""

    username: str = "root"
    hostname: str = "edge-router-01"
    cwd: str = "/root"
    env: dict[str, str] = field(default_factory=dict)
    history: list[str] = field(default_factory=list)
    nodes: dict[str, VNode] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.env:
            self.env = {
                "HOME": f"/root" if self.username == "root" else f"/home/{self.username}",
                "USER": self.username,
                "SHELL": "/bin/bash",
                "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                "TERM": "xterm-256color",
            }
        if not self.nodes:
            self.nodes = default_linux_tree(self.hostname, self.username)

    def resolve(self, path: str | None) -> str:
        if not path:
            return self.cwd
        expanded = path.replace("~", self.env.get("HOME", "/root"), 1) if path.startswith("~") else path
        if not expanded.startswith("/"):
            expanded = posixpath.join(self.cwd, expanded)
        resolved = posixpath.normpath(expanded)
        return "/" if resolved == "." else resolved

    def exists(self, path: str) -> bool:
        return self.resolve(path) in self.nodes

    def is_dir(self, path: str) -> bool:
        node = self.nodes.get(self.resolve(path))
        return node is not None and node.node_type == "dir"

    def mkdir(self, path: str) -> None:
        target = self.resolve(path)
        parent = posixpath.dirname(target) or "/"
        if parent not in self.nodes:
            raise FileNotFoundError(parent)
        if target in self.nodes:
            raise FileExistsError(target)
        self.nodes[target] = VNode(path=target, node_type="dir")

    def write_file(self, path: str, content: str = "") -> None:
        target = self.resolve(path)
        parent = posixpath.dirname(target) or "/"
        if parent not in self.nodes:
            raise FileNotFoundError(parent)
        self.nodes[target] = VNode(
            path=target,
            node_type="file",
            mode="-rw-r--r--",
            content=content,
        )

    def read_file(self, path: str) -> str:
        target = self.resolve(path)
        node = self.nodes.get(target)
        if node is None:
            raise FileNotFoundError(target)
        if node.node_type == "dir":
            raise IsADirectoryError(target)
        return node.content

    def remove(self, path: str, recursive: bool = False) -> None:
        target = self.resolve(path)
        node = self.nodes.get(target)
        if node is None:
            raise FileNotFoundError(target)
        if node.node_type == "dir":
            children = [p for p in self.nodes if p != target and p.startswith(target.rstrip("/") + "/")]
            if children and not recursive:
                raise IsADirectoryError(target)
            for child in children:
                self.nodes.pop(child, None)
        self.nodes.pop(target, None)

    def list_dir(self, path: str | None = None) -> list[VNode]:
        target = self.resolve(path)
        if target not in self.nodes:
            raise FileNotFoundError(target)
        if self.nodes[target].node_type != "dir":
            return [self.nodes[target]]
        prefix = target.rstrip("/") + "/"
        rows = []
        for node_path, node in self.nodes.items():
            if node_path == target:
                continue
            if node_path.startswith(prefix) and "/" not in node_path[len(prefix):]:
                rows.append(node)
        return sorted(rows, key=lambda n: (n.node_type != "dir", n.path))


def default_linux_tree(hostname: str, username: str = "root") -> dict[str, VNode]:
    files = {
        "/etc/hostname": hostname + "\n",
        "/etc/issue": "Ubuntu 22.04.4 LTS \\n \\l\n",
        "/etc/os-release": (
            'PRETTY_NAME="Ubuntu 22.04.4 LTS"\n'
            'NAME="Ubuntu"\nVERSION_ID="22.04"\n'
            'VERSION="22.04.4 LTS (Jammy Jellyfish)"\n'
        ),
        "/etc/passwd": (
            "root:x:0:0:root:/root:/bin/bash\n"
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
            "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
            "ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n"
        ),
        "/root/.bash_history": "ls -la\ncat /etc/os-release\nip addr\n",
        "/root/README.txt": "Maintenance account. Rotate credentials after firmware update.\n",
        "/home/ubuntu/.bash_history": "sudo apt update\nsystemctl status nginx\n",
        "/var/www/html/index.html": "<html><body><h1>It works</h1></body></html>\n",
        "/var/log/auth.log": "Jul  6 21:13:17 edge-router-01 sshd[1041]: Server listening on 0.0.0.0 port 22.\n",
        "/proc/version": "Linux version 5.15.0-91-generic (buildd@lcy02-amd64-044) gcc version 11.4.0\n",
    }
    dirs = {
        "/", "/bin", "/boot", "/dev", "/etc", "/home", "/home/ubuntu", "/root",
        "/tmp", "/usr", "/usr/bin", "/usr/sbin", "/var", "/var/log", "/var/www",
        "/var/www/html", "/proc", "/opt", "/run", "/srv",
    }
    nodes: dict[str, VNode] = {}
    for directory in dirs:
        nodes[directory] = VNode(path=directory, node_type="dir")
    for path, content in files.items():
        nodes[path] = VNode(path=path, node_type="file", mode="-rw-r--r--", content=content)
    for binary in ("bash", "cat", "cp", "ls", "mkdir", "mv", "rm", "touch", "uname", "whoami"):
        nodes[f"/bin/{binary}"] = VNode(path=f"/bin/{binary}", node_type="file", mode="-rwxr-xr-x", content="")
    return nodes


def format_long_listing(nodes: Iterable[VNode]) -> str:
    rows = []
    for node in nodes:
        name = posixpath.basename(node.path) or "/"
        month_day = time.strftime("%b %d %H:%M", time.localtime(node.modified_at))
        rows.append(f"{node.mode} 1 {node.owner:<8} {node.group:<8} {node.size:>6} {month_day} {name}")
    return "\n".join(rows)
