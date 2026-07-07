"""Linux command emulator for SSH/terminal sessions."""

from __future__ import annotations

import posixpath
import random
import shlex
import time
from dataclasses import dataclass

from aegistrap.core.virtual_fs import VirtualSessionState, format_long_listing


@dataclass
class CommandResult:
    output: str = ""
    exit_code: int = 0
    close_session: bool = False


class CommandEngine:
    """Execute commands against a virtual session, never the host OS."""

    def run(self, state: VirtualSessionState, command: str) -> CommandResult:
        state.history.append(command)
        try:
            parts = shlex.split(command)
        except ValueError as exc:
            return CommandResult(str(exc), 2)
        if not parts:
            return CommandResult()
        cmd, args = parts[0], parts[1:]
        handler = getattr(self, f"_cmd_{cmd.replace('-', '_')}", None)
        if handler is None:
            return CommandResult(f"{cmd}: command not found", 127)
        try:
            return handler(state, args)
        except FileNotFoundError as exc:
            return CommandResult(f"{cmd}: cannot access '{exc.filename or exc.args[0]}': No such file or directory", 1)
        except IsADirectoryError as exc:
            return CommandResult(f"{cmd}: '{exc.filename or exc.args[0]}' is a directory", 1)
        except FileExistsError as exc:
            return CommandResult(f"{cmd}: cannot create directory '{exc.filename or exc.args[0]}': File exists", 1)

    def _cmd_pwd(self, state: VirtualSessionState, args: list[str]) -> CommandResult:
        return CommandResult(state.cwd)

    def _cmd_cd(self, state: VirtualSessionState, args: list[str]) -> CommandResult:
        target = state.resolve(args[0] if args else state.env.get("HOME", "/root"))
        if not state.is_dir(target):
            raise FileNotFoundError(target)
        state.cwd = target
        return CommandResult()

    def _cmd_ls(self, state: VirtualSessionState, args: list[str]) -> CommandResult:
        long = "-l" in args or "-la" in args or "-al" in args
        paths = [arg for arg in args if not arg.startswith("-")]
        target = paths[0] if paths else None
        nodes = state.list_dir(target)
        if long:
            return CommandResult(format_long_listing(nodes))
        return CommandResult("  ".join(posixpath.basename(n.path) or "/" for n in nodes))

    def _cmd_cat(self, state: VirtualSessionState, args: list[str]) -> CommandResult:
        if not args:
            return CommandResult("")
        return CommandResult("\n".join(state.read_file(path).rstrip("\n") for path in args))

    def _cmd_whoami(self, state: VirtualSessionState, args: list[str]) -> CommandResult:
        return CommandResult(state.username)

    def _cmd_hostname(self, state: VirtualSessionState, args: list[str]) -> CommandResult:
        return CommandResult(state.hostname)

    def _cmd_uname(self, state: VirtualSessionState, args: list[str]) -> CommandResult:
        if "-a" in args:
            return CommandResult("Linux edge-router-01 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux")
        return CommandResult("Linux")

    def _cmd_touch(self, state: VirtualSessionState, args: list[str]) -> CommandResult:
        for path in args:
            state.write_file(path, state.nodes.get(state.resolve(path), None).content if state.exists(path) else "")
        return CommandResult()

    def _cmd_mkdir(self, state: VirtualSessionState, args: list[str]) -> CommandResult:
        parents = "-p" in args
        for path in [arg for arg in args if not arg.startswith("-")]:
            if parents:
                current = ""
                for part in state.resolve(path).strip("/").split("/"):
                    current = "/" + part if not current else current + "/" + part
                    if not state.exists(current):
                        state.mkdir(current)
            else:
                state.mkdir(path)
        return CommandResult()

    def _cmd_rm(self, state: VirtualSessionState, args: list[str]) -> CommandResult:
        recursive = any(arg in ("-r", "-rf", "-fr") for arg in args)
        for path in [arg for arg in args if not arg.startswith("-")]:
            state.remove(path, recursive=recursive)
        return CommandResult()

    def _cmd_cp(self, state: VirtualSessionState, args: list[str]) -> CommandResult:
        if len(args) < 2:
            return CommandResult("cp: missing file operand", 1)
        state.write_file(args[-1], state.read_file(args[0]))
        return CommandResult()

    def _cmd_mv(self, state: VirtualSessionState, args: list[str]) -> CommandResult:
        if len(args) < 2:
            return CommandResult("mv: missing file operand", 1)
        content = state.read_file(args[0])
        state.write_file(args[-1], content)
        state.remove(args[0])
        return CommandResult()

    def _cmd_ps(self, state: VirtualSessionState, args: list[str]) -> CommandResult:
        return CommandResult(
            "  PID TTY          TIME CMD\n"
            "    1 ?        00:00:03 systemd\n"
            "  721 ?        00:00:00 sshd\n"
            f"{random.randint(1800, 4000):5d} pts/0    00:00:00 bash\n"
            f"{random.randint(4001, 9000):5d} pts/0    00:00:00 ps"
        )

    def _cmd_top(self, state: VirtualSessionState, args: list[str]) -> CommandResult:
        return CommandResult(
            "top - 21:55:03 up 3 days,  4:12,  1 user,  load average: 0.08, 0.04, 0.01\n"
            "Tasks: 119 total,   1 running, 118 sleeping,   0 stopped,   0 zombie\n"
            "%Cpu(s):  1.3 us,  0.7 sy,  0.0 ni, 97.8 id,  0.2 wa\n"
            "MiB Mem :   3927.6 total,   1284.1 free,    841.7 used,   1801.8 buff/cache\n"
            "  PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND\n"
            "    1 root      20   0  167936  11872   8024 S   0.0   0.3   0:03.11 systemd"
        )

    def _cmd_ifconfig(self, state: VirtualSessionState, args: list[str]) -> CommandResult:
        return CommandResult(_network_output_legacy())

    def _cmd_ip(self, state: VirtualSessionState, args: list[str]) -> CommandResult:
        if args[:1] == ["addr"] or args[:1] == ["a"]:
            return CommandResult(_network_output_ip_addr())
        return CommandResult("Usage: ip addr")

    def _cmd_netstat(self, state: VirtualSessionState, args: list[str]) -> CommandResult:
        return CommandResult(
            "Active Internet connections (servers and established)\n"
            "Proto Recv-Q Send-Q Local Address           Foreign Address         State\n"
            "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\n"
            "tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN\n"
            "tcp        0      0 192.168.1.5:22          192.168.1.7:54012       ESTABLISHED"
        )

    def _cmd_history(self, state: VirtualSessionState, args: list[str]) -> CommandResult:
        return CommandResult("\n".join(f"{idx + 1:5d}  {cmd}" for idx, cmd in enumerate(state.history)))

    def _cmd_exit(self, state: VirtualSessionState, args: list[str]) -> CommandResult:
        return CommandResult("logout", close_session=True)

    def _cmd_logout(self, state: VirtualSessionState, args: list[str]) -> CommandResult:
        return self._cmd_exit(state, args)


def _network_output_ip_addr() -> str:
    return (
        "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default\n"
        "    inet 127.0.0.1/8 scope host lo\n"
        "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default\n"
        "    link/ether 08:00:27:4b:91:6c brd ff:ff:ff:ff:ff:ff\n"
        "    inet 192.168.1.5/24 brd 192.168.1.255 scope global dynamic eth0"
    )


def _network_output_legacy() -> str:
    return (
        "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
        "        inet 192.168.1.5  netmask 255.255.255.0  broadcast 192.168.1.255\n"
        "        ether 08:00:27:4b:91:6c  txqueuelen 1000  (Ethernet)\n"
        "lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n"
        "        inet 127.0.0.1  netmask 255.0.0.0"
    )
