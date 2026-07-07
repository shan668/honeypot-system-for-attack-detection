"""Command-line entry point for AegisTrap."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from aegistrap.core.config import load_config, save_config, Config
from aegistrap.orchestrator import AegisTrapService
from aegistrap.utils.network import get_local_ip


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="aegistrap",
        description="AegisTrap - Multi-service honeypot & attack intelligence platform",
    )
    parser.add_argument(
        "-c", "--config", default=None,
        help="Path to YAML configuration file",
    )
    parser.add_argument(
        "--init-config", default=None,
        help="Write a fresh default configuration to the given path and exit",
    )
    parser.add_argument(
        "--no-dashboard", action="store_true",
        help="Disable the analytics dashboard",
    )
    parser.add_argument(
        "--allow-public-dashboard", action="store_true",
        help="Allow the dashboard to bind to a non-local address",
    )
    parser.add_argument(
        "--show-ip", action="store_true",
        help="Print the local LAN IP address and exit",
    )
    parser.add_argument(
        "--print-config", action="store_true",
        help="Print the resolved configuration and exit",
    )
    parser.add_argument(
        "--version", action="store_true",
        help="Print the AegisTrap version and exit",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    if args.version:
        from aegistrap import __version__
        print(f"aegistrap {__version__}")
        return 0

    if args.show_ip:
        print(get_local_ip())
        return 0

    if args.init_config:
        cfg = Config()
        target = Path(args.init_config)
        save_config(cfg, target)
        print(f"Wrote default configuration to {target}")
        return 0

    config = load_config(args.config)
    if args.print_config:
        import json
        print(json.dumps(config.to_dict(), indent=2, default=str))
        return 0

    if args.no_dashboard:
        config.dashboard.enabled = False

    if config.dashboard.enabled and not args.allow_public_dashboard:
        if config.dashboard.host not in ("127.0.0.1", "localhost", "::1"):
            print(
                "Dashboard host was reset to 127.0.0.1 so it is not visible on the LAN. "
                "Use --allow-public-dashboard only if you intentionally want to expose it.",
                file=sys.stderr,
            )
            config.dashboard.host = "127.0.0.1"

    _print_lan_exposure_summary(config)

    service = AegisTrapService(config=config)
    service.start()
    service.wait()
    return 0


def _print_lan_exposure_summary(config: Config) -> None:
    print("LAN exposure summary:")
    for service_name in ("ssh", "ftp", "http"):
        service = getattr(config, service_name)
        if service.enabled:
            print(f"  {service_name.upper()} trap: {service.listen_host}:{service.listen_port}")
    if config.dashboard.enabled:
        print(f"  Dashboard: {config.dashboard.host}:{config.dashboard.port} (local-only)")
    else:
        print("  Dashboard: disabled")


if __name__ == "__main__":
    sys.exit(main())
