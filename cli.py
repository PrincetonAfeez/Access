from __future__ import annotations

from datetime import date, datetime, timedelta

from access_control import AccessController, AccessLevel, build_demo_controller


class VaultOSCLI:
    def __init__(self, controller: AccessController | None = None) -> None:
        self.controller = controller or build_demo_controller()

















def main() -> None:
    VaultOSCLI().run()


if __name__ == "__main__":
    main()
