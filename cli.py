from __future__ import annotations

from datetime import date, datetime, timedelta

from access_control import AccessController, AccessLevel, build_demo_controller


class VaultOSCLI:
    def __init__(self, controller: AccessController | None = None) -> None:
        self.controller = controller or build_demo_controller()

    def run(self) -> None:
        print("Vault OS")
        print("Secure Facility Access Manager")
        print("-" * 40)

        while True:
            self._print_menu()
            try:
                choice = input("Select an option: ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                print("\nShutting down Vault OS.")
                return

            if choice == "1":
                self._issue_keycard()
            elif choice == "2":
                self._revoke_keycard()
            elif choice == "3":
                self._attempt_gate_check()
            elif choice == "4":
                self._view_access_log()
            elif choice == "5":
                self._view_flagged_cards()
            elif choice == "6":
                self._view_active_cards()
            elif choice in {"7", "q", "quit", "exit"}:
                print("Shutting down Vault OS.")
                return
            else:
                print("Unknown option. Choose a number from the menu.")

















def main() -> None:
    VaultOSCLI().run()


if __name__ == "__main__":
    main()
