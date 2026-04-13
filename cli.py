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
    
    def _print_menu(self) -> None:
        print("\nMenu")
        print("1. Issue a keycard")
        print("2. Revoke a keycard")
        print("3. Attempt a gate check")
        print("4. View the access log")
        print("5. View flagged cards")
        print("6. View active cards")
        print("7. Exit")
    
    def _issue_keycard(self) -> None:
        owner_name = input("Owner name: ").strip()
        if not owner_name:
            print("Owner name is required.")
            return

        access_level = self._prompt_access_level()
        if access_level is None:
            return

        valid_days = self._prompt_integer("Expires in how many days? [30]: ", default=30)
        if valid_days is None:
            return

        issue_date = date.today()
        expiry_date = issue_date + timedelta(days=valid_days)
        card = self.controller.registry.issue_keycard(
            owner_name=owner_name,
            access_level=access_level,
            issue_date=issue_date,
            expiry_date=expiry_date,
        )
        print(
            f"Issued {card.card_id} to {card.owner_name} "
            f"({card.access_level.name}) through {card.expiry_date.isoformat()}."
        )



























def main() -> None:
    VaultOSCLI().run()


if __name__ == "__main__":
    main()
