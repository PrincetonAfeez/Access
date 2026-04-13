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
    
    def _revoke_keycard(self) -> None:
        self._view_all_cards()
        card_id = input("Keycard ID to revoke: ").strip().upper()
        if not card_id:
            print("Keycard ID is required.")
            return

        reason = input("Revocation reason: ").strip()
        if not reason:
            print("A revocation reason is required.")
            return

        try:
            card = self.controller.registry.revoke_card(card_id, reason)
        except (KeyError, ValueError) as exc:
            print(exc)
            return

        print(f"{card.card_id} revoked. Reason: {card.revocation_reason}")

    
    def _attempt_gate_check(self) -> None:
        gates = self.controller.list_gates()
        if not gates:
            print("No gates are configured.")
            return

        print("\nAvailable gates")
        for index, gate in enumerate(gates, start=1):
            schedule = gate.time_window.label if gate.time_window else "Always open"
            print(
                f"{index}. {gate.name} | {gate.location} | "
                f"Min level: {gate.required_access_level.name} | {schedule}"
            )

        selection = self._prompt_integer("Choose a gate number: ")
        if selection is None or not (1 <= selection <= len(gates)):
            print("Invalid gate selection.")
            return

        gate = gates[selection - 1]
        self._view_all_cards()
        card_id = input("Keycard ID: ").strip().upper()
        if not card_id:
            print("Keycard ID is required.")
            return

        timestamp = self._prompt_timestamp()
        if timestamp is None:
            return

        try:
            decision = self.controller.attempt_access(card_id, gate.name, timestamp)
        except KeyError as exc:
            print(exc)
            return

        verdict = "GRANTED" if decision.granted else "DENIED"
        print(f"{verdict}: {decision.reason}")
        if decision.warning:
            print(f"WARNING: {decision.warning}")
    
    def _view_access_log(self) -> None:
        entries = self.controller.log.entries()
        if not entries:
            print("No access attempts recorded yet.")
            return

        print("\nAccess Log")
        for entry in entries:
            verdict = "GRANTED" if entry.granted else "DENIED"
            print(
                f"{entry.timestamp.strftime('%Y-%m-%d %H:%M:%S')} | "
                f"{entry.keycard_id} | {entry.gate_name} | {verdict} | {entry.reason}"
            )
    
    def _view_flagged_cards(self) -> None:
        alerts = self.controller.flagged_cards()
        if not alerts:
            print("No flagged cards.")
            return

        print("\nFlagged Cards")
        for alert in alerts:
            print(
                f"{alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')} | "
                f"{alert.keycard_id} | {alert.message}"
            )
    
    def _view_active_cards(self) -> None:
        cards = self.controller.registry.list_active_cards()
        if not cards:
            print("No active cards found.")
            return

        print("\nActive Cards")
        for card in cards:
            print(
                f"{card.card_id} | {card.owner_name} | {card.access_level.name} | "
                f"Expires {card.expiry_date.isoformat()}"
            )

























def main() -> None:
    VaultOSCLI().run()


if __name__ == "__main__":
    main()
