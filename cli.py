"""Interactive CLI for the Day 16 access-control simulator.

Timestamps typed at prompts are parsed as **naive facility local** datetimes and
passed through to :mod:`access_control` (see :func:`access_control.naive_facility_moment`
for how aware values are handled when supplied programmatically).
"""

# Import annotations to allow using class names as type hints before they are fully defined
from __future__ import annotations

# Import standard date and time utilities for handling card expiry and access timestamps
from datetime import date, datetime, timedelta

# Import the core logic components from the access_control module
from access_control import AccessController, AccessLevel, build_demo_controller


# Define the main Command Line Interface class for the Vault OS application
class VaultOSCLI:
    # Initialize the CLI with an optional AccessController; defaults to a demo version if none provided
    def __init__(self, controller: AccessController | None = None) -> None:
        # Assign the provided controller or generate a demo controller to populate initial state
        self.controller = controller or build_demo_controller()

    # The main entry point for the CLI loop
    def run(self) -> None:
        # Print the application header to the console
        print("Vault OS")
        print("Secure Facility Access Manager")
        # Print a decorative separator line
        print("-" * 40)

        # Start an infinite loop to keep the application running until the user exits
        while True:
            # Display the available menu options to the user
            self._print_menu()
            try:
                # Capture user input, remove leading/trailing whitespace, and convert to lowercase
                choice = input("Select an option: ").strip().lower()
            # Handle cases where the user sends an interrupt signal (like Ctrl+C or Ctrl+D)
            except (EOFError, KeyboardInterrupt):
                # Gracefully notify the user and exit the run loop
                print("\nShutting down Vault OS.")
                return

            # Execute the logic corresponding to the user's menu selection
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
            # Allow multiple ways to exit the program (number 7 or common exit strings)
            elif choice in {"7", "q", "quit", "exit"}:
                print("Shutting down Vault OS.")
                return
            # Handle invalid inputs that don't match any menu options
            else:
                print("Unknown option. Choose a number from the menu.")

    # Private method to display the textual menu to the user
    def _print_menu(self) -> None:
        print("\nMenu")
        print("1. Issue a keycard")
        print("2. Revoke a keycard")
        print("3. Attempt a gate check")
        print("4. View the access log")
        print("5. View flagged cards")
        print("6. View active cards")
        print("7. Exit")

    # Private method to handle the workflow of creating a new keycard
    def _issue_keycard(self) -> None:
        # Ask for the name of the person receiving the card
        owner_name = input("Owner name: ").strip()
        # Validate that the name is not empty
        if not owner_name:
            print("Owner name is required.")
            return

        # Prompt the user to select an AccessLevel (VISITOR, STAFF, etc.)
        access_level = self._prompt_access_level()
        # If the prompt failed or was invalid, stop the issuance process
        if access_level is None:
            return

        # Prompt for card duration, defaulting to 30 days if the user just presses Enter
        valid_days = self._prompt_integer("Expires in how many days? [30]: ", default=30)
        # If the integer input was invalid, stop the process
        if valid_days is None:
            return

        # Record today's date as the starting point for the card
        issue_date = date.today()
        # Calculate the future expiration date based on the user's input
        expiry_date = issue_date + timedelta(days=valid_days)
        # Call the registry to create and store the new keycard object
        card = self.controller.registry.issue_keycard(
            owner_name=owner_name,
            access_level=access_level,
            issue_date=issue_date,
            expiry_date=expiry_date,
        )
        # Confirm the successful creation of the card with its details
        print(
            f"Issued {card.card_id} to {card.owner_name} "
            f"({card.access_level.name}) through {card.expiry_date.isoformat()}."
        )

    # Private method to permanently disable an existing keycard
    def _revoke_keycard(self) -> None:
        # Show all cards so the user can see which IDs are available to revoke
        self._view_all_cards()
        # Prompt for the specific ID of the card to be revoked
        card_id = input("Keycard ID to revoke: ").strip().upper()
        # Ensure an ID was actually typed
        if not card_id:
            print("Keycard ID is required.")
            return

        # Ask why the card is being revoked (e.g., "Card lost" or "Employee terminated")
        reason = input("Revocation reason: ").strip()
        # Ensure a reason is provided for the audit trail
        if not reason:
            print("A revocation reason is required.")
            return

        try:
            # Attempt to revoke the card through the registry
            card = self.controller.registry.revoke_card(card_id, reason)
        # Catch errors if the card ID doesn't exist or is already in an invalid state
        except (KeyError, ValueError) as exc:
            print(exc)
            return

        # Confirm that the card is now revoked
        print(f"{card.card_id} revoked. Reason: {card.revocation_reason}")

    # Private method to simulate a person swiping their card at a security gate
    def _attempt_gate_check(self) -> None:
        # Retrieve the list of all gates managed by the controller
        gates = self.controller.list_gates()
        # If no gates exist in the system, the operation cannot proceed
        if not gates:
            print("No gates are configured.")
            return

        # Display the list of gates and their security requirements
        print("\nAvailable gates")
        for index, gate in enumerate(gates, start=1):
            # Check if the gate has specific operating hours or is open 24/7
            schedule = gate.time_window.label if gate.time_window else "Always open"
            print(
                f"{index}. {gate.name} | {gate.location} | "
                f"Min level: {gate.required_access_level.name} | {schedule}"
            )

        # Prompt user to choose a gate by its list number
        selection = self._prompt_integer("Choose a gate number: ")
        # Validate that the choice is a number within the valid range
        if selection is None or not (1 <= selection <= len(gates)):
            print("Invalid gate selection.")
            return

        # Fetch the selected gate object from the list
        gate = gates[selection - 1]
        # Show cards so user knows which IDs to test
        self._view_all_cards()
        # Prompt for the ID of the card being "swiped"
        card_id = input("Keycard ID: ").strip().upper()
        # Ensure an ID was provided
        if not card_id:
            print("Keycard ID is required.")
            return

        # Ask when this attempt is happening (to check against gate schedules/expiry)
        timestamp = self._prompt_timestamp()
        # If the timestamp input was invalid, stop the process
        if timestamp is None:
            return

        try:
            # Ask the controller to evaluate if this card can enter this gate at this time
            decision = self.controller.attempt_access(card_id, gate.name, timestamp)
        # Catch errors if the card ID or gate name are not found in the system
        except KeyError as exc:
            print(exc)
            return

        # Determine the visual "verdict" based on the boolean result from the controller
        verdict = "GRANTED" if decision.granted else "DENIED"
        # Print the final result and the specific reason (e.g., "Access level too low")
        print(f"{verdict}: {decision.reason}")
        # If the system detected suspicious activity (like brute forcing), show the warning
        if decision.warning:
            print(f"WARNING: {decision.warning}")

    # Private method to display a history of all access attempts
    def _view_access_log(self) -> None:
        # Retrieve all entry records from the controller's log
        entries = self.controller.log.entries()
        # If the log is empty, inform the user
        if not entries:
            print("No access attempts recorded yet.")
            return

        print("\nAccess Log")
        # Iterate through every log entry and print formatted details
        for entry in entries:
            verdict = "GRANTED" if entry.granted else "DENIED"
            print(
                f"{entry.timestamp.strftime('%Y-%m-%d %H:%M:%S')} | "
                f"{entry.keycard_id} | {entry.gate_name} | {verdict} | {entry.reason}"
            )

    # Private method to view cards that have been flagged for security reasons
    def _view_flagged_cards(self) -> None:
        # Retrieve any security alerts or flagged card data from the controller
        alerts = self.controller.flagged_cards()
        # If no security issues have been detected, inform the user
        if not alerts:
            print("No flagged cards.")
            return

        print("\nFlagged Cards")
        # Print the timestamp, ID, and the specific reason the card was flagged
        for alert in alerts:
            print(
                f"{alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')} | "
                f"{alert.keycard_id} | {alert.message}"
            )

    # Private method to list only cards that are currently valid and active
    def _view_active_cards(self) -> None:
        # Filter the registry for cards that are not revoked, deactivated, or expired
        cards = self.controller.registry.list_active_cards()
        # Handle the case where no cards meet the "active" criteria
        if not cards:
            print("No active cards found.")
            return

        print("\nActive Cards")
        # Print key details for each active card
        for card in cards:
            print(
                f"{card.card_id} | {card.owner_name} | {card.access_level.name} | "
                f"Expires {card.expiry_date.isoformat()}"
            )

    # Private method to show every card ever issued, regardless of status
    def _view_all_cards(self) -> None:
        # Retrieve the master list of all cards in the system
        cards = self.controller.registry.all_cards()
        # Inform the user if the database is empty
        if not cards:
            print("No cards have been issued.")
            return

        print("\nIssued Cards")
        # Print details including current status (ACTIVE, REVOKED, etc.)
        for card in cards:
            print(
                f"{card.card_id} | {card.owner_name} | {card.access_level.name} | "
                f"{card.status()} | Expires {card.expiry_date.isoformat()}"
            )

    # Helper method to get an AccessLevel enum from user string input
    def _prompt_access_level(self) -> AccessLevel | None:
        # Remind the user of the valid roles
        print("Access levels: VISITOR, STAFF, MANAGER, ADMIN")
        # Get user input and clean it up
        raw_value = input("Access level: ").strip()
        try:
            # Attempt to convert the string into the AccessLevel enum type
            return AccessLevel.from_string(raw_value)
        # Catch errors if the user typed something like "GOD_MODE" that doesn't exist
        except ValueError as exc:
            print(exc)
            return None

    # Helper method to safely capture and validate integer input
    def _prompt_integer(self, prompt: str, default: int | None = None) -> int | None:
        # Display the prompt and capture input
        raw_value = input(prompt).strip()
        # If user pressed Enter and a default value exists, use the default
        if not raw_value and default is not None:
            return default
        try:
            # Try to convert the input string to a whole number
            value = int(raw_value)
        # Catch cases where the user types letters instead of numbers
        except ValueError:
            print("Please enter a whole number.")
            return None

        # Logic check: prevent negative numbers for things like expiry days or IDs
        if value < 0:
            print("Please enter a non-negative number.")
            return None
        # Return the valid integer
        return value

    # Helper method to capture a specific point in time for access simulation
    def _prompt_timestamp(self) -> datetime | None:
        # Ask for a timestamp; clarify that empty input means "right now"
        raw_value = input(
            "Timestamp for the attempt [press Enter for now, or use YYYY-MM-DD HH:MM]: "
        ).strip()
        # Default to the current system time if no input is provided
        if not raw_value:
            return datetime.now()
        try:
            # Parse the string into a datetime object using the specified format
            return datetime.strptime(raw_value, "%Y-%m-%d %H:%M")
        # Catch errors if the date/time string is formatted incorrectly
        except ValueError:
            print("Timestamp must use the format YYYY-MM-DD HH:MM.")
            return None


# Standard function to instantiate the CLI and begin the execution loop
def main() -> None:
    # Create an instance of the CLI and call its run method
    VaultOSCLI().run()


# Standard Python boilerplate to ensure main() only runs if the script is executed directly
if __name__ == "__main__":
    main()