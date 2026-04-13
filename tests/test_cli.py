"""Tests for the CLI module."""

from __future__ import annotations

import io
import unittest
from contextlib import redirect_stdout
from datetime import date, datetime, timedelta
from unittest.mock import patch

from access_control import AccessController, AccessGate, AccessLevel, CardRegistry
from cli import VaultOSCLI, main


class VaultOSCLITests(unittest.TestCase):
    def _make_controller(self) -> AccessController:
        reg = CardRegistry()
        reg.issue_keycard("Pat", AccessLevel.VISITOR, date(2026, 1, 1), date(2026, 12, 31))
        return AccessController(reg, [AccessGate("Lobby", "Main", AccessLevel.VISITOR)])

    def _run_cli(self, inputs: list[str], controller: AccessController) -> str:
        stream = io.StringIO()
        with redirect_stdout(stream):
            with patch("builtins.input", side_effect=inputs):
                VaultOSCLI(controller=controller).run()
        return stream.getvalue()

    def test_exit_via_menu_option_7(self) -> None:
        out = self._run_cli(["7"], self._make_controller())
        self.assertIn("Shutting down", out)

    def test_exit_via_quit_alias(self) -> None:
        out = self._run_cli(["quit"], self._make_controller())
        self.assertIn("Shutting down", out)

    def test_exit_via_eof(self) -> None:
        stream = io.StringIO()
        controller = self._make_controller()

        def raise_eof(_prompt: str = "") -> str:
            raise EOFError

        with redirect_stdout(stream):
            with patch("builtins.input", raise_eof):
                VaultOSCLI(controller=controller).run()
        self.assertIn("Shutting down", stream.getvalue())

    def test_exit_via_keyboard_interrupt(self) -> None:
        stream = io.StringIO()
        controller = self._make_controller()

        def raise_interrupt(_prompt: str = "") -> str:
            raise KeyboardInterrupt

        with redirect_stdout(stream):
            with patch("builtins.input", raise_interrupt):
                VaultOSCLI(controller=controller).run()
        self.assertIn("Shutting down", stream.getvalue())

    def test_unknown_menu_then_exit(self) -> None:
        out = self._run_cli(["99", "7"], self._make_controller())
        self.assertIn("Unknown option", out)
        self.assertIn("Shutting down", out)

    def test_issue_keycard_rejects_blank_owner(self) -> None:
        out = self._run_cli(["1", "", "7"], self._make_controller())
        self.assertIn("Owner name is required", out)

    def test_issue_keycard_rejects_invalid_level(self) -> None:
        out = self._run_cli(["1", "Someone", "NOPE", "7"], self._make_controller())
        self.assertIn("Unknown access level", out)

    def test_issue_keycard_flow(self) -> None:
        controller = self._make_controller()
        out = self._run_cli(
            [
                "1",
                "New Person",
                "STAFF",
                "",
                "7",
            ],
            controller,
        )
        self.assertIn("Issued KC-", out)
        self.assertIn("New Person", out)
        self.assertIn("STAFF", out)

    def test_revoke_requires_reason(self) -> None:
        controller = self._make_controller()
        card_id = next(iter(controller.registry.all_cards())).card_id
        out = self._run_cli(
            [
                "2",
                card_id,
                "",
                "7",
            ],
            controller,
        )
        self.assertIn("revocation reason is required", out.lower())

    def test_gate_check_invalid_selection(self) -> None:
        out = self._run_cli(["3", "99", "7"], self._make_controller())
        self.assertIn("Invalid gate selection", out)

    def test_view_empty_log(self) -> None:
        out = self._run_cli(["4", "7"], self._make_controller())
        self.assertIn("No access attempts", out)

    def test_attempt_gate_granted_shows_verdict(self) -> None:
        controller = self._make_controller()
        card_id = next(iter(controller.registry.all_cards())).card_id
        out = self._run_cli(
            [
                "3",
                "1",
                card_id,
                "2026-06-01 12:00",
                "7",
            ],
            controller,
        )
        self.assertIn("GRANTED", out)

    def test_prompt_timestamp_invalid_format(self) -> None:
        controller = self._make_controller()
        card_id = next(iter(controller.registry.all_cards())).card_id
        out = self._run_cli(
            [
                "3",
                "1",
                card_id,
                "not-a-date",
                "7",
            ],
            controller,
        )
        self.assertIn("YYYY-MM-DD HH:MM", out)

    def test_view_flagged_empty(self) -> None:
        out = self._run_cli(["5", "7"], self._make_controller())
        self.assertIn("No flagged cards", out)

    def test_view_active_cards(self) -> None:
        out = self._run_cli(["6", "7"], self._make_controller())
        self.assertIn("Active Cards", out)
        self.assertIn("KC-", out)

    def test_main_invokes_cli(self) -> None:
        with patch("cli.VaultOSCLI") as mock_cls:
            mock_cls.return_value.run.side_effect = lambda: None
            main()
        mock_cls.assert_called_once()

    def test_exit_aliases_q_and_exit(self) -> None:
        self.assertIn("Shutting down", self._run_cli(["q"], self._make_controller()))
        self.assertIn("Shutting down", self._run_cli(["exit"], self._make_controller()))

    def test_issue_keycard_rejects_non_integer_days(self) -> None:
        out = self._run_cli(["1", "Bob", "VISITOR", "not-int", "7"], self._make_controller())
        self.assertIn("whole number", out.lower())

    def test_issue_keycard_rejects_negative_days(self) -> None:
        out = self._run_cli(["1", "Bob", "VISITOR", "-5", "7"], self._make_controller())
        self.assertIn("non-negative", out.lower())

    def test_revoke_blank_card_id(self) -> None:
        out = self._run_cli(["2", "", "7"], self._make_controller())
        self.assertIn("Keycard ID is required", out)

    def test_revoke_unknown_card_prints_error(self) -> None:
        out = self._run_cli(["2", "KC-9999", "lost", "7"], self._make_controller())
        self.assertIn("No keycard found", out)

    def test_revoke_success(self) -> None:
        controller = self._make_controller()
        card_id = next(iter(controller.registry.all_cards())).card_id
        out = self._run_cli(["2", card_id, "End of contract", "7"], controller)
        self.assertIn("revoked", out.lower())
        self.assertIn("End of contract", out)

    def test_gate_check_no_gates_configured(self) -> None:
        empty = AccessController(CardRegistry(), [])
        out = self._run_cli(["3", "7"], empty)
        self.assertIn("No gates are configured", out)

    def test_gate_check_blank_card_id(self) -> None:
        out = self._run_cli(["3", "1", "", "7"], self._make_controller())
        self.assertIn("Keycard ID is required", out)

    def test_gate_check_denied_shows_verdict(self) -> None:
        controller = self._make_controller()
        card_id = next(iter(controller.registry.all_cards())).card_id
        ctrl = AccessController(
            controller.registry,
            [AccessGate("Vault", "Sub", AccessLevel.ADMIN)],
        )
        out = self._run_cli(
            ["3", "1", card_id, "2026-06-01 12:00", "7"],
            ctrl,
        )
        self.assertIn("DENIED", out)

    def test_view_access_log_after_attempt(self) -> None:
        controller = self._make_controller()
        card_id = next(iter(controller.registry.all_cards())).card_id
        out = self._run_cli(
            ["3", "1", card_id, "2026-06-01 12:00", "4", "7"],
            controller,
        )
        self.assertIn("Access Log", out)
        self.assertIn("GRANTED", out)

    def test_view_flagged_after_suspicious_activity(self) -> None:
        reg = CardRegistry()
        v = reg.issue_keycard("V", AccessLevel.VISITOR, date(2026, 1, 1), date(2026, 12, 31))
        from access_control import SuspiciousActivityMonitor

        monitor = SuspiciousActivityMonitor(threshold=3, window=timedelta(minutes=10))
        ctrl = AccessController(
            reg,
            [AccessGate("AdminOnly", "Tower", AccessLevel.ADMIN)],
            monitor=monitor,
        )
        t0 = datetime(2026, 4, 12, 10, 0)
        out = self._run_cli(
            [
                "3",
                "1",
                v.card_id,
                t0.strftime("%Y-%m-%d %H:%M"),
                "3",
                "1",
                v.card_id,
                (t0 + timedelta(minutes=1)).strftime("%Y-%m-%d %H:%M"),
                "3",
                "1",
                v.card_id,
                (t0 + timedelta(minutes=2)).strftime("%Y-%m-%d %H:%M"),
                "5",
                "7",
            ],
            ctrl,
        )
        self.assertIn("Flagged Cards", out)
        self.assertIn("Suspicious activity", out)

    def test_view_active_cards_empty(self) -> None:
        reg = CardRegistry()
        reg.issue_keycard("Old", AccessLevel.VISITOR, date(2020, 1, 1), date(2020, 2, 1))
        ctrl = AccessController(reg, [AccessGate("G", "L", AccessLevel.VISITOR)])
        out = self._run_cli(["6", "7"], ctrl)
        self.assertIn("No active cards found", out)

    def test_view_all_cards_when_none_issued(self) -> None:
        ctrl = AccessController(CardRegistry(), [AccessGate("G", "L", AccessLevel.VISITOR)])
        out = self._run_cli(["2", "KC-0001", "x", "7"], ctrl)
        self.assertIn("No cards have been issued", out)

    def test_gate_check_uses_now_when_timestamp_blank(self) -> None:
        fixed = datetime(2026, 5, 1, 14, 0, 0)

        class FixedDateTime(datetime):
            @classmethod
            def now(cls, tz=None):  # noqa: ANN001
                return fixed

        controller = self._make_controller()
        card_id = next(iter(controller.registry.all_cards())).card_id
        with patch("cli.datetime", FixedDateTime):
            out = self._run_cli(
                ["3", "1", card_id, "", "4", "7"],
                controller,
            )
        self.assertIn("GRANTED", out)
        self.assertIn(fixed.strftime("%Y-%m-%d %H:%M:%S"), out)

    def test_gate_check_keyerror_from_controller_printed(self) -> None:
        controller = self._make_controller()
        card_id = next(iter(controller.registry.all_cards())).card_id

        def boom(*_a, **_k):
            raise KeyError("simulated")

        with patch.object(controller, "attempt_access", side_effect=boom):
            out = self._run_cli(
                ["3", "1", card_id, "2026-06-01 12:00", "7"],
                controller,
            )
        self.assertIn("simulated", out)

    def test_gate_check_shows_warning_on_flag(self) -> None:
        from access_control import SuspiciousActivityMonitor

        reg = CardRegistry()
        v = reg.issue_keycard("V", AccessLevel.VISITOR, date(2026, 1, 1), date(2026, 12, 31))
        monitor = SuspiciousActivityMonitor(threshold=2, window=timedelta(minutes=10))
        ctrl = AccessController(
            reg,
            [AccessGate("AdminOnly", "Tower", AccessLevel.ADMIN)],
            monitor=monitor,
        )
        t0 = datetime(2026, 4, 12, 10, 0)
        out = self._run_cli(
            [
                "3",
                "1",
                v.card_id,
                t0.strftime("%Y-%m-%d %H:%M"),
                "3",
                "1",
                v.card_id,
                (t0 + timedelta(minutes=1)).strftime("%Y-%m-%d %H:%M"),
                "7",
            ],
            ctrl,
        )
        self.assertIn("WARNING:", out)


if __name__ == "__main__":
    unittest.main()
