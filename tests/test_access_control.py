"""Tests for the access_control module."""

from __future__ import annotations

import unittest
from dataclasses import FrozenInstanceError
from datetime import date, datetime, time, timedelta, timezone

from access_control import (
    AccessController,
    AccessDecision,
    AccessGate,
    AccessLevel,
    AccessLog,
    CardRegistry,
    GateSchedule,
    Keycard,
    SecurityAlert,
    SuspiciousActivityMonitor,
    build_demo_controller,
    naive_facility_moment,
)


class NaiveFacilityMomentTests(unittest.TestCase):
    def test_naive_datetime_unchanged(self) -> None:
        dt = datetime(2026, 4, 12, 10, 30)
        self.assertIs(naive_facility_moment(dt), dt)

    def test_aware_datetime_becomes_naive(self) -> None:
        dt = datetime(2026, 4, 12, 15, 0, tzinfo=timezone.utc)
        out = naive_facility_moment(dt)
        self.assertIsNone(out.tzinfo)

    def test_gate_schedule_accepts_aware_without_error(self) -> None:
        schedule = GateSchedule(time(9, 0), time(17, 0))
        aware = datetime(2026, 4, 12, 14, 0, tzinfo=timezone.utc)
        self.assertIsInstance(schedule.allows(aware), bool)


class AccessLevelTests(unittest.TestCase):
    def test_from_string_accepts_names_case_insensitive(self) -> None:
        self.assertEqual(AccessLevel.from_string("staff"), AccessLevel.STAFF)
        self.assertEqual(AccessLevel.from_string("  MANAGER  "), AccessLevel.MANAGER)

    def test_from_string_unknown_raises(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            AccessLevel.from_string("nope")
        self.assertIn("Unknown access level", str(ctx.exception))


class KeycardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.today = date(2026, 4, 12)

    def test_blank_owner_raises(self) -> None:
        with self.assertRaises(ValueError):
            Keycard("KC-1", "  ", AccessLevel.VISITOR, self.today, self.today + timedelta(days=1))

    def test_expiry_before_issue_raises(self) -> None:
        with self.assertRaises(ValueError):
            Keycard("KC-1", "A", AccessLevel.VISITOR, self.today, self.today - timedelta(days=1))

    def test_update_access_level_type_guard(self) -> None:
        card = Keycard("KC-1", "A", AccessLevel.VISITOR, self.today, self.today + timedelta(days=30))
        with self.assertRaises(TypeError):
            card.update_access_level("STAFF")  # type: ignore[arg-type]

    def test_revoke_requires_reason(self) -> None:
        card = Keycard("KC-1", "A", AccessLevel.VISITOR, self.today, self.today + timedelta(days=30))
        with self.assertRaises(ValueError):
            card.revoke("   ")

    def test_revoke_twice_raises(self) -> None:
        card = Keycard("KC-1", "A", AccessLevel.VISITOR, self.today, self.today + timedelta(days=30))
        card.revoke("lost", revoked_at=datetime(2026, 4, 1, 9, 0))
        with self.assertRaises(ValueError):
            card.revoke("again")

    def test_is_expired_respects_date_and_datetime(self) -> None:
        card = Keycard("KC-1", "A", AccessLevel.VISITOR, self.today, self.today + timedelta(days=1))
        self.assertFalse(card.is_expired(self.today))
        self.assertFalse(card.is_expired(datetime.combine(self.today, time(23, 59))))
        self.assertTrue(card.is_expired(self.today + timedelta(days=2)))

    def test_status_active_and_expired(self) -> None:
        card = Keycard("KC-1", "A", AccessLevel.VISITOR, self.today, self.today + timedelta(days=1))
        self.assertEqual("ACTIVE", card.status(self.today))
        self.assertEqual("EXPIRED", card.status(self.today + timedelta(days=10)))

    def test_status_defaults_to_today_when_none(self) -> None:
        card = Keycard("KC-1", "A", AccessLevel.VISITOR, self.today, self.today + timedelta(days=30))
        self.assertEqual("ACTIVE", card.status(None))

    def test_status_revoked_takes_precedence_over_expiry(self) -> None:
        card = Keycard("KC-1", "A", AccessLevel.VISITOR, self.today, self.today + timedelta(days=1))
        card.revoke("lost", revoked_at=datetime(2026, 4, 1, 9, 0))
        self.assertEqual("REVOKED", card.status(self.today))

    def test_update_access_level_success(self) -> None:
        card = Keycard("KC-1", "A", AccessLevel.VISITOR, self.today, self.today + timedelta(days=1))
        card.update_access_level(AccessLevel.MANAGER)
        self.assertEqual(AccessLevel.MANAGER, card.access_level)

    def test_deactivate_and_reactivate(self) -> None:
        card = Keycard("KC-1", "A", AccessLevel.VISITOR, self.today, self.today + timedelta(days=30))
        card.deactivate()
        self.assertFalse(card.active)
        self.assertEqual("INACTIVE", card.status(self.today))
        card.reactivate()
        self.assertTrue(card.active)
        self.assertEqual("ACTIVE", card.status(self.today))

    def test_cannot_deactivate_or_reactivate_revoked_card(self) -> None:
        card = Keycard("KC-1", "A", AccessLevel.VISITOR, self.today, self.today + timedelta(days=30))
        card.revoke("lost")
        with self.assertRaises(ValueError):
            card.deactivate()
        with self.assertRaises(ValueError):
            card.reactivate()


class GateScheduleTests(unittest.TestCase):
    def test_same_start_end_raises(self) -> None:
        t = time(9, 0)
        with self.assertRaises(ValueError):
            GateSchedule(t, t)

    def test_allows_same_day_window(self) -> None:
        schedule = GateSchedule(time(9, 0), time(17, 0))
        self.assertTrue(schedule.allows(datetime(2026, 4, 12, 12, 0)))
        self.assertFalse(schedule.allows(datetime(2026, 4, 12, 8, 59)))

    def test_allows_overnight_window(self) -> None:
        schedule = GateSchedule(time(22, 0), time(6, 0))
        self.assertTrue(schedule.allows(datetime(2026, 4, 12, 23, 0)))
        self.assertTrue(schedule.allows(datetime(2026, 4, 12, 5, 30)))
        self.assertFalse(schedule.allows(datetime(2026, 4, 12, 12, 0)))

    def test_label(self) -> None:
        schedule = GateSchedule(time(8, 5), time(18, 30))
        self.assertIn("08:05", schedule.label)
        self.assertIn("18:30", schedule.label)


class AccessDecisionTests(unittest.TestCase):
    def test_with_warning_preserves_fields(self) -> None:
        base = AccessDecision(
            granted=False,
            reason="no",
            keycard_id="KC-1",
            gate_name="G",
            timestamp=datetime(2026, 1, 1, 0, 0),
        )
        warned = base.with_warning("watch out")
        self.assertEqual(warned.warning, "watch out")
        self.assertEqual(warned.granted, base.granted)


class AccessGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.today = date(2026, 4, 12)

    def test_blank_name_or_location_raises(self) -> None:
        with self.assertRaises(ValueError):
            AccessGate("  ", "Here", AccessLevel.VISITOR)
        with self.assertRaises(ValueError):
            AccessGate("Gate", "  ", AccessLevel.VISITOR)

    def test_grants_when_level_and_schedule_ok(self) -> None:
        card = Keycard("KC-1", "A", AccessLevel.STAFF, self.today, self.today + timedelta(days=30))
        gate = AccessGate(
            "Ops",
            "East",
            AccessLevel.STAFF,
            time_window=GateSchedule(time(8, 0), time(18, 0)),
        )
        decision = gate.check_access(card, datetime(2026, 4, 12, 10, 0))
        self.assertTrue(decision.granted)

    def test_denies_expired_card(self) -> None:
        card = Keycard("KC-1", "A", AccessLevel.ADMIN, self.today, self.today + timedelta(days=1))
        gate = AccessGate("G", "L", AccessLevel.VISITOR)
        decision = gate.check_access(card, datetime(2026, 6, 1, 10, 0))
        self.assertFalse(decision.granted)
        self.assertIn("expired", decision.reason.lower())

    def test_denies_deactivated_card(self) -> None:
        card = Keycard("KC-1", "A", AccessLevel.ADMIN, self.today, self.today + timedelta(days=30))
        card.deactivate()
        gate = AccessGate("G", "L", AccessLevel.VISITOR)
        decision = gate.check_access(card, datetime(2026, 4, 12, 10, 0))
        self.assertFalse(decision.granted)
        self.assertIn("deactivated", decision.reason.lower())

    def test_check_access_stores_naive_timestamp(self) -> None:
        card = Keycard("KC-1", "A", AccessLevel.VISITOR, self.today, self.today + timedelta(days=30))
        gate = AccessGate("G", "L", AccessLevel.VISITOR)
        aware = datetime(2026, 4, 12, 12, 0, tzinfo=timezone.utc)
        decision = gate.check_access(card, aware)
        self.assertIsNone(decision.timestamp.tzinfo)


class AccessLogTests(unittest.TestCase):
    def test_record_and_alerts(self) -> None:
        log = AccessLog()
        decision = AccessDecision(
            granted=True,
            reason="ok",
            keycard_id="KC-1",
            gate_name="G",
            timestamp=datetime(2026, 1, 1, 0, 0),
        )
        entry = log.record(decision)
        self.assertTrue(entry.granted)
        alert = SecurityAlert(
            timestamp=datetime(2026, 1, 1, 0, 0),
            keycard_id="KC-1",
            denied_attempts=3,
            window_minutes=10,
            message="x",
        )
        log.record_alert(alert)
        self.assertEqual(1, len(log.entries()))
        self.assertEqual(1, len(log.alerts()))

    def test_log_entry_is_frozen(self) -> None:
        from access_control import AccessLogEntry

        entry = AccessLogEntry(
            timestamp=datetime(2026, 1, 1),
            keycard_id="KC-1",
            gate_name="G",
            granted=True,
            reason="ok",
        )
        with self.assertRaises(FrozenInstanceError):
            entry.reason = "Edited"


class SuspiciousActivityMonitorTests(unittest.TestCase):
    def test_invalid_threshold_or_window(self) -> None:
        with self.assertRaises(ValueError):
            SuspiciousActivityMonitor(threshold=0)
        with self.assertRaises(ValueError):
            SuspiciousActivityMonitor(threshold=1, window=timedelta(0))

    def test_granted_attempt_does_not_accumulate(self) -> None:
        from access_control import AccessLogEntry

        monitor = SuspiciousActivityMonitor(threshold=2, window=timedelta(minutes=10))
        entry = AccessLogEntry(
            timestamp=datetime(2026, 4, 12, 10, 0),
            keycard_id="KC-1",
            gate_name="G",
            granted=True,
            reason="ok",
        )
        self.assertIsNone(monitor.observe(entry))
        self.assertEqual(0, len(monitor.flagged_cards()))

    def test_denials_outside_window_are_pruned(self) -> None:
        from access_control import AccessLogEntry

        monitor = SuspiciousActivityMonitor(threshold=5, window=timedelta(minutes=10))
        old = datetime(2026, 4, 12, 9, 0)
        monitor.observe(
            AccessLogEntry(
                timestamp=old,
                keycard_id="KC-1",
                gate_name="G",
                granted=False,
                reason="no",
            )
        )
        newer = old + timedelta(minutes=30)
        monitor.observe(
            AccessLogEntry(
                timestamp=newer,
                keycard_id="KC-1",
                gate_name="G",
                granted=False,
                reason="no",
            )
        )
        self.assertEqual(0, len(monitor.flagged_cards()))


class CardRegistryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.today = date(2026, 4, 12)

    def test_issue_sequence_respects_starting_number(self) -> None:
        reg = CardRegistry(starting_number=42)
        card = reg.issue_keycard("A", AccessLevel.VISITOR, self.today, self.today + timedelta(days=1))
        self.assertEqual("KC-0042", card.card_id)

    def test_get_card_normalizes_id(self) -> None:
        reg = CardRegistry()
        issued = reg.issue_keycard("A", AccessLevel.VISITOR, self.today, self.today + timedelta(days=1))
        self.assertIs(reg.get_card(issued.card_id.lower()), issued)

    def test_require_card_missing_raises(self) -> None:
        reg = CardRegistry()
        with self.assertRaises(KeyError):
            reg.require_card("KC-9999")

    def test_revoke_card_updates_registry_entry(self) -> None:
        reg = CardRegistry()
        issued = reg.issue_keycard("A", AccessLevel.VISITOR, self.today, self.today + timedelta(days=10))
        same = reg.revoke_card(issued.card_id, "lost")
        self.assertTrue(same.revoked)

    def test_list_active_cards_excludes_expired(self) -> None:
        reg = CardRegistry()
        reg.issue_keycard("Old", AccessLevel.VISITOR, self.today - timedelta(days=30), self.today - timedelta(days=1))
        active = reg.issue_keycard("New", AccessLevel.VISITOR, self.today, self.today + timedelta(days=10))
        cards = reg.list_active_cards(self.today)
        self.assertEqual([active], cards)

    def test_list_active_cards_excludes_deactivated(self) -> None:
        reg = CardRegistry()
        on = reg.issue_keycard("On", AccessLevel.VISITOR, self.today, self.today + timedelta(days=10))
        off = reg.issue_keycard("Off", AccessLevel.VISITOR, self.today, self.today + timedelta(days=10))
        off.deactivate()
        self.assertEqual([on], reg.list_active_cards(self.today))

    def test_list_by_access_level_and_all_cards_sorted(self) -> None:
        reg = CardRegistry()
        reg.issue_keycard("B", AccessLevel.STAFF, self.today, self.today + timedelta(days=10))
        visitor = reg.issue_keycard("A", AccessLevel.VISITOR, self.today, self.today + timedelta(days=10))
        self.assertEqual([visitor], reg.list_by_access_level(AccessLevel.VISITOR))
        ids = [card.card_id for card in reg.all_cards()]
        self.assertEqual(ids, sorted(ids))
        self.assertEqual(len(ids), 2)


class AccessControllerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.today = date(2026, 4, 12)

    def test_attempt_unknown_gate_raises(self) -> None:
        reg = CardRegistry()
        ctrl = AccessController(reg, [])
        with self.assertRaises(KeyError):
            ctrl.attempt_access("KC-0001", "Missing", datetime(2026, 4, 12, 10, 0))

    def test_attempt_unknown_keycard_logs_denial(self) -> None:
        reg = CardRegistry()
        gate = AccessGate("G", "L", AccessLevel.VISITOR)
        ctrl = AccessController(reg, [gate])
        decision = ctrl.attempt_access("KC-9999", "G", datetime(2026, 4, 12, 10, 0))
        self.assertFalse(decision.granted)
        self.assertIn("Unknown keycard", decision.reason)
        self.assertEqual(1, len(ctrl.log.entries()))

    def test_add_gate_and_list_gates_sorted(self) -> None:
        reg = CardRegistry()
        ctrl = AccessController(reg, [])
        ctrl.add_gate(AccessGate("B", "L", AccessLevel.MANAGER))
        ctrl.add_gate(AccessGate("A", "L", AccessLevel.VISITOR))
        names = [g.name for g in ctrl.list_gates()]
        self.assertEqual(["A", "B"], names)

    def test_get_gate_case_insensitive(self) -> None:
        reg = CardRegistry()
        gate = AccessGate("Lobby", "Main", AccessLevel.VISITOR)
        ctrl = AccessController(reg, [gate])
        self.assertIs(ctrl.get_gate("lobby"), gate)


class IntegrationRankingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.today = date(2026, 4, 12)

    def test_access_levels_are_ranked(self) -> None:
        self.assertLess(AccessLevel.VISITOR, AccessLevel.STAFF)
        self.assertLess(AccessLevel.STAFF, AccessLevel.MANAGER)
        self.assertLess(AccessLevel.MANAGER, AccessLevel.ADMIN)

    def test_gate_denies_insufficient_access_level(self) -> None:
        registry = CardRegistry()
        visitor_card = registry.issue_keycard(
            "Visitor User",
            AccessLevel.VISITOR,
            issue_date=self.today,
            expiry_date=self.today + timedelta(days=7),
        )
        gate = AccessGate("Control Room", "North Tower", AccessLevel.ADMIN)

        decision = gate.check_access(visitor_card, datetime(2026, 4, 12, 10, 0))

        self.assertFalse(decision.granted)
        self.assertIn("Insufficient access level", decision.reason)

    def test_gate_denies_when_schedule_is_closed(self) -> None:
        registry = CardRegistry()
        staff_card = registry.issue_keycard(
            "Staff User",
            AccessLevel.STAFF,
            issue_date=self.today,
            expiry_date=self.today + timedelta(days=7),
        )
        gate = AccessGate(
            "Operations Wing",
            "East Hall",
            AccessLevel.STAFF,
            time_window=GateSchedule(time(8, 0), time(18, 0)),
        )

        decision = gate.check_access(staff_card, datetime(2026, 4, 12, 7, 30))

        self.assertFalse(decision.granted)
        self.assertIn("Outside allowed access window", decision.reason)

    def test_revoked_card_is_denied(self) -> None:
        registry = CardRegistry()
        manager_card = registry.issue_keycard(
            "Manager User",
            AccessLevel.MANAGER,
            issue_date=self.today,
            expiry_date=self.today + timedelta(days=7),
        )
        manager_card.revoke("Terminated access")
        gate = AccessGate("Vault Antechamber", "Sublevel 2", AccessLevel.MANAGER)

        decision = gate.check_access(manager_card, datetime(2026, 4, 12, 12, 0))

        self.assertFalse(decision.granted)
        self.assertIn("revoked", decision.reason.lower())

    def test_suspicious_activity_flags_repeated_denials(self) -> None:
        registry = CardRegistry()
        visitor_card = registry.issue_keycard(
            "Visitor User",
            AccessLevel.VISITOR,
            issue_date=self.today,
            expiry_date=self.today + timedelta(days=7),
        )
        monitor = SuspiciousActivityMonitor(threshold=3, window=timedelta(minutes=5))
        controller = AccessController(
            registry,
            [AccessGate("Control Room", "North Tower", AccessLevel.ADMIN)],
            monitor=monitor,
        )

        timestamps = [
            datetime(2026, 4, 12, 10, 0),
            datetime(2026, 4, 12, 10, 2),
            datetime(2026, 4, 12, 10, 4),
        ]

        final_decision = None
        for moment in timestamps:
            final_decision = controller.attempt_access(visitor_card.card_id, "Control Room", moment)

        self.assertIsNotNone(final_decision)
        self.assertIsNotNone(final_decision.warning)
        self.assertEqual(1, len(controller.flagged_cards()))
        self.assertEqual(visitor_card.card_id, controller.flagged_cards()[0].keycard_id)


class DemoBuildTests(unittest.TestCase):
    def test_build_demo_controller_smoke(self) -> None:
        ctrl = build_demo_controller()
        self.assertGreaterEqual(len(ctrl.registry.all_cards()), 1)
        self.assertGreaterEqual(len(ctrl.list_gates()), 1)

    def test_build_demo_has_four_cards_and_four_gates(self) -> None:
        ctrl = build_demo_controller()
        self.assertEqual(4, len(ctrl.registry.all_cards()))
        self.assertEqual(4, len(ctrl.list_gates()))


class AccessLevelCompleteTests(unittest.TestCase):
    def test_from_string_all_levels(self) -> None:
        for level in AccessLevel:
            self.assertIs(AccessLevel.from_string(level.name), level)


class KeycardPropertyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.today = date(2026, 4, 12)

    def test_properties_reflect_constructor(self) -> None:
        card = Keycard("KC-9", "  Dana  ", AccessLevel.STAFF, self.today, self.today + timedelta(days=20))
        self.assertEqual("KC-9", card.card_id)
        self.assertEqual("Dana", card.owner_name)
        self.assertEqual(self.today, card.issue_date)
        self.assertEqual(self.today + timedelta(days=20), card.expiry_date)
        self.assertTrue(card.active)
        self.assertFalse(card.revoked)
        self.assertIsNone(card.revocation_reason)
        self.assertIsNone(card.revoked_at)

    def test_revoke_sets_revoked_at_explicit(self) -> None:
        card = Keycard("KC-1", "A", AccessLevel.VISITOR, self.today, self.today + timedelta(days=10))
        at = datetime(2026, 3, 1, 15, 30)
        card.revoke("  left  ", revoked_at=at)
        self.assertEqual("left", card.revocation_reason)
        self.assertEqual(at, card.revoked_at)

    def test_status_with_explicit_date_ref(self) -> None:
        card = Keycard("KC-1", "A", AccessLevel.VISITOR, self.today, self.today + timedelta(days=5))
        self.assertEqual("EXPIRED", card.status(self.today + timedelta(days=10)))

    def test_status_accepts_datetime_reference(self) -> None:
        card = Keycard("KC-1", "A", AccessLevel.VISITOR, self.today, self.today + timedelta(days=5))
        moment = datetime(2026, 4, 14, 15, 0)
        self.assertEqual("ACTIVE", card.status(moment))


class AccessLogEmptyTests(unittest.TestCase):
    def test_entries_and_alerts_start_empty(self) -> None:
        log = AccessLog()
        self.assertEqual((), log.entries())
        self.assertEqual((), log.alerts())


class FrozenDataclassTests(unittest.TestCase):
    def test_access_decision_is_frozen(self) -> None:
        d = AccessDecision(
            granted=True,
            reason="ok",
            keycard_id="KC-1",
            gate_name="G",
            timestamp=datetime(2026, 1, 1, 0, 0),
        )
        with self.assertRaises(FrozenInstanceError):
            d.granted = False

    def test_security_alert_is_frozen(self) -> None:
        alert = SecurityAlert(
            timestamp=datetime(2026, 1, 1, 0, 0),
            keycard_id="KC-1",
            denied_attempts=3,
            window_minutes=10,
            message="m",
        )
        with self.assertRaises(FrozenInstanceError):
            alert.message = "x"


class AccessGateStripAndBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.today = date(2026, 4, 12)

    def test_name_and_location_stripped(self) -> None:
        gate = AccessGate("  North Door  ", "  Wing B  ", AccessLevel.VISITOR)
        self.assertEqual("North Door", gate.name)
        self.assertEqual("Wing B", gate.location)

    def test_schedule_inclusive_endpoints_same_day(self) -> None:
        card = Keycard("KC-1", "A", AccessLevel.STAFF, self.today, self.today + timedelta(days=30))
        gate = AccessGate(
            "Ops",
            "East",
            AccessLevel.STAFF,
            time_window=GateSchedule(time(8, 0), time(18, 0)),
        )
        self.assertTrue(gate.check_access(card, datetime(2026, 4, 12, 8, 0)).granted)
        self.assertTrue(gate.check_access(card, datetime(2026, 4, 12, 18, 0)).granted)

    def test_visitor_granted_at_visitor_gate(self) -> None:
        card = Keycard("KC-1", "A", AccessLevel.VISITOR, self.today, self.today + timedelta(days=30))
        gate = AccessGate("Lobby", "Main", AccessLevel.VISITOR)
        decision = gate.check_access(card, datetime(2026, 4, 12, 3, 0))
        self.assertTrue(decision.granted)
        self.assertEqual("Access granted.", decision.reason)
        self.assertEqual("Lobby", decision.gate_name)
        self.assertEqual("KC-1", decision.keycard_id)


class SuspiciousActivityMonitorEdgeTests(unittest.TestCase):
    def test_no_second_alert_after_flagged(self) -> None:
        from access_control import AccessLogEntry

        monitor = SuspiciousActivityMonitor(threshold=2, window=timedelta(minutes=10))
        base = datetime(2026, 4, 12, 10, 0)

        def denial(offset: int) -> AccessLogEntry:
            return AccessLogEntry(
                timestamp=base + timedelta(minutes=offset),
                keycard_id="KC-1",
                gate_name="G",
                granted=False,
                reason="no",
            )

        self.assertIsNone(monitor.observe(denial(0)))
        first = monitor.observe(denial(1))
        self.assertIsNotNone(first)
        self.assertIsNone(monitor.observe(denial(2)))

    def test_flagged_cards_sorted_by_time(self) -> None:
        from access_control import AccessLogEntry

        monitor = SuspiciousActivityMonitor(threshold=1, window=timedelta(hours=1))
        monitor.observe(
            AccessLogEntry(
                timestamp=datetime(2026, 4, 12, 11, 0),
                keycard_id="KC-B",
                gate_name="G",
                granted=False,
                reason="no",
            )
        )
        monitor.observe(
            AccessLogEntry(
                timestamp=datetime(2026, 4, 12, 10, 0),
                keycard_id="KC-A",
                gate_name="G",
                granted=False,
                reason="no",
            )
        )
        alerts = monitor.flagged_cards()
        self.assertEqual(["KC-A", "KC-B"], [a.keycard_id for a in alerts])


class AccessControllerInjectionTests(unittest.TestCase):
    def test_uses_injected_log_and_monitor_instances(self) -> None:
        reg = CardRegistry()
        reg.issue_keycard("X", AccessLevel.VISITOR, date(2026, 1, 1), date(2026, 12, 31))
        custom_log = AccessLog()
        custom_monitor = SuspiciousActivityMonitor(threshold=99, window=timedelta(hours=1))
        gate = AccessGate("G", "L", AccessLevel.VISITOR)
        ctrl = AccessController(reg, [gate], access_log=custom_log, monitor=custom_monitor)
        self.assertIs(custom_log, ctrl.log)
        self.assertIs(custom_monitor, ctrl.monitor)

    def test_attempt_access_normalizes_aware_timestamp(self) -> None:
        reg = CardRegistry()
        c = reg.issue_keycard("X", AccessLevel.VISITOR, date(2026, 1, 1), date(2026, 12, 31))
        gate = AccessGate("G", "L", AccessLevel.VISITOR)
        ctrl = AccessController(reg, [gate])
        aware = datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc)
        decision = ctrl.attempt_access(c.card_id, "G", aware)
        self.assertIsNone(decision.timestamp.tzinfo)


class CardRegistryEdgeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.today = date(2026, 4, 12)

    def test_get_card_strips_and_uppercases(self) -> None:
        reg = CardRegistry()
        issued = reg.issue_keycard("A", AccessLevel.VISITOR, self.today, self.today + timedelta(days=10))
        self.assertIs(issued, reg.get_card(f"  {issued.card_id.lower()}  "))

    def test_revoke_card_passes_revoked_at(self) -> None:
        reg = CardRegistry()
        issued = reg.issue_keycard("A", AccessLevel.VISITOR, self.today, self.today + timedelta(days=10))
        at = datetime(2026, 4, 1, 9, 0)
        reg.revoke_card(issued.card_id, "gone", revoked_at=at)
        self.assertEqual(at, issued.revoked_at)

    def test_list_active_cards_accepts_datetime_when(self) -> None:
        reg = CardRegistry()
        c = reg.issue_keycard("A", AccessLevel.VISITOR, self.today, self.today + timedelta(days=10))
        when = datetime.combine(self.today, time(12, 0))
        self.assertEqual([c], reg.list_active_cards(when))


if __name__ == "__main__":
    unittest.main()
