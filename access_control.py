"""Facility access control domain model for Vault OS (Day 16).

**Facility time**

Gates may define :class:`GateSchedule` windows using naive :class:`~datetime.time`
values. Those windows are interpreted as **facility local wall clock**. All
:class:`~datetime.datetime` inputs passed into :meth:`AccessGate.check_access` or
:meth:`AccessController.attempt_access` are normalized via
:func:`naive_facility_moment` before evaluation:

* **Naive** datetimes are treated as already expressed in facility local time.
* **Aware** datetimes are converted to the interpreter's *system local* zone, then
  made naive so schedule comparisons stay consistent.

Other Vault OS modules should call :func:`naive_facility_moment` when feeding
timestamps into this layer if their data may be timezone-aware.

**Keycard lifecycle**

* **Active** means the card may be used at gates (subject to expiry and policy).
  :meth:`Keycard.deactivate` / :meth:`Keycard.reactivate` temporarily suspend or
  restore a card without a permanent revocation record.
* **Revoked** is permanent for the lifetime of the object; revoked cards cannot be
  reactivated. :meth:`Keycard.revoke` records a reason and timestamp.

**Suspicious activity monitor**

The first time a keycard crosses the denial threshold within the sliding window,
an alert is emitted and the card id is stored so duplicate alerts are suppressed
until the process restarts (in-memory only).
"""

# Enable postponed evaluation of annotations for type hints (allows self-referencing classes)
from __future__ import annotations

# Import specialized collection types for efficient data handling
from collections import defaultdict, deque
# Import dataclass for clean, readable data structures
from dataclasses import dataclass
# Import date and time utilities for access logic and scheduling
from datetime import date, datetime, time, timedelta
# Import IntEnum for ordered access levels (where ADMIN > VISITOR)
from enum import IntEnum
# Import count to generate sequential numeric IDs
from itertools import count


def naive_facility_moment(moment: datetime) -> datetime:
    """Return *moment* as a naive datetime in facility-local wall-clock semantics.

    Naive inputs are returned unchanged. Aware inputs are shifted to the host
    system's local timezone (``moment.astimezone()``) then stripped of tzinfo.
    """
    # If the datetime is already naive (no timezone), return it as is
    if moment.tzinfo is None:
        return moment
    # Convert aware datetime to local system time and remove the timezone info for comparison
    return moment.astimezone().replace(tzinfo=None)


class AccessLevel(IntEnum):
    """Enumeration representing hierarchical security clearance levels."""
    VISITOR = 1
    STAFF = 2
    MANAGER = 3
    ADMIN = 4

    @classmethod
    def from_string(cls, raw_value: str) -> "AccessLevel":
        """Converts a string input into a valid AccessLevel enum member."""
        # Clean the input string and make it uppercase for matching
        normalized = raw_value.strip().upper()
        try:
            # Attempt to look up the enum member by name
            return cls[normalized]
        except KeyError as exc:
            # Provide a list of valid options if the user provides an invalid string
            valid_levels = ", ".join(level.name for level in cls)
            raise ValueError(
                f"Unknown access level '{raw_value}'. Choose from: {valid_levels}."
            ) from exc


class Keycard:
    """Represents a physical credential with identity and status metadata."""
    # Use __slots__ for memory efficiency and to prevent dynamic attribute creation
    __slots__ = (
        "__card_id",
        "__owner_name",
        "__access_level",
        "__issue_date",
        "__expiry_date",
        "__active",
        "__revoked",
        "__revocation_reason",
        "__revoked_at",
    )

    def __init__(
        self,
        card_id: str,
        owner_name: str,
        access_level: AccessLevel,
        issue_date: date,
        expiry_date: date,
    ) -> None:
        # Validate that the owner name is not just whitespace
        owner_name = owner_name.strip()
        if not owner_name:
            raise ValueError("Owner name cannot be blank.")
        # Logic check: prevent cards from expiring before they are issued
        if expiry_date < issue_date:
            raise ValueError("Expiry date cannot be earlier than issue date.")

        # Initialize private attributes (denoted by __ prefix)
        self.__card_id = card_id
        self.__owner_name = owner_name
        self.__access_level = access_level
        self.__issue_date = issue_date
        self.__expiry_date = expiry_date
        # Default state: card is working and not revoked
        self.__active = True
        self.__revoked = False
        self.__revocation_reason: str | None = None
        self.__revoked_at: datetime | None = None

    # Public read-only properties for private data
    @property
    def card_id(self) -> str:
        return self.__card_id

    @property
    def owner_name(self) -> str:
        return self.__owner_name

    @property
    def access_level(self) -> AccessLevel:
        return self.__access_level

    @property
    def issue_date(self) -> date:
        return self.__issue_date

    @property
    def expiry_date(self) -> date:
        return self.__expiry_date

    @property
    def active(self) -> bool:
        """True when the card is not administratively deactivated."""
        return self.__active

    @property
    def revoked(self) -> bool:
        """True if the card has been permanently invalidated."""
        return self.__revoked

    @property
    def revocation_reason(self) -> str | None:
        return self.__revocation_reason

    @property
    def revoked_at(self) -> datetime | None:
        return self.__revoked_at

    def update_access_level(self, new_level: AccessLevel) -> None:
        """Change the security clearance associated with this card."""
        if not isinstance(new_level, AccessLevel):
            raise TypeError("new_level must be an AccessLevel.")
        self.__access_level = new_level

    def revoke(self, reason: str, revoked_at: datetime | None = None) -> None:
        """Permanently disable the card with a recorded reason."""
        reason = reason.strip()
        if not reason:
            raise ValueError("A revocation reason is required.")
        if self.__revoked:
            raise ValueError("Keycard is already revoked.")

        # Set revocation flags and record metadata
        self.__active = False
        self.__revoked = True
        self.__revocation_reason = reason
        self.__revoked_at = revoked_at or datetime.now()

    def deactivate(self) -> None:
        """Temporarily block gate use without recording a revocation."""
        if self.__revoked:
            raise ValueError("Cannot deactivate a revoked keycard.")
        self.__active = False

    def reactivate(self) -> None:
        """Undo :meth:`deactivate` for a non-revoked card."""
        if self.__revoked:
            raise ValueError("Cannot reactivate a revoked keycard.")
        self.__active = True

    def is_expired(self, when: date | datetime) -> bool:
        """Check if the card is past its expiration date at a specific moment."""
        # Convert datetime to date object for comparison
        if isinstance(when, datetime):
            when = naive_facility_moment(when).date()
        return when > self.__expiry_date

    def status(self, when: date | datetime | None = None) -> str:
        """Returns a string representation of the card's current state."""
        # Determine the reference date for the check
        if when is None:
            ref = date.today()
        elif isinstance(when, datetime):
            ref = naive_facility_moment(when).date()
        else:
            ref = when
            
        # Hierarchy of status: Revocation trumps Expiry, which trumps Inactivity
        if self.__revoked:
            return "REVOKED"
        if self.is_expired(ref):
            return "EXPIRED"
        if not self.__active:
            return "INACTIVE"
        return "ACTIVE"


@dataclass(frozen=True, slots=True)
class GateSchedule:
    """Defines a time window (start to end) during which a gate allows access."""
    start_time: time
    end_time: time

    def __post_init__(self) -> None:
        # Validate that the window isn't zero-length
        if self.start_time == self.end_time:
            raise ValueError("Schedule start and end time cannot be the same.")

    def allows(self, moment: datetime) -> bool:
        """Determines if a given datetime falls within the schedule."""
        moment = naive_facility_moment(moment)
        current_time = moment.time()
        # Handle standard daytime schedules (e.g., 08:00 to 18:00)
        if self.start_time < self.end_time:
            return self.start_time <= current_time <= self.end_time
        # Handle overnight schedules (e.g., 22:00 to 06:00)
        return current_time >= self.start_time or current_time <= self.end_time

    @property
    def label(self) -> str:
        """Returns a formatted string of the schedule hours."""
        return f"{self.start_time.strftime('%H:%M')} - {self.end_time.strftime('%H:%M')}"


@dataclass(frozen=True, slots=True)
class AccessDecision:
    """The result of an access attempt evaluation."""
    granted: bool
    reason: str
    keycard_id: str
    gate_name: str
    timestamp: datetime
    warning: str | None = None

    def with_warning(self, warning: str) -> "AccessDecision":
        """Returns a new Decision object with an added security warning."""
        return AccessDecision(
            granted=self.granted,
            reason=self.reason,
            keycard_id=self.keycard_id,
            gate_name=self.gate_name,
            timestamp=self.timestamp,
            warning=warning,
        )


@dataclass(frozen=True, slots=True)
class AccessLogEntry:
    """A record stored in the system log for audit purposes."""
    timestamp: datetime
    keycard_id: str
    gate_name: str
    granted: bool
    reason: str


@dataclass(frozen=True, slots=True)
class SecurityAlert:
    """A report generated when suspicious activity is detected."""
    timestamp: datetime
    keycard_id: str
    denied_attempts: int
    window_minutes: int
    message: str


class AccessGate:
    """Represents a physical checkpoint with specific security requirements."""
    __slots__ = ("name", "location", "required_access_level", "time_window")

    def __init__(
        self,
        name: str,
        location: str,
        required_access_level: AccessLevel,
        time_window: GateSchedule | None = None,
    ) -> None:
        # Set basic gate identification and requirements
        self.name = name.strip()
        self.location = location.strip()
        self.required_access_level = required_access_level
        self.time_window = time_window

        # Validate gate identity data
        if not self.name:
            raise ValueError("Gate name cannot be blank.")
        if not self.location:
            raise ValueError("Gate location cannot be blank.")

    def check_access(self, keycard: Keycard, timestamp: datetime) -> AccessDecision:
        """The entry point for checking if a card can pass through this gate."""
        ts = naive_facility_moment(timestamp)
        # Delegate the actual logic check to the private _evaluate method
        granted, reason = self._evaluate(keycard, ts)
        return AccessDecision(
            granted=granted,
            reason=reason,
            keycard_id=keycard.card_id,
            gate_name=self.name,
            timestamp=ts,
        )

    def _evaluate(self, keycard: Keycard, timestamp: datetime) -> tuple[bool, str]:
        """Private method containing the logic hierarchy for access granting."""
        # 1. Check if the card is revoked
        if keycard.revoked:
            reason = keycard.revocation_reason or "No reason recorded."
            return False, f"Keycard revoked: {reason}"
        # 2. Check if the card is temporarily deactivated
        if not keycard.active:
            return False, "Keycard is deactivated (not revoked)."
        # 3. Check if the card has expired
        if keycard.is_expired(timestamp):
            return False, f"Keycard expired on {keycard.expiry_date.isoformat()}."
        # 4. Check if the card's access level meets the gate's minimum requirement
        if keycard.access_level < self.required_access_level:
            return (
                False,
                f"Insufficient access level. Requires {self.required_access_level.name}.",
            )
        # 5. Check if the current time is within the gate's operational window
        if self.time_window and not self.time_window.allows(timestamp):
            return (
                False,
                f"Outside allowed access window for this gate ({self.time_window.label}).",
            )
        # Success if all checks pass
        return True, "Access granted."


class AccessLog:
    """A system-wide repository for recording all access attempts and alerts."""
    def __init__(self) -> None:
        self._entries: list[AccessLogEntry] = []
        self._alerts: list[SecurityAlert] = []

    def record(self, decision: AccessDecision) -> AccessLogEntry:
        """Converts a Decision into a Log Entry and stores it."""
        entry = AccessLogEntry(
            timestamp=decision.timestamp,
            keycard_id=decision.keycard_id,
            gate_name=decision.gate_name,
            granted=decision.granted,
            reason=decision.reason,
        )
        self._entries.append(entry)
        return entry

    def record_alert(self, alert: SecurityAlert) -> None:
        """Stores a generated security alert."""
        self._alerts.append(alert)

    def entries(self) -> tuple[AccessLogEntry, ...]:
        """Returns an immutable copy of all log entries."""
        return tuple(self._entries)

    def alerts(self) -> tuple[SecurityAlert, ...]:
        """Returns an immutable copy of all security alerts."""
        return tuple(self._alerts)

    def replace_stored_entries(
        self,
        entries: list[AccessLogEntry],
        alerts: list[SecurityAlert],
    ) -> None:
        """Low-level method used to restore log state from external storage."""
        self._entries = list(entries)
        self._alerts = list(alerts)


class SuspiciousActivityMonitor:
    """Monitors denials to detect potential security breaches (e.g. brute force)."""
    def __init__(self, threshold: int = 3, window: timedelta = timedelta(minutes=10)) -> None:
        # Validate sensitivity settings
        if threshold < 1:
            raise ValueError("Threshold must be at least 1.")
        if window <= timedelta(0):
            raise ValueError("Window must be positive.")

        self.threshold = threshold
        self.window = window
        # Track denial timestamps per card ID using a double-ended queue for speed
        self._denials: dict[str, deque[datetime]] = defaultdict(deque)
        # Track which cards have already triggered an alert to prevent spam
        self._flagged_cards: dict[str, SecurityAlert] = {}

    def observe(self, entry: AccessLogEntry) -> SecurityAlert | None:
        """Evaluates a new log entry to see if it crosses the suspicious threshold."""
        # We only care about denied attempts
        if entry.granted:
            return None

        # Add current denial to the queue for this card
        attempts = self._denials[entry.keycard_id]
        attempts.append(entry.timestamp)
        # Calculate the sliding window cutoff time
        cutoff = entry.timestamp - self.window
        # Remove old denial records that fall outside the current time window
        while attempts and attempts[0] < cutoff:
            attempts.popleft()

        # Trigger alert if threshold is met AND we haven't already flagged this card
        if len(attempts) < self.threshold or entry.keycard_id in self._flagged_cards:
            return None

        # Construct and store the security alert
        window_minutes = int(self.window.total_seconds() // 60)
        alert = SecurityAlert(
            timestamp=entry.timestamp,
            keycard_id=entry.keycard_id,
            denied_attempts=len(attempts),
            window_minutes=window_minutes,
            message=(
                f"Suspicious activity detected: {len(attempts)} denied attempts "
                f"within {window_minutes} minutes."
            ),
        )
        self._flagged_cards[entry.keycard_id] = alert
        return alert

    def flagged_cards(self) -> tuple[SecurityAlert, ...]:
        """Returns all generated alerts sorted by time."""
        alerts = sorted(self._flagged_cards.values(), key=lambda item: item.timestamp)
        return tuple(alerts)

    def replace_flagged_cards_for_restore(self, alerts: dict[str, SecurityAlert]) -> None:
        """Low-level method to restore flagged state from external storage."""
        self._flagged_cards = dict(alerts)


class CardRegistry:
    """Manages the database of all keycards issued by the system."""
    def __init__(self, starting_number: int = 1) -> None:
        # Dictionary for fast lookup by ID
        self._cards: dict[str, Keycard] = {}
        # Iterator for generating unique, sequential card IDs
        self._sequence = count(starting_number)

    def issue_keycard(
        self,
        owner_name: str,
        access_level: AccessLevel,
        issue_date: date,
        expiry_date: date,
    ) -> Keycard:
        """Generates a new Keycard with a unique ID and registers it."""
        card_id = f"KC-{next(self._sequence):04d}"
        card = Keycard(card_id, owner_name, access_level, issue_date, expiry_date)
        self._cards[card.card_id] = card
        return card

    def get_card(self, card_id: str) -> Keycard | None:
        """Looks up a card by ID. Returns None if not found."""
        return self._cards.get(card_id.strip().upper())

    def require_card(self, card_id: str) -> Keycard:
        """Looks up a card by ID. Raises KeyError if not found."""
        card = self.get_card(card_id)
        if card is None:
            raise KeyError(f"No keycard found for ID '{card_id}'.")
        return card

    def revoke_card(self, card_id: str, reason: str, revoked_at: datetime | None = None) -> Keycard:
        """Administrative shortcut to find and revoke a card."""
        card = self.require_card(card_id)
        card.revoke(reason, revoked_at=revoked_at)
        return card

    def list_active_cards(self, when: date | datetime | None = None) -> list[Keycard]:
        """Returns a sorted list of cards that are currently functional."""
        when = when or date.today()
        active_cards = [
            card for card in self._cards.values() if card.active and not card.is_expired(when)
        ]
        return sorted(active_cards, key=lambda card: card.card_id)

    def list_by_access_level(self, level: AccessLevel) -> list[Keycard]:
        """Filters cards by a specific security clearance level."""
        matching_cards = [card for card in self._cards.values() if card.access_level == level]
        return sorted(matching_cards, key=lambda card: card.card_id)

    def all_cards(self) -> list[Keycard]:
        """Returns all cards in the registry sorted by ID."""
        return sorted(self._cards.values(), key=lambda card: card.card_id)

    def ingest_restored_keycard(self, card: Keycard) -> None:
        """Directly adds a pre-constructed card to the registry (for persistence)."""
        self._cards[card.card_id] = card


class AccessController:
    """The central orchestrator connecting Registry, Gates, Logs, and Monitors."""
    def __init__(
        self,
        registry: CardRegistry,
        gates: list[AccessGate],
        access_log: AccessLog | None = None,
        monitor: SuspiciousActivityMonitor | None = None,
    ) -> None:
        self.registry = registry
        # Initialize log and monitor if not provided by caller
        self.log = access_log or AccessLog()
        self.monitor = monitor or SuspiciousActivityMonitor()
        # Internal mapping of gate names to gate objects for lookup
        self._gates = {gate.name.lower(): gate for gate in gates}

    def add_gate(self, gate: AccessGate) -> None:
        """Adds a new physical gate to the controller's management."""
        self._gates[gate.name.lower()] = gate

    def get_gate(self, gate_name: str) -> AccessGate | None:
        """Retrieves a gate by name (case-insensitive)."""
        return self._gates.get(gate_name.strip().lower())

    def list_gates(self) -> list[AccessGate]:
        """Returns all gates, sorted primarily by security level and then by name."""
        return sorted(self._gates.values(), key=lambda gate: (gate.required_access_level, gate.name))

    def attempt_access(
        self,
        card_id: str,
        gate_name: str,
        timestamp: datetime | None = None,
    ) -> AccessDecision:
        """The primary workflow for simulating a person swiping a card at a gate."""
        # Normalize time and IDs
        timestamp = naive_facility_moment(timestamp or datetime.now())
        normalized_card_id = card_id.strip().upper()
        
        # Verify gate existence
        gate = self.get_gate(gate_name)
        if gate is None:
            raise KeyError(f"Unknown gate '{gate_name}'.")

        # Check if the card exists in our database
        card = self.registry.get_card(normalized_card_id)
        if card is None:
            # Deny access immediately if the card is unknown
            decision = AccessDecision(
                granted=False,
                reason="Unknown keycard.",
                keycard_id=normalized_card_id,
                gate_name=gate.name,
                timestamp=timestamp,
            )
        else:
            # Let the gate evaluate the card's credentials
            decision = gate.check_access(card, timestamp)

        # Audit the result and check for suspicious activity patterns
        entry = self.log.record(decision)
        alert = self.monitor.observe(entry)
        if alert:
            # If flagged, record the alert and attach a warning to the decision result
            self.log.record_alert(alert)
            decision = decision.with_warning(alert.message)
        return decision

    def flagged_cards(self) -> tuple[SecurityAlert, ...]:
        """Exposes flagged card alerts via the controller interface."""
        return self.monitor.flagged_cards()


def build_demo_controller() -> AccessController:
    """Factory function that generates a pre-populated system for demonstration."""
    registry = CardRegistry()
    today = date.today()

    # Create dummy users with varying access levels and expiration dates
    registry.issue_keycard(
        owner_name="Avery Stone",
        access_level=AccessLevel.VISITOR,
        issue_date=today,
        expiry_date=today + timedelta(days=14),
    )
    registry.issue_keycard(
        owner_name="Jordan Lee",
        access_level=AccessLevel.STAFF,
        issue_date=today - timedelta(days=5),
        expiry_date=today + timedelta(days=45),
    )
    registry.issue_keycard(
        owner_name="Sam Rivera",
        access_level=AccessLevel.MANAGER,
        issue_date=today - timedelta(days=10),
        expiry_date=today + timedelta(days=30),
    )
    registry.issue_keycard(
        owner_name="Riley Chen",
        access_level=AccessLevel.ADMIN,
        issue_date=today - timedelta(days=30),
        expiry_date=today + timedelta(days=365),
    )

    # Configure the physical layout of the demo facility
    gates = [
        AccessGate("Lobby Turnstile", "Main Entrance", AccessLevel.VISITOR),
        AccessGate(
            "Operations Wing",
            "East Hall",
            AccessLevel.STAFF,
            # Schedule for 8 AM to 6 PM
            time_window=GateSchedule(time(hour=8), time(hour=18)),
        ),
        AccessGate(
            "Vault Antechamber",
            "Sublevel 2",
            AccessLevel.MANAGER,
            # Schedule for 6 AM to 10 PM
            time_window=GateSchedule(time(hour=6), time(hour=22)),
        ),
        AccessGate("Control Room", "North Tower", AccessLevel.ADMIN),
    ]

    # Return the fully configured controller
    return AccessController(registry=registry, gates=gates)