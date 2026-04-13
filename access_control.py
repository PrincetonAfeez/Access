from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import date, datetime, time, timedelta
from enum import IntEnum
from itertools import count

def naive_facility_moment(moment: datetime) -> datetime:

    if moment.tzinfo is None:
        return moment
    return moment.astimezone().replace(tzinfo=None)

class AccessLevel(IntEnum):
    VISITOR = 1
    STAFF = 2
    MANAGER = 3
    ADMIN = 4

    @classmethod 
    def from_string(cls, raw_value: str) -> "AccessLevel":
        normalized = raw_value.strip().upper() 
        try:
            return cls[normalized] 
        except KeyError as exc:
            valid_levels = ", ".join(level.name for level in cls)
            raise ValueError(
                f"Unknown access level '{raw_value}'. Choose from: {valid_levels}."
            ) from exc
 
class Keycard:
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
        owner_name = owner_name.strip()
        if not owner_name:
            raise ValueError("Owner name cannot be blank.")
        if expiry_date < issue_date:
            raise ValueError("Expiry date cannot be earlier than issue date.")

        self.__card_id = card_id
        self.__owner_name = owner_name
        self.__access_level = access_level
        self.__issue_date = issue_date
        self.__expiry_date = expiry_date
        self.__active = True
        self.__revoked = False
        self.__revocation_reason: str | None = None
        self.__revoked_at: datetime | None = None


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
        return self.__active

    @property
    def revoked(self) -> bool:
        return self.__revoked

    @property
    def revocation_reason(self) -> str | None:
        return self.__revocation_reason

    @property
    def revoked_at(self) -> datetime | None:
        return self.__revoked_at
    
    def update_access_level(self, new_level: AccessLevel) -> None:
        if not isinstance(new_level, AccessLevel):
            raise TypeError("new_level must be an AccessLevel.")
        self.__access_level = new_level
    
    def revoke(self, reason: str, revoked_at: datetime | None = None) -> None:
        reason = reason.strip()
        if not reason:
            raise ValueError("A revocation reason is required.")
        if self.__revoked:
            raise ValueError("Keycard is already revoked.")

        self.__active = False
        self.__revoked = True
        self.__revocation_reason = reason
        self.__revoked_at = revoked_at or datetime.now()

    def deactivate(self) -> None:
        if self.__revoked:
            raise ValueError("Cannot deactivate a revoked keycard.")
        self.__active = False

    def reactivate(self) -> None:
        if self.__revoked:
            raise ValueError("Cannot reactivate a revoked keycard.")
        self.__active = True
    
    def is_expired(self, when: date | datetime) -> bool:
        if isinstance(when, datetime):
            when = naive_facility_moment(when).date()
        return when > self.__expiry_date
    
    def status(self, when: date | datetime | None = None) -> str:
        if when is None:
            ref = date.today()
        elif isinstance(when, datetime):
            ref = naive_facility_moment(when).date()
        else:
            ref = when
        if self.__revoked:
            return "REVOKED"
        if self.is_expired(ref):
            return "EXPIRED"
        if not self.__active:
            return "INACTIVE"
        return "ACTIVE"

@dataclass(frozen=True, slots=True)
class GateSchedule:
    start_time: time
    end_time: time

    def __post_init__(self) -> None:
        if self.start_time == self.end_time:
            raise ValueError("Schedule start and end time cannot be the same.")

    def allows(self, moment: datetime) -> bool:
        moment = naive_facility_moment(moment)
        current_time = moment.time()
        if self.start_time < self.end_time:
            return self.start_time <= current_time <= self.end_time
        return current_time >= self.start_time or current_time <= self.end_time

    @property
    def label(self) -> str:
        return f"{self.start_time.strftime('%H:%M')} - {self.end_time.strftime('%H:%M')}"

@dataclass(frozen=True, slots=True)
class AccessDecision:
    granted: bool
    reason: str
    keycard_id: str
    gate_name: str
    timestamp: datetime
    warning: str | None = None

    def with_warning(self, warning: str) -> "AccessDecision":
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
    timestamp: datetime
    keycard_id: str
    gate_name: str
    granted: bool
    reason: str

@dataclass(frozen=True, slots=True)
class SecurityAlert:
    timestamp: datetime
    keycard_id: str
    denied_attempts: int
    window_minutes: int
    message: str


class AccessGate:
    __slots__ = ("name", "location", "required_access_level", "time_window")

    def __init__(
        self,
        name: str,
        location: str,
        required_access_level: AccessLevel,
        time_window: GateSchedule | None = None,
    ) -> None:
        self.name = name.strip()
        self.location = location.strip()
        self.required_access_level = required_access_level
        self.time_window = time_window

        if not self.name:
            raise ValueError("Gate name cannot be blank.")
        if not self.location:
            raise ValueError("Gate location cannot be blank.")

    def check_access(self, keycard: Keycard, timestamp: datetime) -> AccessDecision:
        ts = naive_facility_moment(timestamp)
        granted, reason = self._evaluate(keycard, ts)
        return AccessDecision(
            granted=granted,
            reason=reason,
            keycard_id=keycard.card_id,
            gate_name=self.name,
            timestamp=ts,
        )
    
    def _evaluate(self, keycard: Keycard, timestamp: datetime) -> tuple[bool, str]:
        if keycard.revoked:
            reason = keycard.revocation_reason or "No reason recorded."
            return False, f"Keycard revoked: {reason}"
        if not keycard.active:
            return False, "Keycard is deactivated (not revoked)."
        if keycard.is_expired(timestamp):
            return False, f"Keycard expired on {keycard.expiry_date.isoformat()}."
        if keycard.access_level < self.required_access_level:
            return (
                False,
                f"Insufficient access level. Requires {self.required_access_level.name}.",
            )
        if self.time_window and not self.time_window.allows(timestamp):
            return (
                False,
                f"Outside allowed access window for this gate ({self.time_window.label}).",
            )
        return True, "Access granted."


class AccessLog:
    def __init__(self) -> None:
        self._entries: list[AccessLogEntry] = []
        self._alerts: list[SecurityAlert] = []
    
    def record(self, decision: AccessDecision) -> AccessLogEntry:
        entry = AccessLogEntry(
            timestamp=decision.timestamp,
            keycard_id=decision.keycard_id,
            gate_name=decision.gate_name,
            granted=decision.granted,
            reason=decision.reason,
        )
        self._entries.append(entry)
        return entry


