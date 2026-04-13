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


