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

