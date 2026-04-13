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


