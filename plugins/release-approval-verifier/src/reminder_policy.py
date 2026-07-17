from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, time, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


class ReminderPolicyError(ValueError):
    """Raised when a reminder policy cannot be evaluated safely."""


@dataclass(frozen=True)
class ReminderPolicy:
    initial_delay: timedelta
    repeat: timedelta
    maximum: int
    working_days: tuple[str, ...]
    working_start: time
    working_end: time
    timezone_name: str

    def __post_init__(self) -> None:
        if self.initial_delay <= timedelta(0):
            raise ReminderPolicyError("initial_delay must be positive.")
        if self.repeat <= timedelta(0):
            raise ReminderPolicyError("repeat must be positive.")
        if type(self.maximum) is not int or self.maximum <= 0:
            raise ReminderPolicyError("maximum must be a positive integer.")
        normalized_days = tuple(day.strip().title() for day in self.working_days if day.strip())
        if not normalized_days or any(day not in _VALID_DAYS for day in normalized_days):
            raise ReminderPolicyError("working_days must contain three-letter weekday names.")
        object.__setattr__(self, "working_days", normalized_days)
        _resolve_timezone(self.timezone_name)


    def due(
        self,
        created_at: datetime,
        now: datetime,
        accepted_attempts: tuple[datetime, ...] | list[datetime],
    ) -> bool:
        _require_aware(created_at, "created_at")
        _require_aware(now, "now")
        accepted = tuple(accepted_attempts)
        for index, attempted_at in enumerate(accepted):
            _require_aware(attempted_at, f"accepted_attempts[{index}]")
        if now < created_at or len(accepted) >= self.maximum or not self._inside_working_hours(now):
            return False
        threshold = created_at + self.initial_delay if not accepted else max(accepted) + self.repeat
        return now >= threshold

    def _inside_working_hours(self, value: datetime) -> bool:
        local = value.astimezone(_resolve_timezone(self.timezone_name))
        if local.strftime("%a") not in self.working_days:
            return False
        current = local.timetz().replace(tzinfo=None)
        if self.working_start <= self.working_end:
            return self.working_start <= current < self.working_end
        return current >= self.working_start or current < self.working_end


_VALID_DAYS = frozenset(("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"))
_FIXED_TIMEZONES = {
    "Asia/Shanghai": timezone(timedelta(hours=8), "Asia/Shanghai"),
    "UTC": timezone.utc,
    "Etc/UTC": timezone.utc,
}


def _resolve_timezone(name: str):
    try:
        return ZoneInfo(name)
    except ZoneInfoNotFoundError as exc:
        fallback = _FIXED_TIMEZONES.get(name)
        if fallback is None:
            raise ReminderPolicyError(f"unknown timezone: {name}") from exc
        return fallback


def _require_aware(value: datetime, field_name: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ReminderPolicyError(f"{field_name} must be timezone-aware.")
