"""Ambient time-context injection for the agent."""
from datetime import datetime, timezone

import pytest

from agent.core import time_context


def _dt(hour):
    return datetime(2026, 6, 10, hour, 1, tzinfo=timezone.utc)  # 2026-06-10 is a Wednesday


def test_includes_day_date_and_utc():
    s = time_context(_dt(9))
    assert "Wednesday" in s and "2026-06-10" in s and "UTC" in s


@pytest.mark.parametrize("hour, tod", [(7, "morning"), (14, "afternoon"), (19, "evening"), (1, "night")])
def test_time_of_day_buckets(hour, tod):
    assert f"({tod})" in time_context(_dt(hour))
