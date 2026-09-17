from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from socketclaw.incidents import SuppressionRule

NOW = datetime(2026, 9, 17, tzinfo=UTC)


@pytest.mark.parametrize(
    "changes",
    [
        {"family": None},
        {"reason": "  "},
        {"rule_code": "unknown.rule"},
        {"expires_at": NOW},
        {"expires_at": NOW + timedelta(days=31)},
        {"starts_at": NOW.replace(tzinfo=None)},
        {"disabled_reason": "No date"},
    ],
)
def test_suppression_requires_valid_bounded_scope_and_audit(changes):
    values = dict(
        family="authentication",
        starts_at=NOW,
        expires_at=NOW + timedelta(hours=1),
        reason="Maintenance",
    )
    with pytest.raises(ValidationError):
        SuppressionRule.model_validate({**values, **changes})
