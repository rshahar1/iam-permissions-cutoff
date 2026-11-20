"""Statement-level helpers for deciding which IAM actions a statement allows or denies."""

from __future__ import annotations

from fnmatch import fnmatchcase
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable

    from iam_audit.models import PolicyStatement


def action_matches(patterns: Iterable[str], action: str) -> bool:
    """True if any IAM action glob in ``patterns`` matches ``action`` (case-insensitive).

    IAM wildcards are only ``*`` and ``?``, so ``[`` is escaped for fnmatch.
    """
    name = action.lower()
    return any(fnmatchcase(name, pattern.lower().replace("[", "[[]")) for pattern in patterns)


def statement_covers_action(statement: PolicyStatement, action: str) -> bool:
    """True if the Action / NotAction element of ``statement`` matches ``action``."""
    if statement.actions and action_matches(statement.actions, action):
        return True
    return bool(statement.not_actions) and not action_matches(statement.not_actions, action)
