from __future__ import annotations

import fnmatch
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from iam_audit.models import FiltersApplied, Principal


def filter_by_path_prefix(principals: list[Principal], prefix: str) -> list[Principal]:
    return [p for p in principals if p.path.startswith(prefix)]


def filter_by_name_pattern(principals: list[Principal], pattern: str) -> list[Principal]:
    return [p for p in principals if fnmatch.fnmatch(p.name, pattern)]


def filter_by_tags(principals: list[Principal], tag_filters: dict[str, str]) -> list[Principal]:
    return [p for p in principals if all(p.tags.get(k) == v for k, v in tag_filters.items())]


def apply_filters(principals: list[Principal], filters: FiltersApplied) -> list[Principal]:
    result = principals
    if filters.path_prefix is not None:
        result = filter_by_path_prefix(result, filters.path_prefix)
    if filters.name_pattern is not None:
        result = filter_by_name_pattern(result, filters.name_pattern)
    if filters.tags is not None:
        result = filter_by_tags(result, filters.tags)
    return result
