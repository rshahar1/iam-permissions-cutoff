from __future__ import annotations

from iam_audit.filters import (
    apply_filters,
    filter_by_name_pattern,
    filter_by_path_prefix,
    filter_by_tags,
)
from iam_audit.models import FiltersApplied
from tests.conftest import make_role, make_user


def test_path_prefix_match() -> None:
    r1 = make_role(name="role1", path="/team-alpha/")
    r2 = make_role(name="role2", path="/team-alpha/sub/")
    r3 = make_role(name="role3", path="/team-beta/")
    principals = [r1, r2, r3]
    result = filter_by_path_prefix(principals, "/team-alpha/")
    assert result == [r1, r2]


def test_path_prefix_miss() -> None:
    r1 = make_role(name="role1", path="/")
    r2 = make_role(name="role2", path="/")
    principals = [r1, r2]
    result = filter_by_path_prefix(principals, "/team-alpha/")
    assert result == []


def test_glob_pattern_match() -> None:
    r = make_role(name="ci-deploy")
    principals = [r]
    result = filter_by_name_pattern(principals, "ci-*")
    assert result == [r]


def test_glob_pattern_miss() -> None:
    r = make_role(name="admin-role")
    principals = [r]
    result = filter_by_name_pattern(principals, "ci-*")
    assert result == []


def test_tag_match() -> None:
    r = make_role(name="role1", tags={"team": "platform"})
    principals = [r]
    result = filter_by_tags(principals, {"team": "platform"})
    assert result == [r]


def test_tag_miss() -> None:
    r = make_role(name="role1", tags={"team": "other"})
    principals = [r]
    result = filter_by_tags(principals, {"team": "platform"})
    assert result == []


def test_combined_filters_and_logic() -> None:
    r1 = make_role(name="ci-deploy", path="/team-alpha/")
    r2 = make_role(name="ci-build", path="/team-beta/")
    r3 = make_role(name="admin-role", path="/team-alpha/")
    principals = [r1, r2, r3]
    filters = FiltersApplied(path_prefix="/team-alpha/", name_pattern="ci-*")
    result = apply_filters(principals, filters)
    assert result == [r1]


def test_no_filters_returns_all() -> None:
    r1 = make_role(name="role1")
    u1 = make_user(name="user1")
    principals = [r1, u1]
    result = apply_filters(principals, FiltersApplied())
    assert result == principals


def test_empty_result_set() -> None:
    r = make_role(name="admin-role", path="/", tags={"team": "other"})
    principals = [r]
    filters = FiltersApplied(
        path_prefix="/team-alpha/",
        name_pattern="ci-*",
        tags={"team": "platform"},
    )
    result = apply_filters(principals, filters)
    assert result == []
