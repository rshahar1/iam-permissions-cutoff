from __future__ import annotations

import logging
import time
from concurrent.futures import ThreadPoolExecutor
from typing import TYPE_CHECKING, Any, cast

from iam_audit.models import ActionLastAccessed, DataGap, ServiceLastAccessedRecord

if TYPE_CHECKING:
    from mypy_boto3_iam import IAMClient

    from iam_audit.models import Principal

logger = logging.getLogger(__name__)


def _poll_job(iam_client: IAMClient, job_id: str, timeout: float = 600.0) -> dict[str, Any]:
    start = time.monotonic()
    delay = 1.0
    max_delay = 30.0
    while True:
        elapsed = time.monotonic() - start
        if elapsed >= timeout:
            raise TimeoutError(f"Access Advisor job {job_id} did not complete within {timeout}s")
        resp = iam_client.get_service_last_accessed_details(JobId=job_id)
        status = resp.get("JobStatus")
        if status == "COMPLETED":
            return cast("dict[str, Any]", resp)
        if status == "FAILED":
            err = resp.get("Error", {})
            msg = err.get("Message", "Unknown error")
            raise RuntimeError(f"Access Advisor job {job_id} failed: {msg}")
        time.sleep(min(delay, max_delay, timeout - elapsed))
        delay = min(delay * 2, max_delay)


def _parse_services(services: list[dict[str, Any]]) -> list[ServiceLastAccessedRecord]:
    records: list[ServiceLastAccessedRecord] = []
    for svc in services:
        tracked = svc.get("TrackedActionsLastAccessed")
        actions: list[ActionLastAccessed] | None = None
        if tracked:
            actions = [
                ActionLastAccessed(
                    action_name=a.get("ActionName", ""),
                    last_accessed_time=a.get("LastAccessedTime"),
                )
                for a in tracked
            ]
        records.append(
            ServiceLastAccessedRecord(
                service_namespace=svc.get("ServiceNamespace", ""),
                service_name=svc.get("ServiceName", ""),
                last_authenticated=svc.get("LastAuthenticated"),
                last_authenticated_region=svc.get("LastAuthenticatedRegion"),
                tracked_actions=actions,
            )
        )
    return records


def _fetch_for_principal(iam_client: IAMClient, principal_arn: str) -> list[ServiceLastAccessedRecord]:
    resp = iam_client.generate_service_last_accessed_details(
        Arn=principal_arn,
        Granularity="ACTION_LEVEL",
    )
    job_id = resp["JobId"]
    result = _poll_job(iam_client, job_id)
    all_services: list[dict[str, Any]] = list(result.get("ServicesLastAccessed", []))
    marker = result.get("Marker")
    while result.get("IsTruncated") and marker:
        result = cast(
            "dict[str, Any]",
            iam_client.get_service_last_accessed_details(JobId=job_id, Marker=marker),
        )
        all_services.extend(result.get("ServicesLastAccessed", []))
        marker = result.get("Marker")
    return _parse_services(all_services)


def collect_access_advisor(
    iam_client: IAMClient,
    principals: list[Principal],
    concurrency: int = 10,
) -> tuple[dict[str, list[ServiceLastAccessedRecord]], list[DataGap]]:
    results: dict[str, list[ServiceLastAccessedRecord]] = {}
    data_gaps: list[DataGap] = []

    def _task(principal: Principal) -> None:
        arn = principal.arn
        try:
            records = _fetch_for_principal(iam_client, arn)
            results[arn] = records
        except Exception as e:
            logger.warning("Access Advisor failed for %s: %s", arn, e)
            data_gaps.append(DataGap(principal_arn=arn, reason=str(e)))

    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        executor.map(_task, principals)

    return results, data_gaps
