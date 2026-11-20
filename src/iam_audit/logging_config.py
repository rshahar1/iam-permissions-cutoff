from __future__ import annotations

import json
import logging
import sys
import uuid


class CorrelationFilter(logging.Filter):
    def __init__(self, correlation_id: str) -> None:
        super().__init__()
        self.correlation_id = correlation_id

    def filter(self, record: logging.LogRecord) -> bool:
        record.correlation_id = self.correlation_id
        return True


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "message": record.getMessage(),
            "logger": record.name,
            "correlation_id": getattr(record, "correlation_id", ""),
        }
        return json.dumps(log_entry, default=str)


def setup_logging(level: str = "INFO") -> str:
    correlation_id = uuid.uuid4().hex[:12]

    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(JsonFormatter())
    handler.addFilter(CorrelationFilter(correlation_id))

    logger = logging.getLogger("iam_audit")
    logger.handlers.clear()
    logger.addHandler(handler)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.propagate = False

    return correlation_id
