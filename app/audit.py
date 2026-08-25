"""Structured audit records for authentication, authorization and data access.

Each record is one JSON object on stdout, which is what the cluster's log
shipper collects. The fields are fixed, so a query can count refusals by reason
or trace every read a subject made.

Never pass a token, a secret, or a raw header into `record`. The caller's
subject and the scope it resolved to are the identifying fields; that is enough
to answer who read what, and it keeps credentials out of the log.
"""

import json
import logging
import sys
from datetime import datetime, timezone

AUDIT_LOGGER_NAME = "halden.audit"

_logger = logging.getLogger(AUDIT_LOGGER_NAME)


class JsonFormatter(logging.Formatter):
    """Render a record as a single JSON line.

    Anything the call site passed in `extra={"audit": {...}}` is merged in
    alongside the fixed fields.
    """

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.fromtimestamp(
                record.created, tz=timezone.utc
            ).isoformat(),
            "level": record.levelname,
            "event": record.getMessage(),
        }
        payload.update(getattr(record, "audit", {}))
        return json.dumps(payload, separators=(",", ":"), default=str)


def configure_audit_logging() -> None:
    """Send audit records to stdout as JSON. Safe to call more than once."""
    if _logger.handlers:
        return
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    _logger.addHandler(handler)
    _logger.setLevel(logging.INFO)
    # Audit records are their own stream; they do not also go to the root
    # logger's handlers, where they would be reformatted as plain text.
    _logger.propagate = False


def record(event: str, *, level: int = logging.INFO, **fields: object) -> None:
    """Write one audit record.

    `event` names what happened; `fields` carry the detail. Values must be
    non-secret: a subject, a scope, a route, a count, a refusal reason.
    """
    _logger.log(level, event, extra={"audit": fields})
