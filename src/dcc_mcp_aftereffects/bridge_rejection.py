"""Public-safe rendering of structured broker connection rejections.

When the adobepy broker refuses an After Effects connection or session it can
return a JSON-RPC error carrying ``code``, ``message`` and an optional
``data.missingFields`` list (for example ``-32010`` with
``["adapterOwnedLaunchReceipt"]``).  The adapter's readiness probe used to
collapse each of those failures into a generic line, so the fail-closed reason
was invisible without a separate WebSocket handshake.

This module turns such a rejection into a small, **public-safe** view that the
Bridge panel, ``verify`` output and readiness logs can display: only a numeric
code, a bounded human-readable message and validated field names are exposed.
Broker free-form text is shown only when it is clean; otherwise a curated,
public-safe message is used.  Tokens, local paths, opaque secrets and envelope
diagnostics are never echoed, matching the adapter's existing redaction
contract.  Surfacing a rejection is observability only - it never claims that
launch-receipt / typed-identity connectivity exists.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping

_MAX_CODE = 2_147_483_647
_MAX_MESSAGE_LEN = 220
_MAX_FIELD_LEN = 64
_MAX_MISSING_FIELDS = 16

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
# A single "word" that embeds a credential-like label.
_SECRET_RE = re.compile(
    r"[A-Za-z0-9_.\-]*"
    r"(?:token|secret|password|passwd|credential|bearer|private)"
    r"[A-Za-z0-9_.\-]*",
    re.IGNORECASE,
)
_OPAQUE_RE = re.compile(r"[A-Za-z0-9+/=_-]{28,}")
_PATH_RE = re.compile(r"(?:[A-Za-z]:[\\/]|\\\\|/)[^\s\"',;:]*")
_FIELD_RE = re.compile(r"[A-Za-z][A-Za-z0-9_.:-]{0,%d}" % (_MAX_FIELD_LEN - 1))

_CURATED_MESSAGES: Mapping[int, str] = {
    -32010: (
        "After Effects runtime identity requires a trusted adapter-owned launch "
        "receipt; the connection stays fail-closed"
    ),
}
_DEFAULT_MESSAGE = "The adobepy broker rejected the After Effects bridge session (fail-closed)"


def _valid_code(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if -_MAX_CODE <= value <= _MAX_CODE else None


def _valid_field(value: Any) -> str | None:
    if not isinstance(value, str) or _FIELD_RE.fullmatch(value) is None:
        return None
    if _SECRET_RE.search(value) or _OPAQUE_RE.search(value):
        return None
    return value


def _valid_missing_fields(value: Any) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        return ()
    fields = []
    for raw in value[:_MAX_MISSING_FIELDS]:
        field = _valid_field(raw)
        if field is not None:
            fields.append(field)
    return tuple(fields)


def _clean_text(raw: str) -> str:
    return " ".join(_CONTROL_RE.sub(" ", raw).split())[:_MAX_MESSAGE_LEN].rstrip()


def public_message(raw: Any, *, token: str | None, code: int | None) -> str:
    """Return a public-safe message for a rejection, never raw unsafe text.

    The broker's own ``message`` is useful when it is plain text (for example
    "After Effects runtime identity requires an adapter-owned launch receipt"),
    but it may embed a token, a local path or other diagnostics.  Show it only
    when it is clean; otherwise fall back to a curated, public-safe message.
    """
    curated = (
        _CURATED_MESSAGES.get(code, _DEFAULT_MESSAGE) if code is not None else _DEFAULT_MESSAGE
    )
    if not isinstance(raw, str):
        return curated
    text = _clean_text(raw)
    if not text:
        return curated
    if token and token in text:
        return curated
    if _SECRET_RE.search(text) or _PATH_RE.search(text) or _OPAQUE_RE.search(text):
        return curated
    return text


@dataclass(frozen=True)
class BrokerRejection:
    """A public-safe, structured view of one broker connection rejection."""

    code: int | None
    message: str
    missing_fields: tuple[str, ...] = ()

    def as_public_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable, token-free view for panels and reports."""
        payload: dict[str, Any] = {}
        if self.code is not None:
            payload["code"] = self.code
        payload["message"] = self.message
        if self.missing_fields:
            payload["missingFields"] = list(self.missing_fields)
        return payload

    def render(self) -> str:
        """Render one bounded, single-line suffix appended to a failure reason."""
        parts = []
        if self.code is not None:
            parts.append(f"code {self.code}")
        parts.append(f"message: {self.message}")
        if self.missing_fields:
            parts.append("missingFields: " + ", ".join(self.missing_fields))
        return "broker rejection (" + "; ".join(parts) + ")"


def _from_error(error: Mapping[str, Any], *, token: str | None) -> BrokerRejection | None:
    code = _valid_code(error.get("code"))
    if code is None:
        return None
    data = error.get("data")
    missing = _valid_missing_fields(data.get("missingFields")) if isinstance(data, Mapping) else ()
    return BrokerRejection(
        code=code,
        message=public_message(error.get("message"), token=token, code=code),
        missing_fields=missing,
    )


def extract_rejection(source: Any, *, token: str | None = None) -> BrokerRejection | None:
    """Extract a public-safe rejection from an exception or a JSON-RPC mapping.

    ``source`` may be an SDK exception (``AdobePythonError`` with ``code``,
    ``data`` and ``args``), a JSON-RPC ``error`` mapping, or an envelope that
    contains an ``error`` mapping.  Returns ``None`` when there is no numeric
    broker error code, so generic transport/logic failures keep their existing
    fixed reasons instead of being echoed.
    """
    if isinstance(source, BaseException):
        code = _valid_code(getattr(source, "code", None))
        if code is None:
            return None
        data = getattr(source, "data", None)
        missing = (
            _valid_missing_fields(data.get("missingFields")) if isinstance(data, Mapping) else ()
        )
        raw = source.args[0] if source.args else None
        return BrokerRejection(
            code=code,
            message=public_message(raw, token=token, code=code),
            missing_fields=missing,
        )
    if isinstance(source, Mapping):
        error = source.get("error")
        return (
            _from_error(error, token=token)
            if isinstance(error, Mapping)
            else _from_error(source, token=token)
        )
    return None


__all__ = ["BrokerRejection", "extract_rejection", "public_message"]
