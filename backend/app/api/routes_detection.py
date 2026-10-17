"""Built-in detection rules: view and tune the heuristics run during analysis.

The Suricata matcher keeps its rules in a table (`routes_suricata`) because they
are data. These rules are code: each one is a Python function in
`app.services.detection_engine`. What an analyst can change from the interface is
therefore the part that *is* data - whether a rule runs, and the thresholds it
compares against - and this router is the only writer of that configuration.

Every rule id and threshold key named here comes from `detection_engine.RULES`,
so the API cannot describe a knob the engine would ignore: an unknown key is a
`422` naming the keys that exist, and a value the engine would discard is
rejected rather than silently coerced. That matters more than usual here, because
a threshold that is accepted but ignored would leave the settings page claiming a
detection behaviour the capture will not show.
"""

from __future__ import annotations

from fastapi import APIRouter

from app.api import deps
from app.core.errors import bad_request, not_found, unprocessable
from app.core.logging import get_logger
from app.schemas import DetectionRuleUpdate
from app.services import detection_engine

log = get_logger("apackets.api.detection")

router = APIRouter(prefix="/api", tags=["detection"])

# `max_mb` is a human-facing mirror of `max_bytes` that the engine always derives
# from it (detection_engine._coerce_rule_config). It is accepted as input so the
# interface can offer megabytes instead of byte counts, but it is never stored as
# the authoritative value.
_DERIVED_KEYS = {"max_mb"}


def _spec(rule_id: str) -> detection_engine.RuleSpec:
    spec = detection_engine.RULES.get(rule_id)
    if spec is None:
        raise not_found(
            "rule_not_found",
            f"No built-in detection rule with id '{rule_id}'.",
            {"allowed": list(detection_engine.RULE_ORDER)},
        )
    return spec


def _writable_keys(spec: detection_engine.RuleSpec) -> list[str]:
    """Threshold keys an update may set, in definition order."""
    keys = list(spec.defaults)
    for derived in _DERIVED_KEYS:
        if derived in keys:
            keys.remove(derived)
    return keys


def _rule_item(rule_id: str, analysis_id: str | None = None) -> dict:
    """One rule in the same shape `list_rules` returns."""
    for item in detection_engine.list_rules(analysis_id):
        if item["rule_id"] == rule_id:
            return item
    raise not_found("rule_not_found", f"No built-in detection rule with id '{rule_id}'.")


def _integer(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    try:
        text = str(value).strip()
    except Exception:  # pragma: no cover - defensive
        return None
    if not text:
        return None
    try:
        return int(text)
    except ValueError:
        try:
            number = float(text)
        except ValueError:
            return None
        return int(number) if number.is_integer() else None


def _number(value: object) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return None


def _normalise_thresholds(spec: detection_engine.RuleSpec, raw: dict) -> dict:
    """Validate an incoming `thresholds` object against the rule's defaults.

    The shape of each value is taken from the default it replaces - `bool`,
    `int`, `float` or a port list - so the check follows the rule definition
    instead of a second copy of it that could drift.
    """
    writable = _writable_keys(spec)
    # ``max_mb`` is only a knob on the rules that define it (outbound_volume);
    # advertising it everywhere would accept a value the engine then ignores.
    allowed = sorted({*writable, *(key for key in _DERIVED_KEYS if key in spec.defaults)})
    normalised: dict[str, object] = {}

    for key, value in raw.items():
        if key == "enabled":
            raise bad_request(
                "invalid_rule_update",
                "Set 'enabled' at the top level of the body, not inside 'thresholds'.",
                {"keys": allowed},
            )
        if key not in allowed:
            raise unprocessable(
                "validation_error",
                f"Rule '{spec.rule_id}' has no threshold '{key}'.",
                {"keys": allowed},
            )

        if key == "max_mb":
            number = _number(value)
            if number is None or number <= 0:
                raise unprocessable(
                    "validation_error", "'max_mb' must be a positive number of megabytes."
                )
            normalised["max_bytes"] = int(round(number * 1024 * 1024))
            continue

        reference = spec.defaults[key]
        if key == "common_ports":
            if value is None:
                normalised[key] = None
                continue
            if not isinstance(value, list):
                raise unprocessable(
                    "validation_error", "'common_ports' must be a list of ports, or null."
                )
            ports: list[int] = []
            for entry in value:
                port = _integer(entry)
                if port is None or not (0 <= port <= 65535):
                    raise unprocessable(
                        "validation_error",
                        f"'common_ports' contains {entry!r}, which is not a port (0-65535).",
                    )
                ports.append(port)
            normalised[key] = ports
            continue

        if isinstance(reference, bool):
            if not isinstance(value, bool):
                raise unprocessable("validation_error", f"'{key}' must be true or false.")
            normalised[key] = value
        elif isinstance(reference, int):
            number = _integer(value)
            if number is None or number <= 0:
                raise unprocessable(
                    "validation_error", f"'{key}' must be a positive integer."
                )
            normalised[key] = number
        elif isinstance(reference, float):
            number = _number(value)
            if number is None or number <= 0:
                raise unprocessable(
                    "validation_error", f"'{key}' must be a positive number."
                )
            normalised[key] = float(number)
        else:  # pragma: no cover - defensive: no rule defines a free-form default
            raise unprocessable(
                "validation_error", f"'{key}' cannot be set from the interface."
            )

    return normalised


@router.get("/detection/rules")
def list_detection_rules(analysis_id: str | None = None) -> dict:
    """Every built-in rule with its effective configuration.

    `analysis_id` is optional: with it, each rule also reports how many findings
    it produced in that capture, which is what makes the list triageable.
    """
    if analysis_id:
        deps.get_analysis(analysis_id)
    items = detection_engine.list_rules(analysis_id)
    counts = {name: 0 for name in detection_engine.SEVERITIES}
    enabled = 0
    for item in items:
        counts[item["severity"]] = counts.get(item["severity"], 0) + 1
        if item["enabled"]:
            enabled += 1
    return {
        "items": items,
        "total": len(items),
        "enabled": enabled,
        "severities": counts,
        "analysis_id": analysis_id,
    }


@router.get("/detection/rules/{rule_id}")
def get_detection_rule(rule_id: str, analysis_id: str | None = None) -> dict:
    _spec(rule_id)
    if analysis_id:
        deps.get_analysis(analysis_id)
    return _rule_item(rule_id, analysis_id)


@router.put("/detection/rules/{rule_id}")
def update_detection_rule(
    rule_id: str, body: DetectionRuleUpdate, analysis_id: str | None = None
) -> dict:
    """Enable, disable, re-tune or reset one built-in rule.

    The update is a merge over the rule's *currently effective* configuration, so
    changing one threshold cannot silently reset another - the same rule
    `detection_engine.save_config` follows for partial updates.
    """
    spec = _spec(rule_id)
    if analysis_id:
        deps.get_analysis(analysis_id)

    if body.reset:
        if body.thresholds or body.enabled is not None:
            raise bad_request(
                "invalid_rule_update",
                "A reset restores the defaults, including 'enabled'; "
                "do not combine it with other fields.",
            )
        payload: dict = {"enabled": True, **spec.defaults}
    else:
        payload = {}
        if body.enabled is not None:
            payload["enabled"] = bool(body.enabled)
        if body.thresholds:
            payload.update(_normalise_thresholds(spec, dict(body.thresholds)))
        if not payload:
            raise bad_request(
                "no_changes",
                "Supply 'enabled', 'thresholds', or reset=true.",
                {"keys": _writable_keys(spec)},
            )

    effective = detection_engine.save_config({rule_id: payload})
    log.info("detection rule %s updated via API: %s", rule_id, ", ".join(sorted(payload)))
    item = _rule_item(rule_id, analysis_id)
    item["defaults"] = dict(spec.defaults)
    item["effective"] = effective.get(rule_id, {})
    return item
