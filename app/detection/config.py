"""Validate and fingerprint the exact configuration used for each finding."""

import hashlib
import json
from pathlib import Path


def load_rules(app):
    configured_path = app.config.get("DETECTION_RULES_FILE")
    path = Path(configured_path) if configured_path else Path(__file__).with_name("rules.json")
    try:
        rules = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise RuntimeError(f"Cannot read detection rule configuration: {path}") from error
    expected = {
        "failed_login_burst": {"threshold", "window_seconds", "cooldown_seconds", "weight"},
        "high_request_frequency": {"threshold", "window_seconds", "cooldown_seconds", "weight"},
        "restricted_access": {"cooldown_seconds", "weight"},
        "new_source_context": {"weight"},
    }
    if not isinstance(rules, dict) or set(rules) != set(expected):
        raise RuntimeError("Detection configuration must contain exactly the four supported rules.")
    for name, fields in expected.items():
        rule = rules[name]
        if not isinstance(rule, dict) or set(rule) != fields:
            raise RuntimeError(f"Invalid configuration fields for {name}.")
        for field, value in rule.items():
            maximum = 100 if field == "weight" else 10000 if field == "threshold" else 86400
            if type(value) is not int or not 1 <= value <= maximum:
                raise RuntimeError(f"{name}.{field} must be an integer from 1 to {maximum}.")
    canonical = json.dumps(rules, sort_keys=True, separators=(",", ":"))
    app.extensions["detection"] = {
        "rules": rules,
        "configuration": canonical,
        "version": hashlib.sha256(canonical.encode()).hexdigest(),
    }

