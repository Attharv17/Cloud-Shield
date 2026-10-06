import hashlib
import json
from pathlib import Path


def load_policy(app):
    default = Path(__file__).with_name("policy.json")
    path = Path(app.config.get("RISK_POLICY_FILE") or default)
    try:
        policy = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise RuntimeError(f"Cannot read risk policy: {path}") from error
    expected = set(json.loads(default.read_text(encoding="utf-8")))
    if not isinstance(policy, dict) or set(policy) != expected:
        raise RuntimeError("Risk policy must contain exactly the supported fields.")
    for key, value in policy.items():
        maximum = 86400 if key.endswith("seconds") else 100
        if type(value) is not int or not 1 <= value <= maximum:
            raise RuntimeError(f"Invalid risk policy value: {key}.")
    if not policy["medium_threshold"] < policy["high_threshold"] < policy["critical_threshold"]:
        raise RuntimeError("Risk severity thresholds must be strictly increasing.")
    canonical = json.dumps(policy, sort_keys=True, separators=(",", ":"))
    app.extensions["risk"] = {"policy": policy, "configuration": canonical,
                              "version": hashlib.sha256(canonical.encode()).hexdigest()}
