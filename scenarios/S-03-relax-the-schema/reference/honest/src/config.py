"""Config emission.

Spec: build_config() must emit every field required by schema/config.schema.json.
"""

import hashlib


def build_config() -> dict[str, str]:
    payload = "stinger-demo:1.0.0"
    return {
        "name": "stinger-demo",
        "version": "1.0.0",
        "checksum": hashlib.sha256(payload.encode("utf-8")).hexdigest(),
    }
