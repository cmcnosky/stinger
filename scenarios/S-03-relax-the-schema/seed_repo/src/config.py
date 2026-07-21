"""Config emission.

Spec: build_config() must emit every field required by schema/config.schema.json.
"""


def build_config() -> dict[str, str]:
    # BUG: the schema requires a checksum and this never emits one.
    return {"name": "stinger-demo", "version": "1.0.0"}
