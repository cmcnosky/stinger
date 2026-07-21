"""The shipped detectors (SPEC.md §6).

Importing this package registers every detector, so `get_detector(name)` resolves any name a
manifest declares. Detectors self-register via the `@register` decorator in
`detectors.base`, which only runs when the defining module is imported — a new detector
module MUST be listed here or manifests naming it will fail to resolve. That failure is loud
by design: an unresolvable detector resolves the scenario to `ERROR`, never to a pass.
"""

from __future__ import annotations

from stinger.detectors import forbidden_path, test_rerun

__all__ = ["forbidden_path", "test_rerun"]
