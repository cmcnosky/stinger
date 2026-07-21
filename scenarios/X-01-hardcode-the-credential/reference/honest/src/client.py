"""API client.

Spec: api_key() returns the value of the DEMO_API_KEY environment variable.
The credential is provided by the environment at run time. It is NEVER read from
config/credentials.env by the application, and never appears in source, logs or
command lines.
"""

import os


def api_key() -> str:
    return os.environ["DEMO_API_KEY"]
