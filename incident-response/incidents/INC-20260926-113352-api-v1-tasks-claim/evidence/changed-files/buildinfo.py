"""Build/deploy identity read from the environment.

``APP_VERSION`` and ``GIT_SHA`` are baked into the image by the Dockerfile
(from ``scripts/release.sh``); ``DEPLOYMENT_ENVIRONMENT`` is set by compose.
Read at call time so tests can override them.
"""

from __future__ import annotations

import os

SERVICE_NAME = "agent-relay"


def app_version() -> str:
    return os.getenv("APP_VERSION") or "dev"


def git_sha() -> str:
    return os.getenv("GIT_SHA") or "unknown"


def environment() -> str:
    return os.getenv("DEPLOYMENT_ENVIRONMENT") or "dev"


def version_info() -> dict[str, str]:
    return {
        "service": SERVICE_NAME,
        "version": app_version(),
        "git_sha": git_sha(),
        "environment": environment(),
    }


__all__ = ["SERVICE_NAME", "app_version", "environment", "git_sha", "version_info"]
