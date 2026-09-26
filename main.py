"""FastAPI routes for Agent Relay.

Persistence and SQLite transaction details live in :mod:`database` and
:mod:`storage`; the deterministic local worker is in :mod:`worker`.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import hmac
import logging
import os
import random
import time
from contextlib import asynccontextmanager
from typing import Any, Literal

from fastapi import Depends, FastAPI, Header, Path as FastAPIPath, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse, Response
from opentelemetry.instrumentation.utils import suppress_instrumentation
from sqlalchemy import text
from sqlalchemy.exc import OperationalError

from database import (
    DEFAULT_PAGE_SIZE,
    engine,
    MAX_BODY_BYTES,
    MAX_PAGE_SIZE,
    RECOVERY_INTERVAL_SECONDS,
    db_session,
    init_db,
    recover_expired,
)
import buildinfo
import telemetry
from dashboard import dashboard_html
from errors import RelayError
from logging_config import configure_logging
from telemetry import instruments
from schemas import (
    ClaimRequest,
    ClaimTokenRequest,
    CompleteRequest,
    FailRequest,
    RegisterRequest,
    TaskCreateRequest,
    agent_summary,
    attempt_summary,
    task_summary,
)
from storage import (
    authenticate,
    attempts_for_participant,
    claim_one,
    commit_terminal,
    create_task,
    decode_cursor,
    heartbeat,
    list_agents,
    list_tasks,
    register_agent,
    task_for_participant,
)


configure_logging()
LOGGER = logging.getLogger("agent_relay")
ACCESS_LOGGER = logging.getLogger("agent_relay.access")


def error_response(code: str, message: str, status_code: int) -> JSONResponse:
    return JSONResponse(status_code=status_code, content={"error": {"code": code, "message": message}})


def bearer_value(authorization: str | None) -> str:
    if not authorization:
        raise RelayError("missing_credentials", "Authorization: Bearer <agent-token> is required.", 401)
    scheme, separator, value = authorization.partition(" ")
    if not separator or scheme.lower() != "bearer" or not value.strip():
        raise RelayError("invalid_credentials", "Use Authorization: Bearer <agent-token>.", 401)
    return value.strip()


def current_agent(authorization: str | None = Header(default=None)):
    return authenticate(bearer_value(authorization))


def page_params(limit: int, cursor: str | None) -> tuple[int, tuple[Any, str] | None]:
    if limit < 1 or limit > MAX_PAGE_SIZE:
        raise RelayError("invalid_input", f"limit must be between 1 and {MAX_PAGE_SIZE}.", 400)
    return limit, decode_cursor(cursor)


async def recovery_loop(stop: asyncio.Event) -> None:
    while not stop.is_set():
        try:
            # Background housekeeping every few seconds: don't trace it (it would
            # dominate trace volume); recoveries are counted and logged instead.
            with suppress_instrumentation():
                recovered = await asyncio.to_thread(recover_expired)
            if recovered:
                LOGGER.info("recovered %d expired attempt(s)", recovered)
        except asyncio.CancelledError:
            raise
        except Exception:
            LOGGER.exception("lease recovery pass failed")
        try:
            await asyncio.wait_for(stop.wait(), timeout=RECOVERY_INTERVAL_SECONDS)
        except asyncio.TimeoutError:
            pass


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    stop = asyncio.Event()
    recovery_task = asyncio.create_task(recovery_loop(stop))
    try:
        yield
    finally:
        stop.set()
        recovery_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await recovery_task


app = FastAPI(title="Agent Relay", version="0.1.0", lifespan=lifespan)
# ASGI transports used by small scripts do not always run lifespan handlers;
# initialize the schema at import as well as during normal application startup.
init_db()


@app.exception_handler(RelayError)
async def relay_error_handler(_request: Request, exc: RelayError) -> JSONResponse:
    return error_response(exc.code, exc.message, exc.status_code)


@app.exception_handler(RequestValidationError)
async def request_validation_handler(_request: Request, exc: RequestValidationError) -> JSONResponse:
    # Avoid logging ``exc.errors()``: Pydantic includes submitted values and a
    # malformed claim body could otherwise put a credential in debug logs.
    LOGGER.debug("request validation failed (%d error(s))", len(exc.errors()))
    return error_response("invalid_input", "The request is invalid.", 400)


@app.middleware("http")
async def body_size_limit(request: Request, call_next):
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            too_large = int(content_length) > MAX_BODY_BYTES
        except ValueError:
            too_large = True
        if too_large:
            return error_response("body_too_large", "The request body is too large.", 413)
    return await call_next(request)


@app.middleware("http")
async def access_log(request: Request, call_next):
    # Added after body_size_limit, so it is the outer middleware and also
    # records that middleware's 413 responses. Logs only method, the matched
    # route template (never the raw path, which carries task ids), status and
    # duration: no headers, query strings or bodies.
    started = time.perf_counter()
    status = 500
    try:
        response = await call_next(request)
        status = response.status_code
        return response
    finally:
        route = request.scope.get("route")
        ACCESS_LOGGER.info(
            "%s %s %d",
            request.method,
            getattr(route, "path", None) or "unmatched",
            status,
            extra={
                "fields": {
                    "method": request.method,
                    "route": getattr(route, "path", None) or "unmatched",
                    "status": status,
                    "duration_ms": round((time.perf_counter() - started) * 1000, 2),
                }
            },
        )


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/ready")
async def ready() -> JSONResponse:
    try:
        # The probe is excluded from tracing, so keep its SQL spans out too.
        with suppress_instrumentation(), db_session() as db:
            # Check real tables, not just connectivity: after a volume wipe
            # or failed migration the DB can answer SELECT 1 while every
            # write 500s with "no such table". Missing tables -> 503.
            db.execute(text("SELECT 1 FROM agents LIMIT 1"))
            db.execute(text("SELECT 1 FROM tasks LIMIT 1"))
            db.execute(text("SELECT 1 FROM attempts LIMIT 1"))
    except Exception:
        return JSONResponse(status_code=503, content={"status": "not_ready"})
    return JSONResponse(status_code=200, content={"status": "ready"})


@app.get("/version")
async def version() -> dict[str, str]:
    return buildinfo.version_info()


@app.post("/api/v1/agents", status_code=201)
async def register(
    body: RegisterRequest,
    x_enrollment_secret: str | None = Header(default=None),
) -> dict[str, str]:
    enrollment_secret = os.getenv("RELAY_ENROLLMENT_SECRET") or os.getenv("ENROLLMENT_SECRET")
    if enrollment_secret is not None and not hmac.compare_digest(x_enrollment_secret or "", enrollment_secret):
        raise RelayError("invalid_enrollment", "A valid enrollment secret is required.", 401)
    return register_agent(body.name, body.description)


@app.get("/api/v1/agents")
async def agents(
    current=Depends(current_agent),
    cursor: str | None = Query(default=None),
    limit: int = Query(default=DEFAULT_PAGE_SIZE),
) -> dict[str, Any]:
    del current
    limit, decoded = page_params(limit, cursor)
    rows, next_cursor = list_agents(limit, decoded)
    return {"items": [agent_summary(row) for row in rows], "next_cursor": next_cursor}


@app.get("/api/v1/agents/me")
async def me(current=Depends(current_agent)) -> dict[str, Any]:
    return agent_summary(current)


@app.post("/api/v1/tasks", status_code=201)
async def tasks_create(
    body: TaskCreateRequest,
    current=Depends(current_agent),
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
) -> JSONResponse:
    outcome = "error"
    try:
        if idempotency_key is not None and (
            not idempotency_key.strip() or len(idempotency_key) > 255 or "\x00" in idempotency_key
        ):
            raise RelayError("invalid_input", "Idempotency-Key must be nonempty and at most 255 characters.", 400)
        for retry in range(3):
            try:
                result = create_task(current.id, body.to, body.input, idempotency_key)
                outcome = "ok"
                return JSONResponse(status_code=201, content=result)
            except OperationalError as exc:
                if retry == 2 or "locked" not in str(exc).lower():
                    raise
                await asyncio.sleep(0.05 * (retry + 1))
        raise RelayError("storage_error", "The task could not be persisted.", 503)
    finally:
        instruments.tasks_created.add(1, {"outcome": outcome})


@app.post("/api/v1/tasks/claim")
async def claim(
    body: ClaimRequest,
    current=Depends(current_agent),
) -> Response:
    started = time.monotonic()
    deadline = started + body.wait_seconds
    outcome = "error"
    try:
        while True:
            try:
                result = await asyncio.to_thread(claim_one, current.id, body.worker_id)
            except OperationalError as exc:
                if "locked" not in str(exc).lower():
                    raise
                result = None
            if result is not None:
                outcome = "claimed"
                return JSONResponse(status_code=200, content=result)
            remaining = deadline - time.monotonic()
            if body.wait_seconds == 0 or remaining <= 0:
                outcome = "empty"
                return Response(status_code=204)
            # Polling is deliberate: a task may be submitted by another API
            # process, where an in-process event cannot be signalled.  It also
            # keeps TestClient instances on separate event loops independent.
            await asyncio.sleep(min(remaining, 0.5))
    except asyncio.CancelledError:
        # The caller hung up mid long-poll: nothing was claimed and nothing failed.
        outcome = "empty"
        raise
    finally:
        instruments.tasks_claims.add(1, {"outcome": outcome})
        instruments.claim_duration.record(time.monotonic() - started, {"outcome": outcome})


def metered_terminal(task_id: str, agent_id: str, claim_token: str, action: Literal["complete", "fail"], value: str):
    outcome = "error"
    try:
        result = commit_terminal(task_id, agent_id, claim_token, action=action, value=value)
        outcome = "ok"
        return result
    except RelayError as exc:
        if exc.code in {"stale_claim", "conflicting_terminal"}:
            outcome = "conflict"
        raise
    finally:
        instruments.tasks_terminal.add(1, {"action": action, "outcome": outcome})


def complete_fault_rate() -> float:
    """RELAY_FAULT_COMPLETE_5XX_RATE: fraction (0-1) of complete requests to fail on
    purpose, for incident drills. Read per request; 0 or unset/invalid means off."""

    try:
        rate = float(os.getenv("RELAY_FAULT_COMPLETE_5XX_RATE", "0"))
    except ValueError:
        return 0.0
    return min(max(rate, 0.0), 1.0)


@app.post("/api/v1/tasks/{task_id}/heartbeat")
async def task_heartbeat(
    body: ClaimTokenRequest,
    task_id: str = FastAPIPath(..., min_length=1, max_length=100),
    current=Depends(current_agent),
) -> dict[str, str]:
    return {"lease_expires_at": heartbeat(task_id, current.id, body.claim_token)}


@app.post("/api/v1/tasks/{task_id}/complete")
async def task_complete(
    body: CompleteRequest,
    task_id: str = FastAPIPath(..., min_length=1, max_length=100),
    current=Depends(current_agent),
) -> dict[str, str]:
    rate = complete_fault_rate()
    if rate > 0 and random.random() < rate:
        LOGGER.warning("injected drill fault: failing complete request (RELAY_FAULT_COMPLETE_5XX_RATE=%s)", rate)
        instruments.tasks_terminal.add(1, {"action": "complete", "outcome": "error"})
        raise RelayError("injected_fault", "Injected drill fault.", 500)
    return metered_terminal(task_id, current.id, body.claim_token, "complete", body.output)


@app.post("/api/v1/tasks/{task_id}/fail")
async def task_fail(
    body: FailRequest,
    task_id: str = FastAPIPath(..., min_length=1, max_length=100),
    current=Depends(current_agent),
) -> dict[str, str]:
    return metered_terminal(task_id, current.id, body.claim_token, "fail", body.error)


@app.get("/api/v1/tasks/{task_id}")
async def task_get(
    task_id: str = FastAPIPath(..., min_length=1, max_length=100),
    current=Depends(current_agent),
) -> dict[str, Any]:
    return task_summary(task_for_participant(task_id, current.id))


@app.get("/api/v1/tasks")
async def task_list(
    direction: Literal["sent", "received"] = Query(...),
    status: str | None = Query(default=None),
    cursor: str | None = Query(default=None),
    limit: int = Query(default=DEFAULT_PAGE_SIZE),
    current=Depends(current_agent),
) -> dict[str, Any]:
    if status is not None and status not in {"queued", "processing", "completed", "failed"}:
        raise RelayError("invalid_input", "status is invalid.", 400)
    limit, decoded = page_params(limit, cursor)
    rows, next_cursor = list_tasks(current.id, direction, status, limit, decoded)
    return {"items": [task_summary(row) for row in rows], "next_cursor": next_cursor}


@app.get("/api/v1/tasks/{task_id}/attempts")
async def task_attempts(
    task_id: str = FastAPIPath(..., min_length=1, max_length=100),
    current=Depends(current_agent),
) -> dict[str, Any]:
    return {"items": [attempt_summary(row) for row in attempts_for_participant(task_id, current.id)]}


@app.get("/", response_class=HTMLResponse)
async def dashboard() -> HTMLResponse:
    return HTMLResponse(dashboard_html())


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_alias() -> HTMLResponse:
    return HTMLResponse(dashboard_html())


# Instrument after all middleware/routes are defined. Exports only when
# OTEL_EXPORTER_OTLP_ENDPOINT is set.
telemetry.configure_from_env(app, engine)


def build_cli() -> argparse.ArgumentParser:
    # Kept here so ``python main.py worker ...`` remains the documented command.
    from worker import build_parser

    return build_parser()


def main() -> None:
    from worker import worker_command

    args = build_cli().parse_args()
    if args.slow_seconds < 0 or args.wait_seconds < 0 or args.wait_seconds > 30:
        raise SystemExit("slow-seconds must be >= 0 and wait-seconds must be between 0 and 30")
    asyncio.run(worker_command(args))


if __name__ == "__main__":
    main()


__all__ = ["app", "build_cli", "main"]
