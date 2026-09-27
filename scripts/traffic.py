"""Traffic generator for Agent Relay.

Registers sender agents and worker agents, then has the senders submit tasks at a
fixed rate while each worker long-polls /claim and completes what it gets.

    uv run scripts/traffic.py --rate 5 --duration 180 --workers 2

Prints one summary line every 10 seconds (sent / claimed / completed / errors).
Agent tokens and claim tokens are held in memory only and are never printed.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import signal
import time
from dataclasses import dataclass, field
from pathlib import Path

import httpx


@dataclass
class Stats:
    sent: int = 0
    claimed: int = 0
    completed: int = 0
    errors: int = 0  # 5xx responses and transport failures
    stale: int = 0  # 409 on complete (lease expired), not counted as an error
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)


def is_error(status: int) -> bool:
    return status >= 500


async def register(base_url: str, name: str, enrollment_secret: str | None) -> tuple[str, str]:
    headers = {"X-Enrollment-Secret": enrollment_secret} if enrollment_secret else {}
    async with httpx.AsyncClient(base_url=base_url, timeout=10) as client:
        for attempt in range(10):
            try:
                response = await client.post("/api/v1/agents", json={"name": name}, headers=headers)
                if response.status_code == 201:
                    data = response.json()
                    return data["agent_id"], data["token"]
                reason = f"HTTP {response.status_code}"
            except httpx.HTTPError as exc:
                reason = type(exc).__name__
            print(f"register {name}: {reason}, retrying ({attempt + 1}/10)", flush=True)
            await asyncio.sleep(2)
    raise SystemExit(f"could not register {name}")


async def sender_loop(
    base_url: str, token: str, recipients: list[str], interval: float, stop: asyncio.Event, stats: Stats, index: int
) -> None:
    n = 0
    next_at = time.monotonic() + (index * interval / 3)  # stagger senders a little
    async with httpx.AsyncClient(base_url=base_url, headers={"Authorization": f"Bearer {token}"}, timeout=10) as client:
        while not stop.is_set():
            delay = next_at - time.monotonic()
            if delay > 0:
                try:
                    await asyncio.wait_for(stop.wait(), timeout=delay)
                    return
                except asyncio.TimeoutError:
                    pass
            # Open-loop pacing: if a stalled request made us late, skip the missed slots
            # instead of bursting to catch up (which would flood the queue after an outage).
            next_at = max(next_at + interval, time.monotonic())
            recipient = recipients[n % len(recipients)]
            n += 1
            try:
                response = await client.post(
                    "/api/v1/tasks", json={"to": recipient, "input": f"traffic task {index}-{n}"}
                )
                status = response.status_code
            except httpx.HTTPError:
                status = 599
            async with stats.lock:
                if status == 201:
                    stats.sent += 1
                elif is_error(status):
                    stats.errors += 1


async def worker_loop(
    base_url: str,
    token: str,
    worker_id: str,
    wait_seconds: int,
    work_seconds: float,
    stop: asyncio.Event,
    stats: Stats,
    drain_seconds: float,
) -> None:
    """Claim and complete until `stop` is set, then keep going until the inbox is empty
    (an empty long-poll) or `drain_seconds` passes, so no tasks are stranded for a
    worker that no longer exists."""

    drained = False
    drain_deadline: float | None = None
    async with httpx.AsyncClient(
        base_url=base_url, headers={"Authorization": f"Bearer {token}"}, timeout=wait_seconds + 15
    ) as client:
        while True:
            if stop.is_set():
                drain_deadline = drain_deadline or time.monotonic() + drain_seconds
                if drained or time.monotonic() > drain_deadline:
                    return
            try:
                response = await client.post(
                    "/api/v1/tasks/claim", json={"worker_id": worker_id, "wait_seconds": wait_seconds}
                )
            except httpx.HTTPError:
                async with stats.lock:
                    stats.errors += 1
                await asyncio.sleep(0.5)
                continue
            if response.status_code == 204:
                drained = stop.is_set()
                continue
            drained = False
            if response.status_code != 200:
                if is_error(response.status_code):
                    async with stats.lock:
                        stats.errors += 1
                await asyncio.sleep(0.5)
                continue
            claim = response.json()
            async with stats.lock:
                stats.claimed += 1
            if work_seconds > 0:
                await asyncio.sleep(work_seconds)
            try:
                done = await client.post(
                    f"/api/v1/tasks/{claim['task_id']}/complete",
                    json={"claim_token": claim["claim_token"], "output": claim["input"].upper()},
                )
                status = done.status_code
            except httpx.HTTPError:
                status = 599
            async with stats.lock:
                if status == 200:
                    stats.completed += 1
                elif status == 409:
                    stats.stale += 1
                elif is_error(status):
                    stats.errors += 1
            if is_error(status):
                await asyncio.sleep(0.5)


async def reporter(stats: Stats, stop: asyncio.Event, interval: float, started: float) -> None:
    while True:
        try:
            await asyncio.wait_for(stop.wait(), timeout=interval)
            return
        except asyncio.TimeoutError:
            pass
        print(
            f"[t={time.monotonic() - started:5.0f}s] sent={stats.sent} claimed={stats.claimed} "
            f"completed={stats.completed} errors={stats.errors}",
            flush=True,
        )


async def main_async(args: argparse.Namespace) -> None:
    stats = Stats()
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)

    workers = [
        await register(args.base_url, f"traffic-worker-{i}", args.enrollment_secret) for i in range(args.workers)
    ]
    senders = [
        await register(args.base_url, f"traffic-sender-{i}", args.enrollment_secret) for i in range(args.senders)
    ]
    recipients = [agent_id for agent_id, _ in workers]
    interval = args.senders / args.rate  # each sender's gap so the total is `rate` tasks/s
    print(
        f"traffic: {args.senders} senders -> {args.workers} workers at {args.rate}/s for {args.duration}s "
        f"against {args.base_url}",
        flush=True,
    )

    started = time.monotonic()
    tasks = [
        asyncio.create_task(sender_loop(args.base_url, token, recipients, interval, stop, stats, i))
        for i, (_, token) in enumerate(senders)
    ]
    worker_tasks = [
        asyncio.create_task(
            worker_loop(
                args.base_url, token, f"worker-{i}", args.wait_seconds, args.work_seconds, stop, stats, args.drain_seconds
            )
        )
        for i, (_, token) in enumerate(workers)
    ]
    report = asyncio.create_task(reporter(stats, stop, args.summary_interval, started))

    try:
        await asyncio.wait_for(stop.wait(), timeout=args.duration)
    except asyncio.TimeoutError:
        pass
    stop.set()
    # Senders stop at once; workers drain their inboxes (bounded by --drain-seconds).
    await asyncio.gather(*tasks, return_exceptions=True)
    await asyncio.wait_for(asyncio.gather(*worker_tasks, return_exceptions=True), timeout=args.wait_seconds + args.drain_seconds + 20)
    await report
    print(
        f"[final  {time.monotonic() - started:4.0f}s] sent={stats.sent} claimed={stats.claimed} "
        f"completed={stats.completed} errors={stats.errors} stale={stats.stale}",
        flush=True,
    )


def enrollment_secret_default() -> str | None:
    """RELAY_ENROLLMENT_SECRET from the environment, else from the repo's untracked .env.
    The value is only ever sent as the X-Enrollment-Secret header; it is never printed."""

    value = os.getenv("RELAY_ENROLLMENT_SECRET")
    if value:
        return value
    env_file = Path(__file__).resolve().parent.parent / ".env"
    try:
        for line in env_file.read_text(encoding="utf-8").splitlines():
            key, sep, val = line.strip().partition("=")
            if sep and key.strip() == "RELAY_ENROLLMENT_SECRET":
                return val.strip().strip("'\"") or None
    except OSError:
        pass
    return None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Agent Relay traffic generator")
    parser.add_argument("--base-url", default=os.getenv("RELAY_BASE_URL", "http://localhost:8010"))
    parser.add_argument("--rate", type=float, default=5.0, help="tasks submitted per second, in total")
    parser.add_argument("--duration", type=float, default=60.0, help="seconds to send for")
    parser.add_argument("--workers", type=int, default=2, help="worker agents (each long-polls its own inbox)")
    parser.add_argument("--senders", type=int, default=3, help="sender agents")
    parser.add_argument("--wait-seconds", type=int, default=3, help="claim long-poll seconds (0-30)")
    parser.add_argument("--work-seconds", type=float, default=0.05, help="simulated work time per task")
    parser.add_argument("--drain-seconds", type=float, default=30.0, help="after the duration, keep claiming until the inbox is empty (max)")
    parser.add_argument("--summary-interval", type=float, default=10.0)
    parser.add_argument("--enrollment-secret", default=enrollment_secret_default(),
                        help="defaults to $RELAY_ENROLLMENT_SECRET, then RELAY_ENROLLMENT_SECRET in the repo's .env")
    args = parser.parse_args()
    if args.rate <= 0 or args.workers < 1 or args.senders < 1 or not 0 <= args.wait_seconds <= 30:
        parser.error("rate > 0, workers >= 1, senders >= 1, 0 <= wait-seconds <= 30")
    return args


if __name__ == "__main__":
    asyncio.run(main_async(parse_args()))
