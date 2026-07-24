"""
Scan Log Broadcaster
Simple in-memory pub/sub so the frontend can stream "live terminal" style
scan progress over WebSocket. Logs for a scan are buffered so a client
connecting slightly after the scan started still gets the full transcript.
"""
import asyncio
import time

_buffers: dict[int, list[dict]] = {}
_subscribers: dict[int, list[asyncio.Queue]] = {}


def log(scan_id: int, message: str, level: str = "info"):
    entry = {"ts": time.time(), "level": level, "message": message}
    _buffers.setdefault(scan_id, []).append(entry)
    for q in _subscribers.get(scan_id, []):
        try:
            q.put_nowait(entry)
        except asyncio.QueueFull:
            pass


def get_buffer(scan_id: int):
    return list(_buffers.get(scan_id, []))


def subscribe(scan_id: int) -> asyncio.Queue:
    q: asyncio.Queue = asyncio.Queue(maxsize=200)
    _subscribers.setdefault(scan_id, []).append(q)
    return q


def unsubscribe(scan_id: int, q: asyncio.Queue):
    subs = _subscribers.get(scan_id, [])
    if q in subs:
        subs.remove(q)


def mark_done(scan_id: int):
    log(scan_id, "__DONE__", level="control")
