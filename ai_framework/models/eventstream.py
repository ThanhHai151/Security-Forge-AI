"""AWS ``application/vnd.amazon.eventstream`` binary frame parser.

Kiro's chat surface is AWS CodeWhisperer, which does **not** return JSON — it streams a
sequence of binary EventStream frames. This is a stdlib port of 9router's ``parseEventFrame``
(``Tool/9router/open-sse/executors/kiro.js``): enough of the wire format to pull the JSON
payload and the ``:event-type`` header out of each frame. We ignore CRCs (we only read) and
only decode string headers (type 7), which is all CodeWhisperer emits.

Frame layout (all integers big-endian)::

    [ 0: 4]  total length (bytes, whole frame)
    [ 4: 8]  headers length (bytes)
    [ 8:12]  prelude CRC32            (ignored)
    [12: 12+headers_len]  headers
    [.. : total-4]        payload (JSON, usually)
    [total-4 : total]     message CRC32  (ignored)

Each header::

    [1]  name length (n)
    [n]  name (utf-8)
    [1]  value type   (7 == string; anything else ends header parsing for this frame)
    [2]  value length (m)          # string type only
    [m]  value (utf-8)             # string type only
"""

from __future__ import annotations

import json
import struct
from collections.abc import Iterator
from typing import Any

_PRELUDE = 12  # total-len(4) + headers-len(4) + prelude-crc(4)
_MSG_CRC = 4
_STRING_HEADER = 7


class EventFrame:
    """One decoded frame: its string headers plus the parsed (or raw) payload."""

    __slots__ = ("headers", "payload")

    def __init__(self, headers: dict[str, str], payload: Any) -> None:
        self.headers = headers
        self.payload = payload

    @property
    def event_type(self) -> str:
        return self.headers.get(":event-type", "")


def _parse_headers(frame: bytes, headers_len: int) -> dict[str, str]:
    headers: dict[str, str] = {}
    offset = _PRELUDE
    end = _PRELUDE + headers_len
    while offset < end and offset < len(frame):
        name_len = frame[offset]
        offset += 1
        if offset + name_len > len(frame):
            break
        name = frame[offset : offset + name_len].decode("utf-8", "replace")
        offset += name_len
        if offset >= len(frame):
            break
        value_type = frame[offset]
        offset += 1
        if value_type != _STRING_HEADER:
            # CodeWhisperer only sends string headers on the frames we care about; bail out
            # rather than misparse a type we don't model.
            break
        if offset + 2 > len(frame):
            break
        (value_len,) = struct.unpack_from(">H", frame, offset)
        offset += 2
        value = frame[offset : offset + value_len].decode("utf-8", "replace")
        offset += value_len
        headers[name] = value
    return headers


def _parse_frame(frame: bytes) -> EventFrame | None:
    if len(frame) < _PRELUDE:
        return None
    (headers_len,) = struct.unpack_from(">I", frame, 4)
    headers = _parse_headers(frame, headers_len)
    payload_start = _PRELUDE + headers_len
    payload_end = len(frame) - _MSG_CRC
    if payload_end <= payload_start:
        return EventFrame(headers, None)
    raw = frame[payload_start:payload_end].decode("utf-8", "replace")
    if not raw.strip():
        return EventFrame(headers, None)
    try:
        payload: Any = json.loads(raw)
    except json.JSONDecodeError:
        payload = {"raw": raw}
    return EventFrame(headers, payload)


def iter_events(data: bytes) -> Iterator[EventFrame]:
    """Yield every complete frame in ``data``.

    Trailing bytes that don't form a complete frame are ignored (the whole response body is
    passed in at once — we don't do incremental buffering, since ``Backend.act`` is not a
    streaming interface).
    """
    buf = memoryview(data)
    while len(buf) >= _PRELUDE:
        (total_len,) = struct.unpack_from(">I", buf, 0)
        if total_len < _PRELUDE or total_len > len(buf):
            break
        frame = _parse_frame(bytes(buf[:total_len]))
        buf = buf[total_len:]
        if frame is not None:
            yield frame
