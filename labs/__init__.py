"""Labs / Range (Pillar 5).

PortSwigger-style practice targets, **sandboxed**: every lab emulates its bug against an
in-memory fake database/filesystem — no real SQL, OS commands, or outbound requests. The lab
server is localhost-only, on a separate port, and disabled by default. Each lab links back to
its catalog class and skill, closing the read → practise → automate loop. See
``labs/README.md`` and ``ARCHITECTURE.md`` › Labs.
"""

from __future__ import annotations

from labs.base import Lab, LabRequest, LabResponse
from labs.registry import LabRegistry, default_registry
from labs.server import build_labs_server, labs_enabled

__all__ = [
    "Lab",
    "LabRequest",
    "LabResponse",
    "LabRegistry",
    "default_registry",
    "build_labs_server",
    "labs_enabled",
]
