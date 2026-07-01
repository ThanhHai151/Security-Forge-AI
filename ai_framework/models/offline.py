"""Offline backend — heuristic, no network, no API key.

Drives a demonstrable Hermes loop by reading the transcript and emitting the obvious next
tool call: recon the target first, then record a finding, then stop. Deterministic, so the
loop is testable and the demo runs with no credentials.
"""

from __future__ import annotations

from typing import Any

from ai_framework.agent.contracts import RunConfig, ToolCall, Turn
from ai_framework.models.base import ActResponse


def _was_called(transcript: list[Turn], tool_name: str) -> bool:
    return any(
        tc.name == tool_name
        for turn in transcript
        for tc in turn.tool_calls
    )


class OfflineBackend:
    name = "offline"

    def act(
        self,
        system: str,
        transcript: list[Turn],
        config: RunConfig,
        tools: list[dict[str, Any]],
    ) -> ActResponse:
        n = len(transcript)
        if not _was_called(transcript, "http_get"):
            return ActResponse(
                reasoning="No recon yet; fetch the target to see what it exposes.",
                tool_calls=[
                    ToolCall(id=f"t{n}-c0", name="http_get", arguments={"url": config.target})
                ],
            )
        if not _was_called(transcript, "note_finding"):
            return ActResponse(
                reasoning="Recon returned a response; record what we observed as a finding.",
                tool_calls=[
                    ToolCall(
                        id=f"t{n}-c0",
                        name="note_finding",
                        arguments={
                            "title": f"Reachable target {config.target}",
                            "detail": "Target responded to HTTP GET during recon.",
                        },
                    )
                ],
            )
        return ActResponse(reasoning="Goal coverage reached for the offline demo.", done=True)

    def plan(self, system: str, transcript: list[Turn], config: RunConfig) -> str:
        if not _was_called(transcript, "http_get"):
            return "Start with reconnaissance of the target."
        if not _was_called(transcript, "note_finding"):
            return "Analyze the recon response and look for an exploitable surface."
        return "Stop: initial recon and finding recorded."
