"""Native AI router: many OpenAI-compatible accounts behind one rotating backend.

Ports the useful core of external proxy tools (diverse providers, multi-account rotation,
quota/ban-aware fallback) directly into SecForge so the agent never depends on a separate
download. See ``accounts.py`` (the store) and ``router.py`` (the rotating Backend).
"""
