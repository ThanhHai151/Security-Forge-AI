"""Native AI router: many provider accounts behind one rotating backend.

Ports the useful core of external proxy tools (diverse providers, multi-account rotation,
quota/ban-aware fallback) directly into SecForge so the agent never depends on a separate
download. Each account is one endpoint tagged with an ``api_style`` — ``openai``
(``/chat/completions``) or ``anthropic`` (``/messages``) — and the router picks the matching
wire adapter per call.

Accounts can be created two ways: paste an API key, or sign in through :mod:`oauth` (device-code
or browser PKCE). OAuth accounts carry a ``refresh_token`` + ``token_expiry``; the router
refreshes the access token in place just before it expires.

See ``accounts.py`` (the store), ``router.py`` (the rotating Backend), and ``oauth.py`` (sign-in
flows). The provider catalogue the UI presets from lives in :mod:`backend.providers`.
"""
