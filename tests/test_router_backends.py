"""RouterBackend integration: api_style backend selection + OAuth token refresh.

The chat HTTP is injected (``http_post``) and the OAuth refresh is stubbed, so nothing touches
the network. These lock in the two behaviours added for multi-provider / OAuth support.
"""

from ai_framework.agent.contracts import RunConfig
from ai_framework.router.accounts import Account, AccountStore
from ai_framework.router.router import RouterBackend


def _config():
    return RunConfig(goal="probe", target="example.test")


def test_anthropic_account_routes_to_messages_endpoint(tmp_path):
    store = AccountStore(path=str(tmp_path / "a.json"))
    store.add(Account(label="claude", kind="anthropic", base_url="https://api.anthropic.com/v1",
                      api_key="sk-x", model="claude-sonnet-4-6", api_style="anthropic"))
    seen = {}

    def http_post(url, payload, headers):
        seen["url"] = url
        seen["headers"] = headers
        return {"content": [{"type": "text", "text": "next step"}]}

    out = RouterBackend(store, http_post=http_post).plan("sys", [], _config())
    assert out == "next step"
    assert seen["url"].endswith("/messages")  # anthropic shape, not /chat/completions
    assert seen["headers"]["x-api-key"] == "sk-x"


def test_openai_account_still_routes_to_chat_completions(tmp_path):
    store = AccountStore(path=str(tmp_path / "a.json"))
    store.add(Account(label="oai", kind="openai", base_url="https://api.openai.com/v1",
                      api_key="sk-y", model="gpt-4o-mini"))  # api_style defaults to openai
    seen = {}

    def http_post(url, payload, headers):
        seen["url"] = url
        return {"choices": [{"message": {"content": "ok"}}]}

    out = RouterBackend(store, http_post=http_post).plan("sys", [], _config())
    assert out == "ok"
    assert seen["url"].endswith("/chat/completions")


class _StubOAuth:
    """Stand-in OAuthManager that returns a fresh token without any network."""

    def __init__(self):
        self.calls = []

    def refresh(self, provider, refresh_token, provider_data=None):
        self.calls.append((provider, refresh_token))
        return {"api_key": "FRESH", "refresh_token": refresh_token, "token_expiry": 9_999_999_999}


def test_expired_oauth_token_is_refreshed_before_use(tmp_path):
    store = AccountStore(path=str(tmp_path / "a.json"))
    store.add(Account(
        label="copilot", kind="github-copilot", base_url="https://api.githubcopilot.com",
        api_key="STALE", model="gpt-5.4", oauth_provider="github-copilot",
        refresh_token="GH", token_expiry=1.0,  # far in the past → must refresh
    ))
    stub = _StubOAuth()
    used = {}

    def http_post(url, payload, headers):
        used["auth"] = headers.get("Authorization")
        return {"choices": [{"message": {"content": "done"}}]}

    RouterBackend(store, http_post=http_post, oauth=stub).plan("sys", [], _config())
    assert stub.calls == [("github-copilot", "GH")]
    assert used["auth"] == "Bearer FRESH"  # refreshed key was sent, not the stale one
    assert store.list_accounts()[0].api_key == "FRESH"  # persisted back to the store


def test_valid_oauth_token_is_not_refreshed(tmp_path):
    store = AccountStore(path=str(tmp_path / "a.json"))
    store.add(Account(
        label="copilot", kind="github-copilot", base_url="https://api.githubcopilot.com",
        api_key="GOOD", model="gpt-5.4", oauth_provider="github-copilot",
        refresh_token="GH", token_expiry=9_999_999_999,  # still valid
    ))
    stub = _StubOAuth()
    RouterBackend(store, http_post=lambda *a: {"choices": [{"message": {"content": "x"}}]},
                  oauth=stub).plan("sys", [], _config())
    assert stub.calls == []  # no refresh when the token is fresh
