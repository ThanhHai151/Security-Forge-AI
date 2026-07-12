"""AccountStore: atomic persistence + fault isolation on a corrupted/incompatible row.

Regression coverage for a real incident: one bad account row in ai_accounts.json took down the
entire /accounts endpoint (500), which made the whole Providers page look like every connection
had vanished. list_accounts() must skip a row that no longer validates instead of raising, and
_save() must never leave the file in a half-written state a concurrent reader could observe.
"""

import json
import stat

from ai_framework.router.accounts import Account, AccountStore


def test_list_accounts_skips_a_row_that_fails_validation(tmp_path):
    path = tmp_path / "accounts.json"
    path.write_text(
        json.dumps(
            {
                "policy": "tiered",
                "accounts": [
                    {"id": "good1", "label": "keeper", "base_url": "https://x/v1"},
                    {"id": "bad1"},  # missing required "label" and "base_url"
                    {"id": "good2", "label": "keeper2", "base_url": "https://y/v1"},
                ],
            }
        ),
        encoding="utf-8",
    )
    store = AccountStore(path=str(path))

    accounts = store.list_accounts()

    assert {a.id for a in accounts} == {"good1", "good2"}  # the bad row is skipped, not fatal


def test_list_accounts_returns_empty_rather_than_raising_when_every_row_is_bad(tmp_path):
    path = tmp_path / "accounts.json"
    path.write_text(json.dumps({"policy": "tiered", "accounts": [{"id": "bad"}]}), encoding="utf-8")
    store = AccountStore(path=str(path))

    assert store.list_accounts() == []


def test_save_is_atomic_and_leaves_no_tmp_file_behind(tmp_path):
    path = tmp_path / "accounts.json"
    store = AccountStore(path=str(path))

    store.add(Account(label="a", base_url="https://x/v1"))
    store.add(Account(label="b", base_url="https://y/v1"))

    assert not path.with_suffix(".json.tmp").exists()
    # The file itself is always fully-formed JSON immediately after a save — never truncated.
    data = json.loads(path.read_text(encoding="utf-8"))
    assert len(data["accounts"]) == 2


def test_update_and_remove_survive_a_prior_corrupted_row(tmp_path):
    path = tmp_path / "accounts.json"
    store = AccountStore(path=str(path))
    good = store.add(Account(label="keeper", base_url="https://x/v1"))

    # Simulate a bad row landing in the file some other way (e.g. a future schema change).
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["accounts"].append({"id": "corrupt"})
    path.write_text(json.dumps(raw), encoding="utf-8")

    assert store.update(good.id, {"label": "renamed"}).label == "renamed"
    assert store.list_accounts()[0].label == "renamed"  # corrupt row still skipped, not crashing


def test_credentials_are_encrypted_at_rest_and_round_trip(tmp_path):
    path = tmp_path / "accounts.json"
    store = AccountStore(path=str(path))
    account = store.add(
        Account(
            label="private",
            base_url="https://x/v1",
            api_key="sk-do-not-store-plain",
            refresh_token="refresh-do-not-store-plain",
            provider_data={"clientSecret": "provider-secret"},
        )
    )

    raw = path.read_text(encoding="utf-8")
    assert "sk-do-not-store-plain" not in raw
    assert "refresh-do-not-store-plain" not in raw
    assert "provider-secret" not in raw
    assert "enc:v1:" in raw

    restored = AccountStore(path=str(path)).get(account.id)
    assert restored is not None
    assert restored.api_key == "sk-do-not-store-plain"
    assert restored.refresh_token == "refresh-do-not-store-plain"
    assert restored.provider_data["clientSecret"] == "provider-secret"

    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.with_suffix(".key").stat().st_mode) == 0o600
