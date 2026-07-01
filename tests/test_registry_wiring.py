"""The default registry wires every tool, and all schemas are well-formed for the backend."""

from backend.service import default_registry

EXPECTED = {
    "http_get", "note_finding", "record_asset", "http_request", "inspect_headers",
    "fetch_robots_sitemap", "decode_encode", "jwt_attack", "login", "set_auth",
    "run_recon", "browser_render",
}


def test_all_tools_are_registered():
    reg = default_registry()
    names = {s["name"] for s in reg.schemas()}
    assert EXPECTED <= names, f"missing from registry: {EXPECTED - names}"


def test_every_schema_is_wellformed():
    for s in default_registry().schemas():
        assert s["name"] and s["description"]
        schema = s["input_schema"]
        assert schema["type"] == "object" and isinstance(schema["properties"], dict)


def test_network_tools_declare_flags():
    reg = default_registry()
    for name in ("http_get", "http_request", "run_recon", "browser_render", "login"):
        tool = reg.get(name)
        assert getattr(tool, "touches_network", False) is True
    # Local-only tools don't pace/gate as network.
    for name in ("decode_encode", "note_finding", "record_asset", "jwt_attack", "set_auth"):
        assert getattr(reg.get(name), "touches_network", True) is False
