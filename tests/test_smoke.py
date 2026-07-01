"""Step 0 smoke test: the package imports and sub-packages are present."""

import importlib


def test_package_imports():
    ai = importlib.import_module("ai_framework")
    assert ai.__version__


def test_subpackages_import():
    for name in ("agent", "memory", "models", "skills", "tools"):
        importlib.import_module(f"ai_framework.{name}")
