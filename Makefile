.PHONY: install test lint demo

PKGS = ai_framework backend knowledge_base vuln_search defense i18n

install:
	pip install -e ".[dev]"

test:
	pytest

lint:
	ruff check $(PKGS) tests
	mypy $(PKGS)

demo:
	python -m ai_framework.demo --goal "Recon the target" --target http://localhost:8000 --backend offline
