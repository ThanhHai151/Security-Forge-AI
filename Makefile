.PHONY: install test lint demo labs

PKGS = ai_framework backend knowledge_base vuln_search defense labs i18n

install:
	pip install -e ".[dev]"

test:
	pytest

lint:
	ruff check $(PKGS) tests
	mypy $(PKGS)

demo:
	python -m ai_framework.demo --goal "Recon the target" --target http://localhost:8000 --backend offline

labs:
	SECFORGE_LABS_ENABLED=1 python -m labs.server
