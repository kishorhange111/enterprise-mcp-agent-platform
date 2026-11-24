.PHONY: install lint format test redteam check help

help:  ## list commands
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | sed 's/:.*##/ -/'

install:  ## editable install with dev + fastapi extras
	pip install -e ".[dev,fastapi]"

lint:  ## ruff lint + format check
	ruff check .
	ruff format --check .

format:  ## apply ruff formatting and safe fixes
	ruff check . --fix
	ruff format .

test:  ## full test suite with coverage
	pytest --cov=src --cov-report=term-missing

redteam:  ## security red-team suite only
	pytest tests/redteam

check: lint test  ## same steps as CI
