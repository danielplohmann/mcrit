PYTHON ?= python3

.PHONY: init package publish ruff-check ruff-format ruff-fix lint format typecheck test test-nomongo test-nosleep test-coverage clean

init:
	$(PYTHON) -m pip install --upgrade pip
	$(PYTHON) -m pip install -e ".[dev]"
package:
	rm -rf dist
	$(PYTHON) -m build
publish:
	$(PYTHON) -m twine upload dist/* -u __token__
ruff-check:
	$(PYTHON) -m ruff check .
ruff-format:
	$(PYTHON) -m ruff format .
ruff-fix:
	$(PYTHON) -m ruff check . --fix
lint: ruff-check
format: ruff-format
typecheck:
	$(PYTHON) -m ty check
test:
	$(PYTHON) -m pytest
test-nomongo:
	$(PYTHON) -m pytest -m 'not mongo'
test-nosleep:
	$(PYTHON) -m pytest -m 'not sleep'
test-coverage:
	$(PYTHON) -m pytest --cov=mcrit --cov-report html:./coverage-html
clean:
	rm -rf build dist coverage-html coverage_html_report .coverage
	rm -rf .pytest_cache .ruff_cache
	find . -path ./.venv -prune -o \( -name '__pycache__' -o -name '*.py[co]' \) -print0 | xargs -0 rm -rf
