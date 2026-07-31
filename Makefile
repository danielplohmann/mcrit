PYTHON ?= python3

.PHONY: init package publish ruff-check ruff-format ruff-fix pylint lint format test test-nomongo test-nosleep test-coverage clean

init:
	$(PYTHON) -m ensurepip --upgrade
	$(PYTHON) -m pip install --upgrade pip
	$(PYTHON) -m pip install -r requirements.txt
	$(PYTHON) -m pip install -r requirements-dev.txt
package:
	rm -rf dist/*
	$(PYTHON) setup.py sdist
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
pylint:
	$(PYTHON) -m pylint --rcfile=.pylintrc mcrit
test:
	$(PYTHON) -m pytest
test-nomongo:
	$(PYTHON) -m pytest -m 'not mongo'
test-nosleep:
	$(PYTHON) -m pytest -m 'not sleep'
test-coverage:
	$(PYTHON) -m pytest --cov=mcrit --cov-report html:./coverage-html --cov-config=.coveragerc
clean:
	rm -rf env
	rm -rf coverage-html
	find . | grep -E "(__pycache__|\.pyc|\.pyo$\)" | xargs rm -rf
