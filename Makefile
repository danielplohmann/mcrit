init:
	pip install -r requirements.txt
package:
	rm -rf dist/*
	python setup.py sdist
publish:
	python -m twine upload dist/* -u __token__
pylint:
	python -m pylint --rcfile=.pylintrc mcrit
test:
	python -m pytest 
test-nomongo:
	python -m pytest -m 'not mongo'
test-nosleep:
	python -m pytest -m 'not sleep'
test-coverage:
	python -m pytest --cov=mcrit --cov-report html:./coverage-html --cov-config=.coveragerc
clean:
	rm -rf env
	rm -rf coverage-html
	find . | grep -E "(__pycache__|\.pyc|\.pyo$\)" | xargs rm -rf
