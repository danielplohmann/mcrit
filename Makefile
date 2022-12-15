init:
	pip install -r requirements.txt
package:
	rm -rf dist/*
	python3 setup.py sdist
publish:
	python3 -m twine upload dist/*
pylint:
	python3 -m pylint --rcfile=.pylintrc mcrit
test:
	python3 -m pytest 
test-nomongo:
	python3 -m pytest -m 'not mongo'
test-nosleep:
	python3 -m pytest -m 'not sleep'
test-coverage:
	python3 -m pytest --cov=mcrit --cov-report html:./coverage-html --cov-config=.coveragerc
clean:
	rm -rf env
	rm -rf coverage-html
	find . | grep -E "(__pycache__|\.pyc|\.pyo$\)" | xargs rm -rf
