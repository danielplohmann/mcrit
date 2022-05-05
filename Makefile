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
	python3 -m nose
test-nomongo:
	python3 -m nose -a '!mongo'
test-nosleep:
	python3 -m nose -a '!sleep'
test-coverage:
	python3 -m nose --with-coverage --cover-erase --cover-html-dir=./coverage-html --cover-html --cover-package=mcrit
clean:
	rm -rf env
	rm -rf coverage-html
	find . | grep -E "(__pycache__|\.pyc|\.pyo$\)" | xargs rm -rf
