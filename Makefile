PYTHON := python3.14
VENV := .venv
VENV_READY := $(VENV)/.installed

.PHONY: all dev lint format format-check typecheck test check clean

$(VENV_READY): pyproject.toml
	$(PYTHON) -m venv $(VENV)
	$(VENV)/bin/pip install --upgrade pip
	$(VENV)/bin/pip install $$($(PYTHON) -c "import tomllib; project = tomllib.load(open('pyproject.toml', 'rb'))['project']; print('\n'.join(project['dependencies'] + project['optional-dependencies']['dev']))")
	touch $(VENV_READY)

dev: $(VENV_READY)

lint: $(VENV_READY)
	$(VENV)/bin/ruff check .

format: $(VENV_READY)
	$(VENV)/bin/ruff format .

format-check: $(VENV_READY)
	$(VENV)/bin/ruff format --check .

typecheck: $(VENV_READY)
	$(VENV)/bin/mypy

test: $(VENV_READY)
	$(VENV)/bin/pytest -v

check: lint format-check typecheck test

all: clean
	$(PYTHON) -m pip install --target function/ $$($(PYTHON) -c "import tomllib; print('\n'.join(tomllib.load(open('pyproject.toml', 'rb'))['project']['dependencies']))")
	chmod -R 755 function/
	cd function/ && zip -r ../aws-lambda-email2webhook.zip *

clean:
	rm -rf aws-lambda-email2webhook.zip
	cd function/ && ls | grep -v lambda_function.py | xargs rm -rf
