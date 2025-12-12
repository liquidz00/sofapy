SHELL 			:= /bin/bash
UV 				:= uv
PYPROJECT 		:= pyproject.toml
VENV_DIR 		:= .venv

.PHONY: docs all clean test install pre-commit pre-commit-run pre-commit-update

# Export Python path for script resolution
export PYTHONPATH := $(shell pwd)

install:
	$(UV) sync --extra dev

uninstall:
	rm -rf $(VENV_DIR)

restore: clean flush
	@echo "Full cleanup completed"

clean:
	find . -name "*.pyc" -delete
	find . -name "__pycache__" -delete

flush:
	rm -rf build/ dist/ src/*.egg-info **/__pycache__ .coverage .pytest_cache/ .ruff_cache/ htmlcov/

lint:
	$(UV) run ruff format --check .
	$(UV) run ruff check .

format:
	$(UV) run ruff format .
	$(UV) run ruff check . --fix

lock:
	$(UV) lock

upgrade:
	$(UV) lock --upgrade
	$(UV) sync --extra dev

test:
	@echo "Running all tests..."
	$(UV) run pytest tests/ -v

test-cov:
	@echo "Running unit tests with coverage..."
	$(UV) run pytest tests/ --cov=src --cov-report=term-missing

test-cov-html:
	@echo "Generating HTML coverage report..."
	$(UV) run pytest tests/ --cov=src --cov-report=html
	@echo "Coverage report generated in htmlcov/index.html"

pre-commit:
	@echo "Installing pre-commit hooks..."
	@if [ ! -d "$(VENV_DIR)" ]; then \
		echo "Virtual environment not found. Creating and installing dev dependencies..."; \
		$(MAKE) install-dev; \
	fi
	$(UV) run pre-commit install
	@echo "Pre-commit hooks installed successfully!"

build:
	$(UV) build --sdist --wheel
