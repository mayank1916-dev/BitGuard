.PHONY: up down test lint migrate format help

help:
	@echo "BitGuard Makefile commands:"
	@echo "  make up      - Start all services with Docker Compose"
	@echo "  make down    - Stop all running containers and networks"
	@echo "  make test    - Run pytest across test suites"
	@echo "  make lint    - Run ruff linter and mypy type checks"
	@echo "  make format  - Auto-format codebase using ruff"
	@echo "  make migrate - Run alembic database migrations"

up:
	docker compose up -d --build

down:
	docker compose down --remove-orphans

test:
	python -m pytest backend/tests tests -v

lint:
	ruff check .
	mypy --explicit-package-bases services backend tests

format:
	ruff format .
	ruff check --fix .

migrate:
	alembic -c services/bitguard/alembic.ini upgrade head
