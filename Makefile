.PHONY: install install-py install-ts lint lint-py lint-ts typecheck typecheck-py typecheck-ts test test-py test-ts check

install: install-py install-ts
install-py:
	uv sync --all-packages --frozen
install-ts:
	pnpm install --frozen-lockfile

lint: lint-py lint-ts
lint-py:
	uv run ruff check .
	uv run ruff format --check .
lint-ts:
	pnpm lint

typecheck: typecheck-py typecheck-ts
typecheck-py:
	uv run pyright
typecheck-ts:
	pnpm typecheck

test: test-py test-ts
test-py:
	uv run pytest
test-ts:
	pnpm test

check: lint typecheck test
