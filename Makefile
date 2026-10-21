.PHONY: install install-py install-ts lint lint-py lint-ts typecheck typecheck-py typecheck-ts test test-py test-ts check generate check-generated

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

PY_MODELS := libs/contracts/py/src/fourth_contracts/models
TS_TYPES := libs/contracts/ts/src/generated

generate:
	rm -rf $(PY_MODELS) $(TS_TYPES)
	uv run datamodel-codegen --input libs/contracts/schemas --input-file-type jsonschema \
		--output $(PY_MODELS) --output-model-type pydantic_v2.BaseModel \
		--target-python-version 3.13 --use-annotated --use-standard-collections \
		--use-union-operator --disable-timestamp --formatters ruff-format
	pnpm exec json2ts -i libs/contracts/schemas -o $(TS_TYPES) --imports

check-generated: generate
	git diff --exit-code -- libs/contracts
