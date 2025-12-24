.PHONY: build build-release test test-e2e clippy fmt clean docker-up docker-down check md-fmt md-fmt-check

# build
build:
	cargo build

build-release:
	cargo build --release

build-all:
	cargo build --features "actix sqlx_postgres"

# test
test:
	cargo test --no-fail-fast

test-e2e: docker-up
	cargo test --features sqlx_postgres --test e2e_postgres

test-all: docker-up
	cargo test --no-fail-fast --features "actix sqlx_postgres"

# lint
clippy:
	cargo clippy --all-targets --all-features -- -D warnings

fmt:
	cargo fmt

fmt-check:
	cargo fmt -- --check

md-fmt:
	docker run --rm -v $(PWD):/work -w /work node:23-alpine npx prettier --write --no-error-on-unmatched-pattern "README.md" "src/**/*.md" "examples/**/*.md"

md-fmt-check:
	docker run --rm -v $(PWD):/work -w /work node:23-alpine npx prettier --check --no-error-on-unmatched-pattern "README.md" "src/**/*.md" "examples/**/*.md"

# check (clippy + fmt + test)
check: fmt-check clippy test

# docker
docker-up:
	docker-compose up -d

docker-down:
	docker-compose down

docker-logs:
	docker-compose logs -f

# clean
clean:
	cargo clean

# help
help:
	@echo "available targets:"
	@echo "  build         - build debug"
	@echo "  build-release - build release"
	@echo "  build-all     - build with all features"
	@echo "  test          - run unit tests"
	@echo "  test-e2e      - run e2e tests (starts docker)"
	@echo "  test-all      - run all tests with all features"
	@echo "  clippy        - run clippy lints"
	@echo "  fmt           - format rust code"
	@echo "  fmt-check     - check rust formatting"
	@echo "  md-fmt        - format markdown files (docker)"
	@echo "  md-fmt-check  - check markdown formatting (docker)"
	@echo "  check         - fmt-check + clippy + test"
	@echo "  docker-up     - start postgres container"
	@echo "  docker-down   - stop postgres container"
	@echo "  docker-logs   - tail postgres logs"
	@echo "  clean         - cargo clean"
