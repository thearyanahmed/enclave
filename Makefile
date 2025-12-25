.PHONY: build build-release build-all test unit-test e2e-test e2e-test-local test-all test-all-local clippy fmt fmt-check md-fmt md-fmt-check check lint docker-up docker-down docker-logs clean help

# build
build:
	cargo build

build-release:
	cargo build --release

build-all:
	cargo build --all-features

# test
test:
	cargo test --no-fail-fast

unit-test:
	cargo test --no-fail-fast --all-features --lib

e2e-test:
	cargo test --no-fail-fast --all-features --test e2e_actix --test e2e_jwt --test e2e_postgres --test e2e_postgres_rate_limit

e2e-test-local: docker-up e2e-test

test-all:
	cargo test --no-fail-fast --all-features

test-all-local: docker-up test-all

# lint
clippy:
	cargo clippy --all-targets --all-features -- -D warnings

fmt:
	cargo fmt

fmt-check:
	cargo fmt -- --check

md-fmt:
	npx prettier --write --no-error-on-unmatched-pattern "README.md" "SECURITY.md" "src/**/*.md" "examples/**/*.md"

md-fmt-check:
	npx prettier --check --no-error-on-unmatched-pattern "README.md" "SECURITY.md" "src/**/*.md" "examples/**/*.md"

# check (clippy + fmt + test)
check: fmt-check clippy test

lint: fmt-check md-fmt-check clippy

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
	@echo "Available targets:"
	@echo ""
	@echo "Build:"
	@echo "  build           - build debug"
	@echo "  build-release   - build release"
	@echo "  build-all       - build with all features"
	@echo ""
	@echo "Test:"
	@echo "  test            - run unit tests (quick, no features)"
	@echo "  unit-test       - run unit tests with all features"
	@echo "  e2e-test        - run e2e tests (requires postgres running)"
	@echo "  e2e-test-local  - run e2e tests (starts docker first)"
	@echo "  test-all        - run all tests with all features"
	@echo "  test-all-local  - run all tests (starts docker first)"
	@echo ""
	@echo "Lint:"
	@echo "  clippy          - run clippy lints"
	@echo "  fmt             - format rust code"
	@echo "  fmt-check       - check rust formatting"
	@echo "  md-fmt          - format markdown files"
	@echo "  md-fmt-check    - check markdown formatting"
	@echo "  lint            - fmt-check + md-fmt-check + clippy"
	@echo "  check           - fmt-check + clippy + test"
	@echo ""
	@echo "Docker:"
	@echo "  docker-up       - start postgres container"
	@echo "  docker-down     - stop postgres container"
	@echo "  docker-logs     - tail postgres logs"
	@echo ""
	@echo "Other:"
	@echo "  clean           - cargo clean"
