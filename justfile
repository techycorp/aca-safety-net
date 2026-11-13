# ACO Safety Net - Rust Security Hook

default:
	@just --list

# Build debug version
build:
	cargo build

# Build release version
release:
	cargo build --release

# Run all tests
test:
	cargo test

# Run tests with output
test-verbose:
	cargo test -- --nocapture

# Run clippy linter
lint:
	cargo clippy -- -D warnings

# Format code
fmt:
	cargo fmt

# Check formatting without modifying
fmt-check:
	cargo fmt -- --check

# Clean build artifacts
clean:
	cargo clean

# Check compilation without building
check:
	cargo check

# Run benchmarks (if any)
bench:
	cargo bench

# Generate documentation
doc:
	cargo doc --open

# Full CI check: fmt, lint, test, vendor claims manifest
ci: fmt-check lint test vendor-claims

# Check vendor-claims.toml against the repo
vendor-claims:
	@command -v vending-machine >/dev/null || { echo "vending-machine not installed: clone techycorp/vending-machine and run just install" >&2; exit 1; }
	vending-machine check

# Run the vendor tests against the installed oh-my-pi (omp)
vendor-test:
	bun test tests/vendor

# Run the omp vendor tests and record the omp version they passed on, which the omp hook requires
omp-verify:
	#!/usr/bin/env bash
	set -euo pipefail
	if ! command -v omp >/dev/null; then
		rm -f ~/.config/aca-safety-net/omp-verified.json
		echo "omp not installed: skipped the omp vendor tests and cleared the omp verification record"
		exit 0
	fi
	just vendor-test
	version="$(omp --version | tail -1 | sed 's|^omp/||' | tr -d '[:space:]')"
	repo="$(dirname "$(git rev-parse --path-format=absolute --git-common-dir)")"
	mkdir -p ~/.config/aca-safety-net
	printf '{"version":"%s","repo":"%s"}\n' "$version" "$repo" > ~/.config/aca-safety-net/omp-verified.json
	echo "omp $version passed the vendor tests; recorded in ~/.config/aca-safety-net/omp-verified.json"

# Install binary and config to user directories
install: release test
	mkdir -p ~/.local/bin
	cp target/release/aca-safety-net ~/.local/bin/
	mkdir -p ~/.config/aca-safety-net
	@echo "Installed ~/.local/bin/aca-safety-net"
	mkdir -p ~/.omp/agent/hooks/pre
	cp omp/aca-safety-net.ts ~/.omp/agent/hooks/pre/
	@echo "Installed ~/.omp/agent/hooks/pre/aca-safety-net.ts (oh-my-pi hook)"
	just omp-verify
	@if [ -f ~/.config/aca-safety-net/config.toml ]; then \
		echo "Kept existing ~/.config/aca-safety-net/config.toml (see config.toml for new options)"; \
	else \
		cp config.toml ~/.config/aca-safety-net/config.toml; \
		echo "Installed ~/.config/aca-safety-net/config.toml"; \
	fi

# Uninstall binary and config
uninstall:
	rm -f ~/.local/bin/aca-safety-net
	rm -f ~/.omp/agent/hooks/pre/aca-safety-net.ts ~/.config/aca-safety-net/omp-verified.json
	@echo "Removed ~/.local/bin/aca-safety-net and the oh-my-pi hook"
	@echo "Config at ~/.config/aca-safety-net/config.toml was NOT removed (manual cleanup if needed)"
