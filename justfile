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

# Full CI check: fmt, lint, test
ci: fmt-check lint test

# Install binary and config to user directories
install: release test
	mkdir -p ~/.local/bin
	cp target/release/aca-safety-net ~/.local/bin/
	mkdir -p ~/.config/aca-safety-net
	@echo "Installed ~/.local/bin/aca-safety-net"
	@if [ -f ~/.config/aca-safety-net/config.toml ]; then \
		echo "Kept existing ~/.config/aca-safety-net/config.toml (see config.toml for new options)"; \
	else \
		cp config.toml ~/.config/aca-safety-net/config.toml; \
		echo "Installed ~/.config/aca-safety-net/config.toml"; \
	fi

# Uninstall binary and config
uninstall:
	rm -f ~/.local/bin/aca-safety-net
	@echo "Removed ~/.local/bin/aca-safety-net"
	@echo "Config at ~/.config/aca-safety-net/config.toml was NOT removed (manual cleanup if needed)"
