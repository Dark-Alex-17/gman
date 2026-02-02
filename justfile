# List all recipes
default:
    @just --list

# Format all files
[group: 'style']
fmt:
    @cargo fmt --all

alias clippy := lint
# Run Clippy to inspect all files
[group: 'style']
lint:
    @cargo clippy --all

alias clippy-fix := lint-fix
# Automatically fix clippy issues where possible
[group: 'style']
lint-fix:
    @cargo fix

# Run all tests
[group: 'test']
test:
    @cargo test --all

# Build and run the binary for the current system
run:
    @cargo run

# Build the project for the current system architecture
[group: 'build']
[arg('build_type', pattern="debug|release")]
build build_type='debug':
    @cargo build {{ if build_type == "release" { "--release" } else { "" } }}
