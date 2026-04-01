# Contributing to Duramen

Thank you for your interest in contributing! This guide will help you get started.

## Development Setup

```bash
# Clone and build
git clone https://github.com/anthropics/duramen.git
cd duramen
cargo build

# Run tests (219 tests)
cargo test

# Run benchmarks
cargo bench

# Check formatting and lints
cargo fmt --check
cargo clippy -- -D warnings
```

## How to Contribute

### Reporting Bugs

Open a [GitHub issue](https://github.com/anthropics/duramen/issues) with:
- Steps to reproduce
- Expected vs actual behavior
- Duramen version (`duramen --version`)
- OS and Rust version

### Requesting Features

Open an issue describing the use case and proposed solution. For policy-related features, include example Cedar policies.

### Submitting Code

1. Fork the repo and create a branch from `master`
2. Make your changes
3. Add tests for new functionality
4. Ensure all tests pass: `cargo test`
5. Ensure code is formatted: `cargo fmt`
6. Ensure no clippy warnings: `cargo clippy -- -D warnings`
7. Submit a pull request

## Code Style

- Follow standard Rust conventions (`cargo fmt`)
- No clippy warnings allowed
- Add `///` doc comments to all public types and functions
- Keep test names descriptive: `fn normalizes_git_force_push_as_destructive()`

## Extension Points

There are several ways to extend Duramen without modifying core code:

| Extension | Guide | What to implement |
|-----------|-------|-------------------|
| **New agent** (e.g., Cursor, Codex) | [docs/adding-a-new-agent.md](docs/adding-a-new-agent.md) | `AgentNormalizer` + `ResponseFormatter` + hook scripts |
| **New command handler** (e.g., docker, kubectl) | [docs/adding-command-handlers.md](docs/adding-command-handlers.md) | `CommandHandler` trait in `request-adaptor/src/commands/` |
| **New resource enricher** | [docs/adding-command-handlers.md](docs/adding-command-handlers.md#enrichment-pipeline) | `ResourceEnricher` trait in `request-adaptor/src/enrichers/` |
| **New action classifier** | [docs/adding-command-handlers.md](docs/adding-command-handlers.md#enrichment-pipeline) | `ActionClassifier` trait in `request-adaptor/src/classifiers/` |
| **New Cedar policies** | [README.md](README.md#writing-custom-policies) | `.cedar` files in `policies/examples/` |

## Project Structure

```
crates/
  engine/              Core Cedar evaluation engine
  request-adaptor/     Agent-specific input normalization + enrichment pipeline
  response-formatter/  Agent-specific output formatting
  audit/               JSON-line audit logging
  policy-defaults/     Compile-time embedded policies
  cli/                 Binary with check/validate/init/audit commands
policies/
  default/             Shipped Cedar policies and schema
  examples/            Example policies for users
hooks/
  copilot-cli/         Hook scripts and install for Copilot CLI
docs/                  Guides, specs, benchmarks
```

## Testing

- **Unit tests**: Inline `#[cfg(test)]` modules in each source file
- **Integration tests**: `crates/cli/tests/` — run the binary with `assert_cmd`
- **Hook tests**: `crates/cli/tests/hook_script_test.rs` — test the actual PowerShell hook script
- **Benchmarks**: `crates/engine/benches/` and `crates/cli/benches/`

See [docs/test-coverage.md](docs/test-coverage.md) for the full test inventory.

## Releases

This project uses [Semantic Versioning](https://semver.org/). Version is defined in `Cargo.toml` workspace config.

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
