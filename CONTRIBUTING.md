# Contributing to Phantomwire

Thank you for your interest in contributing! This project welcomes improvements from the
community. By participating you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Development Environment

1. Fork and clone the repository.
2. Create a virtual environment and install dependencies:

   ```bash
   pip install -e .[dev]
   pre-commit install
   ```

3. Run tests and linters locally before submitting a pull request:

   ```bash
   ruff check .
   mypy
   pytest
   ```

4. Ensure coverage remains above 80% for core modules. Add tests alongside new features.

## Commit Guidelines

- Use descriptive commit messages.
- Separate unrelated changes into different commits.
- Include documentation updates when changing behaviour or CLI options.

## Pull Requests

- Describe the motivation and testing performed.
- Ensure CI passes on all supported Python versions (3.10–3.12).
- New functionality must respect the safe-mode model and require explicit consent for active
  operations.

## Reporting Issues

Open an issue with steps to reproduce, expected results, and actual behaviour. For security
concerns see [SECURITY.md](SECURITY.md).
