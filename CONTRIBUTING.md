# Contributing to ESC/P Text Editor

## How to Contribute

### 1. Find or Create Issue
- Check existing issues
- Create new issue with clear description
- Get approval before starting work

### 2. Fork and Branch
git checkout -b feature/your-feature-name

text

### 3. Implement Changes
- Follow [Development Guide](docs/DEVELOPMENT.md)
- Write tests first (TDD)
- Maintain type safety (mypy strict)
- Document all public APIs

### 4. Run Quality Checks
pytest tests/ --cov=src
mypy --strict src/
black src/ tests/
isort src/ tests/
flake8 src/ tests/

text

### 5. Commit and Push
git commit -m "feat: Add amazing feature"
git push origin feature/your-feature-name

text

### 6. Create Pull Request
- Use PR template
- Link related issues
- Add screenshots if UI changed
- Request review

## Code Style

- Follow PEP 8
- Use type hints everywhere
- Write Google-style docstrings
- Line length: 100 characters
- Use `black` for formatting

## Testing Requirements

- Unit tests for all new code
- Coverage > 90%
- Integration tests for critical paths
- All tests must pass

## AI-Assisted Development

You can use AI tools to contribute:
- See [PROMPT_TEMPLATES.md](docs/PROMPT_TEMPLATES.md)
- Always review AI-generated code
- Ensure tests and documentation included
2. LICENSE
text
MIT License

Copyright (c) 2025 Mike-voyager

[Full MIT license text]
