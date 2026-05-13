# Contributing to Project Raven

Thank you for your interest in contributing to Project Raven!

## Development Setup

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/project-raven.git`
3. Create a virtual environment: `python3 -m venv venv`
4. Activate the virtual environment: `source venv/bin/activate`
5. Install development dependencies: `pip install -r requirements.txt`
6. Install test dependencies: `pip install -e ".[dev]"`

## Code Style

We use:
- **Black** for code formatting
- **Flake8** for linting
- **MyPy** for type checking

Run these before committing:
```bash
black raven/
flake8 raven/
mypy raven/
```

## Testing

Run the test suite:
```bash
pytest tests/
```

Run with coverage:
```bash
pytest --cov=raven tests/
```

## Project Structure

```
raven/
├── api/              # FastAPI endpoints
├── core/             # Core business logic
├── ml/               # ML/AI models
├── tools/            # Security tool integrations
├── hunters/          # Threat hunting modules
├── mitigation/       # Response automation
├── monitoring/       # Metrics and dashboards
└── config/           # Configuration
```

## Adding New Features

1. Create a feature branch: `git checkout -b feature/your-feature`
2. Make your changes
3. Write tests for new functionality
4. Ensure all tests pass
5. Update documentation if needed
6. Submit a pull request

## ML Model Contributions

When contributing ML models:
1. Provide training data examples
2. Document model architecture
3. Include performance metrics
4. Add model loading/saving functionality
5. Write unit tests

## Security Tool Integrations

When adding new security tools:
1. Follow the pattern in `raven/tools/`
2. Implement error handling
3. Add configuration options
4. Include safety checks
5. Write integration tests

## Documentation

Keep documentation updated:
- Update README.md for user-facing changes
- Update ARCHITECTURE.md for structural changes
- Add inline comments for complex logic
- Update DEPLOYMENT.md for deployment changes

## Code Review Process

1. All PRs require review
2. At least one approval needed
3. CI checks must pass
4. Security changes require additional review

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
