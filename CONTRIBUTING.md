# Contributing to SecurityPilotAI 🛡️

Thank you for your interest in contributing to **SecurityPilotAI**! We welcome bug reports, feature requests, documentation improvements, and code contributions.

## Development Workflow

1. **Fork & Clone** the repository:
   ```bash
   git clone https://github.com/<your-username>/SecurityPilot-AI.git
   cd SecurityPilotAI
   ```
2. **Create a topic branch**:
   ```bash
   git checkout -b feature/my-new-feature
   ```
3. **Environment Setup**:
   Copy `.env.example` to `.env` and fill in local development credentials.

## Code Guidelines

- Maintain clean, self-documenting code with clear docstrings and comments.
- Follow standard code style rules (e.g., ESLint/Prettier for JavaScript/TypeScript, Black/Ruff for Python).
- Ensure all unit and integration tests pass before submitting PRs.
- Never commit secrets, credentials, or production API keys.

## Submitting Pull Requests

1. Keep PRs focused on a single feature or bug fix.
2. Title PRs using Conventional Commits format (`feat: ...`, `fix: ...`, `docs: ...`, `refactor: ...`).
3. Fill out the PR template and request review from maintainers.
