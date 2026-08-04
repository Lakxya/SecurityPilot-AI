# Changelog

All notable changes to **SecurityPilotAI** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Sprint 7 (Document Generator Engine & 13 Security Artifacts):** Specialized `DocumentGenerators` module (`backend/app/services/ai/document_generators.py`) generating production-ready templates for all 13 core security artifacts: `README.md`, `SRS.md`, `SDS.md`, `ARCHITECTURE.md` (with Mermaid.js architecture diagrams), `DATABASE_DESIGN.md` (with ER diagrams), `API_SPEC.yaml`, `THREAT_MODEL.md` (STRIDE framework with CVSS risk scores), `OWASP_REVIEW.md` (Top 10 matrix), `Dockerfile` (distroless multi-stage), `docker-compose.yml`, `deployment.yaml` (Kubernetes), `main.tf` (Terraform HCL), and `ci.yml` (GitHub Actions). Implemented Pytest test suite (`test_document_generators.py`) and frontend `DocumentWorkspace` 13-tab IDE component with live editing, saving, and SSE streaming.
- **Sprint 6 (AI Orchestration & Streaming Pipeline):** Abstract `BaseLLMProvider` interface and concrete `OpenAIProvider`, `AnthropicProvider`, and `MockLLMProvider` adapters (`backend/app/services/ai/providers.py`). Implemented `PromptSynthesizer` & `SecurityGuardrails` (`prompt_engine.py`), `GenerationService` for SSE token streaming and database persistence, `/api/v1/generation` REST & SSE endpoints, Pytest test suite (`test_generation.py`), frontend `generationService`, and `useSSEStream` custom hook.
- **Sprint 5 (Project Management & Workspace API):** `Project` & `GeneratedDocument` ORM models, Pydantic v2 schemas, `ProjectRepository`, `ProjectService`, `/api/v1/projects/` REST controllers, frontend `projectService` & TypeScript interfaces, and Pytest integration test suite.
- **Sprint 4 (IDE Application Dashboard Shell):** `DashboardSidebar`, `DashboardHeader`, `DashboardFooter`, `DashboardStats`, `RecentProjectsGrid`, `CreateProjectModal`, and `Cmd+K` `CommandSearchModal`.
- **Sprint 3 (Identity & Access Authentication System):** Asymmetric RS256 JWT auth, bcrypt password hashing, `User` model, `/api/v1/auth/` controllers, `AuthContext`, `useAuth`, `ProtectedRoute`, and Login/Register views.
- **Sprint 2 (Public Landing Page):** Hero section, feature cards grid, trusted tech banner, comparison matrix, and FAQ accordion.
- **Sprint 1 (Scaffolding):** Initial directory architecture, React + Vite + TypeScript frontend foundation, Tailwind CSS v4 design tokens, and ESLint/Prettier configurations.
