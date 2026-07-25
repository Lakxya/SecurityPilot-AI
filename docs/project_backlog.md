# SecurityPilotAI — Sprint Project Backlog

**Document Version:** 1.0.0  
**Author:** Lead Technical Program Manager  
**Status:** Approved & Implementation-Ready  
**Target Repository:** `SecurityPilotAI`  

---

## 📌 Backlog Overview

This document contains the complete, implementation-ready GitHub Issues backlog for **SecurityPilotAI**, covering Sprints 2 through 10. Each issue specifies precise acceptance criteria, technical requirements, priority, effort estimations, and dependencies.

### Legend
- **Priority:** `High` | `Medium` | `Low`
- **Effort:** `S` (1-2 days) | `M` (3-5 days) | `L` (1-2 weeks) | `XL` (2+ weeks)

---

## 🏃 Sprint 1: Core Foundation & Scaffolding (COMPLETED)
- [x] **#1.1** React + Vite + TypeScript frontend setup (`High`, `S`)
- [x] **#1.2** Tailwind CSS v4 design tokens and CSS variables configuration (`High`, `S`)
- [x] **#1.3** ESLint & Prettier setup for TypeScript (`Medium`, `S`)
- [x] **#1.4** Scalable frontend directory structure setup (`High`, `S`)

---

## 🚀 Sprint 2: Public Landing Page & Marketing Gateway

### Issue #2.1: Implement Landing Page Shell Layout & Hero Section
- **Sprint:** Sprint 2
- **Priority:** High
- **Effort:** M
- **Dependencies:** None (Sprint 1 Frontend Scaffolding)
- **Description:** Build the responsive public landing page hero section in `frontend/src/pages/LandingPage.tsx`. Features high-contrast dark theme typography, cyber-emerald glow badges, CTA buttons ("Get Started Free", "View Documentation"), and an interactive SVG security scanning animation.
- **Acceptance Criteria:**
  - Responsive across Desktop, Laptop, Tablet, and Mobile.
  - Matches design tokens in `product_design_specification.md`.
  - Accessible CTA buttons navigating to `/register` and `/docs`.

### Issue #2.2: Build Value Proposition & Feature Highlight Grid
- **Sprint:** Sprint 2
- **Priority:** Medium
- **Effort:** S
- **Dependencies:** #2.1
- **Description:** Implement a 6-card feature grid detailing core capabilities: Automated Security Architecture, STRIDE Threat Modeling, OWASP Top 10 Mitigation, Terraform/K8s Scaffolding, Live AI Copilot, and 1-Click Export.
- **Acceptance Criteria:**
  - Uses `Card` UI component from `src/components/ui/Card.tsx`.
  - Hover states feature subtle border glow and 150ms transform transitions.

### Issue #2.3: Build Interactive Security Architecture Sandbox Preview
- **Sprint:** Sprint 2
- **Priority:** High
- **Effort:** L
- **Dependencies:** #2.1
- **Description:** Build an interactive sandbox mockup component on the landing page allowing visitors to toggle between simulated SRS, Threat Model, and Terraform preview tabs without authenticating.
- **Acceptance Criteria:**
  - Syntax-highlighted code preview with mock document streams.
  - Zero API calls required; driven by local mock data.

### Issue #2.4: Build Pricing & Compliance Framework Section
- **Sprint:** Sprint 2
- **Priority:** Medium
- **Effort:** S
- **Dependencies:** #2.1
- **Description:** Construct the pricing tiers card section (Free Developer, Pro SecOps, Enterprise) and a ticker showcasing supported security frameworks (OWASP, SOC 2, HIPAA, PCI-DSS, ISO 27001).
- **Acceptance Criteria:**
  - Clear billing toggle (Monthly / Annual).
  - Highlighting "Most Popular" Pro plan.

### Issue #2.5: Implement Public Header Navigation & Footer
- **Sprint:** Sprint 2
- **Priority:** Low
- **Effort:** S
- **Dependencies:** #2.1
- **Description:** Create `Navbar.tsx` and `Footer.tsx` for public pages featuring brand logo, documentation links, GitHub repository link, theme status, and copyright notice.
- **Acceptance Criteria:**
  - Glassmorphism backdrop blur header (`backdrop-blur-md`).
  - Mobile hamburger drawer menu for screens under 768px.

---

## ⚡ Sprint 3: Backend Core Engine & PostgreSQL Setup

### Issue #3.1: Initialize FastAPI Backend Application & Environment Config
- **Sprint:** Sprint 3
- **Priority:** High
- **Effort:** M
- **Dependencies:** None
- **Description:** Set up the asynchronous FastAPI application structure in `backend/app/main.py`. Configure Pydantic `BaseSettings` for reading environment variables (`.env`), setup structured JSON logging, and register global CORS middleware.
- **Acceptance Criteria:**
  - Server starts cleanly via `uvicorn app.main:app --reload`.
  - Health check endpoint `/api/v1/health/liveness` returns HTTP 200 `{"status": "ok"}`.

### Issue #3.2: Configure PostgreSQL 16 Async Engine & Alembic Migrations
- **Sprint:** Sprint 3
- **Priority:** High
- **Effort:** M
- **Dependencies:** #3.1
- **Description:** Configure SQLAlchemy 2.0 async engine (`async_sessionmaker`) connecting to PostgreSQL 16. Set up Alembic migration framework and script initialization in `backend/alembic/`.
- **Acceptance Criteria:**
  - Async database sessions injected cleanly into API routes.
  - `alembic upgrade head` runs without errors.

### Issue #3.3: Implement Database ORM Models & Schemas
- **Sprint:** Sprint 3
- **Priority:** High
- **Effort:** M
- **Dependencies:** #3.2
- **Description:** Implement initial SQLAlchemy models in `backend/app/models/` for `Users` and `Settings` tables as defined in `technical_architecture_specification.md`. Create corresponding Pydantic schemas in `backend/app/schemas/`.
- **Acceptance Criteria:**
  - `Users` table created with UUID primary keys and indices on `email`.
  - Pydantic models validate email format and password strength.

### Issue #3.4: Set Up Redis Connection Pool & Caching Middleware
- **Sprint:** Sprint 3
- **Priority:** High
- **Effort:** S
- **Dependencies:** #3.1
- **Description:** Integrate `redis-py` async client in `backend/app/core/redis.py`. Implement caching utility functions and health check probe `/api/v1/health/readiness`.
- **Acceptance Criteria:**
  - Readiness probe verifies connectivity to both PostgreSQL and Redis.

---

## 🔐 Sprint 4: Authentication & User Management

### Issue #4.1: Implement Password Hashing & RS256 JWT Token Services
- **Sprint:** Sprint 4
- **Priority:** High
- **Effort:** M
- **Dependencies:** #3.3
- **Description:** Implement password hashing utilities using `passlib[bcrypt]` and asymmetric RS256 JWT token generation/verification services in `backend/app/core/security.py`.
- **Acceptance Criteria:**
  - Access tokens expire in 15 minutes and contain `sub`, `email`, and `role`.
  - Keys loaded securely from configuration or environment.

### Issue #4.2: Build Authentication Controllers (Register, Login, Refresh, Logout)
- **Sprint:** Sprint 4
- **Priority:** High
- **Effort:** M
- **Dependencies:** #4.1
- **Description:** Create authentication API routes in `backend/app/api/v1/controllers/auth.py` for account registration, credential verification, issuing HttpOnly `SameSite=Strict` refresh cookies, and session invalidation.
- **Acceptance Criteria:**
  - Login returns access token in JSON response and sets refresh cookie.
  - Revoked refresh tokens rejected by `/refresh` route via Redis blacklist check.

### Issue #4.3: Implement RBAC Middleware & Security Dependencies
- **Sprint:** Sprint 4
- **Priority:** High
- **Effort:** M
- **Dependencies:** #4.2
- **Description:** Create FastAPI dependency injection helpers `get_current_user` and `require_role(role)` in `backend/app/api/v1/deps.py` enforcing role-based access control.
- **Acceptance Criteria:**
  - Unauthorized requests return HTTP 401; insufficient role permissions return HTTP 403.

### Issue #4.4: Build Frontend Auth State & Authentication Pages
- **Sprint:** Sprint 4
- **Priority:** High
- **Effort:** M
- **Dependencies:** #4.2
- **Description:** Implement `AuthContext` provider in React, store access token in memory, and create `/login` and `/register` views with validation forms using React Hook Form or Zod.
- **Acceptance Criteria:**
  - Automatic silent token refresh via Axios interceptor on HTTP 401.
  - Unauthenticated users redirected away from `/dashboard`.

---

## 📁 Sprint 5: Project Management & Workspace API

### Issue #5.1: Implement Projects & GeneratedDocuments Database Models
- **Sprint:** Sprint 5
- **Priority:** High
- **Effort:** M
- **Dependencies:** #3.3
- **Description:** Create SQLAlchemy ORM models for `Projects`, `GeneratedDocuments`, `Chats`, and `AuditLogs` in `backend/app/models/`. Run Alembic migration to create tables.
- **Acceptance Criteria:**
  - Cascade deletes enforced on project deletion.
  - Foreign key constraints validated.

### Issue #5.2: Create Project Repository & Business Services
- **Sprint:** Sprint 5
- **Priority:** High
- **Effort:** M
- **Dependencies:** #5.1
- **Description:** Implement `ProjectRepository` and `ProjectService` classes handling project creation, pagination, filtering by status/tech stack, and metadata updates.
- **Acceptance Criteria:**
  - Operations scoped strictly to the authenticated user ID.

### Issue #5.3: Build Project API Controllers & 3-Step Wizard API
- **Sprint:** Sprint 5
- **Priority:** High
- **Effort:** S
- **Dependencies:** #5.2
- **Description:** Expose `/api/v1/projects` endpoints (GET, POST, PUT, DELETE). Implement request payload parsing for tech stack selection and compliance framework tags.
- **Acceptance Criteria:**
  - Validates project creation schema and returns created project payload.

### Issue #5.4: Build Frontend Dashboard & Project Wizard UI
- **Sprint:** Sprint 5
- **Priority:** High
- **Effort:** L
- **Dependencies:** #5.3, #4.4
- **Description:** Build `/dashboard` and `/projects` views in React. Implement Dashboard Topbar, Sidebar, Project Cards Grid, and the 3-Step Project Creation Wizard Modal.
- **Acceptance Criteria:**
  - Displays user's recent projects with real-time status indicators.
  - Successfully submits new project payload to backend API.

---

## 🤖 Sprint 6: AI Orchestration & Streaming Pipeline

### Issue #6.1: Build Multi-LLM Provider Adapter Layer
- **Sprint:** Sprint 6
- **Priority:** High
- **Effort:** L
- **Dependencies:** #3.1
- **Description:** Build abstract `LLMProvider` interface and concrete adapters for OpenAI (`GPT-4o`), Anthropic (`Claude 3.5 Sonnet`), and local `Ollama` models in `backend/app/services/ai/`.
- **Acceptance Criteria:**
  - Unified `generate_stream()` method yielding token chunks asynchronously across providers.

### Issue #6.2: Implement Prompt Synthesis Engine & Security Guardrails
- **Sprint:** Sprint 6
- **Priority:** High
- **Effort:** M
- **Dependencies:** #6.1
- **Description:** Build prompt engineering template synthesizers injecting system instructions, tech stack context, and compliance requirements. Implement input sanitization scanning for prompt injection patterns.
- **Acceptance Criteria:**
  - Sanitizes user prompts and injects structured output formatting directives.

### Issue #6.3: Build Server-Sent Events (SSE) Streaming API Controller
- **Sprint:** Sprint 6
- **Priority:** High
- **Effort:** M
- **Dependencies:** #6.2
- **Description:** Create streaming endpoint `POST /api/v1/generation/{project_id}/generate` utilizing FastAPI `EventSourceResponse` to stream LLM tokens to the client.
- **Acceptance Criteria:**
  - Streams tokens with `event: message` and completes with `event: end`.

### Issue #6.4: Integrate Frontend SSE Custom Hook & Stream Buffer
- **Sprint:** Sprint 6
- **Priority:** High
- **Effort:** M
- **Dependencies:** #6.3
- **Description:** Create custom React hook `useSSEStream` handling connection setup, token concatenation, auto-scrolling stream buffers, and error handling.
- **Acceptance Criteria:**
  - Smoothly renders live streaming AI responses in the UI without browser frame drops.

---

## 📜 Sprint 7: Document Generator Engine (13 Security Artifacts)

### Issue #7.1: Implement SRS, SDS & Architecture Generator Modules
- **Sprint:** Sprint 7
- **Priority:** High
- **Effort:** M
- **Dependencies:** #6.3
- **Description:** Build specialized prompt templates and output parsers for generating `README.md`, `SRS.md`, `SDS.md`, and `ARCHITECTURE.md` (with embedded Mermaid.js architecture diagrams).
- **Acceptance Criteria:**
  - Produces valid GitHub-flavored Markdown with syntactically valid Mermaid.js diagrams.

### Issue #7.2: Implement Threat Model (STRIDE) & OWASP Review Engines
- **Sprint:** Sprint 7
- **Priority:** High
- **Effort:** L
- **Dependencies:** #7.1
- **Description:** Build prompt generators for `THREAT_MODEL.md` (STRIDE framework analysis with CVSS scoring) and `OWASP_REVIEW.md` (vulnerability mitigation matrix).
- **Acceptance Criteria:**
  - Generates comprehensive threat tables mapping threats to concrete mitigation controls.

### Issue #7.3: Implement Infrastructure Scaffolding Generators (Docker, K8s, Terraform)
- **Sprint:** Sprint 7
- **Priority:** High
- **Effort:** L
- **Dependencies:** #7.1
- **Description:** Build generation pipelines for `Dockerfile`, `docker-compose.yml`, Kubernetes YAML manifests, `terraform/main.tf`, and `.github/workflows/ci.yml`.
- **Acceptance Criteria:**
  - Outputs syntax-valid HCL, YAML, and Distroless Dockerfiles adhering to security best practices.

### Issue #7.4: Implement Document Versioning & Auto-Save Repositories
- **Sprint:** Sprint 7
- **Priority:** High
- **Effort:** M
- **Dependencies:** #5.1, #7.3
- **Description:** Create `GeneratedDocumentRepository` handling automatic version incrementing, saving document updates, and setting `is_latest` boolean flags.
- **Acceptance Criteria:**
  - Maintains full version history per document without overwriting previous iterations.

---

## 🛠️ Sprint 8: Interactive IDE Workspace & Visualizations

### Issue #8.1: Integrate Monaco Code Editor & Dual-Pane Workspace Layout
- **Sprint:** Sprint 8
- **Priority:** High
- **Effort:** L
- **Dependencies:** #5.4, #7.4
- **Description:** Implement the multi-tab IDE workspace layout in `frontend/src/pages/WorkspacePage.tsx`. Integrate `@monaco-editor/react` with split-screen Markdown/Code preview capabilities.
- **Acceptance Criteria:**
  - Supports side-by-side editing, syntax highlighting, and live split view toggle.

### Issue #8.2: Implement Mermaid.js Architecture Diagram Renderer
- **Sprint:** Sprint 8
- **Priority:** High
- **Effort:** M
- **Dependencies:** #8.1
- **Description:** Build `DiagramViewer.tsx` component using `mermaid` library to dynamically parse and render architecture and sequence diagrams embedded in document markdown.
- **Acceptance Criteria:**
  - Clean zoom/pan controls and graceful fallback display for invalid diagram syntax.

### Issue #8.3: Build Right-Drawer AI Security Copilot Panel
- **Sprint:** Sprint 8
- **Priority:** High
- **Effort:** M
- **Dependencies:** #6.4, #8.1
- **Description:** Build interactive right-drawer AI Security Copilot chat component (`AIChatPanel.tsx`). Supports prompt shortcut chips ("Audit OWASP", "Add AWS KMS") and stream output rendering.
- **Acceptance Criteria:**
  - Persists chat history per project and allows 1-click insertion of code suggestions into the active editor.

### Issue #8.4: Build Document Version History & Diff Compare Modal
- **Sprint:** Sprint 8
- **Priority:** Medium
- **Effort:** M
- **Dependencies:** #8.1
- **Description:** Build version timeline bar and side-by-side diff comparison modal (`VersionDiffModal.tsx`) using `diff-match-patch` or Monaco diff editor.
- **Acceptance Criteria:**
  - Highlights added/deleted lines between selected versions and supports 1-click rollback.

---

## 📦 Sprint 9: Export System & Background Task Worker

### Issue #9.1: Configure Celery Background Task Worker & Redis Broker
- **Sprint:** Sprint 9
- **Priority:** High
- **Effort:** M
- **Dependencies:** #3.4
- **Description:** Set up Celery task worker in `backend/app/core/celery_app.py` backed by Redis for executing asynchronous long-running tasks (archive compression, PDF rendering).
- **Acceptance Criteria:**
  - Celery workers process background jobs independently from API thread pool.

### Issue #9.2: Build Multi-Format Export Engine (ZIP, Markdown Bundle, PDF)
- **Sprint:** Sprint 9
- **Priority:** High
- **Effort:** M
- **Dependencies:** #9.1
- **Description:** Implement background Celery tasks for bundling project artifacts into a formatted ZIP archive, single consolidated Markdown document, or PDF compliance report.
- **Acceptance Criteria:**
  - Generated ZIP contains complete repository folder layout ready for extraction.

### Issue #9.3: Implement AWS S3 Storage Adapter for Generated Exports
- **Sprint:** Sprint 9
- **Priority:** High
- **Effort:** S
- **Dependencies:** #9.2
- **Description:** Implement S3 storage service in `backend/app/services/storage.py` uploading compiled archives and issuing signed, time-limited download URLs.
- **Acceptance Criteria:**
  - Presigned URLs expire after 15 minutes.

### Issue #9.4: Build Export Modal & One-Click Download UI
- **Sprint:** Sprint 9
- **Priority:** High
- **Effort:** S
- **Dependencies:** #9.3, #8.1
- **Description:** Build frontend `ExportModal.tsx` allowing users to select export format (ZIP, Markdown, PDF), initiate background job, and trigger direct file download.
- **Acceptance Criteria:**
  - Real-time progress bar feedback during archive compilation.

---

## ☸️ Sprint 10: DevOps, Hardening & Production Release

### Issue #10.1: Build Production Multi-Stage Dockerfiles
- **Sprint:** Sprint 10
- **Priority:** High
- **Effort:** M
- **Dependencies:** None
- **Description:** Write production `Dockerfile` for backend (`python:3.11-slim` -> distroless non-root image) and frontend (Vite build -> NGINX static server).
- **Acceptance Criteria:**
  - Container images pass Trivy vulnerability scanning with zero Critical/High CVEs.

### Issue #10.2: Create Modular Terraform AWS Infrastructure Configuration
- **Sprint:** Sprint 10
- **Priority:** High
- **Effort:** L
- **Dependencies:** None
- **Description:** Create production Terraform modules in `terraform/` provisioning AWS VPC, EKS cluster, RDS PostgreSQL multi-AZ instance, ElastiCache Redis, and S3 buckets.
- **Acceptance Criteria:**
  - `terraform plan` executes cleanly with least-privilege IAM policies.

### Issue #10.3: Create Kubernetes Helm Deployment Manifests
- **Sprint:** Sprint 10
- **Priority:** High
- **Effort:** M
- **Dependencies:** #10.1
- **Description:** Create Helm chart definitions in `kubernetes/` including Deployments, Services, Ingress routes, HPA auto-scaling, and PodSecurityStandards.
- **Acceptance Criteria:**
  - K8s manifests deploy cleanly to local Minikube / K3s cluster.

### Issue #10.4: Build GitHub Actions CI/CD Pipeline
- **Sprint:** Sprint 10
- **Priority:** High
- **Effort:** M
- **Dependencies:** #10.3
- **Description:** Build `.github/workflows/ci.yml` pipeline running ESLint, Pytest, Semgrep SAST scans, Docker container builds, and automated cluster deployment.
- **Acceptance Criteria:**
  - Pipeline executes on every push to `main` branch.

### Issue #10.5: OWASP Hardening, Load Testing & Production Launch
- **Sprint:** Sprint 10
- **Priority:** High
- **Effort:** L
- **Dependencies:** All previous issues
- **Description:** Perform security hardening (CSP headers, rate limit validation), run Locust load tests (target: 500 concurrent requests), and execute production launch.
- **Acceptance Criteria:**
  - System maintains sub-100ms API response time under target load with zero security vulnerabilities.

---

*This backlog is implementation-ready for SecurityPilotAI development.*
