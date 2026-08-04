# SecurityPilotAI — Technical Architecture Specification (TAS)

**Document Version:** 1.0.0  
**Author:** Chief Software Architect  
**Status:** Approved for Implementation  
**Target Architecture:** Multi-Tier Asynchronous Cloud-Native SaaS  

---

## 1. Overall System Architecture

SecurityPilotAI is built as a multi-tier, cloud-native, microservices-ready SaaS platform. The system separates concerns between high-performance client rendering, asynchronous RESTful backend API handling, stateful database storage, and an AI generation pipeline.

```text
+-----------------------------------------------------------------------------------+
| CLIENT LAYER                                                                      |
| React 18 + Vite + TypeScript + Tailwind CSS v4 + React Router + Monaco Editor     |
+-----------------------------------------+-----------------------------------------+
                                          | HTTPS / SSE (Server-Sent Events)
                                          v
+-----------------------------------------------------------------------------------+
| INGRESS & API GATEWAY LAYER                                                       |
| Cloudflare WAF & CDN ──► NGINX Ingress Controller (Rate Limiting, TLS Termination)|
+-----------------------------------------+-----------------------------------------+
                                          | HTTP / gRPC
                                          v
+-----------------------------------------------------------------------------------+
| BACKEND SERVICE LAYER (Python FastAPI Asynchronous Core)                         |
|  - Auth & RBAC Middleware          - Project Orchestration Service               |
|  - Document Generator Engine       - AI Prompt & Guardrails Pipeline             |
+--------------------+--------------------+--------------------+--------------------+
                     |                    |                    |
        +------------+            +-------+--------+     +-----+--------------+
        |                         |                |     |                    |
        v                         v                v     v                    v
+---------------+        +------------------+  +------------------+  +------------------+
| DATABASE      |        | CACHE & QUEUE    |  | OBJECT STORAGE   |  | EXTERNAL AI APIS |
| PostgreSQL 16 |        | Redis 7 + Celery |  | AWS S3 / MinIO   |  | OpenAI / Anthropic|
| (Relational)  |        | (Sessions/Tasks) |  | (Export Bundles) |  | Ollama (Local)   |
+---------------+        +------------------+  +------------------+  +------------------+
```

### 1.1 Architectural Layers Specification

1. **Frontend Layer:** React 18 SPA compiled via Vite, written in strict TypeScript. Employs Tailwind CSS v4 for zero-runtime styling, Monaco/CodeMirror for live code editing, and Server-Sent Events (SSE) for streaming AI document generation responses.
2. **Ingress & API Gateway Layer:** Cloudflare Edge WAF handles DDoS mitigation, SSL/TLS termination, and global CDN caching. Internal NGINX Ingress Controller directs incoming traffic to backend pods with rate-limiting annotations.
3. **Backend Service Layer:** High-performance, fully asynchronous Python FastAPI framework running under ASGI (Uvicorn/Gunicorn). Handles business logic, Pydantic request validation, JWT authentication, and prompt execution workflows.
4. **Database Layer:** PostgreSQL 16 serves as the primary relational persistence engine for users, projects, and versioned document records. Uses SQLAlchemy 2.0 async ORM with Alembic for database migrations.
5. **Cache & Task Queue Layer:** Redis 7 provides high-speed in-memory caching for session management, token blacklisting, rate-limiting counters, and acts as the message broker for background Celery tasks (e.g., zip bundling, PDF export).
6. **AI Layer:** Multi-provider LLM Orchestration engine supporting OpenAI (GPT-4o), Anthropic (Claude 3.5 Sonnet), and local Ollama models. Implements prompt template engines, input/output security guardrails, and streaming response tokenizers.
7. **Storage Layer:** S3-compatible Object Storage (AWS S3 or MinIO) storing compiled export packages, generated PDF reports, and project backup snapshots.
8. **Authentication & Identity Layer:** Stateless JWT tokens signed via asymmetric RS256 keys, paired with HttpOnly SameSite secure refresh tokens and Redis-backed active session invalidation.
9. **Infrastructure & Cloud Layer:** Provisioned declaratively via Terraform on AWS (EKS, RDS PostgreSQL, ElastiCache Redis, S3, IAM Roles, VPC with public/private subnet isolation).
10. **Deployment & Delivery Layer:** Multi-stage Docker containers deployed to Kubernetes clusters via Helm charts, managed through automated GitHub Actions CI/CD pipelines.

---

## 2. Backend Architecture

The backend codebase is organized inside [`backend/`](file:///c:/Users/Lakshya%20Atulkar/OneDrive/Documents/Projectssss/SecurityPilotAI/backend) using clean, domain-driven layer separation:

```text
backend/
├── app/
│   ├── api/
│   │   └── v1/
│   │       ├── controllers/      # HTTP Request Handlers & API Routers
│   │       └── router.py         # Primary API Router Registration
│   ├── core/                     # App Config, Security Keys, Logging, DB Connection
│   ├── middlewares/              # CORS, Auth, Rate Limiting, Security Headers
│   ├── models/                   # SQLAlchemy ORM Database Entity Definitions
│   ├── repositories/             # Data Access Layer & DB Query Abstractions
│   ├── schemas/                  # Pydantic Schemas for Validation & Serialization
│   ├── services/                 # Business Logic & AI Generation Orchestration
│   └── utils/                    # Helper Functions, Cryptography, Markdown Parser
├── alembic/                      # Database Migration Scripts
├── tests/                        # Unit, Integration, and API Test Suites
├── Dockerfile                    # Production Distroless Dockerfile
└── requirements.txt              # Backend Dependencies
```

### 2.1 Directory Responsibilities

- **`controllers/`:** Implements FastAPI APIRouter endpoints. Handles HTTP parameter extraction, request routing, dependency injection resolution, and returning standard response schemas. Contains zero business logic.
- **`services/`:** Core application domain services. Implements business rules, coordinates calls between repositories, invokes AI LLM wrappers, manages streaming logic, and handles document compilation.
- **`repositories/`:** Encapsulates data access logic. Contains async SQLAlchemy queries (`select`, `insert`, `update`, `delete`). Keeps database execution decoupled from business logic services.
- **`models/`:** Defines database table structures as SQLAlchemy ORM classes mapping directly to PostgreSQL tables and relationships.
- **`schemas/`:** Pydantic models enforcing strict input request payload validation, query parameter parsing, and output JSON response serialization.
- **`middlewares/`:** Global request processing middleware including CORS policy enforcement, rate limiting, JWT token verification, security response headers, and request tracing IDs.
- **`core/`:** Central application configuration (Pydantic `BaseSettings`), database engine initialization (`async_sessionmaker`), Redis connection pools, logger configuration, and environment variable loaders.
- **`utils/`:** Pure utility functions for password hashing (bcrypt), token generation, string sanitization, and format converters.

---

## 3. Frontend Architecture

The frontend application is structured inside [`frontend/src/`](file:///c:/Users/Lakshya%20Atulkar/OneDrive/Documents/Projectssss/SecurityPilotAI/frontend/src) for high modularity:

```text
frontend/src/
├── assets/         # SVGs, Static Images, Web Fonts
├── components/     # UI Component Hierarchy
│   ├── common/     # Generic Reusable Components (Badges, Loaders)
│   ├── layout/     # Structural Layouts (Navbar, Sidebar, AppShell)
│   ├── ui/         # Atomic Primitives (Buttons, Cards, Dialogs, Inputs)
│   └── workspace/  # Project IDE & AI Editor Widgets
├── hooks/          # Custom React Hooks (useAuth, useProject, useSSE)
├── lib/            # Third-Party Configurations (Axios, Monaco, Tailwind)
├── pages/          # Top-Level Page Views (Dashboard, Workspace, Settings)
├── services/       # API Service Layer (HTTP Requests, SSE Listeners)
├── styles/         # Global Tailwind CSS v4 & Theme Variables
├── types/          # TypeScript Interface & Type Definitions
└── utils/          # Pure UI Helper Functions (Class Merging, Date Formatting)
```

### 3.1 Directory Responsibilities

- **`components/`:** Houses modular React UI components using strict atomic grouping (`common/`, `layout/`, `ui/`, `workspace/`).
- **`pages/`:** Page-level container components mapped directly to React Router routes (`/dashboard`, `/projects/:id`, `/settings`).
- **`hooks/`:** Custom React hooks abstracting stateful logic, keyboard shortcuts, SSE stream ingestion, and authentication context bindings.
- **`services/`:** Encapsulates all backend API communication utilizing Axios client instances and native `EventSource` wrappers for streaming endpoints.
- **`lib/`:** Third-party library initializations, path alias bindings (`@/`), and helper setups for Monaco Editor and Tailwind `clsx`/`tailwind-merge`.
- **`types/`:** Shared TypeScript type interfaces mirror backend Pydantic schemas, ensuring full type-safety across API boundaries.
- **`utils/`:** Pure frontend helper utilities (e.g. date formatting, string truncation, Markdown sanitization).
- **`styles/`:** CSS entry point importing Tailwind CSS v4 (`@import "tailwindcss";`) and custom theme CSS custom properties.

---

## 4. Database Schema Design

The relational database uses **PostgreSQL 16**. The schema consists of 10 primary tables designed for high data integrity, strict foreign key constraints, and optimized indexing.

```text
+---------------+       +------------------+       +-----------------------+
| Users         |1    * | Projects         |1    * | GeneratedDocuments    |
+---------------+-------+------------------+-------+-----------------------+
| id (PK)       |       | id (PK)          |       | id (PK)               |
| email         |       | user_id (FK)     |       | project_id (FK)       |
| password_hash |       | title            |       | doc_type              |
| role          |       | tech_stack (JSON)|       | content (Text)        |
+---------------+       +------------------+       | version               |
        |                         |                +-----------------------+
        |1                        |1
        |*                        |*
+---------------+       +------------------+       +-----------------------+
| APIKeys       |       | Chats            |       | Generations           |
+---------------+       +------------------+       +-----------------------+
| id (PK)       |       | id (PK)          |       | id (PK)               |
| user_id (FK)  |       | project_id (FK)  |       | project_id (FK)       |
| key_hash      |       | prompt           |       | doc_type              |
+---------------+       | response         |       | tokens_used           |
                        +------------------+       +-----------------------+
```

### 4.1 Table Specifications

#### 1. `Users`
- **Purpose:** Stores user account identities, authentication credentials, and global authorization roles.
- **Key Columns:**
  - `id`: `UUID` (Primary Key, default `gen_random_uuid()`)
  - `email`: `VARCHAR(255)` (Unique, Indexed, Non-Null)
  - `password_hash`: `VARCHAR(255)` (Bcrypt Hashed String)
  - `full_name`: `VARCHAR(100)`
  - `role`: `VARCHAR(50)` (Enum: `SUPER_ADMIN`, `ORG_ADMIN`, `SECURITY_ENGINEER`, `DEVELOPER`, `AUDITOR`)
  - `is_active`: `BOOLEAN` (Default `TRUE`)
  - `created_at` / `updated_at`: `TIMESTAMPTZ`
- **Relationships:** Has many `Projects`, `APIKeys`, `Settings`, `AuditLogs`, `Notifications`.

#### 2. `Projects`
- **Purpose:** Central entity representing a user's security architecture project workspace.
- **Key Columns:**
  - `id`: `UUID` (Primary Key)
  - `user_id`: `UUID` (Foreign Key -> `Users.id` ON DELETE CASCADE)
  - `name`: `VARCHAR(150)` (Non-Null)
  - `description`: `TEXT`
  - `tech_stack`: `JSONB` (Stores selected frontend, backend, DB, cloud, container runtime)
  - `compliance_frameworks`: `JSONB` (Array: `["OWASP_TOP_10", "SOC_2", "HIPAA"]`)
  - `status`: `VARCHAR(30)` (Default `'ACTIVE'`, `'ARCHIVED'`)
  - `created_at` / `updated_at`: `TIMESTAMPTZ`
- **Relationships:** Belongs to `Users`. Has many `GeneratedDocuments`, `Chats`, `Generations`, `Exports`.

#### 3. `GeneratedDocuments`
- **Purpose:** Stores active and historical versions of the 13 core security & design artifacts per project.
- **Key Columns:**
  - `id`: `UUID` (Primary Key)
  - `project_id`: `UUID` (Foreign Key -> `Projects.id` ON DELETE CASCADE)
  - `doc_type`: `VARCHAR(50)` (Enum: `README`, `SRS`, `SDS`, `ARCHITECTURE`, `DATABASE_DESIGN`, `API_SPEC`, `THREAT_MODEL`, `OWASP_REVIEW`, `DOCKERFILE`, `DOCKER_COMPOSE`, `KUBERNETES`, `TERRAFORM`, `GITHUB_ACTIONS`)
  - `file_path`: `VARCHAR(255)` (Target workspace relative path)
  - `content`: `TEXT` (Raw Markdown, YAML, HCL, or Dockerfile content)
  - `version`: `INTEGER` (Auto-incrementing version number per project/doc_type)
  - `is_latest`: `BOOLEAN` (Indexed flag for active document version)
  - `created_at`: `TIMESTAMPTZ`
- **Relationships:** Belongs to `Projects`. Indexed on `(project_id, doc_type, is_latest)`.

#### 4. `ChatConversations`
- **Purpose:** Persists AI Copilot interaction history for each project workspace, supporting context enrichment and past conversation retrieval.
- **Key Columns:**
  - `id`: `VARCHAR(36)` (Primary Key UUID)
  - `project_id`: `VARCHAR(36)` (Foreign Key -> `Projects.id` ON DELETE CASCADE)
  - `user_id`: `VARCHAR(36)` (Foreign Key -> `Users.id` ON DELETE CASCADE)
  - `role`: `VARCHAR(20)` (`'user'`, `'assistant'`, `'system'`)
  - `content`: `TEXT` (Prompt or response content)
  - `doc_type`: `VARCHAR(50)` (Active document context tag)
  - `created_at`: `TIMESTAMPTZ`
- **Relationships:** Belongs to `Projects` (`chats` back-populates relationship) and `Users`.

#### 5. `Generations`
- **Purpose:** Audit tracking for AI document generation requests, execution duration, and token consumption metrics.
- **Key Columns:**
  - `id`: `UUID` (Primary Key)
  - `project_id`: `UUID` (Foreign Key -> `Projects.id`)
  - `doc_type`: `VARCHAR(50)`
  - `prompt_tokens`: `INTEGER`
  - `completion_tokens`: `INTEGER`
  - `execution_time_ms`: `INTEGER`
  - `status`: `VARCHAR(30)` (`'SUCCESS'`, `'FAILED'`, `'IN_PROGRESS'`)
  - `created_at`: `TIMESTAMPTZ`

#### 6. `Exports`
- **Purpose:** Logs generated project export archives and storage download URLs.
- **Key Columns:**
  - `id`: `UUID` (Primary Key)
  - `project_id`: `UUID` (Foreign Key -> `Projects.id`)
  - `export_format`: `VARCHAR(20)` (`'ZIP'`, `'MARKDOWN_BUNDLE'`, `'PDF'`)
  - `storage_path`: `VARCHAR(255)` (S3 key location)
  - `file_size_bytes`: `BIGINT`
  - `created_at`: `TIMESTAMPTZ`

#### 7. `Settings`
- **Purpose:** Stores user-level system and AI provider preferences.
- **Key Columns:**
  - `id`: `UUID` (Primary Key)
  - `user_id`: `UUID` (Foreign Key -> `Users.id` UNIQUE)
  - `default_ai_model`: `VARCHAR(50)` (Default `'claude-3-5-sonnet'`)
  - `theme`: `VARCHAR(20)` (Default `'dark'`)
  - `custom_api_key_encrypted`: `TEXT` (AES-256 encrypted user-provided API key)
  - `updated_at`: `TIMESTAMPTZ`

#### 8. `APIKeys`
- **Purpose:** Manages programmatic API key credentials for developers interacting with SecurityPilotAI via CLI or external integrations.
- **Key Columns:**
  - `id`: `UUID` (Primary Key)
  - `user_id`: `UUID` (Foreign Key -> `Users.id`)
  - `name`: `VARCHAR(100)`
  - `key_hash`: `VARCHAR(255)` (SHA-256 hashed API token)
  - `prefix`: `VARCHAR(12)` (First 8 characters for key identification e.g., `sec_live_...`)
  - `expires_at`: `TIMESTAMPTZ`
  - `last_used_at`: `TIMESTAMPTZ`

#### 9. `Notifications`
- **Purpose:** Stores user-facing system notifications, generation alerts, and security warnings.
- **Key Columns:**
  - `id`: `UUID` (Primary Key)
  - `user_id`: `UUID` (Foreign Key -> `Users.id`)
  - `title`: `VARCHAR(150)`
  - `message`: `TEXT`
  - `type`: `VARCHAR(30)` (`'INFO'`, `'SUCCESS'`, `'WARNING'`, `'CRITICAL'`)
  - `is_read`: `BOOLEAN` (Default `FALSE`)
  - `created_at`: `TIMESTAMPTZ`

#### 10. `AuditLogs`
- **Purpose:** Immutable compliance audit log tracking all security-sensitive operations across the system.
- **Key Columns:**
  - `id`: `UUID` (Primary Key)
  - `user_id`: `UUID` (Foreign Key -> `Users.id`)
  - `action`: `VARCHAR(100)` (e.g., `'USER_LOGIN'`, `'PROJECT_DELETED'`, `'KEY_CREATED'`)
  - `ip_address`: `VARCHAR(45)`
  - `user_agent`: `TEXT`
  - `payload`: `JSONB` (Metadata associated with the action)
  - `created_at`: `TIMESTAMPTZ` (Indexed for compliance searching)

---

## 5. Authentication & Authorization Architecture

### 5.1 Token & Session Strategy

```text
Client App               Backend API              Redis Cache
    |                         |                        |
    |-- Login Credentials --->|                        |
    |                         |-- Verify Bcrypt Hash ->|
    |<-- Set HttpOnly Refresh |                        |
    |    & Return Access JWT -|-- Store Session ID --->|
    |                         |                        |
    |-- Request + Bearer JWT->|                        |
    |                         |-- Validate RS256 Sig ->|
    |                         |-- Check Blacklist ---->|
    |<-- Protected Resource --|                        |
```

- **Access Token:** Short-lived JWT (15-minute expiration) signed using asymmetric RS256 private key. Contains user claims (`sub`, `email`, `role`, `exp`, `jti`). Verified by backend services using public key.
- **Refresh Token:** Long-lived token (7-day expiration) stored exclusively in a secure `HttpOnly`, `SameSite=Strict`, `Secure` cookie. Hashed token stored in PostgreSQL & Redis to enable instant session revocation.
- **Password Reset:** Cryptographically secure single-use tokens signed with HMAC-SHA256, valid for 60 minutes.
- **Role-Based Access Control (RBAC):** Hierarchical permission enforcement via FastAPI security dependencies:
  - `SUPER_ADMIN`: Full cluster, user management, and system billing access.
  - `ORG_ADMIN`: Organization project controls, team member management.
  - `SECURITY_ENGINEER`: Full project creation, threat model editing, IaC generation, export capabilities.
  - `DEVELOPER`: Project reading, document generation, interactive editing.
  - `AUDITOR`: Read-only access to documents, threat models, and compliance reports.
- **Session Management:** Active sessions tracked in Redis (`session:user_id:session_id`). Allows users to view active logged-in devices and trigger global logout (invalidating all refresh tokens).

---

## 6. AI Orchestration Architecture

### 6.1 Prompt Execution & Response Pipeline Flow

```text
User Request
    │
    ▼
1. Prompt Builder & Context Synthesizer
   (Assembles System Instructions + Tech Stack + Compliance Rules)
    │
    ▼
2. Input Security Guardrails & Sanitizer
   (Scans for Prompt Injections, Secret Leaks, Malicious Payloads)
    │
    ▼
3. Multi-LLM Routing Layer
   (Selects Provider: OpenAI / Anthropic / Ollama based on user config)
    │
    ▼
4. Streaming Engine (Server-Sent Events / SSE)
   (Streams text chunks in real-time to client)
    │
    ▼
5. Output Validation & Parser
   (Validates Syntax: Markdown / YAML / HCL / Dockerfile)
    │
    ▼
6. Persistence Layer
   (Stores Versioned Document in PostgreSQL GeneratedDocuments Table)
    │
    ▼
7. Frontend Client View Render
   (Monaco Editor & Mermaid.js Diagram Render)
```

---

## 7. API Architecture & REST Domain Endpoints

All API endpoints are versioned under `/api/v1/`.

### 7.1 Domain Endpoints Summary

```text
Authentication (/api/v1/auth)
├── POST /register               - User Account Creation
├── POST /login                  - Authenticate & Issue Tokens
├── POST /refresh                - Refresh Access Token via HttpOnly Cookie
├── POST /logout                 - Revoke Current Session & Cookie
└── POST /forgot-password        - Initiate Password Reset Email

Projects (/api/v1/projects)
├── GET  /                       - List User Projects (Paginated & Filtered)
├── POST /                       - Create New Project Workspace
├── GET  /{project_id}           - Retrieve Project Details & Document Tree
├── PUT  /{project_id}           - Update Project Metadata
└── DELETE /{project_id}        - Archive or Delete Project

Generation (/api/v1/generation)
├── POST /{project_id}/generate  - Trigger Single Document Generation (SSE Stream)
├── POST /{project_id}/all       - Trigger Sequential Generation for All 13 Documents
├── GET  /{project_id}/docs/{type} - Fetch Latest Version of Specified Document
└── PUT  /{project_id}/docs/{type} - Save Direct User Edits to Document

History (/api/v1/history)
├── GET  /{project_id}/versions  - List Version History for Documents
├── GET  /{project_id}/diff      - Compare Diffs Between Two Document Versions
└── POST /{project_id}/rollback  - Rollback Document to Selected Version

Export (/api/v1/export)
├── POST /{project_id}/zip       - Package Project Architecture as ZIP Archive
├── POST /{project_id}/bundle    - Generate Merged Markdown Spec Bundle
└── POST /{project_id}/pdf       - Compile PDF Compliance Report

Settings (/api/v1/settings)
├── GET  /                       - Fetch User & Model Preferences
├── PUT  /                       - Update Settings & Custom AI API Keys
└── POST /api-keys               - Issue New Programmatic API Key

AI (/api/v1/ai)
├── POST /{project_id}/chat      - Send Interactive Prompt to Security Copilot
└── GET  /models                 - List Available LLM Providers & Status

Health (/api/v1/health)
├── GET  /liveness               - Kubernetes Liveness Probe
└── GET  /readiness              - Kubernetes Readiness Probe (DB & Redis Check)
```

---

## 8. Security Architecture & Controls

SecurityPilotAI implements a defense-in-depth security model:

1. **Authentication & Authorization:** Asymmetric RS256 JWT validation, strict HttpOnly cookies, fine-grained RBAC per endpoint.
2. **Rate Limiting:** Sliding-window rate limiting managed via Redis (`100 req/min` for API routes, `10 req/min` for AI generation endpoints).
3. **Input Validation & Sanitization:** Strict Pydantic request schema validation. All user input rendered in HTML is sanitized using DOMPurify on the frontend and HTML entity escaping on the backend to prevent XSS.
4. **OWASP Protections:**
   - **SQL Injection:** Prevented by using SQLAlchemy parameterization (zero raw string concatenation).
   - **XSS Protection:** Content Security Policy (CSP) headers disallow inline script execution.
   - **CSRF Protection:** SameSite=Strict cookies combined with custom CSRF validation headers.
   - **HSTS:** Enforced HTTP Strict Transport Security (`max-age=31536000; includeSubDomains`).
5. **Secrets Management:** Secrets stored in AWS Secrets Manager or HashiCorp Vault. User custom API keys encrypted at rest using AES-256-GCM.
6. **Audit Trail & Logging:** Structured JSON logging with user IDs, IP addresses, and request correlation IDs. Sensitive data fields automatically masked.
7. **Encryption:** TLS 1.3 enforced for all in-transit communications. Storage encrypted at rest via AWS KMS (AES-256).

---

## 9. DevOps & Infrastructure Architecture

```text
Developer Push ──► GitHub Actions CI/CD Pipeline
                        │
                        ├─► Linting & Type Checking (ESLint / MyPy)
                        ├─► Automated Unit Tests (Pytest / Vitest)
                        ├─► SAST Security Scan (Trivy / Semgrep)
                        ├─► Build Multi-Stage Docker Images
                        └─► Deploy via Helm to AWS EKS Cluster
```

### 9.1 Containerization & IaC Strategy
- **Docker Multi-Stage Build:** Backend built on `python:3.11-slim`, final stage uses distroless non-root image. Frontend statically compiled with Vite and served via minimal NGINX image.
- **Docker Compose:** Local multi-container setup running Frontend, Backend API, PostgreSQL 16, Redis 7, and LocalStack (mock S3).
- **Terraform Infrastructure Modules:** Provisions AWS VPC (public/private subnets across 3 AZs), EKS cluster, RDS PostgreSQL multi-AZ instance, ElastiCache Redis, S3 buckets, and IAM roles.
- **Kubernetes Helm Orchestration:** Deployment manifests configuring Pod Auto-scaling (HPA based on CPU/Memory), Pod Security Standards (`restricted` profile), and NetworkPolicies isolating backend pods from non-essential traffic.

---

## 10. Monitoring & Observability

- **Prometheus Metrics:** Backend exposes `/metrics` monitoring request latency histograms, status code frequencies, active DB connection pool stats, and AI generation duration timers.
- **Grafana Dashboards:** Pre-configured dashboards tracking System SLA, API Error Rates (5xx/4xx), LLM Token Usage per User, and Memory/CPU consumption.
- **Health Checks:** Probes (`/health/liveness` returning HTTP 200, `/health/readiness` executing real DB `SELECT 1` and Redis `PING`).
- **Structured JSON Logging:** Asynchronous logging shipped via Promtail/Loki for real-time querying.
- **OpenTelemetry Tracing:** Distributed tracing instrumentation tracking requests across NGINX → FastAPI → PostgreSQL → Redis → External AI Provider APIs.

---

## 11. Sprint-by-Sprint Technical Development Roadmap

| Sprint | Focus Area | Technical Deliverables |
| :--- | :--- | :--- |
| **Sprint 1** | **Scaffolding (Done)** | React + Vite + TS frontend foundation, Tailwind CSS v4 design tokens, initial folder hierarchy. |
| **Sprint 2** | **Landing Page (Done)** | Public marketing hero section, feature highlight cards, trusted tech banner, FAQ accordion. |
| **Sprint 3** | **Auth & User System (Done)** | RS256 JWT authentication, bcrypt password hashing, Pydantic schemas, AuthContext & ProtectedRoutes. |
| **Sprint 4** | **Dashboard Shell (Done)** | IDE-style sidebar navigation, top header, status bar, command palette (`Cmd+K`), stats cards. |
| **Sprint 5** | **Project Workspace API (Done)**| Project & GeneratedDocument ORM models, ProjectRepository, ProjectService, RESTful API controllers, frontend projectService. |
| **Sprint 6** | **AI Pipeline & SSE Stream (Done)**| Multi-LLM provider adapters (OpenAI / Anthropic / Mock), PromptSynthesizer, SSE streaming endpoints, frontend `useSSEStream` hook. |
| **Sprint 7** | **Document Engine (13 Docs) (Done)**| 13 security document generators (DocumentGenerators), Mermaid.js diagrams, STRIDE threat matrices, HCL/YAML/Dockerfile templates, frontend `DocumentWorkspace`. |
| **Sprint 8** | **Interactive IDE Workspace (Done)** | Document listing & version history REST endpoints, version snapshot restore, split-screen version diff comparison view, single document regeneration modal. |
| **Sprint 9** | **Export System (Done)** | Multi-format export engine (`ExportService`), ZIP repository bundler, Markdown security bundle, JSON spec exporter, frontend `ExportModal` & `exportService`. |
| **Copilot** | **AI Assistant (Done)** | `ChatConversation` ORM model, `CopilotEngine` context enrichment, `/api/v1/chat/message` SSE endpoint, frontend `CopilotPanel`, `ChatMessage`, `ChatInput`, `useChat`. |
| **Sprint 10** | **Hardening & Launch** | OWASP security audit, load testing (Locust), OpenTelemetry setup, production release. |

---

## 12. Architectural Rationale & Design Decisions

1. **Why FastAPI over Node.js / Django?**  
   FastAPI offers native asynchronous IO performance matching Node.js while providing first-class integration with Python's rich AI/ML ecosystem (LangChain, OpenAI, Anthropic SDKs). Pydantic integration guarantees strict runtime type safety.

2. **Why PostgreSQL 16 over MongoDB?**  
   Security architecture specifications, user accounts, and versioned document histories are highly relational entities requiring strict ACID transactions, foreign key integrity, and precise audit trails. JSONB columns provide schema flexibility where needed.

3. **Why React SPA (Vite) over Next.js Server Components?**  
   The core workspace is an interactive, client-side IDE experience requiring persistent WebSocket/SSE streaming connections, split-pane editing, and Monaco Editor instances. A Vite SPA eliminates unnecessary Server Component overhead and simplifies CDN distribution.

4. **Why Server-Sent Events (SSE) over WebSockets for AI Stream?**  
   AI document generation is unidirectional (server streaming tokens to client). SSE operates natively over standard HTTP/2 without requiring custom WebSocket handshake protocols or proxy complex renegotiation.

5. **Why RS256 Asymmetric JWTs over Symmetric HS256?**  
   RS256 allows microservices and API gateways to verify user access tokens using a public key without requiring access to the private signing key, preventing key leakage risks across microservices.

---

*This specification serves as the authoritative technical architecture specification for SecurityPilotAI.*
