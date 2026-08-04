from app.models.project import Project

class DocumentGenerators:
    """
    Specialized prompt generators for all 13 SecurityPilotAI security artifacts:
    1. README.md
    2. SRS.md
    3. SDS.md
    4. ARCHITECTURE.md
    5. DATABASE_DESIGN.md
    6. API_SPEC.yaml
    7. THREAT_MODEL.md
    8. OWASP_REVIEW.md
    9. Dockerfile
    10. docker-compose.yml
    11. deployment.yaml (Kubernetes)
    12. main.tf (Terraform)
    13. ci.yml (GitHub Actions)
    """

    @classmethod
    def get_template_prompt(cls, doc_type: str, project: Project) -> str:
        tech_stack = project.tech_stack or {}
        frontend = tech_stack.get("frontend", "React 18")
        backend = tech_stack.get("backend", "FastAPI")
        database = tech_stack.get("database", "PostgreSQL 16")
        cloud = tech_stack.get("cloud", "AWS Cloud")
        container = tech_stack.get("container", "Docker + K8s")
        compliance = ", ".join(project.compliance_frameworks or ["OWASP Top 10", "SOC 2 Type II"])

        dt = doc_type.upper()

        if dt == "README":
            return (
                f"# {project.name} 🛡️\n\n"
                f"**System Overview:** {project.description or 'Enterprise secure application'}\n\n"
                f"## 🛠️ Architecture Stack\n"
                f"- **Frontend:** {frontend}\n"
                f"- **Backend:** {backend}\n"
                f"- **Database:** {database}\n"
                f"- **Cloud Infrastructure:** {cloud}\n"
                f"- **Container Runtime:** {container}\n"
                f"- **Compliance Scope:** {compliance}\n\n"
                f"## 🔒 Security Principles\n"
                f"- Zero-trust network segmentation and least-privilege IAM controls.\n"
                f"- Mandatory TLS 1.3 in transit and AES-256-GCM at rest.\n"
                f"- Asymmetric RS256 JWT authorization token verification.\n"
            )

        elif dt == "SRS":
            return (
                f"# Software Requirements Specification (SRS) — {project.name}\n\n"
                f"## 1. Introduction & Security Objectives\n"
                f"This document defines the functional, non-functional, and security requirements for **{project.name}**.\n\n"
                f"## 2. Functional Requirements\n"
                f"- **FR-1:** Secure User Authentication using bcrypt and RS256 JWT.\n"
                f"- **FR-2:** Role-Based Access Control (RBAC) enforcing granular API scoping.\n"
                f"- **FR-3:** Workspace isolation and encrypted metadata storage.\n\n"
                f"## 3. Non-Functional & Compliance Requirements\n"
                f"- **NFR-1 (Availability):** 99.9% uptime SLA using multi-AZ deployment.\n"
                f"- **NFR-2 (Latency):** Sub-100ms API P95 response latency.\n"
                f"- **SEC-1 (Compliance):** Enforces compliance with {compliance}.\n"
            )

        elif dt == "SDS":
            return (
                f"# Software Design Specification (SDS) — {project.name}\n\n"
                f"## 1. Subsystem Architecture\n"
                f"The application comprises an isolated Frontend SPA (`{frontend}`), a high-throughput API gateway (`{backend}`), "
                f"and a hardened transactional datastore (`{database}`).\n\n"
                f"## 2. Component Design & Interfaces\n"
                f"```text\n"
                f"[Client Browser] ──► (HTTPS/TLS 1.3) ──► [API Gateway ({backend})] ──► [Async ORM] ──► [Database ({database})]\n"
                f"```\n"
            )

        elif dt == "ARCHITECTURE":
            return (
                f"# System Architecture & Threat Boundaries — {project.name}\n\n"
                f"## 1. High-Level Mermaid.js Architecture Diagram\n\n"
                f"```mermaid\n"
                f"graph TD\n"
                f"    User[Authenticated User] -->|HTTPS / TLS 1.3| Ingress[Ingress Controller]\n"
                f"    Ingress -->|JWT Auth Header| API[FastAPI Backend Core]\n"
                f"    API -->|Async SQLAlchemy| DB[(PostgreSQL Datastore)]\n"
                f"    API -->|HTTPS SSE Stream| AI[AI Engine Provider]\n"
                f"```\n\n"
                f"## 2. Network Trust Boundaries\n"
                f"- Boundary 1: Public Internet to Cloud Ingress Controller.\n"
                f"- Boundary 2: Ingress Controller to Private VPC Subnet.\n"
                f"- Boundary 3: API Microservice to Encrypted Storage Layer.\n"
            )

        elif dt == "DATABASE_DESIGN":
            return (
                f"# Database Design & Data Security — {project.name}\n\n"
                f"## 1. Datastore Engine: {database}\n\n"
                f"## 2. Entity-Relationship Model\n"
                f"```mermaid\n"
                f"erDiagram\n"
                f"    USERS ||--o{{ PROJECTS : owns\n"
                f"    PROJECTS ||--o{{ GENERATED_DOCUMENTS : contains\n"
                f"    USERS {{\n"
                f"        string id PK\n"
                f"        string email UK\n"
                f"        string password_hash\n"
                f"        string role\n"
                f"    }}\n"
                f"    PROJECTS {{\n"
                f"        string id PK\n"
                f"        string user_id FK\n"
                f"        string name\n"
                f"        json tech_stack\n"
                f"    }}\n"
                f"```\n\n"
                f"## 3. Data Protection Policies\n"
                f"- Column-level hashing for user credentials (bcrypt cost 12).\n"
                f"- Storage encryption via AWS KMS / AES-256.\n"
            )

        elif dt == "API_SPEC":
            return (
                f"openapi: 3.0.3\n"
                f"info:\n"
                f"  title: {project.name} API\n"
                f"  version: 1.0.0\n"
                f"  description: Secure REST API for {project.name}\n"
                f"paths:\n"
                f"  /api/v1/health:\n"
                f"    get:\n"
                f"      summary: System Health Check\n"
                f"      responses:\n"
                f"        '200':\n"
                f"          description: Healthy\n"
            )

        elif dt == "THREAT_MODEL":
            return (
                f"# STRIDE Threat Model & CVSS Vulnerability Matrix — {project.name}\n\n"
                f"| Threat ID | STRIDE Category | Threat Description | CVSS v3.1 | Risk Level | Recommended Mitigation |\n"
                f"| :--- | :--- | :--- | :--- | :--- | :--- |\n"
                f"| **TM-01** | Spoofing | Unauthenticated session impersonation | 8.1 | High | Enforce RS256 JWT tokens with short expiry & refresh token rotation. |\n"
                f"| **TM-02** | Tampering | SQL Injection via unvalidated API payloads | 8.6 | High | Use async SQLAlchemy ORM parameter binding exclusively. |\n"
                f"| **TM-03** | Repudiation | Unlogged unauthorized actions | 6.5 | Medium | Implement immutable audit logging middleware. |\n"
                f"| **TM-04** | Information Disclosure | Secret leakage in logs or headers | 7.5 | High | Redact sensitive keys; strip server identification banners. |\n"
                f"| **TM-05** | Denial of Service | API endpoint flooding | 7.5 | High | Enforce ingress rate-limiting (100 req/min per IP). |\n"
                f"| **TM-06** | Elevation of Privilege | Vertical privilege escalation | 8.8 | High | Enforce RBAC middleware on all protected endpoints. |\n"
            )

        elif dt == "OWASP_REVIEW":
            return (
                f"# OWASP Top 10 Compliance Verification Matrix — {project.name}\n\n"
                f"| OWASP Top 10 (2021) | Status | Implemented Security Control |\n"
                f"| :--- | :--- | :--- |\n"
                f"| **A01: Broken Access Control** | PASS | Mandatory `get_current_user` dependency & RBAC verification on all routes. |\n"
                f"| **A02: Cryptographic Failures** | PASS | TLS 1.3 in transit; bcrypt password hashing; AES-256 storage encryption. |\n"
                f"| **A03: Injection** | PASS | Pydantic v2 validation + SQLAlchemy parameterized queries. |\n"
                f"| **A04: Insecure Design** | PASS | STRIDE threat modeling & automated security guardrails. |\n"
                f"| **A05: Security Misconfiguration** | PASS | Non-root container execution; strict CORS & CSP security headers. |\n"
            )

        elif dt == "DOCKERFILE":
            return (
                f"# Multi-Stage Security Hardened Dockerfile — {project.name}\n"
                f"FROM python:3.11-slim AS builder\n"
                f"WORKDIR /app\n"
                f"COPY requirements.txt .\n"
                f"RUN pip install --no-cache-dir -r requirements.txt\n\n"
                f"FROM python:3.11-slim AS runner\n"
                f"WORKDIR /app\n"
                f"RUN addgroup --system appgroup && adduser --system --ingroup appgroup appuser\n"
                f"COPY --from=builder /usr/local /usr/local\n"
                f"COPY . .\n"
                f"USER appuser\n"
                f"EXPOSE 8000\n"
                f"CMD [\"uvicorn\", \"app.main:app\", \"--host\", \"0.0.0.0\", \"--port\", \"8000\"]\n"
            )

        elif dt == "DOCKER_COMPOSE":
            return (
                f"version: '3.8'\n"
                f"services:\n"
                f"  backend:\n"
                f"    build: .\n"
                f"    ports:\n"
                f"      - \"8000:8000\"\n"
                f"    environment:\n"
                f"      - ENVIRONMENT=production\n"
                f"      - DATABASE_URL=sqlite+aiosqlite:///./securitypilot.db\n"
                f"    restart: unless-stopped\n"
            )

        elif dt == "KUBERNETES":
            return (
                f"apiVersion: apps/v1\n"
                f"kind: Deployment\n"
                f"metadata:\n"
                f"  name: {project.name.lower().replace(' ', '-')}-backend\n"
                f"spec:\n"
                f"  replicas: 2\n"
                f"  selector:\n"
                f"    matchLabels:\n"
                f"      app: {project.name.lower().replace(' ', '-')}\n"
                f"  template:\n"
                f"    metadata:\n"
                f"      labels:\n"
                f"        app: {project.name.lower().replace(' ', '-')}\n"
                f"    spec:\n"
                f"      containers:\n"
                f"      - name: backend\n"
                f"        image: securitypilot/{project.name.lower().replace(' ', '-')}:latest\n"
                f"        ports:\n"
                f"        - containerPort: 8000\n"
                f"        securityContext:\n"
                f"          allowPrivilegeEscalation: false\n"
                f"          readOnlyRootFilesystem: true\n"
                f"          runAsNonRoot: true\n"
            )

        elif dt == "TERRAFORM":
            return (
                f"# Terraform Infrastructure Module — {project.name}\n"
                f"terraform {{\n"
                f"  required_version = \">= 1.5.0\"\n"
                f"  required_providers {{\n"
                f"    aws = {{\n"
                f"      source  = \"hashicorp/aws\"\n"
                f"      version = \"~> 5.0\"\n"
                f"    }}\n"
                f"  }}\n"
                f"}}\n\n"
                f"provider \"aws\" {{\n"
                f"  region = \"us-east-1\"\n"
                f"}}\n\n"
                f"resource \"aws_s3_bucket\" \"security_bucket\" {{\n"
                f"  bucket = \"{project.name.lower().replace(' ', '-')}-artifacts\"\n"
                f"}}\n\n"
                f"resource \"aws_s3_bucket_server_side_encryption_configuration\" \"s3_encryption\" {{\n"
                f"  bucket = aws_s3_bucket.security_bucket.id\n"
                f"  rule {{\n"
                f"    apply_server_side_encryption_by_default {{\n"
                f"      sse_algorithm = \"AES256\"\n"
                f"    }}\n"
                f"  }}\n"
                f"}}\n"
            )

        elif dt == "GITHUB_ACTIONS":
            return (
                f"name: Security Pilot CI/CD Pipeline\n\n"
                f"on:\n"
                f"  push:\n"
                f"    branches: [ main ]\n"
                f"  pull_request:\n"
                f"    branches: [ main ]\n\n"
                f"jobs:\n"
                f"  security_audit:\n"
                f"    runs-on: ubuntu-latest\n"
                f"    steps:\n"
                f"      - uses: actions/checkout@v4\n"
                f"      - name: Run Trivy vulnerability scanner\n"
                f"        uses: aquasecurity/trivy-action@master\n"
                f"        with:\n"
                f"          scan-type: 'fs'\n"
                f"          security-checks: 'vuln,config,secret'\n"
            )

        return (
            f"# {doc_type} — {project.name}\n\n"
            f"Security document artifact for {project.name}.\n"
        )
