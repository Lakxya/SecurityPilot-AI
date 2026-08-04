# SecurityPilotAI — Product Design Specification (PDS)

**Document Version:** 1.0.0  
**Author:** Lead Product Manager & Principal Software Architect  
**Status:** Approved for Implementation  
**Target Platform:** Web (Desktop First, Fully Responsive)  

---

## 1. Product Vision

### 1.1 Purpose
**SecurityPilotAI** is an enterprise-grade, AI-powered Security & Infrastructure Orchestration Platform designed to bridge the gap between software engineering, cloud architecture, and cybersecurity. It empowers teams to automatically design, analyze, generate, document, and remediate secure software architectures, cloud infrastructure specs, compliance benchmarks, and threat models in seconds.

### 1.2 Target Users
SecurityPilotAI serves technical creators and engineering organizations spanning across individual learners, fast-moving startups, and enterprise SecOps teams:
- **Developers & Software Engineers** seeking automated design docs, security reviews, and IaC templates.
- **DevOps & Platform Engineers** requiring secure Docker, Kubernetes, and Terraform scaffolding.
- **Cloud Security & SecOps Engineers** looking for automated OWASP vulnerability assessments and threat modeling.
- **Startup Founders & Technical Leaders** needing rapid compliance documentation (SRS, SDS, Threat Models) for enterprise readiness.
- **Students & Researchers** seeking interactive guidance on secure software development life cycles (SSDLC).

### 1.3 Core Value Proposition
- **Automated Security Architecture:** Instantly generate complete, secure-by-default software design documents (SRS, SDS, API Specs, Threat Models) and infrastructure manifests.
- **Interactive Security Copilot:** Context-aware AI assistant tailored specifically for security architecture, code audits, and vulnerability mitigation.
- **End-to-End Scaffolding:** From high-level architectural blueprints down to production-grade Terraform, Docker Compose, Kubernetes, and GitHub Actions CI/CD workflows.
- **Zero-Friction Editing & Regeneration:** Seamless dual-pane live preview with real-time markdown and code editing, paired with instant AI regeneration capabilities.

---

## 2. User Personas

| Persona | Primary Goal | Key Pain Point | SecurityPilotAI Solution |
| :--- | :--- | :--- | :--- |
| **Alex (Student / Junior Developer)** | Understand secure coding & build portfolio projects. | Overwhelmed by complex SecOps, K8s, and cloud security standards. | Provides structured, security-first templates and step-by-step architectural guidance. |
| **Elena (Software Engineer)** | Rapidly generate SRS, SDS, and API specs for new features. | Writing tedious documentation slows down feature delivery. | 1-click generation of technical design documents and OpenAPI specifications. |
| **Marcus (DevOps Engineer)** | Provision secure, compliant infrastructure (K8s, Terraform, Docker). | Writing boilerplate IaC manifests prone to misconfigurations and security drift. | Automated generation of hardened Terraform modules, Helm charts, and CI/CD pipelines. |
| **Sarah (Cloud Security Engineer)** | Identify architectural threats and enforce OWASP compliance. | Manual threat modeling (STRIDE) is time-consuming and hard to keep updated. | Automated STRIDE threat modeling and OWASP Top 10 mitigation matrix generation. |
| **David (Startup Founder)** | Pass vendor security reviews and achieve SOC 2 compliance. | Lacks dedicated SecOps staff; enterprise deals stall during compliance checks. | Generates enterprise-ready security artifacts, architecture diagrams, and compliance packs. |

---

## 3. Information Architecture

### 3.1 Global Navigation Hierarchy

```text
SecurityPilotAI Navigation Structure
├── 🌐 Public Landing Page (/landing)
├── 🔐 Authentication (/login, /register, /forgot-password)
├── 📊 Main App Dashboard (/dashboard)
│   ├── 📁 Projects Management (/projects)
│   │   ├── ➕ New Project Wizard (/projects/new)
│   │   └── 🛠️ Active Project Workspace (/projects/:projectId)
│   │       ├── 📜 Overview & README (/projects/:projectId/readme)
│   │       ├── 📄 SRS (/projects/:projectId/srs)
│   │       ├── 📐 SDS & Architecture (/projects/:projectId/sds)
│   │       ├── 🗄️ Database Design (/projects/:projectId/database)
│   │       ├── 🔌 API Specification (/projects/:projectId/api)
│   │       ├── 🛡️ Threat Model (/projects/:projectId/threat-model)
│   │       ├── 🔍 OWASP Review (/projects/:projectId/owasp)
│   │       ├── 🐳 Docker & Compose (/projects/:projectId/docker)
│   │       ├── ☸️ Kubernetes Manifests (/projects/:projectId/k8s)
│   │       ├── 🏗️ Terraform IaC (/projects/:projectId/terraform)
│   │       └── ⚡ GitHub Actions CI/CD (/projects/:projectId/github-actions)
│   ├── 🕒 History & Logs (/history)
│   ├── ⚙️ User & Workspace Settings (/settings)
│   │   ├── 👤 Profile & Security
│   │   ├── 🔑 API Keys & Integrations
│   │   └── 💳 Billing & Subscriptions
│   └── 🔔 Notifications Overlay (/notifications)
```

### 3.2 Page Justification & Purpose

1. **Landing Page (`/`):** Primary marketing gateway introducing value proposition, feature demos, security benchmarks, pricing, and interactive sandbox preview.
2. **Authentication (`/login`, `/register`):** Secure login portal supporting Email/Password, Magic Links, and OAuth (GitHub, Google, SSO).
3. **Dashboard (`/dashboard`):** Central command center displaying recent security projects, system health, active AI tasks, vulnerability alerts, and quick actions.
4. **Projects Catalog (`/projects`):** Grid/List view of all active, archived, and shared security architecture projects with search, filter, and tagging capabilities.
5. **Project Workspace (`/projects/:projectId`):** Core IDE-style multi-pane workspace holding all generated technical documents, architecture blueprints, IaC configurations, and live AI assistant chat.
6. **History & Generation Logs (`/history`):** Complete audit log of all document generations, AI prompts, code modifications, and export operations.
7. **Settings (`/settings`):** Global user preferences, AI model selections (OpenAI, Anthropic, Custom LLM endpoints), API keys, team permissions, and security policies.

---

## 4. User Flow

```text
Visitor ──► Landing Page ──► Login / Register ──► Dashboard ──► Create Project
                                                                    │
                                                                    ▼
Export ◄── Preview & Edit ◄── Generate Documents ◄── AI Workspace
```

### 4.1 Detailed Flow Steps

1. **Visitor Landing:** The visitor lands on the high-impact dark-mode marketing site, exploring interactive security architecture cards, compliance feature breakdowns, and CTA buttons ("Get Started Free" / "Book Demo").
2. **Authentication:** The user signs up or logs in via GitHub OAuth or Magic Link. Upon first login, an onboarding modal prompts the user to select their primary role (Developer, DevOps, Security Engineer, Founder).
3. **Dashboard Access:** The user arrives at their personalized dashboard, viewing recent projects, global threat metrics, and a prominent "+ New Security Project" primary action button.
4. **Create Project Wizard:** A streamlined 3-step creation modal guides the user:
   - *Step 1:* Project Name, Category (Web App, Cloud API, Microservices, Mobile Backend).
   - *Step 2:* Tech Stack Selection (Frontend, Backend, Database, Cloud Provider, Container runtime).
   - *Step 3:* Security Compliance Requirements (OWASP Top 10, SOC 2, HIPAA, GDPR, PCI-DSS).
5. **AI Workspace Initialization:** The user enters the IDE-style active workspace. The backend AI orchestrator initializes the project workspace and starts stream-generating the foundational security artifacts.
6. **Generate Documents:** The AI Copilot sequentially generates the 13 core project artifacts (README, SRS, SDS, Threat Models, Terraform, K8s, Docker, GitHub Actions).
7. **Preview & Edit:** The user inspects documents using the dual-pane markdown/code editor, modifies configuration parameters manually, or prompts the AI Copilot to refine specific sections ("Add Redis caching layer to database design").
8. **Export & Integration:** The user exports the entire security architecture as a ZIP archive, raw Markdown/YAML bundles, or pushes directly to their GitHub repository via 1-click sync.

---

## 5. Dashboard Layout Architecture

The main dashboard and project workspace adopt an ultra-sleek, IDE-inspired dark interface inspired by Linear, Cursor, and Vercel.

```text
+-----------------------------------------------------------------------------------+
| Top Navigation (Breadcrumbs | Global Search Ctrl+K | AI Status | Profile | Theme) |
+------------------+----------------------------------+-----------------------------+
| Sidebar          | Main Workspace Canvas            | AI Security Copilot Panel   |
|                  |                                  |                             |
| 📁 Projects      | [ Tab Bar: SRS | SDS | K8s ... ]  | 💬 Chat History             |
| 📜 Document Hub  | -------------------------------- | --------------------------- |
| 🛡️ Threat Engine | Dual-Pane Editor & Live Preview  | 🤖 Prompt Input Area        |
| ☸️ IaC Modules   |                                  | ⚙️ Model Context Selector   |
| ⚙️ Settings      |                                  |                             |
+------------------+----------------------------------+-----------------------------+
| Status Footer (System Normal | Latency: 24ms | Model: SecurityPilot-V1 | Sync: ON)  |
+-----------------------------------------------------------------------------------+
```

### 5.1 Layout Sections Specification

1. **Sidebar Navigation (Collapsible):**
   - Branding logo with quick workspace switching dropdown.
   - Quick navigation links: Dashboard, Projects, Templates, Threat Engine, IaC Library, History, Settings.
   - Project tree navigator (when inside an active project) displaying the 13 document modules.
2. **Top Navigation Header:**
   - Interactive context breadcrumbs (`Workspace / E-Commerce API / Threat Model`).
   - Global command bar shortcut (`Ctrl + K` / `Cmd + K`) for instant search across projects, documents, and AI commands.
   - Active AI model status indicator (e.g., `Claude 3.5 Sonnet` / `GPT-4o Security Engine`).
   - Notification bell badge and User profile avatar with quick dropdown.
3. **Main Workspace Canvas:**
   - Multi-tab document header allowing seamless toggling between SRS, SDS, Database, K8s, and Terraform files.
   - Split-screen view toggle: *Code/Markdown Editor*, *Visual Markdown Render / Architecture Diagram*, or *Split View*.
   - Floating contextual toolbar: "Regenerate Section", "Copy Code", "Format", "Export File".
4. **AI Security Copilot Panel (Right Drawer):**
   - Contextual chat interface pre-seeded with project metadata.
   - Pre-built prompt shortcut chips ("Audit for OWASP Flaws", "Add AWS KMS Encryption", "Generate Helm Chart", "Harden Dockerfile").
   - Live stream output renderer showing thinking steps and code diffs.
5. **Generation History Bar:**
   - Version snapshot timeline allowing developers to compare diffs and rollback to previous document iterations.
6. **Notification System:**
   - Non-intrusive toast notifications (bottom-right) providing feedback on generation completion, export status, and linter warnings.

---

## 6. Project Workspace & Core Artifact Specifications

Each project workspace automatically maintains and orchestrates **13 core security & architecture artifacts**. Every document is fully editable, version-controlled, and AI-regeneratable.

| Artifact | File Target | Format | Description & Security Focus |
| :--- | :--- | :--- | :--- |
| **1. README** | `README.md` | Markdown | Comprehensive project overview, security architecture summary, quick start setup, and security contact details. |
| **2. SRS** | `docs/SRS.md` | Markdown | Software Requirements Specification detailing functional requirements, non-functional security targets, performance metrics, and compliance mandates. |
| **3. SDS** | `docs/SDS.md` | Markdown | Software Design Specification covering system component architecture, data flow diagrams (Mermaid.js), sequence diagrams, and module boundaries. |
| **4. Architecture** | `docs/ARCHITECTURE.md` | Markdown + Mermaid | High-level system architecture, microservices breakdown, network perimeter boundaries, ingress/egress controls, and zero-trust isolation zones. |
| **5. Database Design** | `docs/DATABASE_DESIGN.md` | Markdown + ERD | Entity-Relationship diagrams, SQL schemas, encryption-at-rest strategies (column-level AES-256), index optimizations, and database auditing controls. |
| **6. API Specification** | `docs/API_SPEC.yaml` | OpenAPI 3.0 / YAML | Complete API endpoints, request/response schemas, rate-limiting headers, JWT/OAuth2 security schemes, and CORS policies. |
| **7. Threat Model** | `docs/THREAT_MODEL.md` | Markdown / STRIDE | Comprehensive STRIDE threat analysis, asset classification, attack surface vectors, risk impact scoring (CVSS v3.1), and mitigation controls. |
| **8. OWASP Review** | `docs/OWASP_REVIEW.md` | Markdown | Detailed vulnerability assessment matrix addressing all OWASP Top 10 risks (Injection, Broken Auth, SSRF, Cryptographic Failures) with remediation code patterns. |
| **9. Docker** | `docker/Dockerfile` | Dockerfile | Hardened, multi-stage, non-root Distroless Dockerfile implementing minimal attack surface and security best practices. |
| **10. Docker Compose** | `docker/docker-compose.yml`| YAML | Multi-container development stack configuration with resource limits, isolated bridge networks, health checks, and secure secret volume bindings. |
| **11. Kubernetes** | `kubernetes/*.yaml` | K8s YAML / Helm | Hardened K8s manifests (Deployments, Services, Ingress, NetworkPolicies, PodSecurityStandards, ConfigMaps, Secrets). |
| **12. Terraform** | `terraform/main.tf` | HCL | Production-ready IaC provisioning cloud infrastructure (VPC, private subnets, IAM roles with least privilege, security groups, KMS keys, WAF rules). |
| **13. GitHub Actions** | `.github/workflows/ci.yml`| YAML | Complete CI/CD pipeline featuring SAST (Semgrep/CodeQL), Dependency Vulnerability Scanning (Trivy), Secret Scanning, and automated linting. |

### 6.1 Interactive Editing & Regeneration Capabilities
- **Direct Markdown & Code Editing:** Built-in Monaco/CodeMirror editor with syntax highlighting, inline error highlighting, and autocompletion.
- **Selective AI Prompting:** Highlight any section of code/markdown and invoke `Cmd + K` inline to request modifications ("Make this database connection use SSL with certificate verification").
- **Diff Compare View:** Side-by-side visual diff modal before accepting AI-suggested changes.

---

## 7. Component Hierarchy

The frontend architecture follows a modular atomic design structure built on reusable React components:

```text
src/components/
├── common/
│   ├── Badge.tsx (Security severity tags: Critical, High, Medium, Low)
│   ├── Tooltip.tsx
│   ├── Spinner.tsx
│   ├── StatusIndicator.tsx
│   └── EmptyState.tsx
├── ui/
│   ├── Button.tsx (Primary, Secondary, Ghost, Danger, Outline)
│   ├── Card.tsx (CardHeader, CardContent, CardFooter)
│   ├── Dialog.tsx (Modal overlay, AlertConfirm)
│   ├── Input.tsx & Textarea.tsx
│   ├── Select.tsx & DropdownMenu.tsx
│   ├── Tabs.tsx (TabList, TabTrigger, TabContent)
│   ├── Table.tsx (DataTable with sorting & pagination)
│   ├── Breadcrumbs.tsx
│   ├── Switch.tsx (Toggle switch)
│   ├── Toast.tsx (Notification popups)
│   └── CodeBlock.tsx (Syntax highlighted preview)
├── layout/
│   ├── Sidebar.tsx
│   ├── Navbar.tsx
│   ├── Footer.tsx
│   ├── PageWrapper.tsx
│   └── SplitPaneLayout.tsx
└── project/
    ├── ProjectCard.tsx
    ├── DocumentTabHeader.tsx
    ├── MarkdownRenderer.tsx
    ├── CodeEditor.tsx
    ├── AIChatMessage.tsx
    ├── ThreatMatrixTable.tsx
    ├── DiagramViewer.tsx (Mermaid renderer)
    └── VersionHistoryTimeline.tsx
```

---

## 8. Design System

SecurityPilotAI implements a sleek, high-contrast, security-focused dark design system.

### 8.1 Color Palette (HSL Tailored)

```text
Backgrounds & Surfaces:
- Page Background:      hsl(222, 47%, 7%)   /* #0B0F19 Deep Obsidian */
- Card / Panel Surface: hsl(217, 33%, 12%)  /* #131C2E Dark Slate */
- Hover Surface:        hsl(215, 25%, 17%)  /* #202B3D Lighter Slate */
- Border Color:         hsl(217, 19%, 20%)  /* #293548 Muted Slate Border */

Primary & Brand Accents:
- Primary Indigo:       hsl(239, 84%, 67%)  /* #6366F1 Brand Indigo */
- Cyber Emerald:        hsl(160, 84%, 39%)  /* #10B981 Success / Secure Green */
- Electric Cyan:        hsl(189, 94%, 43%)  /* #06B6D4 Security Highlight */

Status & Severity Colors:
- Critical / Danger:    hsl(346, 87%, 53%)  /* #F43F5E Coral Red */
- High / Warning:       hsl(38, 92%, 50%)   /* #F59E0B Amber Yellow */
- Low / Info:           hsl(199, 89%, 48%)  /* #0EA5E9 Sky Blue */

Typography Colors:
- Headings & Primary:   hsl(210, 40%, 98%)  /* #F8FAFC Pure White-Slate */
- Body & Secondary:     hsl(215, 20%, 65%)  /* #94A3B8 Muted Grey */
- Muted / Disabled:     hsl(215, 16%, 47%)  /* #64748B Subtitle Slate */
```

### 8.2 Typography Scale
- **Font Family:** `Inter`, `-apple-system`, `BlinkMacSystemFont`, `sans-serif`
- **Monospace Font (Code & Editor):** `JetBrains Mono`, `Fira Code`, `monospace`
- **Scale:**
  - `Display / H1`: 32px / 2.25rem (Bold, tracking-tight)
  - `H2`: 24px / 1.5rem (SemiBold)
  - `H3`: 18px / 1.125rem (SemiBold)
  - `Body Base`: 14px / 0.875rem (Regular / Medium)
  - `Caption / Small`: 12px / 0.75rem (Medium)

### 8.3 Radius & Spacing Scale
- **Border Radius:**
  - `sm`: 4px (Buttons, Input elements)
  - `md`: 8px (Cards, Modals, Dropdowns)
  - `lg`: 12px (Workspace Containers, Outer Panels)
  - `full`: 9999px (Pills, Status Badges)
- **Spacing System:** 4px grid system (`4px`, `8px`, `12px`, `16px`, `24px`, `32px`, `48px`, `64px`).

### 8.4 Micro-Animations & Interactions
- **Transitions:** Smooth 150ms–250ms `ease-in-out` transitions on hover states, dropdown reveals, and modal entries.
- **Glassmorphism:** Suble `backdrop-blur-md` on Top Navigation headers and Modal backdrops.
- **Glow Effects:** Subtle cyan/emerald box-shadow glows on active security indicators and primary action buttons.

---

## 9. Responsive Behavior Matrix

| Viewport | Range | Layout Strategy | Sidebar Behavior | AI Workspace Adaptation |
| :--- | :--- | :--- | :--- | :--- |
| **Desktop Ultra** | `1440px+` | Full 3-pane layout (Sidebar + Canvas + AI Copilot). | Expanded fixed left sidebar (260px). | Full side-by-side markdown editor and live preview render. |
| **Laptop** | `1024px – 1439px` | 3-pane layout with compact padding. | Compact collapsable sidebar (64px icon rail). | Dual pane editor with toggleable AI drawer panel. |
| **Tablet** | `768px – 1023px` | 2-pane focus layout. | Slide-over drawer menu triggered by hamburger icon. | Single main canvas; AI Copilot operates as a floating modal/drawer. |
| **Mobile** | `320px – 767px` | Single-column stacked view. | Full-screen overlay menu. | Tabbed switching between Document View, Editor, and AI Chat. |

---

## 10. Future Enterprise Features

1. **Automated Vulnerability Code Review Engine:** Direct static analysis (SAST) of uploaded source files against OWASP Top 10 and CWE benchmarks.
2. **Repository Import (Git Clone & Parse):** Import existing GitHub/GitLab repositories to automatically generate architecture diagrams and threat models from existing code.
3. **Deep GitHub Integration:** Automatic Pull Request comments containing generated threat models and Terraform security linting results.
4. **Cloud Infrastructure Integrations (AWS / Azure / GCP):** 1-click cloud sync to scan active VPCs and deploy generated Terraform state files safely.
5. **Team Collaboration & Live Presence:** Real-time multi-user editing with cursor presence, inline comments, and document approval workflows.
6. **Role-Based Access Control (RBAC):** Granular organization roles (`Admin`, `SecOps Engineer`, `Developer`, `Auditor`) with customized permission scopes.

---

## 11. Sprint-by-Sprint Development Roadmap

```text
Sprint 1: Core Foundation & Scaffolding (COMPLETED)
├── React + Vite + TypeScript setup
├── Tailwind CSS v4 design system tokens
├── ESLint & Prettier configuration
└── Scalable frontend directory structure

Sprint 2: Landing Page & Public Marketing Gateway
├── Hero section with interactive security animation
├── Value proposition grid & feature highlight cards
└── Security compliance benchmarks & pricing table

Sprint 3: Authentication & User Management
├── Auth state management (Context / Zustand)
├── Login & Registration UI components
├── Password reset & Magic Link flows
└── Protected route guards

Sprint 4: Main Application Dashboard (COMPLETED)
├── Dashboard shell layout & Top Navigation bar
├── Collapsible Sidebar navigation
├── Recent Projects grid view & status metrics
└── Project creation 3-step wizard modal

Sprint 5: Project Management & Workspace Module (COMPLETED)
├── Projects & GeneratedDocuments database models
├── ProjectRepository & ProjectService business logic
├── RESTful API Controllers (/api/v1/projects)
└── Frontend projectService & types integration

Sprint 6: Document Generator Engine
├── Frontend state management for 13 document modules
├── Interactive document tab routing
└── Local storage / mock API state persistence

Sprint 7: AI Copilot Integration
├── Right-drawer AI Chat panel UI
├── Streaming AI message renderers & prompt shortcut chips
├── Contextual inline AI prompt (`Cmd+K`) interface
└── Code diff comparison modal

Sprint 8: Export & Integration System
├── Multi-format document exporter (ZIP, Markdown bundle, PDF)
├── Copy-to-clipboard & raw file download utilities
└── GitHub sync modal UI

Sprint 9: Cloud & Infrastructure Deployment
├── Docker multi-stage containerization
├── Kubernetes Helm chart packaging
└── CI/CD deployment pipeline configuration

Sprint 10: Production Release & Hardening
├── Security audit & OWASP headers hardening
├── End-to-end regression testing & performance tuning
└── Production launch & monitoring setup
```

---

*This specification serves as the authoritative product design specification for SecurityPilotAI.*
