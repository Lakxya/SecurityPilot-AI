# Changelog

All notable changes to **SecurityPilotAI** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Sprint 5 (Project Management & Workspace API):** `Project` & `GeneratedDocument` ORM models, Pydantic v2 schemas, `ProjectRepository`, `ProjectService`, `/api/v1/projects/` REST controllers, frontend `projectService` & TypeScript interfaces, and Pytest integration test suite.
- **Sprint 4 (IDE Application Dashboard Shell):** `DashboardSidebar`, `DashboardHeader`, `DashboardFooter`, `DashboardStats`, `RecentProjectsGrid`, `CreateProjectModal`, and `Cmd+K` `CommandSearchModal`.
- **Sprint 3 (Identity & Access Authentication System):** Asymmetric RS256 JWT auth, bcrypt password hashing, `User` model, `/api/v1/auth/` controllers, `AuthContext`, `useAuth`, `ProtectedRoute`, and Login/Register views.
- **Sprint 2 (Public Landing Page):** Hero section, feature cards grid, trusted tech banner, comparison matrix, and FAQ accordion.
- **Sprint 1 (Scaffolding):** Initial directory architecture, React + Vite + TypeScript frontend foundation, Tailwind CSS v4 design tokens, and ESLint/Prettier configurations.
