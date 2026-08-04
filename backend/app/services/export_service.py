import io
import json
import zipfile
from datetime import datetime, timezone
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from app.models.project import Project, GeneratedDocument
from app.services.project_service import ProjectService
from app.services.ai.document_generators import DocumentGenerators

class ExportService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.project_service = ProjectService(db)

    async def get_project_documents(self, project_id: str, user_id: str) -> tuple[Project, list[GeneratedDocument]]:
        project = await self.project_service.get_project(project_id, user_id)
        stmt = (
            select(GeneratedDocument)
            .where(
                GeneratedDocument.project_id == project_id,
                GeneratedDocument.is_latest == True,
            )
            .order_by(GeneratedDocument.doc_type.asc())
        )
        result = await self.db.execute(stmt)
        docs = list(result.scalars().all())
        return project, docs

    async def generate_zip_archive(self, project_id: str, user_id: str) -> bytes:
        project, docs = await self.get_project_documents(project_id, user_id)

        all_doc_types = [
            "README", "SRS", "SDS", "ARCHITECTURE", "DATABASE_DESIGN",
            "API_SPEC", "THREAT_MODEL", "OWASP_REVIEW", "DOCKERFILE",
            "DOCKER_COMPOSE", "KUBERNETES", "TERRAFORM", "GITHUB_ACTIONS"
        ]

        existing_map = {d.doc_type.upper(): d for d in docs}

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
            for doc_type in all_doc_types:
                if doc_type in existing_map:
                    doc = existing_map[doc_type]
                    content = doc.content
                    file_path = doc.file_path
                else:
                    content = DocumentGenerators.get_template_prompt(doc_type, project)
                    file_path_map = {
                        "README": "README.md",
                        "SRS": "docs/SRS.md",
                        "SDS": "docs/SDS.md",
                        "ARCHITECTURE": "docs/ARCHITECTURE.md",
                        "DATABASE_DESIGN": "docs/DATABASE_DESIGN.md",
                        "API_SPEC": "docs/API_SPEC.yaml",
                        "THREAT_MODEL": "docs/THREAT_MODEL.md",
                        "OWASP_REVIEW": "docs/OWASP_REVIEW.md",
                        "DOCKERFILE": "docker/Dockerfile",
                        "DOCKER_COMPOSE": "docker/docker-compose.yml",
                        "KUBERNETES": "kubernetes/deployment.yaml",
                        "TERRAFORM": "terraform/main.tf",
                        "GITHUB_ACTIONS": ".github/workflows/ci.yml",
                    }
                    file_path = file_path_map.get(doc_type, f"docs/{doc_type.lower()}.md")

                zf.writestr(file_path, content)

            manifest = {
                "project_id": project.id,
                "project_name": project.name,
                "description": project.description,
                "tech_stack": project.tech_stack,
                "compliance_frameworks": project.compliance_frameworks,
                "exported_at": datetime.now(timezone.utc).isoformat(),
                "artifact_count": len(all_doc_types),
            }
            zf.writestr("securitypilot-manifest.json", json.dumps(manifest, indent=2))

        zip_buffer.seek(0)
        return zip_buffer.getvalue()

    async def generate_markdown_bundle(self, project_id: str, user_id: str) -> str:
        project, docs = await self.get_project_documents(project_id, user_id)

        all_doc_types = [
            "README", "SRS", "SDS", "ARCHITECTURE", "DATABASE_DESIGN",
            "API_SPEC", "THREAT_MODEL", "OWASP_REVIEW", "DOCKERFILE",
            "DOCKER_COMPOSE", "KUBERNETES", "TERRAFORM", "GITHUB_ACTIONS"
        ]
        existing_map = {d.doc_type.upper(): d for d in docs}

        bundle = [
            f"# Consolidated Security Architecture Bundle — {project.name}\n\n",
            f"**Exported At:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}  \n",
            f"**Description:** {project.description or 'N/A'}  \n",
            f"**Tech Stack:** `{json.dumps(project.tech_stack or {})}`  \n",
            f"**Compliance Frameworks:** `{', '.join(project.compliance_frameworks or [])}`  \n\n",
            "---\n\n"
        ]

        for doc_type in all_doc_types:
            if doc_type in existing_map:
                content = existing_map[doc_type].content
            else:
                content = DocumentGenerators.get_template_prompt(doc_type, project)

            bundle.append(f"## File Artifact: `{doc_type}`\n\n")
            bundle.append(content)
            bundle.append("\n\n---\n\n")

        return "".join(bundle)

    async def generate_json_export(self, project_id: str, user_id: str) -> dict:
        project, docs = await self.get_project_documents(project_id, user_id)
        all_doc_types = [
            "README", "SRS", "SDS", "ARCHITECTURE", "DATABASE_DESIGN",
            "API_SPEC", "THREAT_MODEL", "OWASP_REVIEW", "DOCKERFILE",
            "DOCKER_COMPOSE", "KUBERNETES", "TERRAFORM", "GITHUB_ACTIONS"
        ]
        existing_map = {d.doc_type.upper(): d for d in docs}

        artifacts = []
        for doc_type in all_doc_types:
            if doc_type in existing_map:
                doc = existing_map[doc_type]
                artifacts.append({
                    "doc_type": doc.doc_type,
                    "file_path": doc.file_path,
                    "version": doc.version,
                    "content": doc.content,
                })
            else:
                artifacts.append({
                    "doc_type": doc_type,
                    "file_path": f"docs/{doc_type.lower()}.md",
                    "version": 1,
                    "content": DocumentGenerators.get_template_prompt(doc_type, project),
                })

        return {
            "project_id": project.id,
            "name": project.name,
            "description": project.description,
            "tech_stack": project.tech_stack,
            "compliance_frameworks": project.compliance_frameworks,
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "artifacts": artifacts,
        }
