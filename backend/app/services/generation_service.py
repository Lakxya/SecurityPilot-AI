from typing import AsyncGenerator
from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from app.models.project import Project, GeneratedDocument
from app.services.project_service import ProjectService
from app.services.ai.prompt_engine import PromptSynthesizer
from app.services.ai.providers import LLMFactory

class GenerationService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.project_service = ProjectService(db)

    async def stream_and_save_document(
        self,
        project_id: str,
        doc_type: str,
        user_id: str,
        custom_instructions: str | None = None,
        provider_name: str = "mock",
    ) -> AsyncGenerator[str, None]:
        # 1. Fetch & authorize project workspace
        project = await self.project_service.get_project(project_id, user_id)

        # 2. Resolve Provider Precedence Hierarchy
        # Priority 1: Explicit Multi-Provider Workspace Matrix Assignment
        assignments = project.provider_assignments or {}
        assigned = assignments.get(doc_type.upper())
        resolved_provider_name = provider_name

        if assigned and assigned.get("provider"):
            resolved_provider_name = assigned.get("provider", provider_name).lower()
        else:
            # Priority 2: Intelligent Recommendation Engine Fallback
            from app.services.ai.recommendation_engine import ProviderRecommendationService
            rec = ProviderRecommendationService.recommend_for_project(project, doc_type)
            resolved_provider_name = rec.recommended_provider.lower()

        # 3. Build system and user prompts
        system_prompt = PromptSynthesizer.build_system_prompt(project, doc_type)
        user_prompt = PromptSynthesizer.build_user_prompt(doc_type, custom_instructions)

        # 4. Initialize streaming LLM provider
        provider = LLMFactory.get_provider(resolved_provider_name)

        full_content = []
        async for chunk in provider.generate_stream(
            prompt=user_prompt,
            system_prompt=system_prompt,
            project=project,
            doc_type=doc_type,
        ):
            full_content.append(chunk)
            yield chunk

        complete_text = "".join(full_content)

        # 4. Save generated artifact in database
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
        file_path = file_path_map.get(doc_type.upper(), f"docs/{doc_type.lower()}.md")

        # Mark existing document versions as not latest
        stmt = (
            select(GeneratedDocument)
            .where(GeneratedDocument.project_id == project_id, GeneratedDocument.doc_type == doc_type.upper())
        )
        result = await self.db.execute(stmt)
        existing_docs = result.scalars().all()

        max_version = 0
        for doc in existing_docs:
            doc.is_latest = False
            if doc.version > max_version:
                max_version = doc.version

        new_doc = GeneratedDocument(
            project_id=project_id,
            doc_type=doc_type.upper(),
            file_path=file_path,
            content=complete_text,
            version=max_version + 1,
            is_latest=True,
        )
        self.db.add(new_doc)
        await self.db.commit()

    async def get_latest_document(
        self, project_id: str, doc_type: str, user_id: str
    ) -> GeneratedDocument | None:
        await self.project_service.get_project(project_id, user_id)
        stmt = (
            select(GeneratedDocument)
            .where(
                GeneratedDocument.project_id == project_id,
                GeneratedDocument.doc_type == doc_type.upper(),
                GeneratedDocument.is_latest == True,
            )
        )
        result = await self.db.execute(stmt)
        return result.scalars().first()

    async def list_project_documents(
        self, project_id: str, user_id: str
    ) -> list[GeneratedDocument]:
        await self.project_service.get_project(project_id, user_id)
        stmt = (
            select(GeneratedDocument)
            .where(
                GeneratedDocument.project_id == project_id,
                GeneratedDocument.is_latest == True,
            )
            .order_by(GeneratedDocument.doc_type.asc())
        )
        result = await self.db.execute(stmt)
        return list(result.scalars().all())

    async def get_document_versions(
        self, project_id: str, doc_type: str, user_id: str
    ) -> list[GeneratedDocument]:
        await self.project_service.get_project(project_id, user_id)
        stmt = (
            select(GeneratedDocument)
            .where(
                GeneratedDocument.project_id == project_id,
                GeneratedDocument.doc_type == doc_type.upper(),
            )
            .order_by(GeneratedDocument.version.desc())
        )
        result = await self.db.execute(stmt)
        return list(result.scalars().all())

    async def get_document_by_version(
        self, project_id: str, doc_type: str, version: int, user_id: str
    ) -> GeneratedDocument:
        await self.project_service.get_project(project_id, user_id)
        stmt = (
            select(GeneratedDocument)
            .where(
                GeneratedDocument.project_id == project_id,
                GeneratedDocument.doc_type == doc_type.upper(),
                GeneratedDocument.version == version,
            )
        )
        result = await self.db.execute(stmt)
        doc = result.scalars().first()
        if not doc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Version `{version}` for document `{doc_type}` not found.",
            )
        return doc

    async def update_document_content(
        self, project_id: str, doc_type: str, content: str, user_id: str
    ) -> GeneratedDocument:
        await self.project_service.get_project(project_id, user_id)
        existing = await self.get_latest_document(project_id, doc_type, user_id)
        if existing:
            existing.content = content
            await self.db.commit()
            await self.db.refresh(existing)
            return existing

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
        file_path = file_path_map.get(doc_type.upper(), f"docs/{doc_type.lower()}.md")

        new_doc = GeneratedDocument(
            project_id=project_id,
            doc_type=doc_type.upper(),
            file_path=file_path,
            content=content,
            version=1,
            is_latest=True,
        )
        self.db.add(new_doc)
        await self.db.commit()
        await self.db.refresh(new_doc)
        return new_doc
