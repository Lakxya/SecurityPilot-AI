from datetime import datetime, timezone
from typing import Dict, Any
from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from app.models.project import Project
from app.models.ai_provider import UserAIProvider
from app.schemas.provider_assignment import (
    ProviderAssignmentUpdate,
    ProviderAssignmentSpec,
    ProjectProviderAssignmentsResponse,
)

class ProviderAssignmentService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_assignments(self, project_id: str, user_id: str) -> ProjectProviderAssignmentsResponse:
        project = await self._get_project(project_id, user_id)
        raw_assignments: Dict[str, Any] = project.provider_assignments or {}

        typed_assignments = {}
        for artifact, data in raw_assignments.items():
            typed_assignments[artifact] = ProviderAssignmentSpec(
                artifact=artifact,
                provider=data.get("provider", "MOCK"),
                model=data.get("model", "mock-v1"),
                provider_id=data.get("provider_id"),
                last_updated=data.get("last_updated", datetime.now(timezone.utc).isoformat()),
            )
        return ProjectProviderAssignmentsResponse(project_id=project.id, assignments=typed_assignments)

    async def update_assignment(
        self,
        project_id: str,
        artifact: str,
        payload: ProviderAssignmentUpdate,
        user_id: str,
    ) -> ProviderAssignmentSpec:
        project = await self._get_project(project_id, user_id)

        # Validate vault provider if provider_id is provided
        if payload.provider_id:
            await self._validate_vault_provider(payload.provider_id, user_id)

        raw_assignments = dict(project.provider_assignments or {})
        artifact_upper = artifact.upper()

        now_iso = datetime.now(timezone.utc).isoformat()
        assignment_data = {
            "provider": payload.provider.upper(),
            "model": payload.model,
            "provider_id": payload.provider_id,
            "last_updated": now_iso,
        }

        raw_assignments[artifact_upper] = assignment_data
        project.provider_assignments = raw_assignments
        await self.db.commit()

        return ProviderAssignmentSpec(
            artifact=artifact_upper,
            provider=assignment_data["provider"],
            model=assignment_data["model"],
            provider_id=assignment_data["provider_id"],
            last_updated=now_iso,
        )

    async def remove_assignment(self, project_id: str, artifact: str, user_id: str) -> None:
        project = await self._get_project(project_id, user_id)
        raw_assignments = dict(project.provider_assignments or {})
        artifact_upper = artifact.upper()

        if artifact_upper in raw_assignments:
            del raw_assignments[artifact_upper]
            project.provider_assignments = raw_assignments
            await self.db.commit()

    async def _get_project(self, project_id: str, user_id: str) -> Project:
        stmt = select(Project).where(Project.id == project_id, Project.user_id == user_id)
        result = await self.db.execute(stmt)
        project = result.scalars().first()
        if not project:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")
        return project

    async def _validate_vault_provider(self, provider_id: str, user_id: str) -> None:
        stmt = select(UserAIProvider).where(UserAIProvider.id == provider_id, UserAIProvider.user_id == user_id)
        result = await self.db.execute(stmt)
        provider = result.scalars().first()
        if not provider:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Linked AI Vault provider credential not found")
