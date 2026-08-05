from typing import Sequence
from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from app.repositories.project_repository import ProjectRepository
from app.schemas.project import ProjectCreate, ProjectUpdate, ProjectStatsResponse
from app.models.project import Project

class ProjectService:
    def __init__(self, db: AsyncSession):
        self.repo = ProjectRepository(db)

    async def create_project(self, project_in: ProjectCreate, user_id: str) -> Project:
        return await self.repo.create(project_in, user_id)

    async def get_project(self, project_id: str, user_id: str) -> Project:
        project = await self.repo.get_by_id(project_id, user_id)
        if not project:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Project workspace not found.",
            )
        return project

    async def list_projects(
        self, user_id: str, status_filter: str | None = None, search: str | None = None
    ) -> Sequence[Project]:
        return await self.repo.list_by_user(user_id, status=status_filter, search=search)

    async def update_project(
        self, project_id: str, update_in: ProjectUpdate, user_id: str
    ) -> Project:
        project = await self.get_project(project_id, user_id)
        return await self.repo.update(project, update_in)

    async def delete_project(self, project_id: str, user_id: str) -> None:
        project = await self.get_project(project_id, user_id)
        await self.repo.delete(project)

    async def get_stats(self, user_id: str) -> ProjectStatsResponse:
        projects = await self.repo.list_by_user(user_id)
        total_projects = len(projects)
        total_documents = sum(len(p.documents) for p in projects)
        active_projects = sum(1 for p in projects if p.status == "ACTIVE")

        max_potential_docs = total_projects * 13
        completion_pct = (
            round((total_documents / max_potential_docs) * 100, 1)
            if max_potential_docs > 0
            else 0.0
        )
        if completion_pct > 100.0:
            completion_pct = 100.0

        compliance_distribution: dict[str, int] = {}
        for p in projects:
            for framework in p.compliance_frameworks or []:
                compliance_distribution[framework] = (
                    compliance_distribution.get(framework, 0) + 1
                )

        risk_score = "94% Low Risk" if completion_pct >= 50 else "78% Moderate Risk"

        return ProjectStatsResponse(
            total_projects=total_projects,
            total_documents=total_documents,
            artifact_completion_pct=completion_pct,
            average_risk_score=risk_score,
            compliance_distribution=compliance_distribution,
            active_projects=active_projects,
        )
