from typing import Sequence
from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from app.repositories.project_repository import ProjectRepository
from app.schemas.project import ProjectCreate, ProjectUpdate
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
