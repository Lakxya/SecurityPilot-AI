from typing import Sequence
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload
from sqlalchemy import or_
from app.models.project import Project
from app.schemas.project import ProjectCreate, ProjectUpdate

class ProjectRepository:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def create(self, project_in: ProjectCreate, user_id: str) -> Project:
        tech_stack_dict = (
            project_in.tech_stack.model_dump()
            if hasattr(project_in.tech_stack, "model_dump")
            else (project_in.tech_stack or {})
        )
        project = Project(
            user_id=user_id,
            name=project_in.name,
            description=project_in.description,
            tech_stack=tech_stack_dict,
            compliance_frameworks=project_in.compliance_frameworks or [],
            status="ACTIVE",
        )
        self.db.add(project)
        await self.db.commit()
        fetched = await self.get_by_id(project.id, user_id)
        return fetched if fetched is not None else project

    async def get_by_id(self, project_id: str, user_id: str) -> Project | None:
        stmt = (
            select(Project)
            .options(selectinload(Project.documents))
            .where(Project.id == project_id, Project.user_id == user_id)
        )
        result = await self.db.execute(stmt)
        return result.scalars().first()

    async def list_by_user(
        self, user_id: str, status: str | None = None, search: str | None = None
    ) -> Sequence[Project]:
        stmt = (
            select(Project)
            .options(selectinload(Project.documents))
            .where(Project.user_id == user_id)
        )
        if status:
            stmt = stmt.where(Project.status == status)
        if search:
            search_pattern = f"%{search.lower()}%"
            stmt = stmt.where(
                or_(
                    Project.name.ilike(search_pattern),
                    Project.description.ilike(search_pattern),
                )
            )
        stmt = stmt.order_by(Project.created_at.desc())
        result = await self.db.execute(stmt)
        return result.scalars().all()

    async def update(self, project: Project, update_in: ProjectUpdate) -> Project:
        if update_in.name is not None:
            project.name = update_in.name
        if update_in.description is not None:
            project.description = update_in.description
        if update_in.tech_stack is not None:
            project.tech_stack = (
                update_in.tech_stack.model_dump()
                if hasattr(update_in.tech_stack, "model_dump")
                else update_in.tech_stack
            )
        if update_in.compliance_frameworks is not None:
            project.compliance_frameworks = update_in.compliance_frameworks
        if update_in.status is not None:
            project.status = update_in.status

        await self.db.commit()
        fetched = await self.get_by_id(project.id, project.user_id)
        return fetched if fetched is not None else project

    async def delete(self, project: Project) -> None:
        await self.db.delete(project)
        await self.db.commit()
