from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.database import get_db
from app.api.v1.deps import get_current_user
from app.models.user import User
from app.schemas.project import (
    ProjectCreate,
    ProjectUpdate,
    ProjectResponse,
    ProjectListResponse,
)
from app.services.project_service import ProjectService

router = APIRouter(prefix="/projects", tags=["Projects"])

@router.post("/", response_model=ProjectResponse, status_code=status.HTTP_201_CREATED)
async def create_project(
    project_in: ProjectCreate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    service = ProjectService(db)
    project = await service.create_project(project_in, current_user.id)
    return ProjectResponse.model_validate(project)

@router.get("/", response_model=ProjectListResponse)
async def list_projects(
    status_filter: str | None = Query(None, alias="status"),
    search: str | None = Query(None),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    service = ProjectService(db)
    projects = await service.list_projects(current_user.id, status_filter=status_filter, search=search)
    return ProjectListResponse(
        projects=[ProjectResponse.model_validate(p) for p in projects],
        total=len(projects),
    )

@router.get("/{project_id}", response_model=ProjectResponse)
async def get_project(
    project_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    service = ProjectService(db)
    project = await service.get_project(project_id, current_user.id)
    return ProjectResponse.model_validate(project)

@router.put("/{project_id}", response_model=ProjectResponse)
async def update_project(
    project_id: str,
    update_in: ProjectUpdate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    service = ProjectService(db)
    project = await service.update_project(project_id, update_in, current_user.id)
    return ProjectResponse.model_validate(project)

@router.delete("/{project_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_project(
    project_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    service = ProjectService(db)
    await service.delete_project(project_id, current_user.id)
    return None
