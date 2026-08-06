from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.database import get_db
from app.api.v1.deps import get_current_user
from app.models.user import User
from app.schemas.provider_assignment import (
    ProviderAssignmentUpdate,
    ProviderAssignmentSpec,
    ProjectProviderAssignmentsResponse,
)
from app.services.provider_assignment_service import ProviderAssignmentService

router = APIRouter(prefix="/projects", tags=["Multi-Provider Assignments"])

@router.get("/{project_id}/providers", response_model=ProjectProviderAssignmentsResponse)
async def get_provider_assignments(
    project_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    service = ProviderAssignmentService(db)
    return await service.get_assignments(project_id, current_user.id)

@router.put("/{project_id}/providers/{artifact}", response_model=ProviderAssignmentSpec)
async def update_provider_assignment(
    project_id: str,
    artifact: str,
    payload: ProviderAssignmentUpdate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    service = ProviderAssignmentService(db)
    return await service.update_assignment(project_id, artifact, payload, current_user.id)

@router.delete("/{project_id}/providers/{artifact}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_provider_assignment(
    project_id: str,
    artifact: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    service = ProviderAssignmentService(db)
    await service.remove_assignment(project_id, artifact, current_user.id)
    return None
