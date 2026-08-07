from fastapi import APIRouter, Depends
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.database import get_db
from app.api.v1.deps import get_current_user
from app.models.user import User
from app.schemas.compare import CompareRequest
from app.services.compare_service import CompareService

router = APIRouter(prefix="/generation", tags=["AI Compare Mode"])

@router.post("/{project_id}/compare")
async def compare_provider_streams(
    project_id: str,
    payload: CompareRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    service = CompareService(db)
    return StreamingResponse(
        service.stream_compare_providers(
            project_id=project_id,
            artifact=payload.artifact,
            providers=payload.providers,
            user_id=current_user.id,
            custom_instructions=payload.custom_instructions,
        ),
        media_type="text/event-stream",
    )
