from fastapi import APIRouter, Depends, Query, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from app.core.database import get_db
from app.api.v1.deps import get_current_user
from app.models.user import User
from app.models.project import Project
from app.schemas.ai_recommendation import ModelRecommendationResponse
from app.services.ai.recommendation_engine import ProviderRecommendationService

router = APIRouter(prefix="/projects", tags=["AI Recommendations"])

@router.get("/{project_id}/recommendation", response_model=ModelRecommendationResponse)
async def get_project_recommendation(
    project_id: str,
    doc_type: str = Query("README"),
    cost_sensitivity: str = Query("NORMAL"),
    speed_preference: str = Query("BALANCED"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    stmt = select(Project).where(Project.id == project_id, Project.user_id == current_user.id)
    result = await self_db_exec(db, stmt)
    project = result.scalars().first()
    if not project:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")

    return ProviderRecommendationService.recommend_for_project(
        project=project,
        doc_type=doc_type,
        cost_sensitivity=cost_sensitivity,
        speed_preference=speed_preference,
    )

async def self_db_exec(db: AsyncSession, stmt):
    return await db.execute(stmt)
