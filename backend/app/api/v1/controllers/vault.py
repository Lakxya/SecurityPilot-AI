from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.database import get_db
from app.api.v1.deps import get_current_user
from app.models.user import User
from app.schemas.ai_provider import AIProviderCreate, AIProviderResponse, AIProviderListResponse
from app.services.vault_service import VaultService

router = APIRouter(prefix="/vault", tags=["AI Vault"])

@router.get("/providers", response_model=AIProviderListResponse)
async def list_providers(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    service = VaultService(db)
    providers = await service.list_user_providers(current_user.id)
    return AIProviderListResponse(providers=providers, total=len(providers))

@router.post("/providers", response_model=AIProviderResponse, status_code=status.HTTP_201_CREATED)
async def create_provider(
    provider_in: AIProviderCreate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    service = VaultService(db)
    return await service.create_provider(provider_in, current_user.id)

@router.delete("/providers/{provider_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_provider(
    provider_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    service = VaultService(db)
    await service.delete_provider(provider_id, current_user.id)
    return None

@router.post("/providers/{provider_id}/test")
async def test_provider(
    provider_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    service = VaultService(db)
    return await service.test_provider_connection(provider_id, current_user.id)
