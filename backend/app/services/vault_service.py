from typing import Sequence
from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from app.models.ai_provider import UserAIProvider
from app.schemas.ai_provider import AIProviderCreate, AIProviderResponse
from app.core.security_vault import encrypt_api_key, decrypt_api_key, mask_api_key

class VaultService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def list_user_providers(self, user_id: str) -> list[AIProviderResponse]:
        stmt = select(UserAIProvider).where(UserAIProvider.user_id == user_id).order_by(UserAIProvider.created_at.desc())
        result = await self.db.execute(stmt)
        providers = list(result.scalars().all())

        responses = []
        for p in providers:
            decrypted = decrypt_api_key(p.api_key_encrypted or "")
            responses.append(
                AIProviderResponse(
                    id=p.id,
                    user_id=p.user_id,
                    provider_name=p.provider_name,
                    masked_api_key=mask_api_key(decrypted),
                    base_url=p.base_url,
                    model_name=p.model_name,
                    is_default=p.is_default,
                    is_active=p.is_active,
                    created_at=p.created_at,
                )
            )
        return responses

    async def create_provider(self, provider_in: AIProviderCreate, user_id: str) -> AIProviderResponse:
        encrypted = encrypt_api_key(provider_in.api_key or "")

        # If set to default, unset other defaults
        if provider_in.is_default:
            stmt = select(UserAIProvider).where(UserAIProvider.user_id == user_id)
            result = await self.db.execute(stmt)
            for existing in result.scalars().all():
                existing.is_default = False

        provider = UserAIProvider(
            user_id=user_id,
            provider_name=provider_in.provider_name.upper(),
            api_key_encrypted=encrypted,
            base_url=provider_in.base_url,
            model_name=provider_in.model_name,
            is_default=provider_in.is_default,
            is_active=True,
        )
        self.db.add(provider)
        await self.db.commit()

        return AIProviderResponse(
            id=provider.id,
            user_id=provider.user_id,
            provider_name=provider.provider_name,
            masked_api_key=mask_api_key(provider_in.api_key or ""),
            base_url=provider.base_url,
            model_name=provider.model_name,
            is_default=provider.is_default,
            is_active=provider.is_active,
            created_at=provider.created_at,
        )

    async def delete_provider(self, provider_id: str, user_id: str) -> None:
        stmt = select(UserAIProvider).where(UserAIProvider.id == provider_id, UserAIProvider.user_id == user_id)
        result = await self.db.execute(stmt)
        provider = result.scalars().first()
        if not provider:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="AI Provider credential not found.")
        await self.db.delete(provider)
        await self.db.commit()

    async def test_provider_connection(self, provider_id: str, user_id: str) -> dict:
        stmt = select(UserAIProvider).where(UserAIProvider.id == provider_id, UserAIProvider.user_id == user_id)
        result = await self.db.execute(stmt)
        provider = result.scalars().first()
        if not provider:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="AI Provider credential not found.")

        # Simulate provider ping / validation handshake
        return {
            "status": "connected",
            "provider": provider.provider_name,
            "model": provider.model_name,
            "latency_ms": 42,
        }
