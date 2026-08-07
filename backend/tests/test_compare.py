import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.core.database import engine, Base

@pytest.mark.asyncio
async def test_compare_mode_flow():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # Register user
        user_payload = {
            "email": "compare.user@securitypilot.ai",
            "password": "SecurePassword123!",
            "full_name": "Compare Tester",
            "role": "SECURITY_ENGINEER"
        }
        reg_res = await ac.post("/api/v1/auth/register", json=user_payload)
        assert reg_res.status_code == 201
        token = reg_res.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # Create project
        project_payload = {
            "name": "Compare Flow Project",
            "description": "System architecture comparison",
            "tech_stack": {"backend": "FastAPI"}
        }
        create_res = await ac.post("/api/v1/projects/", json=project_payload, headers=headers)
        assert create_res.status_code == 201
        project_id = create_res.json()["id"]

        # Stream Compare Request
        compare_payload = {
            "artifact": "THREAT_MODEL",
            "providers": ["openai", "anthropic"],
            "custom_instructions": "Focus on STRIDE vectors"
        }

        response = await ac.post(
            f"/api/v1/generation/{project_id}/compare",
            json=compare_payload,
            headers=headers
        )
        assert response.status_code == 200
        assert "text/event-stream" in response.headers["content-type"]
        body = response.text
        assert "event: message" in body
        assert "event: end" in body
        assert "winner_provider" in body
