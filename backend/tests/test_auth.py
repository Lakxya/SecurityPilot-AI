import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.core.database import engine, Base

@pytest.mark.asyncio
async def test_register_and_login_flow():
    # Drop and recreate DB tables for isolated testing
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # 1. Test Registration
        register_payload = {
            "email": "test.engineer@securitypilot.ai",
            "password": "SecurePassword123!",
            "full_name": "Test Security Engineer",
            "role": "SECURITY_ENGINEER"
        }
        response = await ac.post("/api/v1/auth/register", json=register_payload)
        assert response.status_code == 201, response.text
        data = response.json()
        assert "access_token" in data
        assert data["user"]["email"] == "test.engineer@securitypilot.ai"
        token = data["access_token"]

        # 2. Test Fetch Current User (/me)
        headers = {"Authorization": f"Bearer {token}"}
        me_response = await ac.get("/api/v1/auth/me", headers=headers)
        assert me_response.status_code == 200
        me_data = me_response.json()
        assert me_data["email"] == "test.engineer@securitypilot.ai"

        # 3. Test Login
        login_payload = {
            "email": "test.engineer@securitypilot.ai",
            "password": "SecurePassword123!"
        }
        login_response = await ac.post("/api/v1/auth/login", json=login_payload)
        assert login_response.status_code == 200
        assert "access_token" in login_response.json()

        # 4. Test Login Failure
        bad_login = {
            "email": "test.engineer@securitypilot.ai",
            "password": "WrongPassword!"
        }
        bad_response = await ac.post("/api/v1/auth/login", json=bad_login)
        assert bad_response.status_code == 401
