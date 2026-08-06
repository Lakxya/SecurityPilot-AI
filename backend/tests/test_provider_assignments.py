import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.core.database import engine, Base

@pytest.mark.asyncio
async def test_provider_assignments_flow():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # Register user
        user_payload = {
            "email": "matrix.user@securitypilot.ai",
            "password": "SecurePassword123!",
            "full_name": "Matrix Architect",
            "role": "SECURITY_ENGINEER"
        }
        reg_res = await ac.post("/api/v1/auth/register", json=user_payload)
        assert reg_res.status_code == 201
        token = reg_res.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # Create project
        project_payload = {
            "name": "Multi-Model Banking API",
            "description": "PCI-DSS compliant system",
            "tech_stack": {"backend": "FastAPI"},
            "compliance_frameworks": ["OWASP Top 10"]
        }
        create_res = await ac.post("/api/v1/projects/", json=project_payload, headers=headers)
        assert create_res.status_code == 201
        project_id = create_res.json()["id"]

        # 1. Get initial assignments (empty)
        get_res = await ac.get(f"/api/v1/projects/{project_id}/providers", headers=headers)
        assert get_res.status_code == 200
        assert get_res.json()["assignments"] == {}

        # 2. Put assignment for THREAT_MODEL -> ANTHROPIC / Claude 3.5 Sonnet
        assign_payload = {
            "provider": "ANTHROPIC",
            "model": "Claude 3.5 Sonnet",
            "provider_id": None
        }
        put_res = await ac.put(
            f"/api/v1/projects/{project_id}/providers/THREAT_MODEL",
            json=assign_payload,
            headers=headers
        )
        assert put_res.status_code == 200
        data = put_res.json()
        assert data["artifact"] == "THREAT_MODEL"
        assert data["provider"] == "ANTHROPIC"
        assert data["model"] == "Claude 3.5 Sonnet"

        # 3. Verify get assignments returns THREAT_MODEL mapping
        get_res2 = await ac.get(f"/api/v1/projects/{project_id}/providers", headers=headers)
        assert get_res2.status_code == 200
        assignments = get_res2.json()["assignments"]
        assert "THREAT_MODEL" in assignments
        assert assignments["THREAT_MODEL"]["model"] == "Claude 3.5 Sonnet"

        # 4. Remove assignment
        del_res = await ac.delete(f"/api/v1/projects/{project_id}/providers/THREAT_MODEL", headers=headers)
        assert del_res.status_code == 204

        # 5. Verify empty map after deletion
        get_res3 = await ac.get(f"/api/v1/projects/{project_id}/providers", headers=headers)
        assert get_res3.json()["assignments"] == {}
