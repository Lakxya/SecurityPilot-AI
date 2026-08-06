import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.core.database import engine, Base

@pytest.mark.asyncio
async def test_recommendations_flow():
    # Recreate tables for clean test state
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # Register user
        user_payload = {
            "email": "rec.user@securitypilot.ai",
            "password": "SecurePassword123!",
            "full_name": "Rec Tester",
            "role": "SECURITY_ENGINEER"
        }
        reg_res = await ac.post("/api/v1/auth/register", json=user_payload)
        assert reg_res.status_code == 201
        token = reg_res.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # Create project
        project_payload = {
            "name": "Cloud Payment API",
            "description": "PCI-DSS compliant payment gateway",
            "tech_stack": {
                "backend": "FastAPI",
                "database": "PostgreSQL",
                "cloud": "AWS"
            },
            "compliance_frameworks": ["OWASP Top 10", "PCI-DSS"]
        }
        create_res = await ac.post("/api/v1/projects/", json=project_payload, headers=headers)
        assert create_res.status_code == 201
        project_id = create_res.json()["id"]

        # Test Threat Model Recommendation -> Anthropic Claude 3.5 Sonnet
        rec_res1 = await ac.get(f"/api/v1/projects/{project_id}/recommendation?doc_type=THREAT_MODEL", headers=headers)
        assert rec_res1.status_code == 200
        data1 = rec_res1.json()
        assert data1["recommended_provider"] == "ANTHROPIC"
        assert "Claude 3.5 Sonnet" in data1["recommended_model"]
        assert data1["confidence_score"] >= 0.9

        # Test Dockerfile Recommendation -> OpenAI GPT-4o
        rec_res2 = await ac.get(f"/api/v1/projects/{project_id}/recommendation?doc_type=DOCKERFILE", headers=headers)
        assert rec_res2.status_code == 200
        data2 = rec_res2.json()
        assert data2["recommended_provider"] == "OPENAI"
        assert "GPT-4o" in data2["recommended_model"]

        # Test Unauthorized Recommendation Request -> 401
        rec_unauth = await ac.get(f"/api/v1/projects/{project_id}/recommendation?doc_type=THREAT_MODEL")
        assert rec_unauth.status_code == 401
