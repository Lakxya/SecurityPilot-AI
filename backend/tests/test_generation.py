import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.core.database import engine, Base

@pytest.mark.asyncio
async def test_generation_sse_stream_and_persistence():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # 1. Register User
        reg_res = await ac.post("/api/v1/auth/register", json={
            "email": "ai.lead@securitypilot.ai",
            "password": "Password123!",
            "full_name": "AI Engineer",
            "role": "SECURITY_ENGINEER"
        })
        token = reg_res.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # 2. Create Project Workspace
        proj_res = await ac.post("/api/v1/projects/", json={
            "name": "FinTech Auth Engine",
            "description": "Secure microservice",
            "tech_stack": {"frontend": "React", "backend": "FastAPI"},
            "compliance_frameworks": ["OWASP Top 10"]
        }, headers=headers)
        project_id = proj_res.json()["id"]

        # 3. Test SSE Stream Generation API
        gen_payload = {
            "doc_type": "README",
            "custom_instructions": "Focus on MFA and OAuth 2.0 PKCE.",
            "provider": "mock"
        }
        stream_res = await ac.post(f"/api/v1/generation/{project_id}/generate", json=gen_payload, headers=headers)
        assert stream_res.status_code == 200
        assert "text/event-stream" in stream_res.headers["content-type"]
        body_text = stream_res.text
        assert "event: message" in body_text
        assert "event: end" in body_text

        # 4. Fetch Generated Document
        doc_res = await ac.get(f"/api/v1/generation/{project_id}/docs/README", headers=headers)
        assert doc_res.status_code == 200
        doc_data = doc_res.json()
        assert doc_data["doc_type"] == "README"
        assert doc_data["file_path"] == "README.md"
        assert "Security Architecture Specification" in doc_data["content"]

        # 5. Test Document Content Update
        update_res = await ac.put(f"/api/v1/generation/{project_id}/docs/README", json={
            "content": "# Updated Custom README Content\n\nManual edits applied."
        }, headers=headers)
        assert update_res.status_code == 200
        assert update_res.json()["content"] == "# Updated Custom README Content\n\nManual edits applied."
