import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.core.database import engine, Base

@pytest.mark.asyncio
async def test_copilot_chat_flow():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # 1. Register User
        reg_res = await ac.post("/api/v1/auth/register", json={
            "email": "copilot.architect@securitypilot.ai",
            "password": "Password123!",
            "full_name": "Security Architect",
            "role": "SECURITY_ENGINEER"
        })
        token = reg_res.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # 2. Create Project Workspace
        proj_res = await ac.post("/api/v1/projects/", json={
            "name": "E-Commerce Core API",
            "description": "PCI-DSS compliant payment microservice",
            "tech_stack": {"frontend": "React", "backend": "FastAPI", "database": "PostgreSQL 16"},
            "compliance_frameworks": ["OWASP Top 10", "PCI-DSS"]
        }, headers=headers)
        project_id = proj_res.json()["id"]

        # 3. Test Send Chat Message (SSE Stream)
        chat_payload = {
            "project_id": project_id,
            "message": "Explain how OWASP Top 10 A01 Broken Access Control is prevented in this project.",
            "doc_type": "ARCHITECTURE",
            "current_doc_content": "# Architecture Document\nEnforces JWT RS256 authorization.",
            "provider": "mock"
        }
        stream_res = await ac.post("/api/v1/chat/message", json=chat_payload, headers=headers)
        assert stream_res.status_code == 200
        assert "text/event-stream" in stream_res.headers["content-type"]
        assert "event: message" in stream_res.text
        assert "event: end" in stream_res.text

        # 4. Fetch Chat History
        history_res = await ac.get(f"/api/v1/chat/history/{project_id}", headers=headers)
        assert history_res.status_code == 200
        history_data = history_res.json()
        assert history_data["total"] == 2 # 1 user message + 1 assistant message
        assert history_data["messages"][0]["role"] == "user"
        assert history_data["messages"][1]["role"] == "assistant"

        # 5. Clear Chat History
        clear_res = await ac.delete(f"/api/v1/chat/history/{project_id}", headers=headers)
        assert clear_res.status_code == 204

        # Verify history is empty
        history_empty = await ac.get(f"/api/v1/chat/history/{project_id}", headers=headers)
        assert history_empty.status_code == 200
        assert history_empty.json()["total"] == 0
