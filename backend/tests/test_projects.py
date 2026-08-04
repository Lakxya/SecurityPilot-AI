import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.core.database import engine, Base

@pytest.mark.asyncio
async def test_project_crud_flow():
    # Drop and recreate tables for clean test state
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # 1. Register and Login User
        user_payload = {
            "email": "arch.lead@securitypilot.ai",
            "password": "SecurePassword123!",
            "full_name": "Lead Architect",
            "role": "SECURITY_ENGINEER"
        }
        reg_res = await ac.post("/api/v1/auth/register", json=user_payload)
        assert reg_res.status_code == 201
        token = reg_res.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # 2. Test Create Project
        project_payload = {
            "name": "E-Commerce Core Payment API",
            "description": "PCI-DSS compliant payment gateway with microservices isolation",
            "tech_stack": {
                "frontend": "React 18",
                "backend": "FastAPI",
                "database": "PostgreSQL 16",
                "cloud": "AWS Cloud",
                "container": "Docker + K8s"
            },
            "compliance_frameworks": ["OWASP Top 10", "PCI-DSS", "SOC 2 Type II"]
        }
        create_res = await ac.post("/api/v1/projects/", json=project_payload, headers=headers)
        assert create_res.status_code == 201, create_res.text
        proj_data = create_res.json()
        assert proj_data["name"] == "E-Commerce Core Payment API"
        assert proj_data["status"] == "ACTIVE"
        project_id = proj_data["id"]

        # 3. Test List Projects
        list_res = await ac.get("/api/v1/projects/", headers=headers)
        assert list_res.status_code == 200
        list_data = list_res.json()
        assert list_data["total"] == 1
        assert list_data["projects"][0]["id"] == project_id

        # 4. Test Search Projects Filter
        search_res = await ac.get("/api/v1/projects/?search=Payment", headers=headers)
        assert search_res.status_code == 200
        assert len(search_res.json()["projects"]) == 1

        search_empty = await ac.get("/api/v1/projects/?search=NonExistent", headers=headers)
        assert search_empty.status_code == 200
        assert len(search_empty.json()["projects"]) == 0

        # 5. Test Get Project Details
        get_res = await ac.get(f"/api/v1/projects/{project_id}", headers=headers)
        assert get_res.status_code == 200
        assert get_res.json()["id"] == project_id

        # 6. Test Update Project
        update_payload = {"description": "Updated PCI-DSS v4.0 description"}
        update_res = await ac.put(f"/api/v1/projects/{project_id}", json=update_payload, headers=headers)
        assert update_res.status_code == 200
        assert update_res.json()["description"] == "Updated PCI-DSS v4.0 description"

        # 7. Test Delete Project
        del_res = await ac.delete(f"/api/v1/projects/{project_id}", headers=headers)
        assert del_res.status_code == 204

        # Verify project is gone
        get_gone = await ac.get(f"/api/v1/projects/{project_id}", headers=headers)
        assert get_gone.status_code == 404
