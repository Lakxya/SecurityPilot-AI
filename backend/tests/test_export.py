import pytest
import io
import zipfile
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.core.database import engine, Base

@pytest.mark.asyncio
async def test_project_multi_format_export():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # 1. Register User
        reg_res = await ac.post("/api/v1/auth/register", json={
            "email": "export.lead@securitypilot.ai",
            "password": "Password123!",
            "full_name": "DevOps Architect",
            "role": "DEVOPS_ENGINEER"
        })
        token = reg_res.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # 2. Create Project Workspace
        proj_res = await ac.post("/api/v1/projects/", json={
            "name": "Cloud Native Gateway",
            "description": "EKS microservice gateway",
            "tech_stack": {"frontend": "React", "backend": "FastAPI", "cloud": "AWS Cloud"},
            "compliance_frameworks": ["OWASP Top 10", "SOC 2 Type II"]
        }, headers=headers)
        project_id = proj_res.json()["id"]

        # 3. Generate README artifact
        await ac.post(f"/api/v1/generation/{project_id}/generate", json={
            "doc_type": "README",
            "provider": "mock"
        }, headers=headers)

        # 4. Test ZIP Export
        zip_res = await ac.post(f"/api/v1/projects/{project_id}/export/zip", headers=headers)
        assert zip_res.status_code == 200
        assert zip_res.headers["content-type"] == "application/zip"
        
        # Verify ZIP contains full repository layout
        with zipfile.ZipFile(io.BytesIO(zip_res.content), "r") as zf:
            namelist = zf.namelist()
            assert "README.md" in namelist
            assert "docs/SRS.md" in namelist
            assert "docker/Dockerfile" in namelist
            assert "kubernetes/deployment.yaml" in namelist
            assert "terraform/main.tf" in namelist
            assert "securitypilot-manifest.json" in namelist

        # 5. Test Consolidated Markdown Bundle Export
        bundle_res = await ac.post(f"/api/v1/projects/{project_id}/export/bundle", headers=headers)
        assert bundle_res.status_code == 200
        assert "text/markdown" in bundle_res.headers["content-type"]
        assert "Consolidated Security Architecture Bundle" in bundle_res.text

        # 6. Test JSON Export
        json_res = await ac.post(f"/api/v1/projects/{project_id}/export/json", headers=headers)
        assert json_res.status_code == 200
        json_data = json_res.json()
        assert json_data["project_id"] == project_id
        assert len(json_data["artifacts"]) == 13
