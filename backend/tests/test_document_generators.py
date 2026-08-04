import pytest
from app.models.project import Project
from app.services.ai.document_generators import DocumentGenerators

def test_document_generators_templates():
    mock_project = Project(
        name="FinTech Security Gateway",
        description="High throughput banking API",
        tech_stack={
            "frontend": "React 18",
            "backend": "FastAPI",
            "database": "PostgreSQL 16",
            "cloud": "AWS Cloud",
            "container": "Docker + K8s"
        },
        compliance_frameworks=["OWASP Top 10", "SOC 2 Type II", "PCI-DSS"]
    )

    doc_types = [
        "README",
        "SRS",
        "SDS",
        "ARCHITECTURE",
        "DATABASE_DESIGN",
        "API_SPEC",
        "THREAT_MODEL",
        "OWASP_REVIEW",
        "DOCKERFILE",
        "DOCKER_COMPOSE",
        "KUBERNETES",
        "TERRAFORM",
        "GITHUB_ACTIONS",
    ]

    for doc_type in doc_types:
        content = DocumentGenerators.get_template_prompt(doc_type, mock_project)
        assert content is not None
        assert len(content) > 20
        assert mock_project.name in content or "openapi" in content or "FROM python" in content or "services:" in content or "apiVersion" in content or "terraform {" in content or "runs-on:" in content
