from datetime import datetime
from pydantic import BaseModel, Field, ConfigDict

class TechStackSpec(BaseModel):
    frontend: str = "React 18"
    backend: str = "FastAPI"
    database: str = "PostgreSQL 16"
    cloud: str = "AWS Cloud"
    container: str = "Docker + K8s"

class ProjectCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=150)
    description: str | None = None
    tech_stack: dict | TechStackSpec | None = Field(default_factory=dict)
    compliance_frameworks: list[str] = Field(default_factory=list)

class ProjectUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=150)
    description: str | None = None
    tech_stack: dict | TechStackSpec | None = None
    compliance_frameworks: list[str] | None = None
    status: str | None = None

class DocumentResponse(BaseModel):
    id: str
    project_id: str
    doc_type: str
    file_path: str
    content: str
    version: int
    is_latest: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

class ProjectResponse(BaseModel):
    id: str
    user_id: str
    name: str
    description: str | None = None
    tech_stack: dict | None = None
    compliance_frameworks: list[str] | None = None
    status: str
    created_at: datetime
    updated_at: datetime
    documents: list[DocumentResponse] = []

    model_config = ConfigDict(from_attributes=True)

class ProjectListResponse(BaseModel):
    projects: list[ProjectResponse]
    total: int
