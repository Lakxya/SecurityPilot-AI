from datetime import datetime
from pydantic import BaseModel, Field, ConfigDict

class ProviderAssignmentUpdate(BaseModel):
    provider: str = Field(..., min_length=2, max_length=50)
    model: str = Field(..., min_length=2, max_length=100)
    provider_id: str | None = None

class ProviderAssignmentSpec(BaseModel):
    artifact: str
    provider: str
    model: str
    provider_id: str | None = None
    last_updated: datetime | str

    model_config = ConfigDict(from_attributes=True)

class ProjectProviderAssignmentsResponse(BaseModel):
    project_id: str
    assignments: dict[str, ProviderAssignmentSpec]
