from datetime import datetime
from pydantic import BaseModel, Field, ConfigDict

class AIProviderCreate(BaseModel):
    provider_name: str = Field(..., min_length=2, max_length=50)
    api_key: str | None = None
    base_url: str | None = None
    model_name: str = Field(default="gpt-4o")
    is_default: bool = False

class AIProviderResponse(BaseModel):
    id: str
    user_id: str
    provider_name: str
    masked_api_key: str
    base_url: str | None = None
    model_name: str
    is_default: bool
    is_active: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

class AIProviderListResponse(BaseModel):
    providers: list[AIProviderResponse]
    total: int
