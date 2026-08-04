from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field

class ChatMessageRequest(BaseModel):
    project_id: str
    message: str = Field(..., min_length=1)
    doc_type: str | None = None
    current_doc_content: str | None = None
    provider: str = "mock"

class ChatMessageResponse(BaseModel):
    id: str
    project_id: str
    user_id: str
    role: str
    content: str
    doc_type: str | None = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

class ChatHistoryResponse(BaseModel):
    messages: list[ChatMessageResponse]
    total: int
