from pydantic import BaseModel

class GenerateRequest(BaseModel):
    doc_type: str = "README"
    custom_instructions: str | None = None
    provider: str = "mock"

class DocumentUpdatePayload(BaseModel):
    content: str
