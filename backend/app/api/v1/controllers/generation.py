import json
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.database import get_db
from app.api.v1.deps import get_current_user
from app.models.user import User
from app.schemas.generation import GenerateRequest, DocumentUpdatePayload
from app.schemas.project import DocumentResponse
from app.services.generation_service import GenerationService

router = APIRouter(prefix="/generation", tags=["Generation"])

@router.post("/{project_id}/generate")
async def generate_document(
    project_id: str,
    payload: GenerateRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    service = GenerationService(db)

    async def sse_event_generator():
        try:
            async for token in service.stream_and_save_document(
                project_id=project_id,
                doc_type=payload.doc_type,
                user_id=current_user.id,
                custom_instructions=payload.custom_instructions,
                provider_name=payload.provider,
            ):
                data = json.dumps({"chunk": token})
                yield f"event: message\ndata: {data}\n\n"
            yield "event: end\ndata: {\"status\": \"complete\"}\n\n"
        except Exception as e:
            err_data = json.dumps({"error": str(e)})
            yield f"event: error\ndata: {err_data}\n\n"

    return StreamingResponse(sse_event_generator(), media_type="text/event-stream")


@router.get("/{project_id}/docs/{doc_type}", response_model=DocumentResponse)
async def get_document(
    project_id: str,
    doc_type: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    service = GenerationService(db)
    doc = await service.get_latest_document(project_id, doc_type, current_user.id)
    if not doc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Document `{doc_type}` not yet generated for this project.",
        )
    return DocumentResponse.model_validate(doc)


@router.put("/{project_id}/docs/{doc_type}", response_model=DocumentResponse)
async def update_document(
    project_id: str,
    doc_type: str,
    payload: DocumentUpdatePayload,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    service = GenerationService(db)
    doc = await service.update_document_content(project_id, doc_type, payload.content, current_user.id)
    return DocumentResponse.model_validate(doc)
