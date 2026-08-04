import json
from fastapi import APIRouter, Depends, status
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.database import get_db
from app.api.v1.deps import get_current_user
from app.models.user import User
from app.schemas.chat import ChatMessageRequest, ChatMessageResponse, ChatHistoryResponse
from app.services.chat_service import ChatService

router = APIRouter(prefix="/chat", tags=["AI Copilot Chat"])

@router.post("/message")
async def send_chat_message(
    payload: ChatMessageRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    service = ChatService(db)

    async def sse_chat_generator():
        try:
            async for token in service.stream_and_save_chat_response(
                project_id=payload.project_id,
                user_id=current_user.id,
                user_message=payload.message,
                doc_type=payload.doc_type,
                current_doc_content=payload.current_doc_content,
                provider_name=payload.provider,
            ):
                data = json.dumps({"chunk": token})
                yield f"event: message\ndata: {data}\n\n"
            yield "event: end\ndata: {\"status\": \"complete\"}\n\n"
        except Exception as e:
            err_data = json.dumps({"error": str(e)})
            yield f"event: error\ndata: {err_data}\n\n"

    return StreamingResponse(sse_chat_generator(), media_type="text/event-stream")


@router.get("/history/{project_id}", response_model=ChatHistoryResponse)
async def get_chat_history(
    project_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    service = ChatService(db)
    history = await service.get_chat_history(project_id, current_user.id)
    return ChatHistoryResponse(
        messages=[ChatMessageResponse.model_validate(m) for m in history],
        total=len(history),
    )


@router.delete("/history/{project_id}", status_code=status.HTTP_204_NO_CONTENT)
async def clear_chat_history(
    project_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    service = ChatService(db)
    await service.clear_chat_history(project_id, current_user.id)
    return None
