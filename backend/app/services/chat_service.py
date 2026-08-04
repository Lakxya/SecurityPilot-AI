from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from app.models.project import Project, GeneratedDocument
from app.models.chat import ChatConversation
from app.services.project_service import ProjectService
from app.services.generation_service import GenerationService
from app.services.ai.copilot_engine import CopilotEngine

class ChatService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.project_service = ProjectService(db)
        self.generation_service = GenerationService(db)

    async def get_chat_history(self, project_id: str, user_id: str) -> list[ChatConversation]:
        await self.project_service.get_project(project_id, user_id)
        stmt = (
            select(ChatConversation)
            .where(
                ChatConversation.project_id == project_id,
                ChatConversation.user_id == user_id,
            )
            .order_by(ChatConversation.created_at.asc())
        )
        result = await self.db.execute(stmt)
        return list(result.scalars().all())

    async def clear_chat_history(self, project_id: str, user_id: str) -> None:
        history = await self.get_chat_history(project_id, user_id)
        for msg in history:
            await self.db.delete(msg)
        await self.db.commit()

    async def stream_and_save_chat_response(
        self,
        project_id: str,
        user_id: str,
        user_message: str,
        doc_type: str | None = None,
        current_doc_content: str | None = None,
        provider_name: str = "mock",
    ) -> AsyncGenerator[str, None]:
        # 1. Fetch & authorize project
        project = await self.project_service.get_project(project_id, user_id)

        # 2. Save user message in DB
        user_chat = ChatConversation(
            project_id=project_id,
            user_id=user_id,
            role="user",
            content=user_message,
            doc_type=doc_type,
        )
        self.db.add(user_chat)
        await self.db.commit()

        # 3. Fetch recent project context and chat history
        recent_docs = await self.generation_service.list_project_documents(project_id, user_id)
        history = await self.get_chat_history(project_id, user_id)

        # 4. Stream response tokens from CopilotEngine
        full_assistant_reply = []
        async for chunk in CopilotEngine.stream_copilot_response(
            user_message=user_message,
            project=project,
            doc_type=doc_type,
            doc_content=current_doc_content,
            recent_docs=recent_docs,
            chat_history=history,
            provider_name=provider_name,
        ):
            full_assistant_reply.append(chunk)
            yield chunk

        complete_text = "".join(full_assistant_reply)

        # 5. Save assistant response in DB
        assistant_chat = ChatConversation(
            project_id=project_id,
            user_id=user_id,
            role="assistant",
            content=complete_text,
            doc_type=doc_type,
        )
        self.db.add(assistant_chat)
        await self.db.commit()
