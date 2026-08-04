from typing import AsyncGenerator
from app.models.project import Project, GeneratedDocument
from app.models.chat import ChatConversation
from app.services.ai.providers import LLMFactory
from app.services.ai.prompt_engine import SecurityGuardrails

class CopilotEngine:
    @staticmethod
    def build_context_system_prompt(
        project: Project,
        doc_type: str | None = None,
        doc_content: str | None = None,
        recent_docs: list[GeneratedDocument] | None = None,
        chat_history: list[ChatConversation] | None = None,
    ) -> str:
        tech_stack = project.tech_stack or {}
        compliance = ", ".join(project.compliance_frameworks or ["OWASP Top 10", "SOC 2 Type II"])

        prompt_parts = [
            "You are SecurityPilotAI Copilot, an enterprise Principal AI Security Architect and DevSecOps Consultant.\n",
            "Your objective is to provide precise, secure-by-default architecture guidance, OWASP/STRIDE threat explanations, ",
            "and concrete security code fixes tailored specifically to the user's project context.\n\n",
            f"=== PROJECT CONTEXT ===\n",
            f"- Project Name: {project.name}\n",
            f"- Description: {project.description or 'N/A'}\n",
            f"- Frontend: {tech_stack.get('frontend', 'React 18')}\n",
            f"- Backend: {tech_stack.get('backend', 'FastAPI')}\n",
            f"- Database: {tech_stack.get('database', 'PostgreSQL 16')}\n",
            f"- Cloud Infrastructure: {tech_stack.get('cloud', 'AWS Cloud')}\n",
            f"- Container Runtime: {tech_stack.get('container', 'Docker + K8s')}\n",
            f"- Target Security Standards: {compliance}\n\n",
        ]

        if doc_type:
            prompt_parts.append(f"=== CURRENT ACTIVE DOCUMENT ({doc_type}) ===\n")
            if doc_content:
                prompt_parts.append(f"```\n{doc_content[:1500]}\n```\n\n")

        if recent_docs:
            prompt_parts.append("=== GENERATED PROJECT ARTIFACTS ===\n")
            for d in recent_docs[:5]:
                prompt_parts.append(f"- `{d.doc_type}` ({d.file_path}) [v{d.version}]\n")
            prompt_parts.append("\n")

        if chat_history:
            prompt_parts.append("=== RECENT CONVERSATION CONTEXT ===\n")
            for msg in chat_history[-6:]:
                prompt_parts.append(f"[{msg.role.upper()}]: {msg.content[:200]}\n")
            prompt_parts.append("\n")

        prompt_parts.append(
            "=== INSTRUCTIONS ===\n"
            "1. Answer questions concisely, using markdown formatting and syntax-highlighted code blocks where applicable.\n"
            "2. Reference explicit security frameworks (OWASP Top 10, STRIDE, CVSS v3.1) and tech stack specifics.\n"
            "3. If suggesting code fixes, provide complete, drop-in replacement snippets.\n"
        )

        return "".join(prompt_parts)

    @classmethod
    async def stream_copilot_response(
        cls,
        user_message: str,
        project: Project,
        doc_type: str | None = None,
        doc_content: str | None = None,
        recent_docs: list[GeneratedDocument] | None = None,
        chat_history: list[ChatConversation] | None = None,
        provider_name: str = "mock",
    ) -> AsyncGenerator[str, None]:
        sanitized_user_msg = SecurityGuardrails.sanitize_prompt(user_message)
        system_prompt = cls.build_context_system_prompt(
            project=project,
            doc_type=doc_type,
            doc_content=doc_content,
            recent_docs=recent_docs,
            chat_history=chat_history,
        )

        provider = LLMFactory.get_provider(provider_name)
        async for chunk in provider.generate_stream(sanitized_user_msg, system_prompt):
            yield chunk
