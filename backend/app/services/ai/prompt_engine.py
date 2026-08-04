import re
from app.models.project import Project

class SecurityGuardrails:
    INJECTION_PATTERNS = [
        r"ignore previous instructions",
        r"system prompt override",
        r"disregard safety guidelines",
        r"eval\(",
        r"exec\(",
    ]

    @classmethod
    def sanitize_prompt(cls, prompt: str) -> str:
        sanitized = prompt
        for pattern in cls.INJECTION_PATTERNS:
            sanitized = re.sub(pattern, "[FILTERED_SECURITY_VIOLATION]", sanitized, flags=re.IGNORECASE)
        return sanitized


class PromptSynthesizer:
    @staticmethod
    def build_system_prompt(project: Project, doc_type: str) -> str:
        tech_stack = project.tech_stack or {}
        compliance = ", ".join(project.compliance_frameworks or ["OWASP Top 10"])
        
        return (
            f"You are SecurityPilotAI, an enterprise Chief Security Architect and Principal Software Engineer.\n"
            f"Generate a production-grade, secure-by-default `{doc_type}` artifact for the project:\n"
            f"- Project Name: {project.name}\n"
            f"- Description: {project.description or 'N/A'}\n"
            f"- Frontend: {tech_stack.get('frontend', 'React 18')}\n"
            f"- Backend: {tech_stack.get('backend', 'FastAPI')}\n"
            f"- Database: {tech_stack.get('database', 'PostgreSQL 16')}\n"
            f"- Cloud Infrastructure: {tech_stack.get('cloud', 'AWS Cloud')}\n"
            f"- Container Runtime: {tech_stack.get('container', 'Docker + K8s')}\n"
            f"- Compliance Frameworks: {compliance}\n\n"
            f"Requirements:\n"
            f"1. Output clean, syntactically valid code or GitHub-flavored Markdown.\n"
            f"2. Incorporate explicit threat mitigation controls for all architecture components.\n"
            f"3. Do not include conversational preambles (e.g. 'Here is your document:'). Start directly with the document content.\n"
        )

    @staticmethod
    def build_user_prompt(doc_type: str, custom_instructions: str | None = None) -> str:
        prompt = f"Generate complete, secure, and production-ready content for `{doc_type}`."
        if custom_instructions:
            sanitized = SecurityGuardrails.sanitize_prompt(custom_instructions)
            prompt += f"\n\nAdditional Technical Requirements:\n{sanitized}"
        return prompt
