import asyncio
import json
from abc import ABC, abstractmethod
from typing import AsyncGenerator
import httpx
from app.core.config import settings
from app.services.ai.document_generators import DocumentGenerators
from app.models.project import Project

class BaseLLMProvider(ABC):
    @abstractmethod
    async def generate_stream(
        self, prompt: str, system_prompt: str = "", model: str = "claude-3-5-sonnet", project: Project | None = None, doc_type: str = "README"
    ) -> AsyncGenerator[str, None]:
        pass


class MockLLMProvider(BaseLLMProvider):
    """
    Fallback streaming provider for offline testing and development.
    Streams realistic security tokens asynchronously based on document type.
    """
    async def generate_stream(
        self, prompt: str, system_prompt: str = "", model: str = "claude-3-5-sonnet", project: Project | None = None, doc_type: str = "README"
    ) -> AsyncGenerator[str, None]:
        if project:
            sample_response = DocumentGenerators.get_template_prompt(doc_type, project)
        else:
            sample_response = (
                f"### Security Architecture Specification ({doc_type})\n\n"
                f"**Model Engine:** `{model}`  \n"
                f"**System Context:** {system_prompt[:60]}...  \n\n"
                f"#### Overview & Security Controls\n"
                f"Based on the provided prompt context (`{prompt[:40]}...`), the system enforces:\n"
                f"1. **Encryption at Rest:** AES-256-GCM with managed KMS keys.\n"
                f"2. **Transit Security:** Enforced TLS 1.3 with strict cipher suites.\n"
                f"3. **Identity Control:** Asymmetric RS256 JWT tokens with 15-min expiration.\n"
            )

        words = sample_response.split(" ")
        for word in words:
            yield word + " "
            await asyncio.sleep(0.01)


class OpenAIProvider(BaseLLMProvider):
    async def generate_stream(
        self, prompt: str, system_prompt: str = "", model: str = "gpt-4o", project: Project | None = None, doc_type: str = "README"
    ) -> AsyncGenerator[str, None]:
        api_key = getattr(settings, "OPENAI_API_KEY", None)
        if not api_key:
            async for chunk in MockLLMProvider().generate_stream(prompt, system_prompt, model, project, doc_type):
                yield chunk
            return

        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt},
            ],
            "stream": True,
        }
        async with httpx.AsyncClient(timeout=60.0) as client:
            async with client.stream(
                "POST", "https://api.openai.com/v1/chat/completions", headers=headers, json=payload
            ) as response:
                if response.status_code != 200:
                    async for chunk in MockLLMProvider().generate_stream(prompt, system_prompt, model, project, doc_type):
                        yield chunk
                    return
                async for line in response.aiter_lines():
                    if line.startswith("data: ") and not line.startswith("data: [DONE]"):
                        try:
                            data = json.loads(line[6:])
                            delta = data["choices"][0]["delta"].get("content", "")
                            if delta:
                                yield delta
                        except Exception:
                            continue


class AnthropicProvider(BaseLLMProvider):
    async def generate_stream(
        self, prompt: str, system_prompt: str = "", model: str = "claude-3-5-sonnet", project: Project | None = None, doc_type: str = "README"
    ) -> AsyncGenerator[str, None]:
        api_key = getattr(settings, "ANTHROPIC_API_KEY", None)
        if not api_key:
            async for chunk in MockLLMProvider().generate_stream(prompt, system_prompt, model, project, doc_type):
                yield chunk
            return

        headers = {
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        payload = {
            "model": "claude-3-5-sonnet-20240620",
            "max_tokens": 4096,
            "system": system_prompt,
            "messages": [{"role": "user", "content": prompt}],
            "stream": True,
        }
        async with httpx.AsyncClient(timeout=60.0) as client:
            async with client.stream(
                "POST", "https://api.anthropic.com/v1/messages", headers=headers, json=payload
            ) as response:
                if response.status_code != 200:
                    async for chunk in MockLLMProvider().generate_stream(prompt, system_prompt, model, project, doc_type):
                        yield chunk
                    return
                async for line in response.aiter_lines():
                    if line.startswith("data: "):
                        try:
                            data = json.loads(line[6:])
                            if data.get("type") == "content_block_delta":
                                yield data["delta"].get("text", "")
                        except Exception:
                            continue


class LLMFactory:
    @staticmethod
    def get_provider(provider_type: str = "mock") -> BaseLLMProvider:
        providers = {
            "openai": OpenAIProvider(),
            "anthropic": AnthropicProvider(),
            "mock": MockLLMProvider(),
        }
        return providers.get(provider_type.lower(), MockLLMProvider())
