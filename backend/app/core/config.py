import os
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    PROJECT_NAME: str = "SecurityPilotAI API"
    VERSION: str = "0.1.0"
    API_V1_STR: str = "/api/v1"
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")

    SECRET_KEY: str = os.getenv(
        "SECRET_KEY",
        "super-secret-key-change-in-production-securitypilot-2026"
    )
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 24 hours for development

    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///./securitypilot.db")

    model_config = SettingsConfigDict(case_sensitive=True)

settings = Settings()

# Production Startup Validation Guard
if settings.ENVIRONMENT.lower() == "production":
    if settings.SECRET_KEY == "super-secret-key-change-in-production-securitypilot-2026" or len(settings.SECRET_KEY) < 32:
        raise RuntimeError(
            "CRITICAL SECURITY RISK: Production deployment requires a secure, unique SECRET_KEY environment variable (minimum 32 characters)!"
        )
