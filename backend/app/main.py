from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.core.database import engine, Base
from app.api.v1.controllers.auth import router as auth_router
from app.api.v1.controllers.projects import router as projects_router
from app.api.v1.controllers.generation import router as generation_router
from app.api.v1.controllers.export import router as export_router
from app.api.v1.controllers.chat import router as chat_router
from app.api.v1.controllers.vault import router as vault_router
from app.api.v1.controllers.recommendations import router as recommendations_router
from app.api.v1.controllers.provider_assignments import router as provider_assignments_router
from app.api.v1.controllers.compare import router as compare_router
from app.api.v1.controllers.scanners import router as scanners_router

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Automatically initialize database schema tables on startup
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    lifespan=lifespan,
)

# Production HTTP Security Headers Middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response

# CORS middleware for React frontend integration (explicit origins required when allow_credentials=True)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API v1 Controllers
app.include_router(auth_router, prefix=settings.API_V1_STR)
app.include_router(projects_router, prefix=settings.API_V1_STR)
app.include_router(generation_router, prefix=settings.API_V1_STR)
app.include_router(export_router, prefix=settings.API_V1_STR)
app.include_router(chat_router, prefix=settings.API_V1_STR)
app.include_router(vault_router, prefix=settings.API_V1_STR)
app.include_router(recommendations_router, prefix=settings.API_V1_STR)
app.include_router(provider_assignments_router, prefix=settings.API_V1_STR)
app.include_router(compare_router, prefix=settings.API_V1_STR)
app.include_router(scanners_router, prefix=settings.API_V1_STR)
app.include_router(scanners_router, prefix="/api")

@app.get("/health", tags=["Health"])
async def health_check():
    return {"status": "healthy", "service": settings.PROJECT_NAME, "version": settings.VERSION}
