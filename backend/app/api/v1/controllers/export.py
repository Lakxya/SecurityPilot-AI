from fastapi import APIRouter, Depends, Response, status
from fastapi.responses import Response, JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.database import get_db
from app.api.v1.deps import get_current_user
from app.models.user import User
from app.services.export_service import ExportService

router = APIRouter(prefix="/projects", tags=["Export"])

@router.post("/{project_id}/export/zip")
async def export_project_zip(
    project_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    service = ExportService(db)
    zip_data = await service.generate_zip_archive(project_id, current_user.id)
    filename = f"securitypilot_export_{project_id[:8]}.zip"
    return Response(
        content=zip_data,
        media_type="application/zip",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )

@router.post("/{project_id}/export/bundle")
async def export_project_bundle(
    project_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    service = ExportService(db)
    markdown_data = await service.generate_markdown_bundle(project_id, current_user.id)
    filename = f"securitypilot_bundle_{project_id[:8]}.md"
    return Response(
        content=markdown_data,
        media_type="text/markdown",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )

@router.post("/{project_id}/export/json")
async def export_project_json(
    project_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    service = ExportService(db)
    json_data = await service.generate_json_export(project_id, current_user.id)
    return JSONResponse(content=json_data)

@router.post("/{project_id}/export/pdf")
async def export_project_pdf(
    project_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    service = ExportService(db)
    pdf_html = await service.generate_pdf_report(project_id, current_user.id)
    filename = f"securitypilot_report_{project_id[:8]}.html"
    return Response(
        content=pdf_html,
        media_type="text/html",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )
