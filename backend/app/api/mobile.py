import os
import base64
import uuid
import random
import string
from datetime import datetime
from typing import Any
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.geohash import encode_geohash
from app.core.config import settings
from app.models.report import Report
from app.schemas.report import CitizenReportCreate, CitizenReportOut, ReportStatusResponse
from app.services.weather import get_weather_data

router = APIRouter()

def generate_tracking_code(length: int = 8) -> str:
    """
    Generates a unique tracking code for citizen reports.
    """
    return "".join(random.choices(string.ascii_uppercase + string.digits, k=length))

def save_base64_image(base64_data: str) -> str:
    """
    Decodes a base64 string and saves it as a file in the uploads directory.
    Returns the relative file path.
    """
    if not base64_data:
        return None

    # Handle standard Data URL prefixes if present (e.g. "data:image/jpeg;base64,...")
    if "," in base64_data:
        header, base64_data = base64_data.split(",", 1)

    try:
        image_bytes = base64.b64decode(base64_data)
        
        # Define directory path
        uploads_dir = os.path.join(settings.BASE_DIR, "backend", "uploads")
        os.makedirs(uploads_dir, exist_ok=True)
        
        # Generate unique filename
        filename = f"citizen_{uuid.uuid4().hex}.jpg"
        file_path = os.path.join(uploads_dir, filename)
        
        with open(file_path, "wb") as f:
            f.write(image_bytes)
            
        # Return the public/relative URL path
        return f"uploads/{filename}"
    except Exception as e:
        print(f"Error saving base64 uploaded image: {e}")
        return None

@router.post("/register_report", response_model=CitizenReportOut, status_code=status.HTTP_201_CREATED)
def register_mobile_report(
    payload: CitizenReportCreate,
    db: Session = Depends(get_db)
) -> Any:
    """
    Accepts report details sent by citizen application.
    Saves photo to file storage and logs the report with 'Citizen_Pending' state.
    """
    # 1. Decode photo
    photo_rel_path = None
    if payload.photo:
        photo_rel_path = save_base64_image(payload.photo)

    # 2. Get Weather automatically if missing from client
    weather_desc = payload.weather_conditions
    if not weather_desc and payload.latitude and payload.longitude:
        weather_info = get_weather_data(payload.latitude, payload.longitude)
        weather_desc = weather_info["raw_text"]

    # 3. Generate spatial geohash
    gh = encode_geohash(payload.latitude, payload.longitude)
    
    # 4. Generate unique tracking code
    code = generate_tracking_code()
    # Ensure code is unique in database
    while db.query(Report).filter(Report.tracking_code == code).first() is not None:
        code = generate_tracking_code()

    # 5. Create report record
    google_link = f"https://www.google.com/maps?q={payload.latitude},{payload.longitude}"
    new_report = Report(
        status="Citizen_Pending",  # Requires review
        source="citizen",
        citizen_name=payload.citizen_name,
        citizen_email=payload.citizen_email,
        photo_path=photo_rel_path,
        incident_type=payload.incident_type,
        severity_level=payload.severity_level,
        detection_time=payload.detection_time,
        probable_cause=payload.probable_cause,
        affected_area=payload.affected_area,
        vegetation_type=payload.vegetation_type,
        description=payload.description,
        latitude=payload.latitude,
        longitude=payload.longitude,
        google_maps_link=google_link,
        weather_conditions=weather_desc,
        geohash=gh,
        tracking_code=code,
        notification_status="Pending"
    )

    db.add(new_report)
    db.commit()
    db.refresh(new_report)

    return {
        "status": "success",
        "report_id": new_report.id,
        "tracking_code": code,
        "message": "Reporte ciudadano recibido exitosamente y en espera de validación."
    }

@router.get("/report_status/{tracking_code}", response_model=ReportStatusResponse)
def get_mobile_report_status(
    tracking_code: str,
    db: Session = Depends(get_db)
) -> Any:
    """
    Returns the current state of a citizen report.
    """
    report = db.query(Report).filter(Report.tracking_code == tracking_code).first()
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Código de seguimiento no válido. Reporte no encontrado."
        )

    # Translate status to a citizen friendly message
    status_msg = {
        "Citizen_Pending": "Pendiente: En espera de revisión por personal guardaparques.",
        "Approved": "Aprobado: El reporte ha sido verificado y está en proceso de asignación.",
        "Rejected": f"Rechazado: El reporte fue descartado. Motivo: {report.rejection_reason or 'No especificado'}",
        "Discarded": "Descartado: El reporte ha sido cancelado.",
        "First_State": "En proceso: Guardaparques están movilizándose al lugar del incidente.",
        "Second_State": "Controlado: Las brigadas han controlado el foco activo.",
        "Attended": "Atendido: El incidente ha sido completamente extinguido y finalizado."
    }

    friendly_msg = status_msg.get(report.status, "Estado desconocido.")

    return {
        "status": report.status,
        "message": friendly_msg
    }
