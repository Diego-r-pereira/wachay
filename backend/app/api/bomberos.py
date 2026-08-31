from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List, Any
from app.core.database import get_db
from app.models.bombero import Bombero
from app.models.report import Report
from app.schemas.bombero import BomberoCreate, BomberoUpdate, BomberoOut
from app.api.deps import get_current_active_admin, get_current_user
from app.services.messaging import send_whatsapp_message

router = APIRouter()

@router.get("/", response_model=List[BomberoOut])
def get_bomberos(
    db: Session = Depends(get_db),
    current_user: Any = Depends(get_current_user)
):
    """
    Lists all registered firefighters (rangers/admins can view).
    """
    return db.query(Bombero).order_by(Bombero.fire_unit.asc(), Bombero.is_leader.desc(), Bombero.name.asc()).all()

@router.post("/", response_model=BomberoOut, status_code=status.HTTP_201_CREATED)
def create_bombero(
    payload: BomberoCreate,
    db: Session = Depends(get_db),
    current_user: Any = Depends(get_current_active_admin)
):
    """
    Registers a new firefighter contact (Admin only).
    """
    # Check if number already registered
    if payload.whatsapp_number:
        clean_num = payload.whatsapp_number.strip()
        existing = db.query(Bombero).filter(Bombero.whatsapp_number == clean_num).first()
        if existing:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"El número de WhatsApp {clean_num} ya está asignado a otro bombero."
            )
            
    new_bombero = Bombero(
        name=payload.name.strip(),
        last_name=payload.last_name.strip(),
        whatsapp_number=payload.whatsapp_number.strip() if payload.whatsapp_number else None,
        fire_unit=payload.fire_unit.strip(),
        is_leader=payload.is_leader
    )
    db.add(new_bombero)
    db.commit()
    db.refresh(new_bombero)
    return new_bombero

@router.put("/{id}", response_model=BomberoOut)
def update_bombero(
    id: int,
    payload: BomberoUpdate,
    db: Session = Depends(get_db),
    current_user: Any = Depends(get_current_active_admin)
):
    """
    Updates a firefighter's contact details (Admin only).
    """
    bombero = db.query(Bombero).filter(Bombero.id == id).first()
    if not bombero:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Bombero con ID {id} no encontrado."
        )

    update_data = payload.model_dump(exclude_unset=True)
    if "whatsapp_number" in update_data and update_data["whatsapp_number"]:
        clean_num = update_data["whatsapp_number"].strip()
        # Verify unique number excluding current bombero
        existing = db.query(Bombero).filter(Bombero.whatsapp_number == clean_num, Bombero.id != id).first()
        if existing:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"El número de WhatsApp {clean_num} ya está asignado a otro bombero."
            )
        update_data["whatsapp_number"] = clean_num

    for key, value in update_data.items():
        setattr(bombero, key, value)

    db.commit()
    db.refresh(bombero)
    return bombero

@router.delete("/{id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_bombero(
    id: int,
    db: Session = Depends(get_db),
    current_user: Any = Depends(get_current_active_admin)
):
    """
    Deletes a firefighter contact (Admin only).
    """
    bombero = db.query(Bombero).filter(Bombero.id == id).first()
    if not bombero:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Bombero con ID {id} no encontrado."
        )
    db.delete(bombero)
    db.commit()
    return None

@router.post("/notify-unit")
def notify_unit_members(
    fire_unit: str,
    report_id: int,
    db: Session = Depends(get_db),
    current_user: Any = Depends(get_current_user)
):
    """
    Manually sends a WhatsApp fire alert to all non-leader members of a specific unit/brigade.
    """
    report = db.query(Report).filter(Report.id == report_id).first()
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Reporte con ID {report_id} no encontrado."
        )

    # Find members (is_leader == False)
    members = db.query(Bombero).filter(
        Bombero.fire_unit == fire_unit,
        Bombero.is_leader == False,
        Bombero.whatsapp_number != None
    ).all()

    if not members:
        return {"message": f"No se encontraron bomberos de tropa con WhatsApp registrado en la unidad '{fire_unit}'."}

    sent_count = 0
    clean_message = (
        f"🚨 ALERTA BRIGADA - {fire_unit.upper()} 🚨\n\n"
        f"Se solicita apoyo inmediato para combate de incendio:\n"
        f"Tipo: {report.incident_type}\n"
        f"Gravedad: {report.severity_level}\n"
        f"Clima: {report.weather_conditions if report.weather_conditions else 'No especificado'}\n"
        f"Descripción: {report.description if report.description else 'Sin descripción adicional.'}\n"
        f"Ubicación: Lat {report.latitude:.4f}, Lon {report.longitude:.4f}\n"
        f"Mapa: {report.google_maps_link}"
    )

    for m in members:
        if m.whatsapp_number:
            success = send_whatsapp_message(m.whatsapp_number.strip(), clean_message)
            if success:
                sent_count += 1

    return {"message": f"Se enviaron {sent_count} alertas de WhatsApp a la tropa de la unidad '{fire_unit}'."}

@router.post("/notify-member/{id}")
def notify_single_member(
    id: int,
    report_id: int,
    db: Session = Depends(get_db),
    current_user: Any = Depends(get_current_user)
):
    """
    Manually sends a WhatsApp fire alert to a single firefighter.
    """
    bombero = db.query(Bombero).filter(Bombero.id == id).first()
    if not bombero:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Bombero no encontrado."
        )
    if not bombero.whatsapp_number:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="El bombero no tiene un número de WhatsApp registrado."
        )

    report = db.query(Report).filter(Report.id == report_id).first()
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Reporte con ID {report_id} no encontrado."
        )

    clean_message = (
        f"🚨 ALERTA INDIVIDUAL DE APOYO 🚨\n\n"
        f"Estimado/a {bombero.name} {bombero.last_name},\n"
        f"Se solicita su presencia en el siguiente punto de calor:\n"
        f"Tipo: {report.incident_type}\n"
        f"Gravedad: {report.severity_level}\n"
        f"Clima: {report.weather_conditions if report.weather_conditions else 'No especificado'}\n"
        f"Descripción: {report.description if report.description else 'Sin descripción adicional.'}\n"
        f"Ubicación: Lat {report.latitude:.4f}, Lon {report.longitude:.4f}\n"
        f"Mapa: {report.google_maps_link}"
    )

    success = send_whatsapp_message(bombero.whatsapp_number.strip(), clean_message)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error al despachar el mensaje de WhatsApp."
        )

    return {"message": f"Alerta enviada exitosamente a {bombero.name} {bombero.last_name}."}
