import io
from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query, BackgroundTasks
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from sqlalchemy import and_, func
import pandas as pd

from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

from app.core.database import get_db
from app.core.geohash import encode_geohash
from app.api.deps import get_current_active_ranger, get_current_active_admin, get_current_user
from app.models.report import Report
from app.models.user import User
from app.models.bombero import Bombero
from app.schemas.report import ReportCreate, ReportUpdate, ReportOut
from app.services.messaging import send_whatsapp_message, send_telegram_message
from app.services.weather import get_weather_data
import asyncio

router = APIRouter()

# --- Background Task for Alertas ---
def send_report_alerts_background(report_id: int, db: Session):
    """
    Sends WhatsApp and Telegram alerts for a specific report and audits the outcomes in the DB.
    """
    # Fetch report from new session to avoid thread conflicts
    report = db.query(Report).filter(Report.id == report_id).first()
    if not report:
        print(f"Background Alert Error: Report {report_id} not found.")
        return

    # Compile notification message
    alert_message = (
        f"🚨 <b>ALERTA: Foco de Calor / Incidente Registrado!</b> 🚨\n\n"
        f"<b>Origen:</b> {'Guardaparques' if report.source == 'ranger' else 'Ciudadano (App)'}\n"
        f"<b>Responsable/Reportante:</b> {report.ranger_name if report.ranger_name else report.citizen_name}\n"
        f"<b>Tipo de Incidente:</b> {report.incident_type}\n"
        f"<b>Gravedad:</b> {report.severity_level}\n"
        f"<b>Hora de Detección:</b> {report.detection_time.strftime('%Y-%m-%d %H:%M')}\n"
        f"<b>Causa Probable:</b> {report.probable_cause}\n"
        f"<b>Área Afectada:</b> {report.affected_area if report.affected_area else 'No especificado'} Ha/m²\n"
        f"<b>Ubicación:</b> Lat {report.latitude:.4f}, Lon {report.longitude:.4f}\n"
        f"<b>Vegetación:</b> {report.vegetation_type if report.vegetation_type else 'No especificada'}\n"
        f"<b>Clima:</b> {report.weather_conditions if report.weather_conditions else 'No especificado'}\n"
        f"<b>Descripción:</b> {report.description if report.description else 'Sin descripción adicional.'}\n\n"
        f"📍 <a href='{report.google_maps_link}'>Ver en Google Maps</a>"
    )

    whatsapp_success = False
    telegram_success = False
    error_log = []

    # 1. Send Telegram Notification (Broadcast to channel only)
    try:
        telegram_success = asyncio.run(send_telegram_message(alert_message))
    except Exception as e:
        error_log.append(f"Telegram error: {str(e)}")

    # 2. Send WhatsApp Notifications (to Bombero unit leaders only)
    try:
        # Get Bombero Unit Leaders (Jefe de Brigada / Comandante de Incidente)
        leader_contacts = db.query(Bombero).filter(Bombero.whatsapp_number != None, Bombero.is_leader == True).all()

        whatsapp_attempts = 0
        whatsapp_sends = 0

        # Send to Bombero unit leaders (technical name Comandante de Incidente / Jefe de Brigada)
        for leader in leader_contacts:
            if not leader.whatsapp_number or not leader.whatsapp_number.strip():
                continue
            whatsapp_attempts += 1
            clean_message = (
                f"🚨 ALERTA DE INCENDIO - WACHAY 🚨\n\n"
                f"Destinatario: {leader.name} {leader.last_name} (Líder / Comandante de Incidente)\n"
                f"Unidad: {leader.fire_unit}\n"
                f"Origen: {'Guardaparques' if report.source == 'ranger' else 'Ciudadano'}\n"
                f"Reportante: {report.ranger_name if report.ranger_name else report.citizen_name}\n"
                f"Tipo: {report.incident_type}\n"
                f"Gravedad: {report.severity_level}\n"
                f"Clima: {report.weather_conditions if report.weather_conditions else 'No especificado'}\n"
                f"Descripción: {report.description if report.description else 'Sin descripción adicional.'}\n"
                f"Ubicación: Lat {report.latitude:.4f}, Lon {report.longitude:.4f}\n"
                f"Mapa: {report.google_maps_link}"
            )
            if send_whatsapp_message(leader.whatsapp_number.strip(), clean_message):
                whatsapp_sends += 1
        
        if whatsapp_attempts > 0 and whatsapp_sends > 0:
            whatsapp_success = True
        elif whatsapp_attempts > 0:
            error_log.append("WhatsApp failed for all configured contacts.")
    except Exception as e:
        error_log.append(f"WhatsApp error: {str(e)}")

    # 3. Update Audit Fields in Database
    report.telegram_sent = telegram_success
    report.whatsapp_sent = whatsapp_success
    
    if telegram_success and whatsapp_success:
        report.notification_status = "Sent"
    elif telegram_success or whatsapp_success:
        report.notification_status = "Partially Sent"
    else:
        report.notification_status = "Failed"

    if error_log:
        report.notification_error = "; ".join(error_log)
    else:
        report.notification_error = None

    db.commit()
    print(f"Audit completed for report {report_id}: Status {report.notification_status}")


# --- Helper for Filtering ---
def apply_report_filters(query, start_date, end_date, ranger_name, incident_type, severity_level, status, notification_status=None):
    if start_date:
        query = query.filter(Report.detection_time >= start_date)
    if end_date:
        query = query.filter(Report.detection_time <= end_date)
    if ranger_name:
        query = query.filter(
            (Report.ranger_name.ilike(f"%{ranger_name}%")) | 
            (Report.citizen_name.ilike(f"%{ranger_name}%"))
        )
    if incident_type:
        query = query.filter(Report.incident_type == incident_type)
    if severity_level:
        query = query.filter(Report.severity_level == severity_level)
    if status:
        query = query.filter(Report.status == status)
    if notification_status:
        query = query.filter(Report.notification_status == notification_status)
    return query


# --- ENDPOINTS ---

@router.get("/public_summary")
def get_public_summary(db: Session = Depends(get_db)):
    """
    Public statistics and sanitized foci list for unauthenticated landing and live map pages.
    Accessible publicly by any citizen.
    """
    # 1. Aggregations (excluding Rejected/Discarded)
    base_query = db.query(Report).filter(Report.status.notin_(["Rejected", "Discarded"]))
    
    total = base_query.count()
    active = base_query.filter(Report.status == "Second_State").count()
    controlled = base_query.filter(Report.status == "First_State").count()
    attended = base_query.filter(Report.status == "Attended").count()
    
    # 2. Sanitized public foci list (exclude private/personal info)
    reports = (
        base_query.order_by(Report.detection_time.desc())
        .limit(100)
        .all()
    )
    
    public_reports = []
    for r in reports:
        public_reports.append({
            "id": r.id,
            "tracking_code": r.tracking_code,
            "incident_type": r.incident_type,
            "severity": r.severity_level,
            "severity_level": r.severity_level,
            "status": r.status,
            "latitude": r.latitude,
            "longitude": r.longitude,
            "detection_time": r.detection_time.isoformat() if r.detection_time else None,
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "date_reported": r.detection_time.strftime("%Y-%m-%d") if r.detection_time else None,
            "affected_area": r.affected_area,
            "vegetation_type": r.vegetation_type,
        })
        
    return {
        "stats": {
            "total": total,
            "active": active,
            "controlled": controlled,
            "closed": attended
        },
        "reports": public_reports
    }


@router.get("/", response_model=List[ReportOut])
def get_reports(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    ranger_name: Optional[str] = None,
    incident_type: Optional[str] = None,
    severity_level: Optional[str] = None,
    status: Optional[str] = None
):
    """
    Returns filtered list of all reports. Accessible by logged-in users.
    """
    query = db.query(Report)
    query = apply_report_filters(query, start_date, end_date, ranger_name, incident_type, severity_level, status)
    return query.order_by(Report.detection_time.desc()).all()


@router.post("/", response_model=ReportOut, status_code=status.HTTP_201_CREATED)
def create_report(
    payload: ReportCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_ranger)
):
    """
    Creates a new manual report. Centered on First_State.
    Fetches real-time weather telemetery automatically if coordinates are provided.
    Triggers Telegram and WhatsApp notifications in background.
    """
    # Fetch weather automatically if missing
    weather_desc = payload.weather_conditions
    if payload.latitude and payload.longitude and not weather_desc:
        weather_info = get_weather_data(payload.latitude, payload.longitude)
        weather_desc = weather_info["raw_text"]

    # Autogenerate google maps link from coordinates if missing
    g_maps_link = payload.google_maps_link
    if payload.latitude and payload.longitude and not g_maps_link:
        g_maps_link = f"https://www.google.com/maps?q={payload.latitude},{payload.longitude}"

    # Calculate Geohash
    gh = None
    if payload.latitude and payload.longitude:
        gh = encode_geohash(payload.latitude, payload.longitude)

    initial_status = payload.status if payload.status in ["First_State", "Second_State", "Attended"] else "First_State"

    new_report = Report(
        status=initial_status,
        source="ranger",
        ranger_name=payload.ranger_name,
        incident_type=payload.incident_type,
        severity_level=payload.severity_level,
        detection_time=payload.detection_time,
        arrival_time=payload.arrival_time,
        probable_cause=payload.probable_cause,
        latitude=payload.latitude,
        longitude=payload.longitude,
        google_maps_link=g_maps_link,
        weather_conditions=weather_desc,
        vegetation_type=payload.vegetation_type,
        description=payload.description,
        geohash=gh,
        notification_status="Pending"
    )

    db.add(new_report)
    db.commit()
    db.refresh(new_report)

    # Queue alert messages in the background to prevent request hanging
    background_tasks.add_task(send_report_alerts_background, new_report.id, db)

    return new_report


@router.put("/{id}", response_model=ReportOut)
def update_report(
    id: int,
    payload: ReportUpdate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_ranger)
):
    """
    Updates report fields. Handles Transition from First_State to Second_State.
    """
    report = db.query(Report).filter(Report.id == id).first()
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Reporte con ID {id} no encontrado."
        )

    # Prevent editing final reports
    if report.status == "Attended" and current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Los reportes finalizados ('Atendido') son de solo lectura."
        )

    # Check for approval transition
    is_approving = False
    if report.status == "Citizen_Pending" and payload.status in ["First_State", "Approved", "Second_State"]:
        is_approving = True

    # Update fields dynamically
    update_data = payload.model_dump(exclude_unset=True)
    
    # If coordinates are modified, recalculate geohash and link
    if "latitude" in update_data or "longitude" in update_data:
        lat = update_data.get("latitude", report.latitude)
        lon = update_data.get("longitude", report.longitude)
        if lat and lon:
            update_data["geohash"] = encode_geohash(lat, lon)
            update_data["google_maps_link"] = f"https://www.google.com/maps?q={lat},{lon}"

    # Auto transition to Second_State if control fields are provided
    if "control_time" in update_data and update_data["control_time"] is not None:
        update_data["status"] = "Second_State"

    for key, value in update_data.items():
        setattr(report, key, value)

    db.commit()
    db.refresh(report)

    # If it was a citizen report being approved, trigger notifications now
    if is_approving:
        background_tasks.add_task(send_report_alerts_background, report.id, db)

    return report


@router.patch("/{id}/status", response_model=ReportOut)
def patch_report_status(
    id: int,
    payload: ReportUpdate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_ranger)
):
    """
    Partially updates report status.
    """
    return update_report(id=id, payload=payload, background_tasks=background_tasks, db=db, current_user=current_user)


@router.delete("/{id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_report(
    id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_admin)
):
    """
    Removes a report completely. Admin only.
    """
    report = db.query(Report).filter(Report.id == id).first()
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Reporte con ID {id} no encontrado."
        )
    db.delete(report)
    db.commit()
    return None


@router.post("/{id}/finalize", response_model=ReportOut)
def finalize_report(
    id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_ranger)
):
    """
    Closes a report, marking it as Attended. Ready for KPIs.
    """
    report = db.query(Report).filter(Report.id == id).first()
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Reporte con ID {id} no encontrado."
        )

    # Set status
    report.status = "Attended"
    db.commit()
    db.refresh(report)
    return report


@router.post("/{id}/retry-notification", response_model=ReportOut)
def retry_notification(
    id: int,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_ranger)
):
    """
    Manually retries sending WhatsApp and Telegram alerts for a failed notification audit.
    """
    report = db.query(Report).filter(Report.id == id).first()
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Reporte con ID {id} no encontrado."
        )

    report.notification_status = "Pending"
    db.commit()

    background_tasks.add_task(send_report_alerts_background, report.id, db)
    return report


@router.get("/kpis")
def get_kpi_dashboard_data(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    ranger_name: Optional[str] = None,
    incident_type: Optional[str] = None,
    severity_level: Optional[str] = None,
    status: Optional[str] = None
):
    """
    Calculates aggregated KPI statistics for the charts and metrics.
    """
    query = db.query(Report)
    query = apply_report_filters(query, start_date, end_date, ranger_name, incident_type, severity_level, status)
    reports = query.all()

    total_incidents = len(reports)
    
    # Calculate response times (Arrival - Detection) in minutes
    response_times = []
    control_times = []
    total_affected_area = 0.0
    false_alarms = 0
    
    cause_dist = {}
    veg_dist = {}
    severity_dist = {}
    monthly_trend = {}
    locations = []

    for r in reports:
        total_affected_area += (r.affected_area or 0.0)
        if r.incident_type == "Falso Alarma":
            false_alarms += 1

        # Response time
        if r.arrival_time and r.detection_time:
            delta = (r.arrival_time - r.detection_time).total_seconds() / 60.0
            response_times.append(delta)

        # Control time
        if r.control_time and r.arrival_time:
            delta = (r.control_time - r.arrival_time).total_seconds() / 60.0
            control_times.append(delta)

        # Categorical distributions
        cause_dist[r.probable_cause] = cause_dist.get(r.probable_cause, 0) + 1
        veg_dist[r.vegetation_type or "No especificado"] = veg_dist.get(r.vegetation_type or "No especificado", 0) + 1
        severity_dist[r.severity_level] = severity_dist.get(r.severity_level, 0) + 1

        # Monthly trends
        month_key = r.detection_time.strftime("%Y-%m")
        monthly_trend[month_key] = monthly_trend.get(month_key, 0) + 1

        # Map points
        if r.latitude and r.longitude:
            locations.append({
                "id": r.id,
                "latitude": r.latitude,
                "longitude": r.longitude,
                "incident_type": r.incident_type,
                "severity_level": r.severity_level,
                "status": r.status
            })

    avg_response = round(sum(response_times) / len(response_times), 2) if response_times else 0.0
    avg_control = round(sum(control_times) / len(control_times), 2) if control_times else 0.0
    false_alarm_rate = round((false_alarms / total_incidents) * 100, 2) if total_incidents > 0 else 0.0

    return {
        "executive_summary": {
            "total_incidents": total_incidents,
            "avg_response_time_minutes": avg_response,
            "avg_control_time_minutes": avg_control,
            "total_affected_area_km2": round(total_affected_area, 2),
            "false_alarm_rate_percent": false_alarm_rate
        },
        "distributions": {
            "cause": cause_dist,
            "vegetation": veg_dist,
            "severity": severity_dist,
            "monthly_trend": dict(sorted(monthly_trend.items()))
        },
        "locations": locations
    }


# --- EXPORT SERVICES ---

@router.get("/export/excel")
def export_kpi_excel(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_admin),
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    ranger_name: Optional[str] = None,
    incident_type: Optional[str] = None,
    severity_level: Optional[str] = None,
    status: Optional[str] = None,
    notification_status: Optional[str] = None
):
    """
    Exports filtered reports as an Excel download using openpyxl.
    """
    query = db.query(Report)
    query = apply_report_filters(query, start_date, end_date, ranger_name, incident_type, severity_level, status, notification_status)
    reports = query.order_by(Report.detection_time.desc()).all()

    # Format filters description
    filters_desc = f"Rango: {start_date or 'Inicio'} a {end_date or 'Fin'} | Tipo: {incident_type or 'Todos'} | Gravedad: {severity_level or 'Todas'} | Estado: {status or 'Todos'} | Reportante: {ranger_name or 'Todos'} | Notificaciones: {notification_status or 'Todas'}"

    # Build DataFrame
    data_list = []
    for r in reports:
        data_list.append({
            "ID": r.id,
            "Estado": r.status,
            "Origen": r.source,
            "Código de Seguimiento": r.tracking_code or "N/A",
            "Guardaparques": r.ranger_name or "N/A",
            "Ciudadano": r.citizen_name or "N/A",
            "Correo Ciudadano": r.citizen_email or "N/A",
            "Tipo de Incidente": r.incident_type,
            "Nivel de Gravedad": r.severity_level,
            "Fecha Detección": r.detection_time.strftime("%Y-%m-%d %H:%M") if r.detection_time else "",
            "Fecha Llegada": r.arrival_time.strftime("%Y-%m-%d %H:%M") if r.arrival_time else "N/A",
            "Fecha Control": r.control_time.strftime("%Y-%m-%d %H:%M") if r.control_time else "N/A",
            "Causa Probable": r.probable_cause,
            "Área Afectada (Ha)": r.affected_area or 0.0,
            "Costo Estimado ($)": r.estimated_cost or 0.0,
            "Latitud": r.latitude,
            "Longitud": r.longitude,
            "Tipo de Vegetación": r.vegetation_type or "N/A",
            "Notificaciones": r.notification_status
        })

    df = pd.DataFrame(data_list)
    
    # Save to buffer
    buffer = io.BytesIO()
    import openpyxl
    from openpyxl.styles import Font
    
    with pd.ExcelWriter(buffer, engine="openpyxl") as writer:
        # Create sheet
        workbook = writer.book
        worksheet = workbook.create_sheet(title="Reportes WACHAY")
        writer.sheets["Reportes WACHAY"] = worksheet
        
        # Write Title and Filters
        worksheet["A1"] = "WACHAY - REPORTE OPERATIVO DE INCENDIOS"
        worksheet["A1"].font = Font(bold=True, size=13, color="2E7D32")
        worksheet["A2"] = f"Generado el: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Filtros: {filters_desc}"
        worksheet["A2"].font = Font(italic=True, size=9, color="555555")
        
        # Write DataFrame starting at row 4
        df.to_excel(writer, sheet_name="Reportes WACHAY", startrow=3, index=False)
        
    buffer.seek(0)

    filename = f"Reporte_WACHAY_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
    return StreamingResponse(
        buffer,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@router.get("/export/pdf")
def export_kpi_pdf(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_admin),
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    ranger_name: Optional[str] = None,
    incident_type: Optional[str] = None,
    severity_level: Optional[str] = None,
    status: Optional[str] = None,
    notification_status: Optional[str] = None
):
    """
    Generates a clean PDF summary containing a filtered list of reports using ReportLab.
    """
    query = db.query(Report)
    query = apply_report_filters(query, start_date, end_date, ranger_name, incident_type, severity_level, status, notification_status)
    reports = query.order_by(Report.detection_time.desc()).all()

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
    story = []

    # Styles
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "PDFTitle",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=20,
        textColor=colors.HexColor("#2E7D32"),
        spaceAfter=15
    )
    subtitle_style = ParagraphStyle(
        "PDFSubtitle",
        parent=styles["Normal"],
        fontSize=10,
        textColor=colors.HexColor("#757575"),
        spaceAfter=20
    )
    cell_style = ParagraphStyle(
        "CellText",
        parent=styles["Normal"],
        fontSize=8,
        leading=10
    )
    header_style = ParagraphStyle(
        "HeaderCellText",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=9,
        leading=11,
        textColor=colors.white
    )

    # Document Header
    story.append(Paragraph("WACHAY - Reporte Operativo de Incendios", title_style))
    filter_desc = f"Filtros aplicados - Rango: {start_date or 'Inicio'} a {end_date or 'Fin'} | Tipo: {incident_type or 'Todos'} | Gravedad: {severity_level or 'Todas'} | Estado: {status or 'Todos'} | Reportante: {ranger_name or 'Todos'} | Notificaciones: {notification_status or 'Todas'}"
    story.append(Paragraph(f"Generado el: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | {filter_desc}", subtitle_style))
    story.append(Spacer(1, 10))

    # Build Table
    table_data = [[
        Paragraph("ID", header_style),
        Paragraph("Fecha", header_style),
        Paragraph("Tipo de Incidente", header_style),
        Paragraph("Severidad", header_style),
        Paragraph("Estado", header_style),
        Paragraph("Área (Ha)", header_style),
        Paragraph("Lat/Lon", header_style)
    ]]

    for r in reports:
        date_str = r.detection_time.strftime("%Y-%m-%d")
        area_str = f"{r.affected_area:.2f}" if r.affected_area else "0.0"
        coords_str = f"{r.latitude:.3f}, {r.longitude:.3f}" if r.latitude else "N/A"
        
        table_data.append([
            Paragraph(str(r.id), cell_style),
            Paragraph(date_str, cell_style),
            Paragraph(r.incident_type, cell_style),
            Paragraph(r.severity_level, cell_style),
            Paragraph(r.status, cell_style),
            Paragraph(area_str, cell_style),
            Paragraph(coords_str, cell_style)
        ])

    # Table layout adjustments (Widths)
    col_widths = [30, 60, 150, 60, 80, 50, 110]
    report_table = Table(table_data, colWidths=col_widths)
    
    # Table Styling (Forest Green Theme)
    t_style = TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2E7D32")),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
        ("TOPPADDING", (0, 0), (-1, 0), 8),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E0E0E0")),
    ])
    
    # Add row stripe colors
    for i in range(1, len(table_data)):
        bg_color = colors.HexColor("#F5F5F5") if i % 2 == 0 else colors.white
        t_style.add("BACKGROUND", (0, i), (-1, i), bg_color)
        t_style.add("TOPPADDING", (0, i), (-1, i), 6)
        t_style.add("BOTTOMPADDING", (0, i), (-1, i), 6)

    report_table.setStyle(t_style)
    story.append(report_table)

    # Build PDF
    doc.build(story)
    buffer.seek(0)
    
    filename = f"Reporte_WACHAY_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    return StreamingResponse(
        buffer,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

@router.post("/backup")
def run_database_backup(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_admin)
):
    """
    Triggers a consistent hot backup of the SQLite database. Admin only.
    """
    import os
    from app.backup import perform_hot_backup
    try:
        backup_path = perform_hot_backup()
        filename = os.path.basename(backup_path)
        return {
            "status": "success",
            "message": f"Backup creado exitosamente: {filename}",
            "filename": filename
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al generar el backup: {str(e)}"
        )


@router.get("/backups")
def list_database_backups(
    current_user: User = Depends(get_current_active_admin)
):
    """
    Lists existing database backup files with size and creation timestamp.
    """
    import os
    from app.core.config import settings
    backup_dir = os.path.join(settings.BASE_DIR, "backend", "instance", "backups")
    os.makedirs(backup_dir, exist_ok=True)

    backups = []
    for f in os.listdir(backup_dir):
        if f.endswith(".db"):
            fpath = os.path.join(backup_dir, f)
            stat = os.stat(fpath)
            backups.append({
                "filename": f,
                "size_bytes": stat.st_size,
                "size_kb": round(stat.st_size / 1024, 2),
                "created_at": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
            })

    # Sort newest first
    backups.sort(key=lambda x: x["created_at"], reverse=True)
    return backups


@router.get("/backups/download/{filename}")
def download_database_backup(
    filename: str,
    current_user: User = Depends(get_current_active_admin)
):
    """
    Downloads a specific backup .db file. Admin only.
    """
    import os
    from fastapi.responses import FileResponse
    from app.core.config import settings

    backup_dir = os.path.join(settings.BASE_DIR, "backend", "instance", "backups")
    file_path = os.path.join(backup_dir, filename)

    if not os.path.exists(file_path) or not filename.endswith(".db"):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Archivo de respaldo no encontrado."
        )

    return FileResponse(
        path=file_path,
        media_type="application/x-sqlite3",
        filename=filename
    )
