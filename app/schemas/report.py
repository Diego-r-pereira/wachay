from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime

class ReportBase(BaseModel):
    incident_type: str = Field(..., max_length=50)
    severity_level: str = Field(..., max_length=20)
    detection_time: datetime
    arrival_time: Optional[datetime] = None
    probable_cause: str = Field(..., max_length=50)
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    google_maps_link: Optional[str] = Field(None, max_length=200)
    weather_conditions: Optional[str] = None
    vegetation_type: Optional[str] = Field(None, max_length=50)
    description: Optional[str] = None

class ReportCreate(ReportBase):
    ranger_name: str = Field(..., max_length=100)
    status: Optional[str] = Field("First_State", max_length=30)

class ReportUpdate(BaseModel):
    ranger_name: Optional[str] = Field(None, max_length=100)
    incident_type: Optional[str] = Field(None, max_length=50)
    severity_level: Optional[str] = Field(None, max_length=20)
    detection_time: Optional[datetime] = None
    arrival_time: Optional[datetime] = None
    probable_cause: Optional[str] = Field(None, max_length=50)
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    google_maps_link: Optional[str] = Field(None, max_length=200)
    weather_conditions: Optional[str] = None
    vegetation_type: Optional[str] = Field(None, max_length=50)
    description: Optional[str] = None
    status: Optional[str] = Field(None, max_length=30)
    
    # Second State fields
    control_time: Optional[datetime] = None
    affected_area: Optional[float] = None
    deployed_resources: Optional[str] = None
    materials_used: Optional[str] = None
    estimated_cost: Optional[float] = None

class CitizenReportCreate(BaseModel):
    citizen_name: str = Field(..., max_length=100)
    citizen_email: Optional[str] = Field(None, max_length=100)
    photo: Optional[str] = None  # Base64 encoded image
    incident_type: str = Field(..., max_length=50)
    severity_level: str = Field(..., max_length=20)
    affected_area: Optional[float] = None
    probable_cause: str = Field(..., max_length=50)
    vegetation_type: Optional[str] = Field(None, max_length=50)
    description: Optional[str] = None
    latitude: float
    longitude: float
    detection_time: datetime
    weather_conditions: Optional[str] = None

class CitizenReportOut(BaseModel):
    status: str
    report_id: int
    tracking_code: str
    message: str

class ReportStatusResponse(BaseModel):
    status: str
    message: str

class ReportOut(ReportBase):
    id: int
    status: str
    source: str
    tracking_code: Optional[str] = None
    rejection_reason: Optional[str] = None
    
    # Citizen details
    citizen_name: Optional[str] = None
    citizen_email: Optional[str] = None
    photo_path: Optional[str] = None
    
    # First State
    ranger_name: Optional[str] = None
    geohash: Optional[str] = None

    # Second State
    control_time: Optional[datetime] = None
    affected_area: Optional[float] = None
    deployed_resources: Optional[str] = None
    materials_used: Optional[str] = None
    estimated_cost: Optional[float] = None

    # Notifications status
    notification_status: Optional[str] = None
    whatsapp_sent: Optional[bool] = None
    telegram_sent: Optional[bool] = None
    notification_error: Optional[str] = None

    # Audit fields
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True
