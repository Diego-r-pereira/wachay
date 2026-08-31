# 🗄️ WACHAY — Scripts SQL y Modelos SQLAlchemy (V2.0)
**Proyecto:** Wildfire Alert & Cochabamba Heat Analysis System  
**Versión:** 2.0 (FastAPI Upgrade)  
**Motor:** SQLite (desarrollo) | Compatible con PostgreSQL en la nube  

---

## 1. Script de Creación SQL (DDL)

```sql
-- =============================================================================
-- WACHAY - Creación de Base de Datos
-- Motor: SQLite (desarrollo) | SQL Standard
-- =============================================================================

-- Habilitar soporte de claves foráneas y WAL en SQLite
PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;

-- =============================================================================
-- TABLA: user
-- Almacena administradores y guardaparques del sistema.
-- =============================================================================
CREATE TABLE IF NOT EXISTS "user" (
    id                  INTEGER     NOT NULL PRIMARY KEY AUTOINCREMENT,
    username            VARCHAR(80) NOT NULL UNIQUE,
    password_hash       VARCHAR(128) NOT NULL,
    name                VARCHAR(100) NOT NULL,
    last_name           VARCHAR(100) NOT NULL,
    telegram_id         VARCHAR(100) UNIQUE,
    whatsapp_number     VARCHAR(100) UNIQUE,
    role                VARCHAR(20)  NOT NULL DEFAULT 'ranger'
                            CHECK (role IN ('admin', 'ranger')),
    preferred_language  VARCHAR(10)  NOT NULL DEFAULT 'es'
                            CHECK (preferred_language IN ('en', 'es', 'qu'))
);

-- =============================================================================
-- TABLA: report
-- Almacena reportes de origen guardaparques (web) o ciudadano (móvil).
-- =============================================================================
CREATE TABLE IF NOT EXISTS report (
    id                  INTEGER      NOT NULL PRIMARY KEY AUTOINCREMENT,
    status              VARCHAR(30)  NOT NULL DEFAULT 'First_State'
                            CHECK (status IN (
                                'Citizen_Pending',
                                'Approved',
                                'Rejected',
                                'Discarded',
                                'First_State',
                                'Second_State',
                                'Attended'
                            )),
    source              VARCHAR(20)  NOT NULL DEFAULT 'ranger'
                            CHECK (source IN ('ranger', 'citizen')),
    tracking_code       VARCHAR(50)  UNIQUE,
    rejection_reason    TEXT,

    -- Datos ciudadanos (móvil)
    citizen_name        VARCHAR(100),
    citizen_email       VARCHAR(100),
    photo_path          VARCHAR(200),

    -- Primer Estado: datos de detección (obligatorios)
    ranger_name         VARCHAR(100),
    incident_type       VARCHAR(50) NOT NULL,
    severity_level      VARCHAR(20) NOT NULL,
    detection_time      DATETIME    NOT NULL,
    arrival_time        DATETIME,
    probable_cause      VARCHAR(50) NOT NULL,
    latitude            FLOAT,
    longitude           FLOAT,
    google_maps_link    VARCHAR(200),
    weather_conditions  TEXT,
    vegetation_type     VARCHAR(50),
    description         TEXT,
    geohash             VARCHAR(20),

    -- Segundo Estado: datos de control (opcionales al inicio)
    control_time        DATETIME,
    affected_area       FLOAT,
    deployed_resources  TEXT,
    materials_used      TEXT,
    estimated_cost      FLOAT,

    -- Notificaciones
    notification_status VARCHAR(30)  DEFAULT 'Pending',
    whatsapp_sent       BOOLEAN      DEFAULT 0,
    telegram_sent       BOOLEAN      DEFAULT 0,
    notification_error  TEXT,

    -- Auditoría
    created_at          DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME
);

-- ÍNDICES RECOMENDADOS
CREATE INDEX IF NOT EXISTS idx_report_status ON report (status);
CREATE INDEX IF NOT EXISTS idx_report_tracking_code ON report (tracking_code);
CREATE INDEX IF NOT EXISTS idx_report_geohash ON report (geohash);
```

---

## 2. Equivalente en Modelos de SQLAlchemy (FastAPI)

### A. Modelo de Usuario (`app/models/user.py`)
```python
from sqlalchemy import Column, Integer, String
from app.core.database import Base
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class User(Base):
    __tablename__ = "user"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(80), unique=True, index=True, nullable=False)
    password_hash = Column(String(128), nullable=False)
    name = Column(String(100), nullable=False)
    last_name = Column(String(100), nullable=False)
    telegram_id = Column(String(100), unique=True, nullable=True)
    whatsapp_number = Column(String(100), unique=True, nullable=True)
    role = Column(String(20), nullable=False)  # 'admin' o 'ranger'
    preferred_language = Column(String(10), default="es", nullable=True)

    def set_password(self, password: str):
        self.password_hash = pwd_context.hash(password)

    def check_password(self, password: str) -> bool:
        return pwd_context.verify(password, self.password_hash)
```

### B. Modelo de Reporte (`app/models/report.py`)
```python
from sqlalchemy import Column, Integer, String, Float, DateTime, Boolean, Text, func
from app.core.database import Base

class Report(Base):
    __tablename__ = "report"

    id = Column(Integer, primary_key=True, index=True)
    status = Column(String(30), default="First_State", nullable=False)
    source = Column(String(20), default="ranger", nullable=False)
    tracking_code = Column(String(50), unique=True, index=True, nullable=True)
    rejection_reason = Column(Text, nullable=True)

    # Datos ciudadanos
    citizen_name = Column(String(100), nullable=True)
    citizen_email = Column(String(100), nullable=True)
    photo_path = Column(String(200), nullable=True)

    # Primer Estado
    ranger_name = Column(String(100), nullable=True)
    incident_type = Column(String(50), nullable=False)
    severity_level = Column(String(20), nullable=False)
    detection_time = Column(DateTime, nullable=False)
    arrival_time = Column(DateTime, nullable=True)
    probable_cause = Column(String(50), nullable=False)
    latitude = Column(Float, nullable=True)
    longitude = Column(Float, nullable=True)
    google_maps_link = Column(String(200), nullable=True)
    weather_conditions = Column(Text, nullable=True)
    vegetation_type = Column(String(50), nullable=True)
    description = Column(Text, nullable=True)
    geohash = Column(String(20), nullable=True, index=True)

    # Segundo Estado
    control_time = Column(DateTime, nullable=True)
    affected_area = Column(Float, nullable=True)
    deployed_resources = Column(Text, nullable=True)
    materials_used = Column(Text, nullable=True)
    estimated_cost = Column(Float, nullable=True)

    # Notificaciones
    notification_status = Column(String(30), default="Pending", nullable=True)
    whatsapp_sent = Column(Boolean, default=False, nullable=True)
    telegram_sent = Column(Boolean, default=False, nullable=True)
    notification_error = Column(Text, nullable=True)

    # Auditoría
    created_at = Column(DateTime, server_default=func.now(), nullable=False)
    updated_at = Column(DateTime, onupdate=func.now(), nullable=True)
```
