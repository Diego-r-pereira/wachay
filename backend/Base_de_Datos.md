# =============================================================================
# WACHAY - DOCUMENTACIÓN DE BASE DE DATOS
# =============================================================================
# Proyecto: Sistema de Detección y Reporte de Incendios Forestales
# Versión: 2.0 (FastAPI Upgrade)
# Motor de Base de Datos: SQLite (Desarrollo) | PostgreSQL (Producción)
# ORM: SQLAlchemy (Declarative Base)
# Concurrencia: SQLite en modo WAL (Write-Ahead Logging) habilitado
# =============================================================================

# =============================================================================
# 1. DIAGRAMA ENTIDAD-RELACIÓN (DER)
# =============================================================================

┌─────────────────────────────────────────────────────────────────┐
│                          TABLA USER                              │
├─────────────────────────────────────────────────────────────────┤
│ PK  id              INTEGER (Auto-increment)                     │
│     username        VARCHAR(80) UNIQUE NOT NULL                  │
│     password_hash   VARCHAR(128) NOT NULL                        │
│     name            VARCHAR(100) NOT NULL                        │
│     last_name       VARCHAR(100) NOT NULL                        │
│     telegram_id     VARCHAR(100) UNIQUE NULL                     │
│     whatsapp_number VARCHAR(100) UNIQUE NULL                     │
│     role            VARCHAR(20) NOT NULL                         │
│     preferred_language VARCHAR(10) DEFAULT "es"                  │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                         TABLA REPORT                             │
├─────────────────────────────────────────────────────────────────┤
│ PK  id                  INTEGER (Auto-increment)                 │
│     ranger_name         VARCHAR(100) NULL                        │
│     incident_type       VARCHAR(50) NOT NULL                     │
│     severity_level      VARCHAR(20) NOT NULL                     │
│     detection_time      DATETIME NOT NULL                        │
│     arrival_time        DATETIME NULL                            │
│     control_time        DATETIME NULL                            │
│     affected_area       FLOAT NULL                               │
│     probable_cause      VARCHAR(50) NOT NULL                     │
│     deployed_resources  TEXT NULL                                │
│     materials_used      TEXT NULL                                │
│     estimated_cost      FLOAT NULL                               │
│     latitude            FLOAT NULL                               │
│     longitude           FLOAT NULL                               │
│     google_maps_link    VARCHAR(200) NULL                        │
│     weather_conditions  TEXT NULL                                │
│     vegetation_type     VARCHAR(50) NULL                         │
│     description         TEXT NULL                                │
│     geohash             VARCHAR(20) NULL                         │
│     status              VARCHAR(30) DEFAULT "First_State"        │
│     source              VARCHAR(20) DEFAULT "ranger"             │
│     notification_status VARCHAR(30) DEFAULT "Pending"            │
│     whatsapp_sent       BOOLEAN DEFAULT FALSE                    │
│     telegram_sent       BOOLEAN DEFAULT FALSE                    │
│     notification_error  TEXT NULL                                │
│     citizen_name        VARCHAR(100) NULL                        │
│     citizen_email       VARCHAR(100) NULL                        │
│     photo_path          VARCHAR(200) NULL                        │
│     tracking_code       VARCHAR(50) UNIQUE NULL                  │
│     rejection_reason    TEXT NULL                                │
│     created_at          DATETIME DEFAULT CURRENT_TIMESTAMP       │
│     updated_at          DATETIME NULL                            │
└─────────────────────────────────────────────────────────────────┘

# =============================================================================
# 2. DESCRIPCIÓN DETALLADA DE TABLAS
# =============================================================================

## 2.1 TABLA USER

### Propósito
Almacena la información de todos los usuarios del sistema, tanto 
administradores como guardaparques autorizados para acceder a los paneles web.

### Campos

┌──────────────────┬───────────────┬────────────────────────────────┐
│ Campo            │ Tipo          │ Descripción                    │
├──────────────────┼───────────────┼────────────────────────────────┤
│ id               │ INTEGER       │ Identificador único del usuario│
│                  │               │ (clave primaria, auto-increment)│
├──────────────────┼───────────────┼────────────────────────────────┤
│ username         │ VARCHAR(80)   │ Nombre de usuario único para   │
│                  │               │ autenticación                  │
├──────────────────┼───────────────┼────────────────────────────────┤
│ password_hash    │ VARCHAR(128)  │ Hash de la contraseña generado │
│                  │               │ con passlib (Bcrypt)           │
├──────────────────┼───────────────┼────────────────────────────────┤
│ name             │ VARCHAR(100)  │ Nombre real del usuario        │
├──────────────────┼───────────────┼────────────────────────────────┤
│ last_name        │ VARCHAR(100)  │ Apellido del usuario           │
├──────────────────┼───────────────┼────────────────────────────────┤
│ telegram_id      │ VARCHAR(100)  │ ID de usuario de Telegram para │
│                  │               │ notificaciones (opcional)      │
├──────────────────┼───────────────┼────────────────────────────────┤
│ whatsapp_number  │ VARCHAR(100)  │ Número de WhatsApp para        │
│                  │               │ notificaciones (opcional)      │
├──────────────────┼───────────────┼────────────────────────────────┤
│ role             │ VARCHAR(20)   │ Rol del usuario:               │
│                  │               │ - "admin": Administrador       │
│                  │               │ - "ranger": Guardaparques      │
├──────────────────┼───────────────┼────────────────────────────────┤
│ preferred_       │ VARCHAR(10)   │ Idioma preferido del usuario:  │
│ language         │               │ - "en": Inglés                 │
│                  │               │ - "es": Español (por defecto)  │
│                  │               │ - "qu": Quechua                │
└──────────────────┴───────────────┴────────────────────────────────┘

### Restricciones
- PK: id (clave primaria)
- UNIQUE: username
- UNIQUE: telegram_id (si no es NULL)
- UNIQUE: whatsapp_number (si no es NULL)
- NOT NULL: username, password_hash, name, last_name, role
- DEFAULT: preferred_language = "es"

### Índices creados automáticamente
- idx_user_username: sobre username
