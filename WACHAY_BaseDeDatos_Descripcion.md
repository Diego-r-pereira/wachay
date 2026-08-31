# 🗄️ WACHAY — Documentación de Base de Datos (V2.0)
**Proyecto:** Wildfire Alert & Cochabamba Heat Analysis System  
**Versión:** 2.0 (FastAPI Upgrade)  
**Motor:** SQLite (desarrollo) / SQLAlchemy Declarative ORM  

---

## 1. Modelo Entidad-Relación (Descripción)

El sistema WACHAY utiliza **dos entidades principales**: `User` y `Report`. La relación entre ellas es opcional e indirecta: un reporte técnico hace referencia al nombre del guardaparques que lo atiende, mientras que los reportes de origen ciudadano no requieren estar vinculados a un usuario registrado.

```
+----------+          +----------+
|   User   |          |  Report  |
+----------+          +----------+
| id (PK)  |          | id (PK)  |
| username |          | ranger_name --------> (referencia textual a User.name)
| password |          | status   |
| role     |          | source   |
| ...      |          | ...      |
+----------+          +----------+
```

**Lógica de Negocio:**
*   Un `User` con el rol de `ranger` (guardaparques) crea reportes a través de la aplicación web (origen `source = ranger`).
*   Las denuncias ciudadanas provienen de la app móvil (origen `source = citizen`). Estas no se vinculan a un `user_id` de la tabla `User`; en su lugar, se registran los campos `citizen_name` y `citizen_email`.
*   La vinculación del reporte a la patrulla de guardaparques es textual (`ranger_name`) para facilitar la flexibilidad e histórico, reduciendo dependencias directas en la base de datos local SQLite.

---

## 2. Tablas y Estructura de Columnas

### 2.1 Tabla: `User`
Almacena al personal autorizado del SERNAP (Administradores y Guardaparques).

| Campo | Tipo | Nulo | Descripción |
|-------|------|------|-------------|
| `id` | INTEGER | NO | Identificador único autoincremental (Clave Primaria). |
| `username` | VARCHAR(80) | NO | Nombre de usuario único para autenticación en la web. |
| `password_hash` | VARCHAR(128) | NO | Hash de contraseña seguro usando passlib (Bcrypt). |
| `name` | VARCHAR(100) | NO | Nombre real del guardaparques o administrador. |
| `last_name` | VARCHAR(100) | NO | Apellido real. |
| `telegram_id` | VARCHAR(100) | SÍ | ID único de Telegram del usuario para notificaciones personalizadas. |
| `whatsapp_number` | VARCHAR(100) | SÍ | Teléfono único de WhatsApp para alertas automáticas. |
| `role` | VARCHAR(20) | NO | Rol del usuario: `admin` o `ranger`. |
| `preferred_language` | VARCHAR(10) | SÍ | Idioma preferido: `en` (Inglés), `es` (Español), `qu` (Quechua). |

---

### 2.2 Tabla: `Report`
Almacena todos los incidentes y focos de calor detectados.

#### A. Identificación, Origen y Estado
| Campo | Tipo | Nulo | Descripción |
|-------|------|------|-------------|
| `id` | INTEGER | NO | Identificador único autoincremental (Clave Primaria). |
| `status` | VARCHAR(30) | NO | Estado del reporte: `Citizen_Pending`, `First_State`, `Second_State`, `Attended`, `Rejected`. |
| `source` | VARCHAR(20) | NO | Origen de la alerta: `ranger` (web) o `citizen` (móvil). |
| `tracking_code` | VARCHAR(50) | SÍ | Código alfanumérico único para que el ciudadano consulte su estado. |
| `rejection_reason` | TEXT | SÍ | Razón del rechazo si el reporte ciudadano es descartado. |

#### B. Datos del Ciudadano (Solo si `source = citizen`)
| Campo | Tipo | Nulo | Descripción |
|-------|------|------|-------------|
| `citizen_name` | VARCHAR(100) | SÍ | Nombre del ciudadano reportante. |
| `citizen_email` | VARCHAR(100) | SÍ | Correo electrónico de contacto. |
| `photo_path` | VARCHAR(200) | SÍ | Ruta física en el servidor donde se aloja la foto enviada. |

#### C. Primer Estado - Detección (Datos obligatorios al reportar)
| Campo | Tipo | Nulo | Descripción |
|-------|------|------|-------------|
| `ranger_name` | VARCHAR(100) | SÍ | Nombre del guardaparques que crea u oficializa el reporte. |
| `incident_type` | VARCHAR(50) | NO | Tipo: `Incendio Forestal`, `Quema Agrícola`, `Fogata No Controlada`, etc. |
| `severity_level` | VARCHAR(20) | NO | Severidad del fuego: `Bajo`, `Medio`, `Alto`, `Crítico`. |
| `detection_time` | DATETIME | NO | Fecha y hora en la que se avistó el fuego. |
| `arrival_time` | DATETIME | SÍ | Fecha y hora en la que la patrulla llegó a la zona cero. |
| `probable_cause` | VARCHAR(50) | NO | Causa probable: `Chaqueo Agrícola`, `Colilla de Cigarrillo`, `Intencional`, etc. |
| `latitude` | FLOAT | SÍ | Coordenada latitud. |
| `longitude` | FLOAT | SÍ | Coordenada longitud. |
| `google_maps_link` | VARCHAR(200) | SÍ | Enlace directo generado automáticamente. |
| `weather_conditions` | TEXT | SÍ | Datos del clima (Temperatura, viento, humedad). |
| `vegetation_type` | VARCHAR(50) | SÍ | Vegetación predominante: `Bosque Seco`, `Matorrales`, `Pastizales`, etc. |
| `description` | TEXT | SÍ | Descripción escrita con detalles. |
| `geohash` | VARCHAR(20) | SÍ | Código Geohash para búsquedas espaciales y agrupaciones. |

#### D. Segundo Estado - Control de Focos
| Campo | Tipo | Nulo | Descripción |
|-------|------|------|-------------|
| `control_time` | DATETIME | SÍ | Fecha y hora de sofocación completa. |
| `affected_area` | FLOAT | SÍ | Superficie afectada (en Hectáreas). |
| `deployed_resources` | TEXT | SÍ | Lista de personal y carros de bomberos movilizados. |
| `materials_used` | TEXT | SÍ | Cantidad de batefuegos, agua o mochilas extintoras usadas. |
| `estimated_cost` | FLOAT | SÍ | Costo monetario estimado en la sofocación (Bs / USD). |

#### E. Estado de Notificaciones y Auditoría
| Campo | Tipo | Nulo | Descripción |
|-------|------|------|-------------|
| `notification_status` | VARCHAR(30) | SÍ | Estado del canal de alertas: `Pending`, `Sent`, `Failed`. |
| `whatsapp_sent` | BOOLEAN | SÍ | Flag de confirmación para alerta WhatsApp (Twilio). |
| `telegram_sent` | BOOLEAN | SÍ | Flag de confirmación para alerta en canal Telegram. |
| `notification_error` | TEXT | SÍ | Bitácora de error si el SMS o Telegram fallaron. |
| `created_at` | DATETIME | NO | Marca de tiempo automática de creación del registro. |
| `updated_at` | DATETIME | SÍ | Marca de tiempo de última actualización. |
