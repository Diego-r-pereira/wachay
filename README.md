# WACHAY - Detección de Incendios Forestales

Este es un proyecto de aplicación web para la detección de incendios forestales, reportes manuales y notificaciones.

## Baby Steps para Ejecutar la Aplicación

Sigue estos pasos para poner en marcha la aplicación:

### 1. Clonar el Repositorio

```bash
git clone https://github.com/tu-usuario/wachay.git
cd wachay
```

### 2. Crear y Activar un Entorno Virtual

Es recomendable utilizar un entorno virtual para aislar las dependencias del proyecto.

**En Windows:**

```bash
python -m venv venv
.\venv\Scripts\activate
```

**En macOS y Linux:**

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Instalar las Dependencias

Instala todas las librerías necesarias para el proyecto con el siguiente comando:

```bash
pip install -r requirements.txt
```

### 4. Configurar las Notificaciones

Abre el archivo `notifications.py` y reemplaza los placeholders con tus credenciales de Twilio y Telegram:

```python
# Tu Account SID y Auth Token de twilio.com/console
# y tu Token de Bot de Telegram de BotFather
ACCOUNT_SID = 'TU_TWILIO_ACCOUNT_SID'
AUTH_TOKEN = 'TU_TWILIO_AUTH_TOKEN'
TELEGRAM_BOT_TOKEN = 'TU_TELEGRAM_BOT_TOKEN'
TELEGRAM_CHAT_ID = 'TU_TELEGRAM_CHAT_ID'
```

### 5. Entrenar el Modelo de Detección

Ejecuta el siguiente script para entrenar el modelo de detección de incendios. Este comando creará un archivo `fire_detection_model.h5`.

```bash
python train_model.py
```

### 6. Ejecutar la Aplicación

Ahora puedes iniciar la aplicación Flask:

```bash
python app.py
```

La aplicación estará disponible en `http://127.0.0.1:5000`.

### 7. Acceder a la Aplicación

*   **Página de Inicio:** `http://127.0.0.1:5000/`
*   **Login:** `http://127.0.0.1:5000/login`
    *   **Usuario Administrador:**
        *   **Usuario:** `admin`
        *   **Contraseña:** `admin`
    *   **Usuario Guardia:** (Debes crearlo desde el panel de administrador)
*   **Página de Monitoreo (solo para Guardias):** `http://127.0.0.1:5000/monitoring`
*   **Página de Administración (solo para Administradores):** `http://127.0.0.1:5000/admin`

### 8. Desactivar el Entorno Virtual

Cuando termines de trabajar en el proyecto, puedes desactivar el entorno virtual:

```bash
deactivate
```
