# WACHAY - Detalles del Proyecto de Detección de Incendios Forestales

## 1. Introducción

WACHAY es una aplicación web diseñada para la detección y reporte de incendios forestales. El sistema permite a los usuarios autorizados (guardabosques) monitorear imágenes en busca de incendios y, en caso de detectar uno, generar un reporte manual que se almacena en una base de datos. Además, el sistema envía notificaciones a través de WhatsApp y Telegram para alertar sobre nuevos reportes.

## 2. Metodología

El desarrollo de este proyecto se ha basado en una metodología de **desarrollo incremental**. Se ha comenzado con la implementación de las funcionalidades básicas y se ha ido añadiendo complejidad de forma progresiva. Este enfoque permite tener una versión funcional del software en cada etapa del desarrollo y facilita la adaptación a nuevos requisitos.

Los "baby steps" utilizados para construir la aplicación son un reflejo de esta metodología, donde cada paso representa un incremento en la funcionalidad del sistema.

## 3. Arquitectura del Sistema

La aplicación sigue una arquitectura de software basada en el patrón **Modelo-Vista-Controlador (MVC)**, adaptado a la estructura de una aplicación web con Flask.

*   **Modelo:** Representado por los archivos `models.py` y la base de datos `wachay.db`. Define la estructura de los datos (usuarios y reportes) y la lógica para interactuar con ellos. Se utiliza **Flask-SQLAlchemy** como ORM para mapear los objetos de Python a las tablas de la base de datos.
*   **Vista:** Compuesta por los archivos HTML en la carpeta `templates/`. Se encarga de la presentación de los datos al usuario. Se utiliza el motor de plantillas **Jinja2**, que viene integrado con Flask, para generar el contenido HTML de forma dinámica.
*   **Controlador:** Implementado en el archivo `app.py`. Contiene la lógica de la aplicación, maneja las peticiones de los usuarios, interactúa con el modelo para obtener y guardar datos, y renderiza las vistas correspondientes.

### Tecnologías Utilizadas

*   **Backend:**
    *   **Flask:** Un micro-framework de Python para el desarrollo de aplicaciones web. Es el núcleo de la aplicación.
    *   **Flask-SQLAlchemy:** Una extensión de Flask que facilita el uso de SQLAlchemy, un ORM de Python.
    *   **Flask-Login:** Una extensión de Flask para gestionar las sesiones de usuario y la autenticación.
    *   **TensorFlow/Keras:** Bibliotecas de machine learning para construir y entrenar el modelo de detección de incendios.
    *   **Twilio:** Un servicio de comunicación en la nube para enviar notificaciones por WhatsApp.
    *   **Telebot (pyTelegramBotAPI):** Una librería de Python para interactuar con la API de bots de Telegram.
*   **Frontend:**
    *   **HTML5:** Para la estructura de las páginas web.
    *   **CSS3:** Para el diseño y la presentación visual.
    *   **JavaScript:** Para la interactividad en el lado del cliente, como el carrusel de imágenes.
*   **Base de Datos:**
    *   **SQLite:** Un motor de base de datos ligero y basado en archivos, ideal para el desarrollo y prototipado.

## 4. Estructura de Archivos y Explicación

A continuación, se detalla la función de cada archivo y directorio importante en el proyecto:

*   `app.py`:
    *   **Función:** Es el archivo principal de la aplicación Flask.
    *   **Cómo funciona:** Inicializa la aplicación Flask, la base de datos y el gestor de login. Define todas las rutas (URLs) de la aplicación, como la página de inicio, el login, el monitoreo, etc. Contiene la lógica para manejar las peticiones de los usuarios, procesar formularios, interactuar con la base de datos y renderizar las plantillas HTML.

*   `fireSet.py`:
    *   **Función:** Contiene la lógica para la predicción de incendios.
    *   **Cómo funciona:** Carga el modelo de machine learning pre-entrenado (`fire_detection_model.h5`). La función `predict_image` toma la ruta de una imagen, la pre-procesa (cambia el tamaño y normaliza los píxeles) y utiliza el modelo para predecir si la imagen contiene fuego o no.

*   `train_model.py`:
    *   **Función:** Script para entrenar el modelo de detección de incendios.
    *   **Cómo funciona:** Carga las imágenes de entrenamiento, las pre-procesa y las utiliza para entrenar un modelo de red neuronal convolucional (CNN) con Keras. Una vez entrenado, el modelo se guarda en el archivo `fire_detection_model.h5`. **Este script solo se ejecuta una vez (o cada vez que se quiera re-entrenar el modelo) y no forma parte de la aplicación web en ejecución.**

*   `models.py`:
    *   **Función:** Define los modelos de la base de datos.
    *   **Cómo funciona:** Utiliza `Flask-SQLAlchemy` para definir las clases `User` y `Report` como modelos de la base de datos. Cada clase se corresponde con una tabla en la base de datos y sus atributos con las columnas de la tabla. Esto permite interactuar con la base de datos de una manera más intuitiva y orientada a objetos.

*   `notifications.py`:
    *   **Función:** Gestiona el envío de notificaciones.
    *   **Cómo funciona:** Contiene las funciones `send_whatsapp_message` y `send_telegram_message`. Estas funciones utilizan las librerías de Twilio y Telebot para enviar mensajes a los números y chats especificados. **Requiere credenciales que deben ser configuradas por el usuario.**

*   `requirements.txt`:
    *   **Función:** Lista todas las dependencias de Python del proyecto.
    *   **Cómo funciona:** Permite instalar todas las librerías necesarias con un solo comando (`pip install -r requirements.txt`), asegurando que el entorno de desarrollo sea consistente.

*   `README.md`:
    *   **Función:** Proporciona una guía rápida para configurar y ejecutar el proyecto.

*   `PROJECT_DETAILS.md` (este archivo):
    *   **Función:** Ofrece una explicación detallada y profunda del proyecto.

*   **Carpeta `templates/`:**
    *   **Función:** Contiene todas las plantillas HTML de la aplicación.
    *   **Cómo funciona:**
        *   `base.html`: Es la plantilla base que contiene la estructura común de todas las páginas (navegación, footer, etc.). Las demás plantillas heredan de esta.
        *   `index.html`: La página de inicio (Landing Page).
        *   `login.html`: El formulario de inicio de sesión.
        *   `monitoring.html`: La página de monitoreo con el carrusel de imágenes.
        *   `admin.html`: El panel de administración de usuarios.
        *   `report.html`: El formulario para crear un nuevo reporte de incendio.

*   **Carpeta `static/`:**
    *   **Función:** Almacena todos los archivos estáticos que se sirven directamente al navegador.
    *   **Cómo funciona:**
        *   `css/style.css`: Contiene los estilos CSS para dar formato a la aplicación.
        *   `js/main.js`: Contiene el código JavaScript para la interactividad del frontend, como el carrusel.
        *   `images/`: Contiene las imágenes utilizadas en la aplicación, incluyendo las imágenes del carrusel.

*   **Carpeta `instance/`:**
    *   **Función:** Es una carpeta creada por Flask para almacenar archivos específicos de la instancia de la aplicación, como la base de datos.
    *   `wachay.db`: El archivo de la base de datos SQLite.

## 5. Baby Steps para Ejecutar la Aplicación

Sigue estos pasos para poner en marcha la aplicación:

### 1. Clonar el Repositorio

```bash
git clone https://github.com/Diego-r-pereira/wachay.git
cd wachay
```

### 2. Crear y Activar un Entorno Virtual

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

```bash
pip install -r requirements.txt
```

### 4. Configurar las Notificaciones

Abre el archivo `notifications.py` y reemplaza los placeholders con tus credenciales de Twilio y Telegram.

### 5. Entrenar el Modelo de Detección

```bash
python train_model.py
```

### 6. Ejecutar la Aplicación

```bash
python app.py
```

La aplicación estará disponible en `http://127.0.0.1:5000`.

### 7. Acceder a la Aplicación

*   **Página de Inicio:** `http://127.0.0.1:5000/`
*   **Login:** `http://127.0.0.1:5000/login`
    *   **Usuario Administrador:** `admin`, **Contraseña:** `admin`
*   **Página de Monitoreo (solo para Guardias):** `http://127.0.0.1:5000/monitoring`
*   **Página de Administración (solo para Administradores):** `http://127.0.0.1:5000/admin`
