Eres un Ingeniero senior asignado a construir una aplicación web moderna desde 0 y con el mayor detalle posible como corresponde a tu experiencia.

## Objetivo

Construir un sitio web que permita realizar "DETECCIÓN de INCENDIOS FORESTALES" para poder, a traves de un formulario, reportar el siniestro manualmente y mandar mensajes de alerta a través de WhatsApp y Telegram.

## Estrutura

Flask for the kernel and logic, html and JS for web structure, CSS for styling, Flask-SQLAlchemy for DB.

## Tasks

3 Páginas:
1. Landing Page.- Página de aterrizaje con las siguientes secciones:
	- Hero Section (Encabezado Principal) con un botón especial llamativo para poder reportar un incendio.
	- Problema & Solución (El desafío de los incendios forestales).
	- Tecnologías y características principales del sistema.
	- Muestra de la imagen del último reporte registrado en la base de datos con una pequeña descripción explicativa.
	- Proyecto Académico (Proyecto de Grado Universitario; Universidad:[Tu Universidad]; Carrera: [Tu Carrera]; Estudiante: [Tu Nombre]; Tutor: [Nombre del Tutor])
	- Contacto de emergencia e Información generalizada de los parques nacionales de Bolivia.
	- Footer
La estructura de la navegación es la siguiente: logo WACHAY, Inicio, Monitoring, Admin, About.

2. Página de monitoreo.- Mostrar en un recuadro centrado un carrusel de 50 imagenes que se pueden cambiar a traves de botones y estan localizadas en una carpeta con los nombres de los archivos del 1 al 50 en el que se presentan escenarios de incendios y otros solamente bosques, el sistema de python cuando detecte un incendio forestal se habilite un boton para hacer reportes manuales en los que se registraran en una base de datos.

3. Página de administrador.- Una página en dónde se pueda administrar CRUD de usuarios, hay 3 tipos de usuario que intervienen la página, Guardia, Administrador y Usuario Común, el Usuario Común no necesita credenciales y sólo puede ver la landing page, el guardia sólo puede ver la "Página de monitoreo" y el administrador sólo puede ver la "Página de administrador".

## Resportes manuales

Los reportes deben poder registrar los siguientes datos: 
1. Nombre del guardabosque.
2. Hora del reporte.
3. Fecha del reporte
4. Un link de google 

## Output requirements

Muéstrame el código en baby steps desde 0 y listo para pegarlo en mi editor WebStorm.

## Codigo python base

Tengo el codigo en python de reconocimiento de incendios forestales y necesito que utilices ese codigo. Este codigo entrena cada vez que lo haces correr, asi que crea un nuevo archivo con un modelo pre entrenado optimo para la pagina web que estamos construyendo porfa.

## Notes

Realiza un diseño minimalista. Seguí las guías de código de las grandes industrias y optimiza el código para un mejor rendimiento. Las variables y los comentarios del código deben estar en Inglés.