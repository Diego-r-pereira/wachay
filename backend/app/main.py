import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import engine, Base, SessionLocal
from app.models.user import User
from app.models.bombero import Bombero
from app.api import auth, reports, mobile, ml, bomberos

# 1. Initialize DB tables at startup and seed default admin
Base.metadata.create_all(bind=engine)

# Seed default admin user if not present (matches v1.0 logic)
db: Session = SessionLocal()
try:
    admin_user = db.query(User).filter(User.username == "admin").first()
    if not admin_user:
        new_admin = User(
            username="admin",
            name="Default",
            last_name="Admin",
            role="admin",
            preferred_language="es"
        )
        new_admin.set_password("adminpass")  # Default password
        db.add(new_admin)
        db.commit()
        print("Database Seed: Default admin user created (admin/adminpass).")
finally:
    db.close()

# 2. Initialize FastAPI Application
app = FastAPI(
    title="WACHAY API",
    description="API REST del Sistema Inteligente de Monitoreo y Alerta Temprana de Incendios Forestales (WACHAY v2.0)",
    version="2.0.0"
)

# 3. Configure CORS Middleware
# Allows request sharing from React Vite server (typically port 5173) and React Native simulators
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify actual URLs for stricter security
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 4. Include Route Modules
app.include_router(auth.router, prefix="/api/auth", tags=["Autenticación"])
app.include_router(reports.router, prefix="/api/reports", tags=["Gestión de Reportes"])
app.include_router(mobile.router, prefix="/api/mobile", tags=["Aplicación Móvil"])
app.include_router(ml.router, prefix="/api/ml", tags=["Modelos de Inteligencia Artificial"])
app.include_router(bomberos.router, prefix="/api/bomberos", tags=["Gestión de Bomberos"])

# 5. Mount Static Uploads Folder for Photos
uploads_dir = os.path.join(settings.BASE_DIR, "backend", "uploads")
os.makedirs(uploads_dir, exist_ok=True)
app.mount("/uploads", StaticFiles(directory=uploads_dir), name="uploads")

@app.get("/")
def read_root():
    return {
        "app": "WACHAY API",
        "version": "2.0.0",
        "docs_url": "/docs",
        "description": "Servidor backend de detección y reporte de incendios forestales activo."
    }
