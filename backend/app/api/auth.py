from typing import Any
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import create_access_token, verify_password
from app.models.user import User
from app.schemas.user import Token
from app.api.deps import get_current_user, get_current_active_admin

router = APIRouter()

@router.post("/login", response_model=Token)
def login(
    db: Session = Depends(get_db),
    form_data: OAuth2PasswordRequestForm = Depends()
) -> Any:
    """
    OAuth2 compatible token login, returning JWT token on success.
    """
    # Query user by username
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not user.check_password(form_data.password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Nombre de usuario o contraseña incorrectos."
        )
    
    # Generate token
    access_token = create_access_token(subject=user.username)
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "role": user.role,
        "username": user.username,
        "name": f"{user.name} {user.last_name}"
    }

@router.get("/users")
def get_users(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
) -> Any:
    """
    Returns a list of all registered users in the database.
    """
    from app.api.deps import get_current_user
    users = db.query(User).all()
    return [
        {
            "id": u.id,
            "username": u.username,
            "name": u.name,
            "last_name": u.last_name,
            "role": u.role,
            "telegram_id": u.telegram_id,
            "whatsapp_number": u.whatsapp_number
        }
        for u in users
    ]

@router.post("/users")
def create_user(
    req_data: dict,
    db: Session = Depends(get_db),
    current_admin: User = Depends(get_current_active_admin)
) -> Any:
    """
    Creates a new user (admin or ranger). Restricted to Admin role.
    """
    from app.api.deps import get_current_active_admin
    username = req_data.get("username")
    password = req_data.get("password")
    name = req_data.get("name")
    last_name = req_data.get("last_name")
    role = req_data.get("role", "ranger")
    whatsapp_number = req_data.get("whatsapp_number")
    telegram_id = req_data.get("telegram_id")
    
    if not username or not password or not name or not last_name:
        raise HTTPException(status_code=400, detail="Faltan campos obligatorios.")
        
    existing = db.query(User).filter(User.username == username).first()
    if existing:
        raise HTTPException(status_code=400, detail="El nombre de usuario ya está registrado.")
        
    new_user = User(
        username=username,
        name=name,
        last_name=last_name,
        role=role,
        whatsapp_number=whatsapp_number,
        telegram_id=telegram_id
    )
    new_user.set_password(password)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"success": True, "user_id": new_user.id}

@router.delete("/users/{user_id}")
def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_admin: User = Depends(get_current_active_admin)
) -> Any:
    """
    Deletes a user by ID. Restricted to Admin role.
    """
    from app.api.deps import get_current_active_admin
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado.")
    if user.username == "admin":
        raise HTTPException(status_code=400, detail="No se puede eliminar al administrador por defecto.")
    db.delete(user)
    db.commit()
    return {"success": True, "message": "Usuario eliminado con éxito."}

@router.put("/users/{user_id}")
def update_user(
    user_id: int,
    req_data: dict,
    db: Session = Depends(get_db),
    current_admin: User = Depends(get_current_active_admin)
) -> Any:
    """
    Updates user details by ID. Restricted to Admin role.
    """
    from app.api.deps import get_current_active_admin
    from sqlalchemy.exc import IntegrityError
    
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado.")
    
    try:
        # Update fields if provided
        user.name = req_data.get("name", user.name)
        user.last_name = req_data.get("last_name", user.last_name)
        user.role = req_data.get("role", user.role)
        
        # Convert empty strings to None to prevent unique constraint conflicts in SQLite
        whatsapp = req_data.get("whatsapp_number")
        user.whatsapp_number = None if (whatsapp == "" or whatsapp is None) else whatsapp
        
        telegram = req_data.get("telegram_id")
        user.telegram_id = None if (telegram == "" or telegram is None) else telegram
        
        # Update password if provided
        password = req_data.get("password")
        if password:
            user.set_password(password)
            
        db.commit()
        return {"success": True, "message": "Usuario actualizado con éxito."}
        
    except IntegrityError as ie:
        db.rollback()
        raise HTTPException(
            status_code=400,
            detail="Error de integridad: El número de WhatsApp o ID de Telegram ya está registrado para otro usuario."
        )
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail=f"Error al actualizar el usuario: {str(e)}"
        )
