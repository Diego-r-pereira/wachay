from typing import Generator
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.models.user import User
from app.schemas.user import TokenPayload

# OAuth2PasswordBearer specifies the endpoint where client sends login credentials to get JWT
reusable_oauth2 = OAuth2PasswordBearer(
    tokenUrl="/api/auth/login"
)

def get_current_user(
    db: Session = Depends(get_db), token: str = Depends(reusable_oauth2)
) -> User:
    """
    Decodes the JWT token to authenticate the incoming request user.
    """
    try:
        payload = jwt.decode(
            token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
        )
        token_data = TokenPayload(**payload)
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="No se pudieron validar las credenciales del token.",
        )
    
    # Sub stores the username or user id (we use username)
    user = db.query(User).filter(User.username == token_data.sub).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="El usuario del token no existe.",
        )
    return user

def get_current_active_admin(
    current_user: User = Depends(get_current_user)
) -> User:
    """
    Checks that the authenticated user has the 'admin' role.
    """
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Operación no autorizada. Requiere rol de Administrador.",
        )
    return current_user

def get_current_active_ranger(
    current_user: User = Depends(get_current_user)
) -> User:
    """
    Checks that the authenticated user has 'ranger' or 'admin' role.
    """
    if current_user.role not in ["ranger", "admin"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Operación no autorizada. Requiere rol de Guardaparques o Administrador.",
        )
    return current_user
