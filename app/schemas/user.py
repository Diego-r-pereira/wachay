from pydantic import BaseModel, Field
from typing import Optional

class UserBase(BaseModel):
    username: str = Field(..., max_length=80)
    name: str = Field(..., max_length=100)
    last_name: str = Field(..., max_length=100)
    telegram_id: Optional[str] = Field(None, max_length=100)
    whatsapp_number: Optional[str] = Field(None, max_length=100)
    role: str = Field(..., max_length=20)  # admin or ranger
    preferred_language: Optional[str] = Field("es", max_length=10)

class UserCreate(UserBase):
    password: str = Field(..., min_length=4)

class UserUpdate(BaseModel):
    username: Optional[str] = Field(None, max_length=80)
    password: Optional[str] = Field(None, min_length=4)
    name: Optional[str] = Field(None, max_length=100)
    last_name: Optional[str] = Field(None, max_length=100)
    telegram_id: Optional[str] = Field(None, max_length=100)
    whatsapp_number: Optional[str] = Field(None, max_length=100)
    role: Optional[str] = Field(None, max_length=20)
    preferred_language: Optional[str] = Field(None, max_length=10)

class UserOut(UserBase):
    id: int

    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str
    role: str
    username: str
    name: str

class TokenPayload(BaseModel):
    sub: Optional[str] = None
