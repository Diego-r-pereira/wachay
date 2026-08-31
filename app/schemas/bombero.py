from pydantic import BaseModel, Field
from typing import Optional

class BomberoBase(BaseModel):
    name: str = Field(..., max_length=100)
    last_name: str = Field(..., max_length=100)
    whatsapp_number: Optional[str] = Field(None, max_length=100)
    fire_unit: str = Field(..., max_length=100)
    is_leader: bool = Field(False)

class BomberoCreate(BomberoBase):
    pass

class BomberoUpdate(BaseModel):
    name: Optional[str] = Field(None, max_length=100)
    last_name: Optional[str] = Field(None, max_length=100)
    whatsapp_number: Optional[str] = Field(None, max_length=100)
    fire_unit: Optional[str] = Field(None, max_length=100)
    is_leader: Optional[bool] = None

class BomberoOut(BomberoBase):
    id: int

    class Config:
        from_attributes = True
