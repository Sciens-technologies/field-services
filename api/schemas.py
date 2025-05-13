import datetime
from typing import List, Optional
from uuid import UUID, uuid4


from pydantic import BaseModel, Field, EmailStr
from db.models import *


class UserBase(BaseModel):
    email: EmailStr
    first_name: str
    last_name: str
    role: UserRole


class Loginrequest(BaseModel):
    email: EmailStr
    password: str


class UserCreate(UserBase):
    pass


class UserUpdate(UserBase):
    is_active: bool



class UserResponse(UserBase):
    id: int
    is_active: bool
    created_at: datetime.datetime
    updated_at: datetime.datetime

    class Config:
        orm_mode = True


class WorkOrderBase(BaseModel):
    title: str
    description: str


class WorkOrderCreate(WorkOrderBase):
    pass


class WorkOrderUpdate(BaseModel):
    status: WorkOrderStatus


class WorkOrderResponse(WorkOrderBase):
    id: int
    status: WorkOrderStatus
    created_at: datetime.datetime
    updated_at: datetime.datetime
    created_by: UserResponse  # Include creator details
    assigned_to: Optional[UserResponse] = None

    class Config:
        orm_mode = True



class TokenSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int



class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str


class UpdateProfileRequest(BaseModel):
    first_name: str
    last_name: str