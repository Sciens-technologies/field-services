from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, EmailStr, validator

# --- User Schemas ---
class UserBase(BaseModel):
    email: EmailStr
    first_name: str
    last_name: str
    role: str

class UserCreate(UserBase):
    pass

class UserUpdate(UserBase):
    phone_number: Optional[str] = None

class UserResponse(BaseModel):
    id: int
    email: EmailStr
    first_name: str
    last_name: str
    role: str
    status: str
    phone_number: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    @validator('role', pre=True)
    def convert_role_to_string(cls, v):
        if hasattr(v, 'name'):
            return v.name
        return v

    class Config:
        from_attributes = True

# --- Auth ---


class LoginJSONRequest(BaseModel):
    email: EmailStr
    password: str


class UserInfo(BaseModel):
    email: str
    first_name: str
    last_name: str
    role: str

class TokenSchema(BaseModel):
    access_token: str
    refresh_token: str
    expires_in: int
    user: UserInfo

class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str

class UpdateProfileRequest(BaseModel):
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    email: Optional[EmailStr] = None
    phone_number: Optional[str] = None

class SignupRequest(BaseModel):
    email: EmailStr
    password: str
    first_name: str
    last_name: str
    role: str = "agent"

class RefreshTokenRequest(BaseModel):
    refresh_token: str

class AdminCreateUserRequest(BaseModel):
    email: EmailStr
    first_name: str
    last_name: str
    role: str

# --- Work Order ---
class WorkOrderBase(BaseModel):
    title: str
    description: str

class WorkOrderCreate(WorkOrderBase):
    pass

class WorkOrderUpdate(BaseModel):
    status: str

class WorkOrderResponse(WorkOrderBase):
    id: int
    status: str
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

# --- Feedback/Support ---
class FeedbackRequest(BaseModel):
    request_id: str
    subject: str
    description: str

class FeedbackCreate(BaseModel):
    email: Optional[EmailStr] = None
    subject: str
    message: str

class FeedbackResponse(BaseModel):
    id: int
    subject: str
    message: str
    status: str
    created_at: datetime

class SupportTicketCreate(BaseModel):
    subject: str
    description: str
    ticket_type: Optional[str] = "technical"

# --- Work Center ---
class WorkCenterAssignment(BaseModel):
    email: EmailStr
    work_center_id: int

class WorkCenterAssignmentResponse(BaseModel):
    user_id: int
    work_center_id: int
    message: str

# --- Notification Preferences ---
class NotificationPreferencesResponse(BaseModel):
    user_id: int
    email: bool
    sms: bool
    push: bool

class NotificationPreferencesUpdate(BaseModel):
    email: Optional[bool] = None
    sms: Optional[bool] = None
    push: Optional[bool] = None

# --- Password Reset ---
class ResetPasswordRequest(BaseModel):
    email: EmailStr
    new_password: str

class LoginRequest(BaseModel):
    email: EmailStr
    password: str