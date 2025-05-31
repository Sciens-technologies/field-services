import datetime
from typing import List, Optional, Dict
from pydantic import BaseModel, Field, EmailStr, validator
# If you use WorkOrderStatus Enum, import it like this:
# from db.models import WorkOrderStatus

# --- User Schemas ---
class UserBase(BaseModel):
    email: EmailStr
    first_name: str
    last_name: str
    role: str

class UserCreate(UserBase):
    pass
class UpdateProfileRequest(BaseModel):
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    email: Optional[EmailStr] = None
    phone_number: Optional[str] = None
class UserUpdate(UserBase):
    is_active: bool

class UserResponse(BaseModel):
    id: int
    email: EmailStr
    first_name: str
    last_name: str
    role: str
    status: str
    phone_number: Optional[str] = None
    created_at: datetime.datetime
    updated_at: datetime.datetime

    @validator('role', pre=True)
    def convert_role_to_string(cls, v):
        if hasattr(v, 'name'):
            return v.name
        return v

    class Config:
        orm_mode = True
        from_attributes = True
        arbitrary_types_allowed = True

    @classmethod
    def from_orm(cls, obj):
        data = {}
        for field in cls._fields_:
            if hasattr(obj, field):
                value = getattr(obj, field)
                if field == 'role' and value is not None:
                    if hasattr(value, 'name'):
                        data[field] = value.name
                    else:
                        data[field] = str(value)
                else:
                    data[field] = value
        return cls(**data)

# --- Auth Schemas ---
class LoginRequest(BaseModel):
    username: EmailStr
    password: str

class TokenSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int

class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str

class SignupRequest(BaseModel):
    email: EmailStr
    password: str
    first_name: str
    last_name: str
    role: str = "agent"

class RefreshTokenRequest(BaseModel):
    refresh_token: str

class AdminCreateUserRequest(UserBase):
    pass

# --- Work Order Schemas ---
class WorkOrderBase(BaseModel):
    title: str
    description: str

class WorkOrderCreate(WorkOrderBase):
    pass

class WorkOrderUpdate(BaseModel):
    # status: WorkOrderStatus  # Uncomment if using Enum
    status: str

class WorkOrderResponse(WorkOrderBase):
    id: int
    # status: WorkOrderStatus  # Uncomment if using Enum
    status: str
    created_at: datetime.datetime
    updated_at: datetime.datetime
    # created_by: UserResponse  # Uncomment if you want to include creator details
    # assigned_to: Optional[UserResponse] = None

    class Config:
        orm_mode = True
        from_attributes = True

# --- Work Center Schemas ---
class WorkCenterAssignment(BaseModel):
    email: EmailStr
    work_center_id: int

class WorkCenterAssignmentResponse(BaseModel):
    user_id: int
    work_center_id: int
    message: str

# --- Feedback/Support Schemas ---
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
    created_at: datetime.datetime

    class Config:
        from_attributes = True

class SupportTicketCreate(BaseModel):
    subject: str
    description: str
    ticket_type: Optional[str] = "technical"

# --- Notification Preferences Schemas ---
class NotificationPreferencesResponse(BaseModel):
    user_id: int
    email: bool
    sms: bool
    push: bool

class NotificationPreferencesUpdate(BaseModel):
    email: Optional[bool] = None
    sms: Optional[bool] = None
    push: Optional[bool] = None

class NotificationPreferencesUpdateFull(BaseModel):
    email_notifications: Optional[Dict[str, bool]] = None
    sms_notifications: Optional[Dict[str, bool]] = None
    push_notifications: Optional[Dict[str, bool]] = None

class NotificationPreferencesResponseFull(BaseModel):
    user_id: int
    email_notifications: Dict[str, bool]
    sms_notifications: Dict[str, bool]
    push_notifications: Dict[str, bool]

# --- Password Reset ---
class ResetPasswordRequest(BaseModel):
    email: EmailStr
    new_password: str

# --- Permissions ---
class PermissionAssignRequest(BaseModel):
    role_name: str = Field(..., example="admin")
    permissions: List[str] = Field(..., example=["create", "delete", "view"])

class PermissionCreateRequest(BaseModel):
    name: str
    description: str = ""

# --- User Login Response ---
class UserLoginResponse(BaseModel):
    access_token: str
    token_type: str
    id: int
    first_name: str
    last_name: str
    role: str
    email: EmailStr

class UserInfo(BaseModel):
    id: int
    email: EmailStr
    first_name: str
    last_name: str
    role: str

class LoginResponse(BaseModel):
    access_token: str
    token_type: str
    user: UserInfo
    id: int
    first_name: str
    last_name: str
    role: str
    email: EmailStr