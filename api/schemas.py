import datetime
from typing import List, Optional, Dict, Any, Union
from pydantic import BaseModel, Field, EmailStr, validator
from enum import Enum
from datetime import datetime
# If you use WorkOrderStatus Enum, import it like this:
# from db.models import WorkOrderStatus

# --- Enums ---
class UserStatus(str, Enum):
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"
    BLOCKED = "BLOCKED"
    DELETED = "DELETED"

class WorkOrderStatus(str, Enum):
    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    CANCELLED = "CANCELLED"
    REJECTED = "REJECTED"

class NotificationType(str, Enum):
    EMAIL = "EMAIL"
    SMS = "SMS"
    PUSH = "PUSH"
    IN_APP = "IN_APP"

class RequestType(str, Enum):
    NEW_CONNECTION = "NEW_CONNECTION"
    SUBSCRIPTION = "SUBSCRIPTION"
    COMPLAINT = "COMPLAINT"
    TERMINATION = "TERMINATION"
    OTHER = "OTHER"

class DeviceStatus(str, Enum):
    REGISTERED = "REGISTERED"
    ACTIVE = "ACTIVE"
    BLOCKED = "BLOCKED"
    DEACTIVATED = "DEACTIVATED"
    READY_TO_ACTIVATE = "READY_TO_ACTIVATE"

class DeviceSourceType(str, Enum):
    PURCHASED = "PURCHASED"
    LEASED = "LEASED"
    TRANSFERRED = "TRANSFERRED"
    DONATED = "DONATED"
    MANUFACTURED = "MANUFACTURED"
    OTHER = "OTHER"

class DeviceSourceDestination(str, Enum):
    REGIONAL_PLANET = "REGIONAL_PLANET"
    CENTER_PLANET = "CENTER_PLANET"
    OPERATIONAL_PLANET = "OPERATIONAL_PLANET"
    WORK_CENTER = "WORK_CENTER"
    OTHER = "OTHER"

class DeviceAssignmentRole(str, Enum):
    TECHNICIAN = "TECHNICIAN"
    SUPERVISOR = "SUPERVISOR"
    MANAGER = "MANAGER"
    ADMIN = "ADMIN"
    WAREHOUSE = "WAREHOUSE"
    OTHER = "OTHER"

# --- Base Schemas ---
class BaseSchema(BaseModel):
    class Config:
        from_attributes = True
        arbitrary_types_allowed = True

class LoginRequest(BaseSchema):
    """
    Schema for user login request.
    
    Attributes:
        username (str): User's username or email
        password (str): User's password
    """
    username: str
    password: str

class NotificationChannelPreferences(BaseModel):
    enabled: bool = True
    types: List[str] = []

class NotificationPreferencesUpdate(BaseModel):
    """
    Schema for updating user notification preferences.
    
    Attributes:
        email_enabled (bool): Whether to enable/disable email notifications
        sms_enabled (bool): Whether to enable/disable SMS notifications
        push_enabled (bool): Whether to enable/disable push notifications
    """
    email_enabled: bool = True
    sms_enabled: bool = True
    push_enabled: bool = True

class NotificationPreferencesResponse(BaseModel):
    """
    Schema for user notification preferences response.
    
    Attributes:
        user_id (int): User's ID
        email_enabled (bool): Whether email notifications are enabled
        sms_enabled (bool): Whether SMS notifications are enabled
        push_enabled (bool): Whether push notifications are enabled
    """
    user_id: int
    email_enabled: bool
    sms_enabled: bool
    push_enabled: bool

class NotificationPreferencesUpdateFull(BaseModel):
    """
    Schema for updating detailed user notification preferences.
    
    Attributes:
        email_notifications (Optional[Dict[str, bool]]): Email notification type preferences
        sms_notifications (Optional[Dict[str, bool]]): SMS notification type preferences
        push_notifications (Optional[Dict[str, bool]]): Push notification type preferences
    """
    email_notifications: Optional[Dict[str, bool]] = None
    sms_notifications: Optional[Dict[str, bool]] = None
    push_notifications: Optional[Dict[str, bool]] = None

class NotificationPreferencesResponseFull(BaseModel):
    """
    Schema for detailed user notification preferences response.
    
    Attributes:
        user_id (int): User's ID
        email_notifications (Dict[str, bool]): Email notification type preferences
        sms_notifications (Dict[str, bool]): SMS notification type preferences
        push_notifications (Dict[str, bool]): Push notification type preferences
    """
    user_id: int
    email_notifications: Dict[str, bool]
    sms_notifications: Dict[str, bool]
    push_notifications: Dict[str, bool]

# --- User Schemas ---
class UserBase(BaseSchema):
    """
    Base schema for user data containing common fields.
    
    Attributes:
        username (str): Unique username for the user
        email (EmailStr): User's email address
        first_name (Optional[str]): User's first name
        last_name (Optional[str]): User's last name
    """
    username: str = Field(..., description="Unique username for the user")
    email: EmailStr = Field(..., description="User's email address")
    first_name: Optional[str] = Field(None, description="User's first name")
    last_name: Optional[str] = Field(None, description="User's last name")

    class Config:
        json_schema_extra = {
            "example": {
                "username": "johndoe",
                "email": "john.doe@example.com",
                "first_name": "John",
                "last_name": "Doe"
            }
        }

class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    first_name: str = Field(..., min_length=1, max_length=50)
    last_name: str = Field(..., min_length=1, max_length=50)
    roles: List[str] = Field(default_factory=list, description="List of role names to assign to the user")

class UserUpdate(BaseModel):
    username: Optional[str] = Field(None, min_length=3, max_length=50)
    first_name: Optional[str] = Field(None, min_length=1, max_length=50)
    last_name: Optional[str] = Field(None, min_length=1, max_length=50)

class UserResponse(BaseSchema):
    user_id: int
    uuid: str
    username: str
    email: EmailStr
    first_name: str
    last_name: str
    status: str
    created_at: datetime
    updated_at: datetime

    class Config:
        json_encoders = {
            datetime: lambda dt: dt.isoformat()
        }

# --- Role Schemas ---
class PermissionBase(BaseSchema):
    """
    Base schema for permissions.
    
    Attributes:
        feature_name (str): The feature name for the permission
        description (Optional[str]): Description of the permission
    """
    feature_name: str = Field(..., description="The feature name for the permission")
    description: Optional[str] = Field(None, description="Description of the permission")

class PermissionCreate(PermissionBase):
    """
    Schema for creating a new permission.
    """
    pass

class PermissionCreateRequest(BaseSchema):
    name: str
    description: str = ""

class PermissionResponse(BaseModel):
    permission_id: int
    feature_name: str
    description: Optional[str] = None
    active: bool
    created_at: datetime
    updated_at: Optional[datetime] = None

class RoleBase(BaseModel):
    name: str = Field(..., description="Name of the role")
    description: Optional[str] = Field(None, description="Description of the role")

class RoleCreate(RoleBase):
    permission_ids: Optional[List[int]] = Field(None, description="List of permission IDs to assign")

class RoleUpdate(RoleBase):
    pass

class RoleResponse(RoleBase):
    id: int
    permissions: List[PermissionResponse]

    class Config:
        from_attributes = True

class PermissionAssignment(BaseModel):
    add_permission_ids: Optional[List[int]] = Field(None, description="List of permission IDs to add")
    remove_permission_ids: Optional[List[int]] = Field(None, description="List of permission IDs to remove")

# --- Device Schemas ---
class DeviceBase(BaseSchema):
    serial_number: str
    model: Optional[str] = None
    location: Optional[str] = None
    work_center_id: Optional[int] = None

class DeviceCreate(DeviceBase):
    pass

class DeviceUpdate(BaseSchema):
    model: Optional[str] = None
    status: Optional[DeviceStatus] = None
    location: Optional[str] = None
    work_center_id: Optional[int] = None
    active: Optional[bool] = None

class DeviceResponse(DeviceBase):
    device_id: int
    status: DeviceStatus
    last_communication: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime
    active: bool

class DeviceArtifactBase(BaseSchema):
    device_id: int
    source_type: DeviceSourceType
    source_reference: Optional[str] = None
    source_details: Optional[Dict[str, Any]] = None
    source_destination: Optional[DeviceSourceDestination] = None
    acquisition_date: Optional[datetime] = None
    remarks: Optional[str] = None

class DeviceArtifactCreate(DeviceArtifactBase):
    added_by: int

class DeviceArtifactUpdate(BaseSchema):
    source_type: Optional[DeviceSourceType] = None
    source_reference: Optional[str] = None
    source_details: Optional[Dict[str, Any]] = None
    source_destination: Optional[DeviceSourceDestination] = None
    remarks: Optional[str] = None
    status: Optional[str] = None
    active: Optional[bool] = None

class DeviceArtifactResponse(DeviceArtifactBase):
    artifact_id: int
    added_by: int
    status: Optional[str] = None
    active: bool
    created_at: datetime

class DeviceAssignmentBase(BaseSchema):
    device_id: int
    user_id: Optional[int] = None
    role: Optional[DeviceAssignmentRole] = None

class DeviceAssignmentCreate(DeviceAssignmentBase):
    assigned_by_user_id: Optional[int] = None
    assigned_by_role: Optional[DeviceAssignmentRole] = None

class DeviceAssignmentUpdate(BaseSchema):
    user_id: Optional[int] = None
    role: Optional[DeviceAssignmentRole] = None
    assigned_by_role: Optional[DeviceAssignmentRole] = None
    unassigned_at: Optional[datetime] = None
    status: Optional[str] = None
    active: Optional[bool] = None

class DeviceAssignmentResponse(DeviceAssignmentBase):
    assignment_id: int
    assigned_by_user_id: Optional[int] = None
    assigned_by_role: Optional[DeviceAssignmentRole] = None
    assigned_at: datetime
    unassigned_at: Optional[datetime] = None
    status: Optional[str] = None
    active: bool
    updated_at: Optional[datetime] = None

# --- Work Order Schemas ---
class WorkOrderBase(BaseSchema):
    wo_number: str
    title: str
    description: Optional[str] = None
    work_order_type: Optional[str] = None
    customer_id: Optional[str] = None
    customer_name: Optional[str] = None
    location: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    scheduled_date: Optional[datetime] = None
    due_date: Optional[datetime] = None
    priority: Optional[str] = "MEDIUM"
    work_centre_id: int

class WorkOrderCreate(WorkOrderBase):
    created_by: int

class WorkOrderUpdate(BaseSchema):
    title: Optional[str] = None
    description: Optional[str] = None
    status: Optional[WorkOrderStatus] = None
    scheduled_date: Optional[datetime] = None
    due_date: Optional[datetime] = None
    priority: Optional[str] = None
    active: Optional[bool] = None

class WorkOrderResponse(WorkOrderBase):
    work_order_id: int
    status: WorkOrderStatus
    created_at: datetime
    updated_at: datetime
    active: bool

# --- Work Order Assignment Schemas ---
class WorkOrderAssignmentBase(BaseSchema):
    work_order_id: int
    agent_id: int

class WorkOrderAssignmentCreate(WorkOrderAssignmentBase):
    pass

class WorkOrderAssignmentUpdate(BaseSchema):
    reassigned: Optional[bool] = None
    reassignment_reason: Optional[str] = None
    status: Optional[str] = None
    active: Optional[bool] = None

class WorkOrderAssignmentResponse(BaseSchema):
    assignment_id: int
    work_order_id: int
    wo_number: str
    agent_id: int
    reassigned: bool
    assigned_at: datetime
    status: Optional[str] = None
    active: bool
    updated_at: Optional[datetime] = None

# --- Work Order Execution Schemas ---
class WorkOrderExecutionBase(BaseSchema):
    work_order_id: int
    agent_id: int
    start_time: datetime
    gps_lat: Optional[float] = None
    gps_long: Optional[float] = None

class WorkOrderExecutionCreate(WorkOrderExecutionBase):
    pass

class WorkOrderExecutionUpdate(BaseSchema):
    end_time: Optional[datetime] = None
    parts_used: Optional[str] = None
    synced: Optional[bool] = None
    status: Optional[str] = None
    active: Optional[bool] = None

class WorkOrderExecutionResponse(WorkOrderExecutionBase):
    execution_id: int
    end_time: Optional[datetime] = None
    parts_used: Optional[str] = None
    synced: bool
    status: Optional[str] = None
    active: bool

# --- Picture Module Schemas ---
class PictureMetadataBase(BaseSchema):
    work_order_id: int
    agent_id: int
    request_type: RequestType
    meter_number: Optional[str] = None
    supply_point_number: Optional[str] = None
    cycle: Optional[str] = None
    location: Optional[str] = None
    file_name: str
    file_path: str
    file_format: str

class PictureMetadataCreate(PictureMetadataBase):
    pass

class PictureMetadataUpdate(BaseSchema):
    meter_number: Optional[str] = None
    supply_point_number: Optional[str] = None
    cycle: Optional[str] = None
    location: Optional[str] = None
    status: Optional[str] = None
    active: Optional[bool] = None

class PictureMetadataResponse(PictureMetadataBase):
    picture_id: int
    captured_at: datetime
    status: Optional[str] = None
    active: bool

# --- Picture Qualification Schemas ---
class PictureQualificationBase(BaseSchema):
    picture_id: int
    qualified_by: int
    qualification_status: str
    comments: Optional[str] = None

class PictureQualificationCreate(PictureQualificationBase):
    pass

class PictureQualificationResponse(PictureQualificationBase):
    qualification_id: int
    qualified_at: datetime
    active: bool

# --- Auth Schemas ---
class SignupRequest(BaseSchema):
    username: str
    email: EmailStr
    password: str = Field(..., min_length=8)
    first_name: str
    last_name: str
    preferred_lang: Optional[str] = None
    timezone_id: Optional[str] = None

class RefreshTokenRequest(BaseSchema):
    refresh_token: str

class TokenResponse(BaseSchema):
    """
    Schema for authentication token response.
    
    Attributes:
        access_token (str): JWT access token
        token_type (str): Type of token (default: "bearer")
        expires_in (int): Token expiration time in seconds
    """
    access_token: str
    token_type: str = "bearer"
    expires_in: int

class ForgotPasswordResponse(BaseSchema):
    """
    Schema for forgot password response.
    
    Attributes:
        message (str): Response message
        reset_key (str): Password reset key
        email (str): User's email
    """
    message: str
    reset_key: str
    email: str

class LoginResponse(BaseSchema):
    """
    Schema for login response that includes both token and user details.
    
    Attributes:
        token (TokenResponse): Authentication token details
        user (UserResponse): User details
        roles (List[str]): List of user roles
    """
    token: TokenResponse
    user: UserResponse
    roles: List[str]

class ChangePasswordRequest(BaseModel):
    current_password: str = Field(..., min_length=8)
    new_password: str = Field(..., min_length=8)

# --- Work Centre Schemas ---
class WorkCentreBase(BaseSchema):
    name: str
    registration_number: str
    tax_id: Optional[str] = None
    contact_email: Optional[EmailStr] = None
    contact_phone: Optional[str] = None
    website_url: Optional[str] = None
    address_line1: Optional[str] = None
    address_line2: Optional[str] = None
    city: Optional[str] = None
    state: Optional[str] = None
    postal_code: Optional[str] = None
    country: Optional[str] = None

class WorkCentreCreate(WorkCentreBase):
    created_by: int

class WorkCentreUpdate(BaseSchema):
    name: Optional[str] = None
    tax_id: Optional[str] = None
    contact_email: Optional[EmailStr] = None
    contact_phone: Optional[str] = None
    website_url: Optional[str] = None
    address_line1: Optional[str] = None
    address_line2: Optional[str] = None
    city: Optional[str] = None
    state: Optional[str] = None
    postal_code: Optional[str] = None
    country: Optional[str] = None
    status: Optional[str] = None
    active: Optional[bool] = None

class WorkCentreResponse(WorkCentreBase):
    work_centre_id: int
    status: str
    active: bool
    created_at: datetime
    updated_at: datetime

# --- Subcontractor Schemas ---
class SubcontractorBase(BaseSchema):
    company_name: str
    telephone: Optional[str] = None
    email: Optional[EmailStr] = None
    description: Optional[str] = None
    location: Optional[str] = None

class SubcontractorCreate(SubcontractorBase):
    pass

class SubcontractorUpdate(BaseSchema):
    company_name: Optional[str] = None
    telephone: Optional[str] = None
    email: Optional[EmailStr] = None
    description: Optional[str] = None
    location: Optional[str] = None
    status: Optional[str] = None
    active: Optional[bool] = None

class SubcontractorResponse(SubcontractorBase):
    subcontractor_id: int
    status: Optional[str] = None
    active: bool
    created_at: datetime

# --- Work Center Schemas ---
class WorkCenterAssignment(BaseModel):
    email: EmailStr
    work_center_id: int

class WorkCenterAssignmentResponse(BaseModel):
    user_id: int
    work_center_id: int
    message: str

# --- Feedback/Support Schemas ---
class FeedbackCategory(str, Enum):
    BUG = "BUG"
    FEATURE_REQUEST = "FEATURE_REQUEST"
    GENERAL = "GENERAL"

class FeedbackPriority(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"

class FeedbackCreate(BaseModel):
    title: str = Field(..., min_length=5, max_length=100)
    description: str = Field(..., min_length=10)
    category: str = Field(..., min_length=3, max_length=50)
    severity: str = Field(..., min_length=3, max_length=20)

class FeedbackResponse(BaseModel):
    feedback_id: int
    user_id: int
    title: str
    description: str
    category: str
    severity: str
    status: str
    created_at: datetime
    updated_at: datetime

class TicketCategory(str, Enum):
    TECHNICAL = "TECHNICAL"
    ACCOUNT = "ACCOUNT"
    BILLING = "BILLING"
    OTHER = "OTHER"

class TicketPriority(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    URGENT = "URGENT"

class TicketStatus(str, Enum):
    OPEN = "OPEN"
    IN_PROGRESS = "IN_PROGRESS"
    ON_HOLD = "ON_HOLD"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"

class SupportTicketCreate(BaseModel):
    subject: str = Field(..., min_length=5, max_length=100)
    description: str = Field(..., min_length=10)
    priority: str = Field(..., min_length=3, max_length=20)
    category: str = Field(..., min_length=3, max_length=50)

class SupportTicketResponse(BaseModel):
    ticket_id: int
    user_id: int
    subject: str
    description: str
    priority: str
    category: str
    status: str
    created_at: datetime
    updated_at: datetime

# --- User Status Audit Schemas ---
class UserStatusAuditBase(BaseSchema):
    user_id: int
    old_status: UserStatus
    new_status: UserStatus
    reason: str
    remarks: Optional[str] = None

class UserStatusAuditCreate(UserStatusAuditBase):
    changed_by: str

class UserStatusAuditResponse(UserStatusAuditBase):
    id: int
    changed_by: str
    changed_at: datetime

# --- User Auth Provider Schemas ---
class UserAuthProviderBase(BaseSchema):
    provider: str  # 'LOCAL', 'AZURE', 'GOOGLE', 'FACEBOOK'
    provider_user_id: str
    provider_username: Optional[str] = None

class UserAuthProviderCreate(UserAuthProviderBase):
    user_id: int

class UserAuthProviderResponse(UserAuthProviderBase):
    id: int
    user_id: int
    created_at: datetime
    updated_at: Optional[datetime] = None

# --- User Auth Metadata Schemas ---
class UserAuthMetadataBase(BaseSchema):
    provider: str
    external_user_id: str
    access_token: Optional[str] = None
    refresh_token: Optional[str] = None
    token_expires_at: Optional[datetime] = None

class UserAuthMetadataCreate(UserAuthMetadataBase):
    user_id: int

class UserAuthMetadataResponse(UserAuthMetadataBase):
    id: int
    user_id: int

# --- Notification Schemas ---
class NotificationTemplateBase(BaseSchema):
    """
    Base schema for notification templates.
    
    Attributes:
        name (str): Template name
        template_key (str): Unique key for the template
        subject (str): Email subject or notification title
        content (str): Template content/body
        notification_type (NotificationType): Type of notification
    """
    name: str
    template_key: str
    subject: str
    content: str
    notification_type: NotificationType

class NotificationTemplateCreate(NotificationTemplateBase):
    """Schema for creating a new notification template."""
    pass

class NotificationTemplateUpdate(BaseSchema):
    """
    Schema for updating a notification template.
    
    Attributes:
        name (Optional[str]): Template name
        subject (Optional[str]): Email subject or notification title
        content (Optional[str]): Template content/body
        notification_type (Optional[NotificationType]): Type of notification
        active (Optional[bool]): Whether the template is active
        status (Optional[str]): Template status
    """
    name: Optional[str] = None
    subject: Optional[str] = None
    content: Optional[str] = None
    notification_type: Optional[NotificationType] = None
    active: Optional[bool] = None
    status: Optional[str] = None

class NotificationTemplateResponse(NotificationTemplateBase):
    """
    Schema for notification template response.
    
    Attributes:
        template_id (int): Template ID
        active (bool): Whether the template is active
        status (Optional[str]): Template status
        created_at (datetime): When the template was created
    """
    template_id: int
    active: bool
    status: Optional[str] = None
    created_at: datetime

class UserNotificationBase(BaseSchema):
    """
    Base schema for user notifications.
    
    Attributes:
        user_id (Optional[int]): Target user ID
        target_type (Optional[str]): Type of notification target
        target_value (Optional[str]): Value of the target
        template_id (Optional[int]): ID of the notification template
        title (str): Notification title
        message (str): Notification message
        metadata (Optional[Dict[str, Any]]): Additional notification metadata
    """
    user_id: Optional[int] = None
    target_type: Optional[str] = None
    target_value: Optional[str] = None
    template_id: Optional[int] = None
    title: str
    message: str
    metadata: Optional[Dict[str, Any]] = None

class UserNotificationCreate(UserNotificationBase):
    """Schema for creating a new user notification."""
    pass

class UserNotificationUpdate(BaseSchema):
    """
    Schema for updating a user notification.
    
    Attributes:
        status (Optional[str]): Notification status
        read_at (Optional[datetime]): When the notification was read
    """
    status: Optional[str] = None
    read_at: Optional[datetime] = None

class UserNotificationResponse(UserNotificationBase):
    """
    Schema for user notification response.
    
    Attributes:
        notification_id (int): Notification ID
        status (str): Notification status
        created_at (datetime): When the notification was created
        sent_at (Optional[datetime]): When the notification was sent
        read_at (Optional[datetime]): When the notification was read
    """
    notification_id: int
    status: str
    created_at: datetime
    sent_at: Optional[datetime] = None
    read_at: Optional[datetime] = None

# --- Data Capture Schemas ---
class WorkOrderDataCaptureBase(BaseSchema):
    work_order_id: int
    request_type: RequestType
    agent_id: int
    offline_captured: Optional[bool] = False
    synced: Optional[bool] = True

class WorkOrderDataCaptureCreate(WorkOrderDataCaptureBase):
    pass

class WorkOrderDataCaptureUpdate(BaseSchema):
    offline_captured: Optional[bool] = None
    synced: Optional[bool] = None
    status: Optional[str] = None
    active: Optional[bool] = None

class WorkOrderDataCaptureResponse(WorkOrderDataCaptureBase):
    capture_id: int
    captured_at: datetime
    status: Optional[str] = None
    active: bool

class NewConnectionCaptureBase(BaseSchema):
    capture_id: int
    installation_checklist: Optional[str] = None
    initial_meter_reading: Optional[float] = None
    customer_contact: Optional[str] = None
    customer_address: Optional[str] = None
    id_proof_type: Optional[str] = None
    id_proof_number: Optional[str] = None

class NewConnectionCaptureCreate(NewConnectionCaptureBase):
    pass

class NewConnectionCaptureUpdate(BaseSchema):
    installation_checklist: Optional[str] = None
    initial_meter_reading: Optional[float] = None
    customer_contact: Optional[str] = None
    customer_address: Optional[str] = None
    id_proof_type: Optional[str] = None
    id_proof_number: Optional[str] = None
    status: Optional[str] = None
    active: Optional[bool] = None

class NewConnectionCaptureResponse(NewConnectionCaptureBase):
    status: Optional[str] = None
    active: bool

class SubscriptionCaptureBase(BaseSchema):
    capture_id: int
    plan_name: Optional[str] = None
    billing_cycle: Optional[str] = None
    service_features: Optional[str] = None
    discount_applied: Optional[bool] = False
    activation_status: Optional[str] = "PENDING"
    customer_preferences: Optional[str] = None

class SubscriptionCaptureCreate(SubscriptionCaptureBase):
    pass

class SubscriptionCaptureUpdate(BaseSchema):
    plan_name: Optional[str] = None
    billing_cycle: Optional[str] = None
    service_features: Optional[str] = None
    discount_applied: Optional[bool] = None
    activation_status: Optional[str] = None
    customer_preferences: Optional[str] = None
    active: Optional[bool] = None

class SubscriptionCaptureResponse(SubscriptionCaptureBase):
    active: bool

class ComplaintCaptureBase(BaseSchema):
    capture_id: int
    issue_description: Optional[str] = None
    affected_service: Optional[str] = None
    resolution_status: Optional[str] = "UNRESOLVED"
    attempted_fixes: Optional[str] = None
    evidence_url: Optional[str] = None

class ComplaintCaptureCreate(ComplaintCaptureBase):
    pass

class ComplaintCaptureUpdate(BaseSchema):
    issue_description: Optional[str] = None
    affected_service: Optional[str] = None
    resolution_status: Optional[str] = None
    attempted_fixes: Optional[str] = None
    evidence_url: Optional[str] = None
    active: Optional[bool] = None

class ComplaintCaptureResponse(ComplaintCaptureBase):
    active: bool

class TerminationCaptureBase(BaseSchema):
    capture_id: int
    final_meter_reading: Optional[float] = None
    disconnect_status: Optional[str] = "PENDING"
    termination_reason: Optional[str] = None
    service_end_date: Optional[datetime] = None
    final_billing_info: Optional[str] = None

class TerminationCaptureCreate(TerminationCaptureBase):
    pass

class TerminationCaptureUpdate(BaseSchema):
    final_meter_reading: Optional[float] = None
    disconnect_status: Optional[str] = None
    termination_reason: Optional[str] = None
    service_end_date: Optional[datetime] = None
    final_billing_info: Optional[str] = None
    active: Optional[bool] = None

class TerminationCaptureResponse(TerminationCaptureBase):
    active: bool

class OtherRequestCaptureBase(BaseSchema):
    capture_id: int
    custom_notes: Optional[str] = None
    additional_instructions: Optional[str] = None

class OtherRequestCaptureCreate(OtherRequestCaptureBase):
    pass

class OtherRequestCaptureUpdate(BaseSchema):
    custom_notes: Optional[str] = None
    additional_instructions: Optional[str] = None
    status: Optional[str] = None
    active: Optional[bool] = None

class OtherRequestCaptureResponse(OtherRequestCaptureBase):
    status: Optional[str] = None
    active: bool

class WorkOrderAcknowledgmentBase(BaseSchema):
    work_order_id: int
    agent_id: int
    acknowledgment_type: str
    notes: Optional[str] = None
    location: Optional[str] = None
    gps_lat: Optional[float] = None
    gps_long: Optional[float] = None

class WorkOrderAcknowledgmentCreate(BaseModel):
    work_order_id: int
    agent_id: int
    status: str  # e.g., "ACCEPTED", "REJECTED"
    remarks: Optional[str] = None
    customer_signature: Optional[str] = None

class WorkOrderAcknowledgmentUpdate(BaseSchema):
    acknowledgment_type: Optional[str] = None
    notes: Optional[str] = None
    location: Optional[str] = None
    gps_lat: Optional[float] = None
    gps_long: Optional[float] = None
    status: Optional[str] = None
    active: Optional[bool] = None

class WorkOrderAcknowledgmentResponse(WorkOrderAcknowledgmentBase):
    acknowledgment_id: int
    acknowledged_at: datetime
    status: Optional[str] = None
    active: bool

class WorkOrderNoteBase(BaseSchema):
    work_order_id: int
    agent_id: int
    note_text: str
    note_type: Optional[str] = None
    visibility: Optional[str] = "internal"  # internal/external

class WorkOrderNoteCreate(WorkOrderNoteBase):
    pass

class WorkOrderNoteUpdate(BaseSchema):
    note_text: Optional[str] = None
    note_type: Optional[str] = None
    visibility: Optional[str] = None
    status: Optional[str] = None
    active: Optional[bool] = None

class WorkOrderNoteResponse(WorkOrderNoteBase):
    note_id: int
    created_at: datetime
    updated_at: Optional[datetime] = None
    status: Optional[str] = None
    active: bool

class WorkOrderStatusLogBase(BaseSchema):
    work_order_id: int
    old_status: WorkOrderStatus
    new_status: WorkOrderStatus
    changed_by: int
    reason: Optional[str] = None
    notes: Optional[str] = None

class WorkOrderStatusLogCreate(WorkOrderStatusLogBase):
    pass

class WorkOrderStatusLogUpdate(BaseSchema):
    reason: Optional[str] = None
    notes: Optional[str] = None
    active: Optional[bool] = None

class WorkOrderStatusLogResponse(BaseModel):
    status_log_id: int
    status: str
    changed_at: datetime
    changed_by: int

class WorkOrderAttachmentBase(BaseSchema):
    work_order_id: int
    file_name: str
    file_path: str
    file_type: str
    file_size: int
    uploaded_by: int
    description: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

class WorkOrderAttachmentCreate(WorkOrderAttachmentBase):
    pass

class WorkOrderAttachmentUpdate(BaseSchema):
    description: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None
    status: Optional[str] = None
    active: Optional[bool] = None

class WorkOrderAttachmentResponse(WorkOrderAttachmentBase):
    attachment_id: int
    uploaded_at: datetime
    status: Optional[str] = None
    active: bool

class WorkOrderFeedbackBase(BaseSchema):
    work_order_id: int
    agent_id: int
    rating: int
    feedback_text: Optional[str] = None
    feedback_type: str  # customer/agent/supervisor
    feedback_category: Optional[str] = None

class WorkOrderFeedbackCreate(WorkOrderFeedbackBase):
    pass

class WorkOrderFeedbackUpdate(BaseSchema):
    rating: Optional[int] = None
    feedback_text: Optional[str] = None
    feedback_category: Optional[str] = None
    status: Optional[str] = None
    active: Optional[bool] = None

class WorkOrderFeedbackResponse(WorkOrderFeedbackBase):
    feedback_id: int
    submitted_at: datetime
    status: Optional[str] = None
    active: bool

class UpdateProfileRequest(BaseSchema):
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    profile_image: Optional[str] = None
    preferred_lang: Optional[str] = None
    timezone_id: Optional[str] = None
    phone_number: Optional[str] = None
    address: Optional[str] = None
    bio: Optional[str] = None

class DeviceHealthLogBase(BaseSchema):
    device_id: int
    health_status: str  # HEALTHY, WARNING, CRITICAL
    cpu_usage: Optional[float] = None
    memory_usage: Optional[float] = None
    disk_usage: Optional[float] = None
    battery_level: Optional[float] = None
    signal_strength: Optional[float] = None
    temperature: Optional[float] = None
    error_code: Optional[str] = None
    error_message: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

class DeviceHealthLogCreate(DeviceHealthLogBase):
    pass

class DeviceHealthLogUpdate(BaseSchema):
    health_status: Optional[str] = None
    cpu_usage: Optional[float] = None
    memory_usage: Optional[float] = None
    disk_usage: Optional[float] = None
    battery_level: Optional[float] = None
    signal_strength: Optional[float] = None
    temperature: Optional[float] = None
    error_code: Optional[str] = None
    error_message: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None
    status: Optional[str] = None
    active: Optional[bool] = None

class DeviceHealthLogResponse(DeviceHealthLogBase):
    log_id: int
    logged_at: datetime
    status: Optional[str] = None
    active: bool

class SystemFeedbackRequest(BaseModel):
    category: str = Field(..., description="Feedback category, e.g., BUG, FEATURE, etc.")
    subject: str = Field(..., description="Short summary of the feedback")
    description: str = Field(..., description="Detailed feedback description")
    priority: str = Field("MEDIUM", description="Priority of the feedback: LOW, MEDIUM, HIGH")

class SystemFeedbackResponse(BaseModel):
    feedback_id: int
    user_id: int
    category: str
    subject: str
    description: str
    priority: str
    status: str
    submitted_at: datetime
    active: bool

    class Config:
        from_attributes = True

class WorkOrderDetailResponse(BaseModel):
    work_order_id: int
    wo_number: str
    title: str
    description: Optional[str] = None
    work_order_type: Optional[str] = None
    customer_id: Optional[str] = None
    customer_name: Optional[str] = None
    scheduled_date: Optional[datetime] = None
    due_date: Optional[datetime] = None
    priority: str
    status: str
    created_by: int
    work_centre_id: int
    created_at: datetime
    updated_at: datetime
    active: bool
    assignments: List[WorkOrderAssignmentResponse]
    status_logs: List[WorkOrderStatusLogResponse]