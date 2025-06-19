from sqlalchemy import (
    Column, Integer, String, Boolean, DateTime, ForeignKey, Text, Enum as SQLAlchemyEnum, DECIMAL, JSON, BigInteger
)
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import JSONB
import datetime as dt
from enum import Enum
from db.database import Base
from sqlalchemy.ext.hybrid import hybrid_property
from datetime import datetime
from typing import Dict, Any

# --- Enums ---
class UserStatus(str, Enum):
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"
    BLOCKED = "BLOCKED"
    DEACTIVATED = "DEACTIVATED"

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
    UNREGISTERED = "UNREGISTERED"
    IN_SERVICE = "IN_SERVICE"
    OUT_OF_SERVICE = "OUT_OF_SERVICE"

class DeviceSourceType(str, Enum):
    PURCHASED = "PURCHASED"
    LEASED = "LEASED"
    OWNED = "OWNED"

class DeviceSourceDestination(str, Enum):
    REGIONAL_PLANET = "REGIONAL_PLANET"
    CENTER_PLANET = "CENTER_PLANET"
    OTHER = "OTHER"

class DeviceAssignmentRole(str, Enum):
    TECHNICIAN = "TECHNICIAN"
    SUPERVISOR = "SUPERVISOR"
    OTHER = "OTHER"

# --- Models ---
class User(Base):
    __tablename__ = "users"

    user_id = Column(BigInteger, primary_key=True)
    uuid = Column(String(75), unique=True)
    username = Column(String(100), unique=True, nullable=False)
    email = Column(String(150), unique=True, nullable=False)
    password_hash = Column(String(100), nullable=False)
    
    first_name = Column(String(50))
    last_name = Column(String(50))
    profile_image = Column(String(256))
    preferred_lang = Column(String(10))
    timezone_id = Column(String(75))
    
    is_2fa_enabled = Column(Boolean, default=False)
    activated = Column(Boolean, default=True)
    status = Column(SQLAlchemyEnum(UserStatus), default=UserStatus.ACTIVE)
    
    external_id = Column(String(75))
    token = Column(Text)
    activation_key = Column(String(64))
    reset_key = Column(String(64))
    
    login_ip = Column(String(75))
    last_login_ip = Column(String(75))
    login_date = Column(DateTime)
    last_login = Column(DateTime)
    
    created_by = Column(String(50), nullable=False)
    created_at = Column(DateTime, default=dt.datetime.utcnow)
    reset_at = Column(DateTime)
    last_modified_by = Column(String(50))
    updated_at = Column(DateTime, default=dt.datetime.utcnow)

    # Relationships
    roles = relationship("UserRole", back_populates="user")
    auth_providers = relationship("UserAuthProvider", back_populates="user")
    auth_metadata = relationship("UserAuthMetadata", back_populates="user")
    notifications = relationship("UserNotification", back_populates="user")
    status_audits = relationship("UserStatusAudit", back_populates="user")
    notification_preferences = relationship("UserNotificationPreferences", back_populates="user", uselist=False)
    tokens = relationship("Token", back_populates="user")

    @hybrid_property
    def user_id_value(self) -> int:
        """Get user_id as a plain integer."""
        val = getattr(self, "user_id", None)
        if isinstance(val, int):
            return val
        if val is None:
            return 0
        try:
            return int(val)
        except (TypeError, ValueError):
            return 0

    @hybrid_property
    def uuid_value(self) -> str:
        """Get uuid as a plain string."""
        return str(self.uuid) if self.uuid is not None else ""

    @hybrid_property
    def username_value(self) -> str:
        """Get username as a plain string."""
        return str(self.username) if self.username is not None else ""

    @hybrid_property
    def email_value(self) -> str:
        """Get email as a plain string."""
        return str(self.email) if self.email is not None else ""

    @hybrid_property
    def first_name_value(self) -> str:
        """Get first_name as a plain string."""
        return str(self.first_name) if self.first_name is not None else ""

    @hybrid_property
    def last_name_value(self) -> str:
        """Get last_name as a plain string."""
        return str(self.last_name) if self.last_name is not None else ""

    @hybrid_property
    def status_value(self) -> str:
        """Get status as a plain string."""
        return str(self.status) if self.status is not None else ""

    @hybrid_property
    def created_at_value(self) -> datetime:
        """Get created_at as a plain datetime."""
        val = getattr(self, "created_at", None)
        if isinstance(val, datetime):
            return val
        if val is None:
            return datetime.utcnow()
        try:
            if isinstance(val, str):
                return datetime.fromisoformat(val)
            return datetime.fromtimestamp(float(val))
        except (TypeError, ValueError):
            return datetime.utcnow()

    @hybrid_property
    def updated_at_value(self) -> datetime:
        """Get updated_at as a plain datetime."""
        val = getattr(self, "updated_at", None)
        if isinstance(val, datetime):
            return val
        if val is None:
            return datetime.utcnow()
        try:
            if isinstance(val, str):
                return datetime.fromisoformat(val)
            return datetime.fromtimestamp(float(val))
        except (TypeError, ValueError):
            return datetime.utcnow()

    def to_dict(self) -> Dict[str, Any]:
        """Convert User model to dictionary."""
        return {
            "user_id": self.user_id_value,
            "uuid": self.uuid_value,
            "username": self.username_value,
            "email": self.email_value,
            "first_name": self.first_name_value,
            "last_name": self.last_name_value,
            "status": self.status_value,
            "created_at": self.created_at_value,
            "updated_at": self.updated_at_value
        }

class UserNotificationPreferences(Base):
    __tablename__ = "user_notification_preferences"

    id = Column(BigInteger, primary_key=True)
    user_id = Column(BigInteger, ForeignKey("users.user_id"), unique=True)
    email_enabled = Column(Boolean, default=True)
    sms_enabled = Column(Boolean, default=False)
    push_enabled = Column(Boolean, default=True)
    in_app_enabled = Column(Boolean, default=True)
    quiet_hours_start = Column(String(5))  # Format: "HH:MM"
    quiet_hours_end = Column(String(5))    # Format: "HH:MM"
    timezone = Column(String(50))
    created_at = Column(DateTime, default=dt.datetime.utcnow)
    updated_at = Column(DateTime, default=dt.datetime.utcnow)

    # Relationships
    user = relationship("User", back_populates="notification_preferences")

class UserNotification(Base):
    __tablename__ = "user_notifications"

    notification_id = Column(BigInteger, primary_key=True)
    user_id = Column(BigInteger, ForeignKey("users.user_id"))
    template_id = Column(BigInteger, ForeignKey("notification_templates.template_id"))
    title = Column(String(255), nullable=False)
    message = Column(Text, nullable=False)
    status = Column(String(20), default="PENDING")  # PENDING, SENT, FAILED, READ
    notification_metadata = Column(JSON)
    created_at = Column(DateTime, default=dt.datetime.utcnow)
    sent_at = Column(DateTime)
    read_at = Column(DateTime)

    # Relationships
    user = relationship("User", back_populates="notifications")
    template = relationship("NotificationTemplate")

class UserAuthProvider(Base):
    __tablename__ = "user_auth_providers"

    id = Column(BigInteger, primary_key=True)
    user_id = Column(BigInteger, ForeignKey("users.user_id"))
    provider = Column(String(20), nullable=False)  # LOCAL, AZURE, GOOGLE, FACEBOOK
    provider_user_id = Column(String(150), nullable=False)
    provider_username = Column(String(150))
    created_at = Column(DateTime, default=dt.datetime.utcnow)
    updated_at = Column(DateTime, default=dt.datetime.utcnow)

    # Relationships
    user = relationship("User", back_populates="auth_providers")

class UserAuthMetadata(Base):
    __tablename__ = "user_auth_metadata"

    id = Column(BigInteger, primary_key=True)
    user_id = Column(BigInteger, ForeignKey("users.user_id"))
    provider = Column(String(50))
    external_user_id = Column(String(100))
    access_token = Column(Text)
    refresh_token = Column(Text)
    token_expires_at = Column(DateTime)

    # Relationships
    user = relationship("User", back_populates="auth_metadata")

class NotificationTemplate(Base):
    __tablename__ = "notification_templates"

    template_id = Column(BigInteger, primary_key=True)
    name = Column(String(100), nullable=False)
    template_key = Column(String(50), nullable=False, unique=True)
    subject = Column(String(255), nullable=False)
    content = Column(Text, nullable=False)
    notification_type = Column(SQLAlchemyEnum(NotificationType), nullable=False)
    active = Column(Boolean, default=True)
    status = Column(String(75))
    created_at = Column(DateTime, default=dt.datetime.utcnow)

    # Relationships
    notifications = relationship("UserNotification", back_populates="template")

class NotificationHistory(Base):
    __tablename__ = "notification_history"

    history_id = Column(BigInteger, primary_key=True)
    notification_id = Column(BigInteger, ForeignKey("user_notifications.notification_id"))
    status = Column(String(20), nullable=False)  # SENT, FAILED, READ
    error_message = Column(Text)
    delivery_timestamp = Column(DateTime, default=dt.datetime.utcnow)
    delivery_metadata = Column(JSON)

    # Relationships
    notification = relationship("UserNotification")

class Role(Base):
    __tablename__ = "roles"

    role_id = Column(BigInteger, primary_key=True)
    role_name = Column(String(100), unique=True, nullable=False)
    description = Column(Text)
    status = Column(String(75))
    active = Column(Boolean, default=True)
    created_by = Column(String(50), nullable=False)
    created_at = Column(DateTime, default=dt.datetime.utcnow)
    last_modified_by = Column(String(50))
    updated_at = Column(DateTime, default=dt.datetime.utcnow)

    # Relationships
    user_roles = relationship("UserRole", back_populates="role")
    permissions = relationship("RolePermission", back_populates="role")

class UserRole(Base):
    __tablename__ = "user_roles"

    id = Column(BigInteger, primary_key=True)
    role_id = Column(BigInteger, ForeignKey("roles.role_id"))
    user_id = Column(BigInteger, ForeignKey("users.user_id"))
    created_at = Column(DateTime, default=dt.datetime.utcnow)
    updated_at = Column(DateTime, default=dt.datetime.utcnow)
    status = Column(String(75))
    active = Column(Boolean, default=True)

    # Relationships
    user = relationship("User", back_populates="roles")
    role = relationship("Role", back_populates="user_roles")

class Permission(Base):
    __tablename__ = "permissions"

    permission_id = Column(BigInteger, primary_key=True)
    feature = Column(String(100), nullable=False)
    description = Column(Text)
    created_by = Column(String(50), nullable=False)
    created_at = Column(DateTime, default=dt.datetime.utcnow)
    last_modified_by = Column(String(50))
    updated_at = Column(DateTime, default=dt.datetime.utcnow)
    status = Column(String(75))
    active = Column(Boolean, default=True)

    # Relationships
    role_permissions = relationship("RolePermission", back_populates="permission")

class RolePermission(Base):
    __tablename__ = "role_permissions"

    role_id = Column(BigInteger, ForeignKey("roles.role_id"), primary_key=True)
    permission_id = Column(BigInteger, ForeignKey("permissions.permission_id"), primary_key=True)
    status = Column(String(75))
    active = Column(Boolean, default=True)
    created_by = Column(String(50), nullable=False)
    created_at = Column(DateTime, default=dt.datetime.utcnow)
    last_modified_by = Column(String(50))
    updated_at = Column(DateTime, default=dt.datetime.utcnow)

    # Relationships
    role = relationship("Role", back_populates="permissions")
    permission = relationship("Permission", back_populates="role_permissions")

class UserStatusAudit(Base):
    __tablename__ = "user_status_audit"

    id = Column(BigInteger, primary_key=True)
    user_id = Column(BigInteger, ForeignKey("users.user_id"))
    changed_by = Column(String(50), nullable=False)
    old_status = Column(SQLAlchemyEnum(UserStatus), nullable=False)
    new_status = Column(SQLAlchemyEnum(UserStatus), nullable=False)
    reason = Column(Text, nullable=False)
    remarks = Column(Text)
    changed_at = Column(DateTime, default=dt.datetime.utcnow)

    # Relationships
    user = relationship("User", back_populates="status_audits")

class Token(Base):
    __tablename__ = "auth_tokens"

    id = Column(BigInteger, primary_key=True, index=True)
    user_id = Column(BigInteger, ForeignKey("users.user_id", ondelete="CASCADE"))
    access_token = Column(Text, nullable=False, unique=True)
    refresh_token = Column(Text, nullable=False, unique=True)
    expires_at = Column(DateTime, nullable=True)
    revoked = Column(Boolean, default=False)
    created_at = Column(DateTime, default=dt.datetime.utcnow)
    last_used_at = Column(DateTime, nullable=True)
    ip_address = Column(String(100), nullable=True)
    device_info = Column(Text, nullable=True)

    user = relationship("User", back_populates="tokens")

    def __repr__(self):
        return f"<AuthToken(user_id='{self.user_id}')>"

class Device(Base):
    __tablename__ = "devices"

    device_id = Column(BigInteger, primary_key=True)
    serial_number = Column(String(100), unique=True)
    model = Column(String(100))
    status = Column(SQLAlchemyEnum(DeviceStatus), default=DeviceStatus.REGISTERED)
    last_communication = Column(DateTime)
    location = Column(String(100))
    work_center_id = Column(BigInteger, ForeignKey("work_centres.work_centre_id"))
    created_at = Column(DateTime, default=dt.datetime.utcnow)
    updated_at = Column(DateTime, default=dt.datetime.utcnow)
    active = Column(Boolean, default=True)

    # Relationships
    work_center = relationship("WorkCentre", back_populates="devices")
    artifacts = relationship("DeviceArtifact", back_populates="device")
    assignments = relationship("DeviceAssignment", back_populates="device")
    health_logs = relationship("DeviceHealthLog", back_populates="device")
    status_audits = relationship("DeviceStatusAudit", back_populates="device")

class DeviceArtifact(Base):
    __tablename__ = "device_artifacts"

    artifact_id = Column(BigInteger, primary_key=True)
    device_id = Column(BigInteger, ForeignKey("devices.device_id"), nullable=False)
    source_type = Column(SQLAlchemyEnum(DeviceSourceType), nullable=False)
    source_reference = Column(String(255))
    source_details = Column(JSONB)
    source_destination = Column(SQLAlchemyEnum(DeviceSourceDestination))
    acquisition_date = Column(DateTime)
    added_by = Column(BigInteger, ForeignKey("users.user_id"))
    remarks = Column(Text)
    status = Column(String(75))
    active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=dt.datetime.utcnow)

    # Relationships
    device = relationship("Device", back_populates="artifacts")
    added_by_user = relationship("User")

class DeviceAssignment(Base):
    __tablename__ = "device_assignments"

    assignment_id = Column(BigInteger, primary_key=True)
    device_id = Column(BigInteger, ForeignKey("devices.device_id"), nullable=False)
    user_id = Column(BigInteger, ForeignKey("users.user_id"))
    role = Column(SQLAlchemyEnum(DeviceAssignmentRole))
    assigned_by_user_id = Column(BigInteger, ForeignKey("users.user_id"))
    assigned_by_role = Column(SQLAlchemyEnum(DeviceAssignmentRole))
    assigned_at = Column(DateTime, default=dt.datetime.utcnow)
    unassigned_at = Column(DateTime)
    status = Column(String(50))
    active = Column(Boolean, default=True)
    updated_at = Column(DateTime, default=dt.datetime.utcnow)

    # Relationships
    device = relationship("Device", back_populates="assignments")
    user = relationship("User", foreign_keys=[user_id])
    assigned_by = relationship("User", foreign_keys=[assigned_by_user_id])

class DeviceHealthLog(Base):
    __tablename__ = "device_health_logs"

    health_id = Column(BigInteger, primary_key=True)
    device_id = Column(BigInteger, ForeignKey("devices.device_id"))
    battery_status = Column(String(20))
    network_status = Column(String(20))
    touch_screen = Column(String(20))
    camera_status = Column(String(20))
    gps_status = Column(String(20))
    logged_by = Column(BigInteger, ForeignKey("users.user_id"))
    logged_at = Column(DateTime, default=dt.datetime.utcnow)
    status = Column(String(50))
    active = Column(Boolean, default=True)

    # Relationships
    device = relationship("Device", back_populates="health_logs")
    user = relationship("User")

class DeviceStatusAudit(Base):
    __tablename__ = "device_status_audit"

    audit_id = Column(BigInteger, primary_key=True)
    device_id = Column(BigInteger, ForeignKey("devices.device_id"))
    status_before = Column(String(50))
    status_after = Column(String(50))
    reason = Column(Text)
    changed_by_user_id = Column(BigInteger, ForeignKey("users.user_id"))
    changed_at = Column(DateTime, default=dt.datetime.utcnow)
    status = Column(String(75))
    active = Column(Boolean, default=True)

    # Relationships
    device = relationship("Device", back_populates="status_audits")
    changed_by = relationship("User")

class WorkCentre(Base):
    __tablename__ = "work_centres"

    work_centre_id = Column(BigInteger, primary_key=True)
    name = Column(String(255), nullable=False)
    registration_number = Column(String(100), unique=True)
    tax_id = Column(String(100))
    
    contact_email = Column(String(150))
    contact_phone = Column(String(50))
    website_url = Column(String(255))
    
    address_line1 = Column(String(255))
    address_line2 = Column(String(255))
    city = Column(String(100))
    state = Column(String(100))
    postal_code = Column(String(20))
    country = Column(String(100))

    status = Column(String(75), default="ACTIVE")
    active = Column(Boolean, default=True)
    
    created_at = Column(DateTime, default=dt.datetime.utcnow)
    updated_at = Column(DateTime, default=dt.datetime.utcnow)
    created_by = Column(BigInteger, ForeignKey("users.user_id"))
    updated_by = Column(BigInteger, ForeignKey("users.user_id"))

    # Relationships
    devices = relationship("Device", back_populates="work_center")
    created_by_user = relationship("User", foreign_keys=[created_by])
    updated_by_user = relationship("User", foreign_keys=[updated_by])

class WorkOrder(Base):
    __tablename__ = "work_orders"

    work_order_id = Column(BigInteger, primary_key=True)
    wo_number = Column(String(100), unique=True, nullable=False)
    title = Column(String(255))
    description = Column(Text)
    work_order_type = Column(String(100))
    customer_id = Column(String(100))
    customer_name = Column(String(255))
    location = Column(String(255))
    latitude = Column(DECIMAL(10, 8))
    longitude = Column(DECIMAL(11, 8))
    scheduled_date = Column(DateTime)
    due_date = Column(DateTime)
    priority = Column(String(10), default="MEDIUM")
    status = Column(SQLAlchemyEnum(WorkOrderStatus), default=WorkOrderStatus.PENDING)
    created_by = Column(BigInteger, ForeignKey("users.user_id"))
    work_centre_id = Column(BigInteger, ForeignKey("work_centres.work_centre_id"))
    created_at = Column(DateTime, default=dt.datetime.utcnow)
    updated_at = Column(DateTime, default=dt.datetime.utcnow)
    active = Column(Boolean, default=True)

    # Relationships
    creator = relationship("User", foreign_keys=[created_by])
    work_centre = relationship("WorkCentre")
    assignments = relationship("WorkOrderAssignment", back_populates="work_order")
    executions = relationship("WorkOrderExecution", back_populates="work_order")
    acknowledgments = relationship("WorkOrderAcknowledgment", back_populates="work_order")
    notes = relationship("WorkOrderNote", back_populates="work_order")
    status_logs = relationship("WorkOrderStatusLog", back_populates="work_order")
    attachments = relationship("WorkOrderAttachment", back_populates="work_order")
    feedback = relationship("WorkOrderFeedback", back_populates="work_order")

class WorkOrderAssignment(Base):
    __tablename__ = "work_order_assignments"

    assignment_id = Column(BigInteger, primary_key=True)
    work_order_id = Column(BigInteger, ForeignKey("work_orders.work_order_id"), nullable=False)
    agent_id = Column(BigInteger, ForeignKey("users.user_id"), nullable=False)
    assigned_by = Column(BigInteger, ForeignKey("users.user_id"), nullable=False)
    reassigned = Column(Boolean, default=False)
    reassignment_reason = Column(Text)
    assigned_at = Column(DateTime, default=dt.datetime.utcnow)
    status = Column(String(75))
    active = Column(Boolean, default=True)
    updated_at = Column(DateTime, default=dt.datetime.utcnow)

    # Relationships
    work_order = relationship("WorkOrder", back_populates="assignments")
    agent = relationship("User", foreign_keys=[agent_id])
    assigner = relationship("User", foreign_keys=[assigned_by])

class WorkOrderExecution(Base):
    __tablename__ = "work_order_execution"

    execution_id = Column(BigInteger, primary_key=True)
    work_order_id = Column(BigInteger, ForeignKey("work_orders.work_order_id"), nullable=False)
    agent_id = Column(BigInteger, ForeignKey("users.user_id"))
    start_time = Column(DateTime)
    end_time = Column(DateTime)
    gps_lat = Column(DECIMAL(10, 8))
    gps_long = Column(DECIMAL(11, 8))
    parts_used = Column(Text)
    synced = Column(Boolean, default=False)
    status = Column(String(75))
    active = Column(Boolean, default=True)

    # Relationships
    work_order = relationship("WorkOrder", back_populates="executions")
    agent = relationship("User")
    anomalies = relationship("WorkOrderExecutionAnomaly", back_populates="execution")

class Anomaly(Base):
    __tablename__ = "anomalies"

    anomaly_id = Column(BigInteger, primary_key=True)
    name = Column(String(100), unique=True, nullable=False)
    description = Column(Text)
    status = Column(String(75))
    active = Column(Boolean, default=True)

    # Relationships
    execution_anomalies = relationship("WorkOrderExecutionAnomaly", back_populates="anomaly")

class WorkOrderExecutionAnomaly(Base):
    __tablename__ = "work_order_execution_anomalies"

    id = Column(BigInteger, primary_key=True)
    execution_id = Column(BigInteger, ForeignKey("work_order_execution.execution_id", ondelete="CASCADE"))
    anomaly_id = Column(BigInteger, ForeignKey("anomalies.anomaly_id", ondelete="RESTRICT"))
    active = Column(Boolean, default=True)

    # Relationships
    execution = relationship("WorkOrderExecution", back_populates="anomalies")
    anomaly = relationship("Anomaly", back_populates="execution_anomalies")

class WorkOrderAcknowledgment(Base):
    __tablename__ = "work_order_acknowledgments"

    ack_id = Column(BigInteger, primary_key=True)
    work_order_id = Column(BigInteger, ForeignKey("work_orders.work_order_id"), nullable=False)
    agent_id = Column(BigInteger, ForeignKey("users.user_id"))
    customer_signature = Column(Text)
    remarks = Column(Text)
    acknowledged_at = Column(DateTime, default=dt.datetime.utcnow)
    status = Column(String(75))
    active = Column(Boolean, default=True)

    # Relationships
    work_order = relationship("WorkOrder", back_populates="acknowledgments")
    agent = relationship("User")

class WorkOrderNote(Base):
    __tablename__ = "work_order_notes"

    note_id = Column(BigInteger, primary_key=True)
    work_order_id = Column(BigInteger, ForeignKey("work_orders.work_order_id"), nullable=False)
    added_by = Column(BigInteger, ForeignKey("users.user_id"), nullable=False)
    note = Column(Text)
    note_type = Column(String(20))  # FIELD_AGENT, REVIEWER, SYSTEM
    added_at = Column(DateTime, default=dt.datetime.utcnow)
    status = Column(String(75))
    active = Column(Boolean, default=True)

    # Relationships
    work_order = relationship("WorkOrder", back_populates="notes")
    author = relationship("User")

class WorkOrderStatusLog(Base):
    __tablename__ = "work_order_status_logs"

    status_log_id = Column(BigInteger, primary_key=True)
    work_order_id = Column(BigInteger, ForeignKey("work_orders.work_order_id"), nullable=False)
    previous_status = Column(String(50))
    new_status = Column(String(50))
    changed_by = Column(BigInteger, ForeignKey("users.user_id"))
    reason = Column(Text)
    changed_at = Column(DateTime, default=dt.datetime.utcnow)
    status = Column(String(75))
    active = Column(Boolean, default=True)

    # Relationships
    work_order = relationship("WorkOrder", back_populates="status_logs")
    user = relationship("User")

class WorkOrderAttachment(Base):
    __tablename__ = "work_order_attachments"

    attachment_id = Column(BigInteger, primary_key=True)
    work_order_id = Column(BigInteger, ForeignKey("work_orders.work_order_id"), nullable=False)
    file_path = Column(Text)
    file_name = Column(String(255))
    type = Column(String(20))  # IMAGE, DOCUMENT, SIGNATURE
    uploaded_by = Column(BigInteger, ForeignKey("users.user_id"))
    uploaded_at = Column(DateTime, default=dt.datetime.utcnow)
    status = Column(String(75))
    active = Column(Boolean, default=True)

    # Relationships
    work_order = relationship("WorkOrder", back_populates="attachments")
    uploader = relationship("User")

class WorkOrderFeedback(Base):
    __tablename__ = "work_order_feedback"

    feedback_id = Column(BigInteger, primary_key=True)
    work_order_id = Column(BigInteger, ForeignKey("work_orders.work_order_id"), nullable=False)
    feedback_by = Column(BigInteger, ForeignKey("users.user_id"))
    feedback_type = Column(String(20))  # REVIEW, REWORK_REQUEST, COMMENT
    comments = Column(Text)
    feedback_at = Column(DateTime, default=dt.datetime.utcnow)
    status = Column(String(75))
    active = Column(Boolean, default=True)

    # Relationships
    work_order = relationship("WorkOrder", back_populates="feedback")
    user = relationship("User")

# Data Capture Module
class WorkOrderDataCapture(Base):
    __tablename__ = "work_order_data_capture"

    capture_id = Column(BigInteger, primary_key=True)
    work_order_id = Column(BigInteger, ForeignKey("work_orders.work_order_id"), nullable=False)
    request_type = Column(SQLAlchemyEnum(RequestType), nullable=False)
    agent_id = Column(BigInteger, ForeignKey("users.user_id"), nullable=False)
    captured_at = Column(DateTime, default=dt.datetime.utcnow)
    offline_captured = Column(Boolean, default=False)
    synced = Column(Boolean, default=True)
    status = Column(String(75))
    active = Column(Boolean, default=True)

    # Relationships
    work_order = relationship("WorkOrder")
    agent = relationship("User")
    validation_logs = relationship("DataCaptureValidationLog", back_populates="capture")
    offline_queue = relationship("OfflineCaptureQueue", back_populates="capture")

class DataCaptureValidationLog(Base):
    __tablename__ = "data_capture_validation_logs"

    validation_id = Column(BigInteger, primary_key=True)
    capture_id = Column(BigInteger, ForeignKey("work_order_data_capture.capture_id", ondelete="CASCADE"))
    field_name = Column(String(100))
    error_message = Column(Text)
    resolved = Column(Boolean, default=False)
    logged_at = Column(DateTime, default=dt.datetime.utcnow)
    status = Column(String(75))
    active = Column(Boolean, default=True)

    # Relationships
    capture = relationship("WorkOrderDataCapture", back_populates="validation_logs")

class OfflineCaptureQueue(Base):
    __tablename__ = "offline_capture_queue"

    queue_id = Column(BigInteger, primary_key=True)
    capture_id = Column(BigInteger, ForeignKey("work_order_data_capture.capture_id", ondelete="CASCADE"))
    device_id = Column(String(100))
    sync_status = Column(String(20), default="PENDING")  # PENDING, SYNCED, FAILED
    last_attempt = Column(DateTime)
    active = Column(Boolean, default=True)

    # Relationships
    capture = relationship("WorkOrderDataCapture", back_populates="offline_queue")

# Picture Module
class PictureMetadata(Base):
    __tablename__ = "picture_metadata"

    picture_id = Column(BigInteger, primary_key=True)
    work_order_id = Column(BigInteger, ForeignKey("work_orders.work_order_id"), nullable=False)
    agent_id = Column(BigInteger, ForeignKey("users.user_id"), nullable=False)
    request_type = Column(SQLAlchemyEnum(RequestType), nullable=False)
    meter_number = Column(String(100))
    supply_point_number = Column(String(100))
    cycle = Column(String(50))
    location = Column(String(255))
    file_name = Column(String(255))
    file_path = Column(Text, nullable=False)
    file_format = Column(String(10))
    captured_at = Column(DateTime, default=dt.datetime.utcnow)
    status = Column(String(75))
    active = Column(Boolean, default=True)

    # Relationships
    work_order = relationship("WorkOrder")
    agent = relationship("User")
    qualifications = relationship("PictureQualification", back_populates="picture")
    annotations = relationship("PictureAnnotation", back_populates="picture")
    downloads = relationship("PictureDownloadLog", back_populates="picture")

class PictureQualification(Base):
    __tablename__ = "picture_qualification"

    qualification_id = Column(BigInteger, primary_key=True)
    picture_id = Column(BigInteger, ForeignKey("picture_metadata.picture_id", ondelete="CASCADE"))
    qualified_by = Column(BigInteger, ForeignKey("users.user_id"))
    qualification_status = Column(String(10), nullable=False)  # OK, NOT_OK
    comments = Column(Text)
    qualified_at = Column(DateTime, default=dt.datetime.utcnow)
    active = Column(Boolean, default=True)

    # Relationships
    picture = relationship("PictureMetadata", back_populates="qualifications")
    qualifier = relationship("User")

class OcrTechnique(Base):
    __tablename__ = "ocr_techniques"

    ocr_id = Column(BigInteger, primary_key=True)
    technique_name = Column(String(100), unique=True, nullable=False)
    description = Column(Text)
    status = Column(String(75))
    active = Column(Boolean, default=True)

    # Relationships
    annotations = relationship("PictureAnnotation", back_populates="ocr_technique")

class PictureAnnotation(Base):
    __tablename__ = "picture_annotation"

    annotation_id = Column(BigInteger, primary_key=True)
    picture_id = Column(BigInteger, ForeignKey("picture_metadata.picture_id", ondelete="CASCADE"))
    annotated_by = Column(BigInteger, ForeignKey("users.user_id"))
    ocr_id = Column(BigInteger, ForeignKey("ocr_techniques.ocr_id", ondelete="RESTRICT"))
    annotation_data = Column(Text)
    created_at = Column(DateTime, default=dt.datetime.utcnow)
    status = Column(String(75))
    active = Column(Boolean, default=True)

    # Relationships
    picture = relationship("PictureMetadata", back_populates="annotations")
    annotator = relationship("User")
    ocr_technique = relationship("OcrTechnique", back_populates="annotations")

class PictureDownloadLog(Base):
    __tablename__ = "picture_download_log"

    download_id = Column(BigInteger, primary_key=True)
    picture_id = Column(BigInteger, ForeignKey("picture_metadata.picture_id", ondelete="SET NULL"))
    downloaded_by = Column(BigInteger, ForeignKey("users.user_id"))
    is_batch = Column(Boolean, default=False)
    format = Column(String(10))
    downloaded_at = Column(DateTime, default=dt.datetime.utcnow)
    status = Column(String(75))
    active = Column(Boolean, default=True)

    # Relationships
    picture = relationship("PictureMetadata", back_populates="downloads")
    downloader = relationship("User")

class PictureQualityMetrics(Base):
    __tablename__ = "picture_quality_metrics"

    metric_id = Column(BigInteger, primary_key=True)
    agent_id = Column(BigInteger, ForeignKey("users.user_id"))
    total_uploaded = Column(Integer, default=0)
    total_ok = Column(Integer, default=0)
    total_not_ok = Column(Integer, default=0)
    last_updated = Column(DateTime, default=dt.datetime.utcnow)
    status = Column(String(75))
    active = Column(Boolean, default=True)

    # Relationships
    agent = relationship("User")

# Admin Module
class SubcontractorCompany(Base):
    __tablename__ = "subcontractor_companies"

    subcontractor_id = Column(BigInteger, primary_key=True)
    company_name = Column(String(255), nullable=False)
    telephone = Column(String(50))
    email = Column(String(150))
    description = Column(Text)
    location = Column(String(255))
    created_at = Column(DateTime, default=dt.datetime.utcnow)
    status = Column(String(75))
    active = Column(Boolean, default=True)

    # Relationships
    work_centre_assignments = relationship("WorkCentreSubcontractor", back_populates="subcontractor")

class WorkCentreSubcontractor(Base):
    __tablename__ = "work_centre_subcontractors"

    assignment_id = Column(BigInteger, primary_key=True)
    work_centre_id = Column(BigInteger, ForeignKey("work_centres.work_centre_id"))
    subcontractor_id = Column(BigInteger, ForeignKey("subcontractor_companies.subcontractor_id"))
    assigned_by = Column(BigInteger, ForeignKey("users.user_id"))
    assigned_at = Column(DateTime, default=dt.datetime.utcnow)
    status = Column(String(75))
    active = Column(Boolean, default=True)

    # Relationships
    work_centre = relationship("WorkCentre")
    subcontractor = relationship("SubcontractorCompany", back_populates="work_centre_assignments")
    assigner = relationship("User")

class UserActivityLog(Base):
    __tablename__ = "user_activity_logs"

    id = Column(BigInteger, primary_key=True)
    user_id = Column(BigInteger, ForeignKey("users.user_id"))
    actor_id = Column(BigInteger, ForeignKey("users.user_id"))
    action = Column(String(100), nullable=False)
    details = Column(Text)
    timestamp = Column(DateTime, default=dt.datetime.utcnow)
    ip_address = Column(String(100))
    user_agent = Column(String(255))

    # Relationships
    user = relationship("User", foreign_keys=[user_id])
    actor = relationship("User", foreign_keys=[actor_id])

class SystemFeedback(Base):
    __tablename__ = "system_feedback"

    feedback_id = Column(BigInteger, primary_key=True)
    user_id = Column(BigInteger, ForeignKey("users.user_id"), nullable=False)
    category = Column(String(50), nullable=False)  # BUG, FEATURE_REQUEST, GENERAL
    subject = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    priority = Column(String(20), default="MEDIUM")  # LOW, MEDIUM, HIGH
    status = Column(String(20), default="PENDING")  # PENDING, IN_REVIEW, RESOLVED, REJECTED
    resolution = Column(Text)
    submitted_at = Column(DateTime, default=dt.datetime.utcnow)
    resolved_at = Column(DateTime)
    active = Column(Boolean, default=True)

    # Relationships
    user = relationship("User")
    attachments = relationship("FeedbackAttachment", back_populates="feedback")

class FeedbackAttachment(Base):
    __tablename__ = "feedback_attachments"

    attachment_id = Column(BigInteger, primary_key=True)
    feedback_id = Column(BigInteger, ForeignKey("system_feedback.feedback_id", ondelete="CASCADE"))
    file_path = Column(Text, nullable=False)
    file_name = Column(String(255), nullable=False)
    file_type = Column(String(50))  # IMAGE, DOCUMENT, VIDEO
    uploaded_at = Column(DateTime, default=dt.datetime.utcnow)
    active = Column(Boolean, default=True)

    # Relationships
    feedback = relationship("SystemFeedback", back_populates="attachments")

class SupportTicket(Base):
    __tablename__ = "support_tickets"

    ticket_id = Column(BigInteger, primary_key=True)
    user_id = Column(BigInteger, ForeignKey("users.user_id"), nullable=False)
    category = Column(String(50), nullable=False)  # TECHNICAL, ACCOUNT, BILLING, OTHER
    subject = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    priority = Column(String(20), default="MEDIUM")  # LOW, MEDIUM, HIGH, URGENT
    status = Column(String(20), default="OPEN")  # OPEN, IN_PROGRESS, ON_HOLD, RESOLVED, CLOSED
    assigned_to = Column(BigInteger, ForeignKey("users.user_id"))
    resolution = Column(Text)
    created_at = Column(DateTime, default=dt.datetime.utcnow)
    updated_at = Column(DateTime, default=dt.datetime.utcnow)
    resolved_at = Column(DateTime)
    active = Column(Boolean, default=True)

    # Relationships
    user = relationship("User", foreign_keys=[user_id])
    assignee = relationship("User", foreign_keys=[assigned_to])
    messages = relationship("TicketMessage", back_populates="ticket")
    attachments = relationship("TicketAttachment", back_populates="ticket")

class TicketMessage(Base):
    __tablename__ = "ticket_messages"

    message_id = Column(BigInteger, primary_key=True)
    ticket_id = Column(BigInteger, ForeignKey("support_tickets.ticket_id", ondelete="CASCADE"))
    sender_id = Column(BigInteger, ForeignKey("users.user_id"), nullable=False)
    message = Column(Text, nullable=False)
    is_internal = Column(Boolean, default=False)  # For staff-only notes
    sent_at = Column(DateTime, default=dt.datetime.utcnow)
    active = Column(Boolean, default=True)

    # Relationships
    ticket = relationship("SupportTicket", back_populates="messages")
    sender = relationship("User")

class TicketAttachment(Base):
    __tablename__ = "ticket_attachments"

    attachment_id = Column(BigInteger, primary_key=True)
    ticket_id = Column(BigInteger, ForeignKey("support_tickets.ticket_id", ondelete="CASCADE"))
    file_path = Column(Text, nullable=False)
    file_name = Column(String(255), nullable=False)
    file_type = Column(String(50))  # IMAGE, DOCUMENT, VIDEO
    uploaded_by = Column(BigInteger, ForeignKey("users.user_id"), nullable=False)
    uploaded_at = Column(DateTime, default=dt.datetime.utcnow)
    active = Column(Boolean, default=True)

    # Relationships
    ticket = relationship("SupportTicket", back_populates="attachments")
    uploader = relationship("User")
