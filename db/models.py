from sqlalchemy import (
    Column, Integer, String, Boolean, DateTime, ForeignKey, Text, Enum as SQLAlchemyEnum, DECIMAL, JSON
)
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import JSONB
import datetime as dt
from enum import Enum
from db.database import Base

# --- Enums ---
class UserRole(Enum):
    SUPER_ADMIN = "super_admin"
    MANAGER = "manager"
    AGENT = "agent"

class UserStatus(str, Enum):
    active = "active"
    inactive = "inactive"

class RoleEnum(str, Enum):
    super_admin = "super_admin"
    manager = "manager"
    agent = "agent"

class CommentType(str, Enum):
    comment = "comment"
    feedback = "feedback"

class WorkOrderStatus(str, Enum):
    pending = "pending"
    approved = "approved"
    rejected = "rejected"
    in_progress = "in_progress"
    completed = "completed"

# --- Models ---
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(100), unique=True, nullable=False)
    first_name = Column(String(50))
    last_name = Column(String(50))
    phone_number = Column(String(20), nullable=True)
    hashed_password = Column(Text, nullable=False)
    role_id = Column(Integer, ForeignKey("roles.id"))
    status = Column(String(20), default="active")
    created_at = Column(DateTime, default=dt.datetime.utcnow)
    updated_at = Column(DateTime, default=dt.datetime.utcnow, onupdate=dt.datetime.utcnow)
    blocked_at = Column(DateTime, nullable=True)
    block_reason = Column(String, nullable=True)
    work_center_id = Column(Integer, ForeignKey("work_centers.id"), nullable=True)

    role = relationship("Role", back_populates="users")
    tokens = relationship("Token", back_populates="user", cascade="all, delete-orphan")
    login_activities = relationship("LoginActivity", back_populates="user", cascade="all, delete-orphan", foreign_keys="LoginActivity.agent_id")
    work_orders_managed = relationship("WorkOrder", foreign_keys="WorkOrder.manager_id", back_populates="manager")
    work_orders_assigned = relationship("WorkOrder", foreign_keys="WorkOrder.agent_id", back_populates="agent")
    devices = relationship("Device", back_populates="manager")
    work_order_comments = relationship("WorkOrderComment", back_populates="user")
    notifications = relationship("Notification", back_populates="user")
    user_permissions = relationship("UserPermission", back_populates="user")
    notification_preferences = relationship("UserNotificationPreferences", uselist=False, back_populates="user")
    activity_logs = relationship("UserActivityLog", foreign_keys="[UserActivityLog.user_id]", back_populates="user")
    actions_performed = relationship("UserActivityLog", foreign_keys="[UserActivityLog.actor_id]", back_populates="actor")
    work_center = relationship("WorkCenter", back_populates="users")

class Role(Base):
    __tablename__ = "roles"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(50), unique=True, nullable=False)

    users = relationship("User", back_populates="role")
    role_permissions = relationship("RolePermission", back_populates="role", overlaps="permissions")
    permissions = relationship("Permission", secondary="role_permissions", back_populates="roles", overlaps="role_permissions")

    def __repr__(self):
        return f"<Role(name='{self.name}')>"

class Permission(Base):
    __tablename__ = "permissions"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, nullable=False)
    description = Column(String)

    role_permissions = relationship("RolePermission", back_populates="permission", overlaps="roles,permissions")
    user_permissions = relationship("UserPermission", back_populates="permission")
    roles = relationship("Role", secondary="role_permissions", back_populates="permissions", overlaps="role_permissions")

    def __repr__(self):
        return f"<Permission(name='{self.name}')>"

class RolePermission(Base):
    __tablename__ = "role_permissions"

    id = Column(Integer, primary_key=True, index=True)
    role_id = Column(Integer, ForeignKey("roles.id", ondelete="CASCADE"))
    permission_id = Column(Integer, ForeignKey("permissions.id", ondelete="CASCADE"))
    created_at = Column(DateTime, default=dt.datetime.utcnow)

    role = relationship("Role", back_populates="role_permissions", overlaps="permissions,roles")
    permission = relationship("Permission", back_populates="role_permissions", overlaps="roles,permissions")

    def __repr__(self):
        return f"<RolePermission(role_id='{self.role_id}', permission_id='{self.permission_id}')>"

class Token(Base):
    __tablename__ = "auth_tokens"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"))
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

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    device_type = Column(String(100))
    serial_number = Column(String(100), unique=True)
    location = Column(String)
    gps_latitude = Column(DECIMAL(10, 6))
    gps_longitude = Column(DECIMAL(10, 6))
    manager_id = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime, default=dt.datetime.utcnow)
    updated_at = Column(DateTime, default=dt.datetime.utcnow, onupdate=dt.datetime.utcnow)

    manager = relationship("User", back_populates="devices")
    work_orders = relationship("WorkOrder", back_populates="device")

    def __repr__(self):
        return f"<Device(name='{self.name}')>"

class WorkOrder(Base):
    __tablename__ = "work_orders"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(150))
    description = Column(String)
    status = Column(SQLAlchemyEnum(WorkOrderStatus), nullable=False)
    complition_pct = Column(Integer)
    manager_id = Column(Integer, ForeignKey("users.id"))
    agent_id = Column(Integer, ForeignKey("users.id"))
    device_id = Column(Integer, ForeignKey("devices.id"))
    target_complition_date = Column(DateTime)
    start_date = Column(DateTime)
    end_date = Column(DateTime)
    created_at = Column(DateTime, default=dt.datetime.utcnow)
    updated_at = Column(DateTime, default=dt.datetime.utcnow, onupdate=dt.datetime.utcnow)

    manager = relationship("User", foreign_keys=[manager_id], back_populates="work_orders_managed")
    agent = relationship("User", foreign_keys=[agent_id], back_populates="work_orders_assigned")
    device = relationship("Device", back_populates="work_orders")
    work_order_comments = relationship("WorkOrderComment", back_populates="work_order")
    work_order_forms = relationship("WorkOrderForm", back_populates="work_order")
    work_order_status_histories = relationship("WorkOrderStatusHistory", back_populates="work_order")

    def __repr__(self):
        return f"<WorkOrder(title='{self.title}', status='{self.status}')>"

class WorkOrderComment(Base):
    __tablename__ = "work_order_comments"

    id = Column(Integer, primary_key=True, index=True)
    work_order_id = Column(Integer, ForeignKey("work_orders.id", ondelete="CASCADE"))
    user_id = Column(Integer, ForeignKey("users.id"))
    comment_type = Column(SQLAlchemyEnum(CommentType))
    comment_text = Column(String)
    created_at = Column(DateTime, default=dt.datetime.utcnow)

    work_order = relationship("WorkOrder", back_populates="work_order_comments")
    user = relationship("User", back_populates="work_order_comments")

    def __repr__(self):
        return f"<WorkOrderComment(work_order_id='{self.work_order_id}', comment_type='{self.comment_type}')>"

class WorkOrderForm(Base):
    __tablename__ = "work_order_forms"

    id = Column(Integer, primary_key=True, index=True)
    work_order_id = Column(Integer, ForeignKey("work_orders.id", ondelete="CASCADE"))
    step_number = Column(Integer, nullable=False)
    form_data = Column(JSON)
    submitted_at = Column(DateTime, default=dt.datetime.utcnow)

    work_order = relationship("WorkOrder", back_populates="work_order_forms")

    def __repr__(self):
        return f"<WorkOrderForm(work_order_id='{self.work_order_id}', step_number='{self.step_number}')>"

class WorkOrderStatusHistory(Base):
    __tablename__ = "work_order_status_history"

    id = Column(Integer, primary_key=True, index=True)
    work_order_id = Column(Integer, ForeignKey("work_orders.id", ondelete="CASCADE"))
    status = Column(String(30), nullable=False)
    changed_by = Column(Integer, ForeignKey("users.id"))
    changed_at = Column(DateTime, default=dt.datetime.utcnow)
    comment = Column(String)

    work_order = relationship("WorkOrder", back_populates="work_order_status_histories")
    changed_by_user = relationship("User")

    def __repr__(self):
        return f"<WorkOrderStatusHistory(work_order_id='{self.work_order_id}', status='{self.status}')>"

class LoginActivity(Base):
    __tablename__ = "agent_activity_logs"

    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), name="user_id")
    login_time = Column(DateTime, default=dt.datetime.utcnow)
    logout_time = Column(DateTime, nullable=True)
    ip_address = Column(String, nullable=True)
    device_info = Column(String, nullable=True, name="user_agent")

    user = relationship("User", back_populates="login_activities")

    def __repr__(self):
        return f"<ActivityLog(user_id='{self.agent_id}', login_time='{self.login_time}', logout_time='{self.logout_time}')>"

class Notification(Base):
    __tablename__ = "notifications"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    title = Column(String(150))
    message = Column(Text)
    is_read = Column(Boolean, default=False)
    created_at = Column(DateTime, default=dt.datetime.utcnow)

    user = relationship("User", back_populates="notifications")

    def __repr__(self):
        return f"<Notification(user_id='{self.user_id}', title='{self.title}')>"

class UserPermission(Base):
    __tablename__ = "user_permissions"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"))
    permission_id = Column(Integer, ForeignKey("permissions.id", ondelete="CASCADE"))
    created_at = Column(DateTime, default=dt.datetime.utcnow)

    user = relationship("User", back_populates="user_permissions")
    permission = relationship("Permission", back_populates="user_permissions")

    def __repr__(self):
        return f"<UserPermission(user_id='{self.user_id}', permission_id='{self.permission_id}')>"

class UserNotificationPreferences(Base):
    __tablename__ = "user_notification_preferences"
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    email_enabled = Column(Boolean, default=True)
    sms_enabled = Column(Boolean, default=True)
    push_enabled = Column(Boolean, default=True)
    email_notifications = Column(JSONB, nullable=False, default=dict)
    sms_notifications = Column(JSONB, nullable=False, default=dict)
    push_notifications = Column(JSONB, nullable=False, default=dict)
    created_at = Column(DateTime, default=dt.datetime.utcnow)
    updated_at = Column(DateTime, default=dt.datetime.utcnow, onupdate=dt.datetime.utcnow)
    user = relationship("User", back_populates="notification_preferences", lazy="select")

class NotificationHistory(Base):
    __tablename__ = "notification_history"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    type = Column(String(10), nullable=False)  # email, sms, push
    event = Column(String(50), nullable=False)  # e.g., password_changes
    message = Column(Text, nullable=False)
    status = Column(String(20), nullable=False)  # delivered, failed
    sent_at = Column(DateTime, default=dt.datetime.utcnow)

    user = relationship("User")

class UserActivityLog(Base):
    __tablename__ = "user_activity_logs"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    actor_id = Column(Integer, ForeignKey("users.id"))
    action = Column(String(50), nullable=False)
    details = Column(Text)
    timestamp = Column(DateTime, default=dt.datetime.utcnow)

    user = relationship("User", foreign_keys=[user_id], back_populates="activity_logs")
    actor = relationship("User", foreign_keys=[actor_id], back_populates="actions_performed")

class Feedback(Base):
    __tablename__ = "feedback"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    subject = Column(String(150), nullable=False)
    message = Column(Text, nullable=False)
    status = Column(String(20), default="open")
    created_at = Column(DateTime, default=dt.datetime.utcnow)

class WorkCenter(Base):
    __tablename__ = "work_centers"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    location = Column(String(100))
    created_at = Column(DateTime, default=dt.datetime.utcnow)
    users = relationship("User", back_populates="work_center")

