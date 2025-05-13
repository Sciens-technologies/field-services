from datetime import datetime as dt
from sqlalchemy import Column, String, Integer, DateTime, ForeignKey, Enum, Boolean, DECIMAL, JSON
from sqlalchemy.orm import relationship
from sqlalchemy.orm import joinedload
from enum import Enum as PyEnum

from db.database import Base

class UserRole(PyEnum):
    SUPER_ADMIN = "super_admin"
    MANAGER = "manager"
    AGENT = "agent"

class UserStatus(str, PyEnum):
    active = "active"
    inactive = "inactive"

class RoleEnum(str, PyEnum):
    super_admin = "super_admin"
    manager = "manager"
    agent = "agent"


class CommentType(str, PyEnum):
    comment = "comment"
    feedback = "feedback"


class WorkOrderStatus(str, PyEnum):
    pending = "pending"
    approved = "approved"
    rejected = "rejected"
    in_progress = "in_progress"
    completed = "completed"


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(100), unique=True, nullable=False)
    name = Column(String(100))
    hashed_password = Column(String, nullable=False)
    role_id = Column(Integer, ForeignKey("roles.id"))
    status = Column(Enum(UserStatus), default=UserStatus.active)
    created_at = Column(DateTime, default=dt.utcnow)
    updated_at = Column(DateTime, default=dt.utcnow, onupdate=dt.utcnow)

    role = relationship("Role", back_populates="users")
    auth_tokens = relationship("Token", back_populates="user")
    devices = relationship("Device", back_populates="manager")
    work_orders_managed = relationship("WorkOrder", back_populates="manager")
    work_orders_assigned = relationship("WorkOrder", back_populates="agent")
    work_order_comments = relationship("WorkOrderComment", back_populates="user")
    notifications = relationship("Notification", back_populates="user")
    agent_activity_logs = relationship("LoginActivity", back_populates="agent")

    def __repr__(self):
        return f"<User(email='{self.email}')>"


class Role(Base):
    __tablename__ = "roles"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(50), unique=True, nullable=False)

    users = relationship("User", back_populates="role")
    role_permissions = relationship("RolePermission", back_populates="role")

    def __repr__(self):
        return f"<Role(name='{self.name}')>"


class Permission(Base):
    __tablename__ = "permissions"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, nullable=False)
    description = Column(String)

    role_permissions = relationship("RolePermission", back_populates="permission")

    def __repr__(self):
        return f"<Permission(name='{self.name}')>"


class RolePermission(Base):
    __tablename__ = "role_permissions"

    id = Column(Integer, primary_key=True, index=True)
    role_id = Column(Integer, ForeignKey("roles.id", ondelete="CASCADE"))
    permission_id = Column(Integer, ForeignKey("permissions.id", ondelete="CASCADE"))

    role = relationship("Role", back_populates="role_permissions")
    permission = relationship("Permission", back_populates="role_permissions")

    def __repr__(self):
        return f"<RolePermission(role_id='{self.role_id}', permission_id='{self.permission_id}')>"



class Token(Base):
    __tablename__ = "auth_tokens"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"))
    access_token = Column(String, unique=True, nullable=False)
    refresh_token = Column(String, unique=True, nullable=False)
    expires_at = Column(DateTime)
    revoked = Column(Boolean, default=False)
    created_at = Column(DateTime, default=dt.utcnow)
    last_used_at = Column(DateTime)
    ip_address = Column(String(100))
    device_info = Column(String)

    user = relationship("User", back_populates="auth_tokens")

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
    created_at = Column(DateTime, default=dt.utcnow)
    updated_at = Column(DateTime, default=dt.utcnow, onupdate=dt.utcnow)

    manager = relationship("User", back_populates="devices")
    work_orders = relationship("WorkOrder", back_populates="device")

    def __repr__(self):
        return f"<Device(name='{self.name}')>"



class WorkOrder(Base):
    __tablename__ = "work_orders"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(150))
    description = Column(String)
    status = Column(Enum(WorkOrderStatus), nullable=False)
    complition_pct = Column(Integer)
    manager_id = Column(Integer, ForeignKey("users.id"))
    agent_id = Column(Integer, ForeignKey("users.id"))
    device_id = Column(Integer, ForeignKey("devices.id"))
    target_complition_date = Column(DateTime)
    start_date = Column(DateTime)
    end_date = Column(DateTime)
    created_at = Column(DateTime, default=dt.utcnow)
    updated_at = Column(DateTime, default=dt.utcnow, onupdate=dt.utcnow)

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
    comment_type = Column(Enum(CommentType))
    comment_text = Column(String)
    created_at = Column(DateTime, default=dt.utcnow)

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
    submitted_at = Column(DateTime, default=dt.utcnow)

    work_order = relationship("WorkOrder", back_populates="work_order_forms")

    def __repr__(self):
        return f"<WorkOrderForm(work_order_id='{self.work_order_id}', step_number='{self.step_number}')>"



class WorkOrderStatusHistory(Base):
    __tablename__ = "work_order_status_history"

    id = Column(Integer, primary_key=True, index=True)
    work_order_id = Column(Integer, ForeignKey("work_orders.id", ondelete="CASCADE"))
    status = Column(String(30), nullable=False)
    changed_by = Column(Integer, ForeignKey("users.id"))
    changed_at = Column(DateTime, default=dt.utcnow)
    comment = Column(String)

    work_order = relationship("WorkOrder", back_populates="work_order_status_histories")
    changed_by_user = relationship("User")

    def __repr__(self):
        return f"<WorkOrderStatusHistory(work_order_id='{self.work_order_id}', status='{self.status}')>"



class LoginActivity(Base):
    __tablename__ = "login_activity"

    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(Integer, ForeignKey("users.id"))
    login_time = Column(DateTime)
    logout_time = Column(DateTime)
    ip_address = Column(String(100))
    device_info = Column(String)

    agent = relationship("User", back_populates="login_activity_logs")

    def __repr__(self):
        return f"<ActivityLog(agent_id='{self.agent_id}', login_time='{self.login_time}', logout_time='{self.logout_time}')>"



class Notification(Base):
    __tablename__ = "notifications"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"))
    title = Column(String(150))
    message = Column(String)
    is_read = Column(Boolean, default=False)
    created_at = Column(DateTime, default=dt.utcnow)

    user = relationship("User", back_populates="notifications")

    def __repr__(self):
        return f"<Notification(user_id='{self.user_id}', title='{self.title}')>"

