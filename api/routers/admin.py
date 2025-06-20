from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from sqlalchemy import or_, text, update, select
import secrets
import string
from datetime import date as dt
from db.models import WorkCentre
from db.models import User, Role, UserActivityLog, NotificationHistory
from db.database import get_db
from api.services.users import get_current_user, get_user_by_email
from api.schemas import UserResponse, UserCreate, ExistingUserResponse
from passlib.hash import bcrypt
from api.utils.email import send_email, send_temporary_password_email
from typing import List, Optional
from db.models import User, Role, UserRole, Permission, RolePermission, UserStatusAudit, NotificationHistory, UserStatus
from db.database import get_db
from api.services.users import get_current_user, role_required, user_to_response
from api.schemas import (
    UserResponse, UserCreate, RoleResponse, RoleCreate, PermissionResponse, PermissionCreate, PermissionAssignment
)
from uuid import uuid4
from passlib.context import CryptContext
from api.utils.util import generate_secure_password

admin_router = APIRouter()

# Initialize password context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# --- User Management ---
@admin_router.post("/users/{user_id}/deactivate/")
async def deactivate_user(
    user_id: int,
    reason: str = Query(..., description="Reason for deactivation"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Deactivate a user account."""
    try:
        # Get user
        user = db.query(User).filter(User.user_id == user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
            
        # Store old status
        old_status = user.status
        
        # Update user status using update()
        update_stmt = (
            update(User)
            .where(User.user_id == user_id)
            .values(
                status=UserStatus.DEACTIVATED,
                updated_at=datetime.utcnow(),
                last_modified_by=current_user.username
            )
        )
        db.execute(update_stmt)
        
        # Create status audit log
        audit_log = UserStatusAudit(
            user_id=user_id,
            changed_by=str(current_user.username),
            old_status=old_status,
            new_status=UserStatus.DEACTIVATED,
            reason=reason,
            changed_at=datetime.utcnow()
        )
        db.add(audit_log)
        db.commit()
        
        return {"message": f"User {user_id} has been deactivated"}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

@admin_router.post("/users/{user_id}/reactivate/")
@role_required(["admin", "super_admin"])
async def reactivate_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # Get user status using scalar()
    user_status = db.scalar(select(User.status).where(User.user_id == user_id))
    if not user_status:
        raise HTTPException(status_code=404, detail="User not found")
    if user_status != UserStatus.DEACTIVATED:
        raise HTTPException(status_code=400, detail="User is not deactivated")
    
    # Update user status using update()
    update_stmt = (
        update(User)
        .where(User.user_id == user_id)
        .values(
            status=UserStatus.ACTIVE,
            updated_at=datetime.utcnow(),
            last_modified_by=current_user.username
        )
    )
    db.execute(update_stmt)
    
    # Create audit log
    audit = UserStatusAudit(
        user_id=user_id,
        changed_by=current_user.username,
        old_status=user_status,
        new_status=UserStatus.ACTIVE,
        reason="User reactivated by admin",
        changed_at=datetime.utcnow()
    )
    db.add(audit)
    db.commit()
    return {"message": "User reactivated successfully", "user_id": user_id, "status": UserStatus.ACTIVE}

@admin_router.get("/users", response_model=List[UserResponse])
@role_required(["admin", "super_admin"])
async def admin_get_users(
    name: Optional[str] = Query(None),
    email: Optional[str] = Query(None),
    role_name: Optional[str] = Query(None),
    status: Optional[str] = Query(None, regex="^(ACTIVE|INACTIVE|BLOCKED|DEACTIVATED)$"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = db.query(User)
    if name:
        query = query.filter(
            or_(User.first_name.ilike(f"%{name}%"), User.last_name.ilike(f"%{name}%"))
        )
    if email:
        query = query.filter(User.email.ilike(f"%{email}%"))
    if role_name:
        query = query.join(UserRole).join(Role).filter(Role.role_name == role_name)
    if status:
        query = query.filter(User.status == status)
    users = query.all()
    return [user_to_response(user, db) for user in users]

@admin_router.post("/users", response_model=None)
async def admin_create_user(
    user_data: UserCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Create a new user (admin only). The password is generated and sent to the user by email. 'created_by' is set automatically."""
    try:
        # Check if username already exists
        existing_username = db.query(User).filter(User.username == user_data.username).first()
        if existing_username:
            return {
                "message": f"Username '{user_data.username}' already exists",
                "existing_user": {
                    "user_id": existing_username.user_id,
                    "username": existing_username.username,
                    "email": existing_username.email,
                    "first_name": existing_username.first_name,
                    "last_name": existing_username.last_name,
                    "status": existing_username.status
                }
            }
        
        # Check if email already exists
        existing_email = db.query(User).filter(User.email == user_data.email).first()
        if existing_email:
            return {
                "message": f"Email '{user_data.email}' already exists",
                "existing_user": {
                    "user_id": existing_email.user_id,
                    "username": existing_email.username,
                    "email": existing_email.email,
                    "first_name": existing_email.first_name,
                    "last_name": existing_email.last_name,
                    "status": existing_email.status
                }
            }
        
        # Generate a secure password
        temp_password = generate_secure_password()
        print(f"Generated password: '{temp_password}' (length: {len(temp_password)})")
        
        # Create user
        new_user = User(
            uuid=str(uuid4()),
            username=user_data.username,
            email=user_data.email,
            password_hash=temp_password,  # Store plain text password in password_hash column
            first_name=user_data.first_name,
            last_name=user_data.last_name,
            status=UserStatus.ACTIVE,
            activated=True,
            created_by=str(current_user.username),
            created_at=datetime.utcnow()
        )
        print(f"Storing password in DB: '{new_user.password_hash}' (length: {len(str(new_user.password_hash))})")
        db.add(new_user)
        db.flush()  # Get the user_id
        # Get role ID from role name
        role = db.query(Role).filter(Role.role_name == user_data.roles[0]).first()
        if not role:
            raise HTTPException(status_code=400, detail=f"Invalid role: {user_data.roles[0]}")
        # Create user role
        user_role = UserRole(
            user_id=new_user.user_id,
            role_id=role.role_id,  # Use the actual role_id from the Role table
            active=True,
            created_at=datetime.utcnow()
        )
        db.add(user_role)
        db.commit()
        # Send temporary password email
        try:
            email_val = str(getattr(new_user, 'email', ''))
            username_val = str(getattr(new_user, 'username', ''))
            await send_temporary_password_email(email_val, username_val, temp_password)
        except Exception as email_exc:
            db.rollback()
            raise HTTPException(status_code=500, detail=f"User created but failed to send email: {str(email_exc)}")
        
        # Create response with password included
        response_data = user_to_response(new_user, db)
        response_data['password_hash'] = temp_password  # Include plain text password in response
        return UserResponse(**response_data)
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

# --- Notification History ---
@admin_router.get("/notifications/history/")
@role_required(["admin", "super_admin"])
async def get_notification_history(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    limit: int = 50,
    offset: int = 0
):
    total = db.query(NotificationHistory).count()
    notifications = db.query(NotificationHistory).order_by(NotificationHistory.delivery_timestamp.desc()).offset(offset).limit(limit).all()
    return {
        "total": total,
        "notifications": [
            {
                "id": n.history_id,
                "notification_id": n.notification_id,
                "status": n.status,
                "error_message": n.error_message,
                "delivery_timestamp": n.delivery_timestamp.isoformat() if n.delivery_timestamp is not None else None,
                "delivery_metadata": n.delivery_metadata
            }
            for n in notifications
        ]
    }

# --- Role Management ---
@admin_router.post("/roles", response_model=RoleResponse, status_code=201)
@role_required(["admin", "super_admin"])
async def create_role(
    role: RoleCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if db.query(Role).filter(Role.role_name == role.name).first():
        raise HTTPException(status_code=409, detail={"error": "Role name already exists"})
    permissions = []
    if role.permission_ids:
        permissions = db.query(Permission).filter(Permission.permission_id.in_(role.permission_ids)).all()
        if len(permissions) != len(role.permission_ids):
            raise HTTPException(status_code=400, detail={"error": "One or more permission IDs are invalid"})
    new_role = Role(role_name=role.name, description=role.description, created_by=current_user.username)
    db.add(new_role)
    db.flush()
    for perm in permissions:
        db.add(RolePermission(role_id=new_role.role_id, permission_id=perm.permission_id, created_by=current_user.username))
    db.commit()
    db.refresh(new_role)
    perms = db.query(Permission).join(RolePermission).filter(RolePermission.role_id == new_role.role_id).all()
    return RoleResponse(
        id=safe_value(sa_instance_value(new_role, 'role_id'), 0),
        name=safe_value(sa_instance_value(new_role, 'role_name'), ""),
        description=sa_instance_value(new_role, 'description'),
        permissions=[
            PermissionResponse(
                permission_id=safe_value(sa_instance_value(p, 'permission_id'), 0),
                feature_name=safe_value(sa_instance_value(p, 'feature'), ""),
                description=sa_instance_value(p, 'description'),
                active=safe_value(sa_instance_value(p, 'active'), False),
                created_at=safe_value(sa_instance_value(p, 'created_at'), datetime.utcnow()),
                updated_at=safe_value(sa_instance_value(p, 'updated_at'), datetime.utcnow())
            ) for p in perms
        ]
    )

@admin_router.get("/roles", response_model=List[RoleResponse])
@role_required(["admin", "super_admin"])
async def get_roles(
    name: Optional[str] = None,
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = db.query(Role)
    if name:
        query = query.filter(Role.role_name.ilike(f"%{name}%"))
    roles = query.offset((page - 1) * limit).limit(limit).all()
    result = []
    for role in roles:
        perms = db.query(Permission).join(RolePermission).filter(RolePermission.role_id == role.role_id).all()
        result.append(RoleResponse(
            id=safe_value(sa_instance_value(role, 'role_id'), 0),
            name=safe_value(sa_instance_value(role, 'role_name'), ""),
            description=sa_instance_value(role, 'description'),
            permissions=[
                PermissionResponse(
                    permission_id=safe_value(sa_instance_value(p, 'permission_id'), 0),
                    feature_name=safe_value(sa_instance_value(p, 'feature'), ""),
                    description=sa_instance_value(p, 'description'),
                    active=safe_value(sa_instance_value(p, 'active'), False),
                    created_at=safe_value(sa_instance_value(p, 'created_at'), datetime.utcnow()),
                    updated_at=safe_value(sa_instance_value(p, 'updated_at'), datetime.utcnow()),
                ) for p in perms
            ]
        ))
    return result

# --- Permission Management ---
@admin_router.post("/permissions", response_model=PermissionResponse, status_code=201)
@role_required(["admin", "super_admin"])
async def create_permission(
    permission: PermissionCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if db.query(Permission).filter(Permission.feature == permission.feature_name).first():
        raise HTTPException(status_code=409, detail={"error": "Permission feature already exists"})
    new_permission = Permission(
        feature=permission.feature_name,
        description=permission.description,
        active=True,
        created_by=current_user.username
    )
    db.add(new_permission)
    db.commit()
    db.refresh(new_permission)
    updated_at_val = getattr(new_permission, 'updated_at', None)
    if isinstance(updated_at_val, type(None)):
        updated_at_val = None
    return PermissionResponse(
        permission_id=safe_value(sa_instance_value(new_permission, 'permission_id'), 0),
        feature_name=safe_value(sa_instance_value(new_permission, 'feature'), ""),
        description=sa_instance_value(new_permission, 'description'),
        active=safe_value(sa_instance_value(new_permission, 'active'), False),
        created_at=safe_value(sa_instance_value(new_permission, 'created_at'), datetime.utcnow()),
        updated_at=safe_value(sa_instance_value(new_permission, 'updated_at'), datetime.utcnow())
    )

@admin_router.get("/permissions", response_model=List[PermissionResponse])
@role_required(["admin", "super_admin"])
async def get_permissions(
    feature: Optional[str] = None,
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = db.query(Permission)
    if feature:
        query = query.filter(Permission.feature.ilike(f"%{feature}%"))
    perms = query.offset((page - 1) * limit).limit(limit).all()
    return [
        PermissionResponse(
            permission_id=safe_value(sa_instance_value(p, 'permission_id'), 0),
            feature_name=safe_value(sa_instance_value(p, 'feature'), ""),
            description=sa_instance_value(p, 'description'),
            active=safe_value(sa_instance_value(p, 'active'), False),
            created_at=safe_value(sa_instance_value(p, 'created_at'), datetime.utcnow()),
            updated_at=safe_value(sa_instance_value(p, 'updated_at'), datetime.utcnow()),
        ) for p in perms
    ]

@admin_router.patch("/roles/{role_id}/permissions", response_model=List[PermissionResponse])
@role_required(["admin", "super_admin"])
async def update_role_permissions(
    role_id: int,
    assignment: PermissionAssignment,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    role = db.query(Role).filter(Role.role_id == role_id).first()
    if not role:
        raise HTTPException(status_code=404, detail={"error": "Role not found"})
    all_permission_ids = set()
    if assignment.add_permission_ids:
        all_permission_ids.update(assignment.add_permission_ids)
    if assignment.remove_permission_ids:
        all_permission_ids.update(assignment.remove_permission_ids)
    if all_permission_ids:
        perms = db.query(Permission).filter(Permission.permission_id.in_(all_permission_ids)).all()
        if len(perms) != len(all_permission_ids):
            raise HTTPException(status_code=400, detail={"error": "One or more permission IDs are invalid"})
    if assignment.add_permission_ids:
        for pid in assignment.add_permission_ids:
            exists = db.query(RolePermission).filter(RolePermission.role_id == role_id, RolePermission.permission_id == pid).first()
            if not exists:
                db.add(RolePermission(role_id=role_id, permission_id=pid, created_by=current_user.username))
    if assignment.remove_permission_ids:
        db.query(RolePermission).filter(RolePermission.role_id == role_id, RolePermission.permission_id.in_(assignment.remove_permission_ids)).delete(synchronize_session=False)
    db.commit()
    updated_perms = db.query(Permission).join(RolePermission).filter(RolePermission.role_id == role_id).all()
    return [
        PermissionResponse(
            permission_id=safe_value(sa_instance_value(p, 'permission_id'), 0),
            feature_name=safe_value(sa_instance_value(p, 'feature'), ""),
            description=sa_instance_value(p, 'description'),
            active=safe_value(sa_instance_value(p, 'active'), False),
            created_at=safe_value(sa_instance_value(p, 'created_at'), datetime.utcnow()),
            updated_at=safe_value(sa_instance_value(p, 'updated_at'), datetime.utcnow())
        ) for p in updated_perms
    ]

def sa_instance_value(obj, attr):
    val = getattr(obj, attr)
    # If it's a SQLAlchemy Column, get the value from the instance's __dict__
    if hasattr(val, 'key') and hasattr(obj, '__dict__'):
        return obj.__dict__.get(attr)
    return val

def safe_value(val, default):
    return val if val is not None else default
