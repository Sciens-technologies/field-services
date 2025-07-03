from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status, Query, UploadFile, File
from sqlalchemy.orm import Session
from sqlalchemy import or_, text, update, select, and_
import secrets
import string
from datetime import date as dt
from db.models import WorkCentre, WorkOrder
from db.models import User, Role, UserActivityLog, NotificationHistory
from db.database import get_db
from api.services.users import get_current_user, get_user_by_email, get_user_roles
from api.schemas import UserResponse, UserCreate, ExistingUserResponse, UserResponseWithoutPassword
from passlib.hash import bcrypt
from api.utils.email import send_email, send_temporary_password_email
from typing import List, Optional
from db.models import (
    User,
    Role,
    UserRole,
    Permission,
    RolePermission,
    UserStatusAudit,
    NotificationHistory,
    UserStatus,
)
from db.database import get_db
from api.services.users import get_current_user, role_required, user_to_response
from api.schemas import (
    UserResponse,
    UserCreate,
    RoleResponse,
    RoleCreate,
    PermissionResponse,
    PermissionCreate,
    PermissionAssignment,
)
from uuid import uuid4
from passlib.context import CryptContext
from api.utils.util import generate_secure_password
from functools import wraps
import logging
import csv
import pandas as pd
import io
import numpy as np
from pydantic import BaseModel, EmailStr

admin_router = APIRouter()

# Initialize password context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Initialize logger
logger = logging.getLogger(__name__)


# --- User Management ---
@admin_router.post("/users/{user_id}/deactivate/")
@role_required(["admin", "super_admin", "supervisor"])
async def deactivate_user(
    user_id: int,
    reason: str = Query(..., description="Reason for deactivation"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
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
                last_modified_by=current_user.username,
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
            changed_at=datetime.utcnow(),
        )
        db.add(audit_log)
        db.commit()

        return {"message": f"User {user_id} has been deactivated"}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))


@admin_router.post("/users/{user_id}/reactivate/")
@role_required(["admin", "super_admin", "supervisor"])
async def reactivate_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
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
            last_modified_by=current_user.username,
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
        changed_at=datetime.utcnow(),
    )
    db.add(audit)
    db.commit()
    return {
        "message": "User reactivated successfully",
        "user_id": user_id,
        "status": UserStatus.ACTIVE,
    }


@admin_router.get("/users", response_model=List[UserResponseWithoutPassword])
@role_required(["admin", "super_admin", "supervisor"])
async def admin_get_users(
    name: Optional[str] = Query(None),
    email: Optional[str] = Query(None),
    role_name: Optional[str] = Query(None),
    status: Optional[str] = Query(
        None, regex="^(ACTIVE|INACTIVE|BLOCKED|DEACTIVATED)$"
    ),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
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
    
    # Convert users to response without password
    user_responses = []
    for user in users:
        # Get user roles
        user_roles = db.query(UserRole).filter(
            UserRole.user_id == user.user_id,
            UserRole.active == True
        ).all()
        
        role_names = []
        for user_role in user_roles:
            role = db.query(Role).filter(Role.role_id == user_role.role_id).first()
            if role:
                role_names.append(role.role_name)
        
        # Get professional details (workorder info)
        workcenter_id = None
        workcenter_name = None
        workorder_created_at = None
        workorder_status = None
        if hasattr(user, 'work_centre_id') and user.work_centre_id:
            wc = db.query(WorkCentre).filter(WorkCentre.work_centre_id == user.work_centre_id).first()
            if wc:
                workcenter_id = wc.work_centre_id
                workcenter_name = wc.name
        # Get the most recent work order for this user
        work_order = db.query(WorkOrder).filter(WorkOrder.created_by == user.user_id).order_by(WorkOrder.created_at.desc()).first()
        if work_order:
            workorder_created_at = work_order.created_at
            workorder_status = work_order.status
        
        # Create response without password
        user_response = {
            "user_id": user.user_id,
            "uuid": user.uuid,
            "username": user.username,
            "email": user.email,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "status": user.status,
            "created_at": user.created_at,
            "updated_at": user.updated_at,
            "roles": role_names,
            "address": getattr(user, "address", None),
            "workcenter_id": workcenter_id,
            "workcenter_name": workcenter_name,
            "workcenter_created_at": workorder_created_at,
            "workcenter_status": workorder_status,
        }
        user_responses.append(user_response)
    
    return user_responses


@admin_router.post("/users", response_model=None)
@role_required(["admin", "super_admin", "supervisor"])
async def admin_create_user(
    user_data: UserCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Create a new user (admin only). The password is generated and sent to the user by email. 'created_by' is set automatically."""
    try:
        # Check if username already exists
        existing_username = (
            db.query(User).filter(User.username == user_data.username).first()
        )
        if existing_username:
            return {
                "message": f"Username '{user_data.username}' already exists",
                "existing_user": {
                    "user_id": existing_username.user_id,
                    "username": existing_username.username,
                    "email": existing_username.email,
                    "first_name": existing_username.first_name,
                    "last_name": existing_username.last_name,
                    "status": existing_username.status,
                },
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
                    "status": existing_email.status,
                },
            }

        # Generate a secure password
        temp_password = generate_secure_password()
        logger.info(f"Generated temporary password for user {user_data.username}")

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
            created_at=datetime.utcnow(),
        )
        
        db.add(new_user)
        db.flush()  # Get the user_id
        
        # Send temporary password email
        try:
            email_val = str(getattr(new_user, "email", ""))
            username_val = str(getattr(new_user, "username", ""))
            
            logger.info(f"Sending temporary password email to {email_val}")
            email_sent = await send_temporary_password_email(email_val, username_val, temp_password)
            
            if not email_sent:
                logger.warning(f"Failed to send temporary password email to {email_val}")
                # Don't rollback - still create the user, just log the email failure
                logger.warning("User created but email notification failed. Password included in response.")
            
            logger.info(f"Email sending attempt completed for {email_val}")
            
        except Exception as email_exc:
            logger.error(f"Error sending email to {user_data.email}: {str(email_exc)}")
            # Don't rollback - still create the user, just log the email failure
            logger.warning("User created but email notification failed. Password included in response.")

        # Commit the transaction
        db.commit()
        logger.info(f"Successfully created user {user_data.username}")

        # Create response with password included
        response_data = user_to_response(new_user, db)
        response_data[
            "password_hash"
        ] = temp_password  # Include plain text password in response
        return UserResponse(**response_data)
        
    except HTTPException as he:
        # Re-raise HTTP exceptions as-is
        raise he
    except Exception as e:
        logger.error(f"Unexpected error creating user {user_data.username}: {str(e)}")
        db.rollback()
        raise HTTPException(status_code=500, detail=f"User creation failed: {str(e)}")


# --- Notification History ---
@admin_router.get("/notifications/history/")
@role_required(["admin", "super_admin"])
async def get_notification_history(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    limit: int = 50,
    offset: int = 0,
):
    total = db.query(NotificationHistory).count()
    notifications = (
        db.query(NotificationHistory)
        .order_by(NotificationHistory.delivery_timestamp.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    return {
        "total": total,
        "notifications": [
            {
                "id": n.history_id,
                "notification_id": n.notification_id,
                "status": n.status,
                "error_message": n.error_message,
                "delivery_timestamp": n.delivery_timestamp.isoformat()
                if n.delivery_timestamp is not None
                else None,
                "delivery_metadata": n.delivery_metadata,
            }
            for n in notifications
        ],
    }


# --- Role Management ---
@admin_router.post("/roles", response_model=RoleResponse, status_code=201)
@role_required(["admin", "super_admin"])
async def create_role(
    role: RoleCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if db.query(Role).filter(Role.role_name == role.name).first():
        raise HTTPException(
            status_code=409, detail={"error": "Role name already exists"}
        )
    permissions = []
    if role.permission_ids:
        permissions = (
            db.query(Permission)
            .filter(Permission.permission_id.in_(role.permission_ids))
            .all()
        )
        if len(permissions) != len(role.permission_ids):
            raise HTTPException(
                status_code=400,
                detail={"error": "One or more permission IDs are invalid"},
            )
    new_role = Role(
        role_name=role.name,
        description=role.description,
        created_by=current_user.username,
    )
    db.add(new_role)
    db.flush()
    for perm in permissions:
        db.add(
            RolePermission(
                role_id=new_role.role_id,
                permission_id=perm.permission_id,
                created_by=current_user.username,
            )
        )
    db.commit()
    db.refresh(new_role)
    perms = (
        db.query(Permission)
        .join(RolePermission)
        .filter(RolePermission.role_id == new_role.role_id)
        .all()
    )
    return RoleResponse(
        id=safe_value(sa_instance_value(new_role, "role_id"), 0),
        name=safe_value(sa_instance_value(new_role, "role_name"), ""),
        description=sa_instance_value(new_role, "description"),
        permissions=[
            PermissionResponse(
                permission_id=safe_value(sa_instance_value(p, "permission_id"), 0),
                feature_name=safe_value(sa_instance_value(p, "feature"), ""),
                description=sa_instance_value(p, "description"),
                active=safe_value(sa_instance_value(p, "active"), False),
                created_at=safe_value(
                    sa_instance_value(p, "created_at"), datetime.utcnow()
                ),
                updated_at=safe_value(
                    sa_instance_value(p, "updated_at"), datetime.utcnow()
                ),
            )
            for p in perms
        ],
    )


@admin_router.get("/roles", response_model=List[RoleResponse])
@role_required(["admin", "super_admin"])
async def get_roles(
    name: Optional[str] = None,
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query = db.query(Role)
    if name:
        query = query.filter(Role.role_name.ilike(f"%{name}%"))
    roles = query.offset((page - 1) * limit).limit(limit).all()
    result = []
    for role in roles:
        perms = (
            db.query(Permission)
            .join(RolePermission)
            .filter(RolePermission.role_id == role.role_id)
            .all()
        )
        result.append(
            RoleResponse(
                id=safe_value(sa_instance_value(role, "role_id"), 0),
                name=safe_value(sa_instance_value(role, "role_name"), ""),
                description=sa_instance_value(role, "description"),
                permissions=[
                    PermissionResponse(
                        permission_id=safe_value(
                            sa_instance_value(p, "permission_id"), 0
                        ),
                        feature_name=safe_value(sa_instance_value(p, "feature"), ""),
                        description=sa_instance_value(p, "description"),
                        active=safe_value(sa_instance_value(p, "active"), False),
                        created_at=safe_value(
                            sa_instance_value(p, "created_at"), datetime.utcnow()
                        ),
                        updated_at=safe_value(
                            sa_instance_value(p, "updated_at"), datetime.utcnow()
                        ),
                    )
                    for p in perms
                ],
            )
        )
    return result


# --- Permission Management ---
@admin_router.post("/permissions", response_model=PermissionResponse, status_code=201)
@role_required(["admin", "super_admin"])
async def create_permission(
    permission: PermissionCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if (
        db.query(Permission)
        .filter(Permission.feature == permission.feature_name)
        .first()
    ):
        raise HTTPException(
            status_code=409, detail={"error": "Permission feature already exists"}
        )
    new_permission = Permission(
        feature=permission.feature_name,
        description=permission.description,
        active=True,
        created_by=current_user.username,
    )
    db.add(new_permission)
    db.commit()
    db.refresh(new_permission)
    updated_at_val = getattr(new_permission, "updated_at", None)
    if isinstance(updated_at_val, type(None)):
        updated_at_val = None
    return PermissionResponse(
        permission_id=safe_value(sa_instance_value(new_permission, "permission_id"), 0),
        feature_name=safe_value(sa_instance_value(new_permission, "feature"), ""),
        description=sa_instance_value(new_permission, "description"),
        active=safe_value(sa_instance_value(new_permission, "active"), False),
        created_at=safe_value(
            sa_instance_value(new_permission, "created_at"), datetime.utcnow()
        ),
        updated_at=safe_value(
            sa_instance_value(new_permission, "updated_at"), datetime.utcnow()
        ),
    )


@admin_router.get("/permissions", response_model=List[PermissionResponse])
@role_required(["admin", "super_admin"])
async def get_permissions(
    feature: Optional[str] = None,
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query = db.query(Permission)
    if feature:
        query = query.filter(Permission.feature.ilike(f"%{feature}%"))
    perms = query.offset((page - 1) * limit).limit(limit).all()
    return [
        PermissionResponse(
            permission_id=safe_value(sa_instance_value(p, "permission_id"), 0),
            feature_name=safe_value(sa_instance_value(p, "feature"), ""),
            description=sa_instance_value(p, "description"),
            active=safe_value(sa_instance_value(p, "active"), False),
            created_at=safe_value(
                sa_instance_value(p, "created_at"), datetime.utcnow()
            ),
            updated_at=safe_value(
                sa_instance_value(p, "updated_at"), datetime.utcnow()
            ),
        )
        for p in perms
    ]


@admin_router.patch(
    "/roles/{role_id}/permissions", response_model=List[PermissionResponse]
)
@role_required(["admin", "super_admin"])
async def update_role_permissions(
    role_id: int,
    assignment: PermissionAssignment,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # Check if role exists
    role = db.query(Role).filter(Role.role_id == role_id).first()
    if not role:
        raise HTTPException(status_code=404, detail={"error": "Role not found"})
    
    # Validate add_permission_ids against permissions table
    if assignment.add_permission_ids:
        add_perms = db.query(Permission).filter(Permission.permission_id.in_(assignment.add_permission_ids)).all()
        found_add_ids = {getattr(p, 'permission_id') for p in add_perms}
        invalid_add_ids = set(assignment.add_permission_ids) - found_add_ids
        if invalid_add_ids:
            raise HTTPException(
                status_code=400,
                detail={"error": f"Invalid permission IDs to add: {list(invalid_add_ids)}"},
            )
    
    # Validate remove_permission_ids against role_permissions table for this role
    if assignment.remove_permission_ids:
        existing_role_perms = db.query(RolePermission).filter(and_(RolePermission.role_id == role_id, RolePermission.permission_id.in_(assignment.remove_permission_ids))).all()
        existing_remove_ids = {getattr(rp, 'permission_id') for rp in existing_role_perms}
        invalid_remove_ids = set(assignment.remove_permission_ids) - existing_remove_ids
        if invalid_remove_ids:
            raise HTTPException(
                status_code=400,
                detail={"error": f"Permission IDs not assigned to role: {list(invalid_remove_ids)}"},
            )
    
    # Add new permissions
    if assignment.add_permission_ids:
        for pid in assignment.add_permission_ids:
            # Check if permission is already assigned to this role
            exists = (
                db.query(RolePermission)
                .filter(
                    and_(
                        RolePermission.role_id == role_id,
                        RolePermission.permission_id == pid,
                    )
                )
                .first()
            )
            if not exists:
                db.add(
                    RolePermission(
                        role_id=role_id,
                        permission_id=pid,
                        created_by=current_user.username,
                    )
                )
    
    # Remove permissions
    if assignment.remove_permission_ids:
        db.query(RolePermission).filter(
            and_(
                RolePermission.role_id == role_id,
                RolePermission.permission_id.in_(assignment.remove_permission_ids),
            )
        ).delete(synchronize_session=False)
    
    db.commit()
    
    # Return updated permissions for this role
    updated_perms = (
        db.query(Permission)
        .join(RolePermission)
        .filter(RolePermission.role_id == role_id)
        .all()
    )
    return [
        PermissionResponse(
            permission_id=safe_value(sa_instance_value(p, "permission_id"), 0),
            feature_name=safe_value(sa_instance_value(p, "feature"), ""),
            description=sa_instance_value(p, "description"),
            active=safe_value(sa_instance_value(p, "active"), False),
            created_at=safe_value(
                sa_instance_value(p, "created_at"), datetime.utcnow()
            ),
            updated_at=safe_value(
                sa_instance_value(p, "updated_at"), datetime.utcnow()
            ),
        )
        for p in updated_perms
    ]


@admin_router.delete("/permissions/{permission_id}")
@role_required(["admin", "super_admin"])
async def delete_permission(permission_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """
    Delete a permission by its ID (admin only). Safely removes all role-permission links first.
    """
    permission = db.query(Permission).filter(Permission.permission_id == permission_id).first()
    if not permission:
        raise HTTPException(status_code=404, detail="Permission not found")
    # Delete all role-permission links first
    db.query(RolePermission).filter(RolePermission.permission_id == permission_id).delete()
    db.delete(permission)
    db.commit()
    return {"detail": "Permission deleted successfully"}


def sa_instance_value(obj, attr):
    val = getattr(obj, attr)
    # If it's a SQLAlchemy Column, get the value from the instance's __dict__
    if hasattr(val, "key") and hasattr(obj, "__dict__"):
        return obj.__dict__.get(attr)
    return val


def safe_value(val, default):
    return val if val is not None else default


def role_required(required_roles):
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, current_user, db, **kwargs):
            # Get user roles from DB
            stmt = (
                select(UserRole)
                .join(Role)
                .where(
                    and_(
                        UserRole.user_id == current_user.user_id,
                        UserRole.active.is_(True),
                    )
                )
            )
            user_roles = db.execute(stmt).scalars().all()
            role_names = []
            for role in user_roles:
                role_name = db.scalar(
                    select(Role.role_name).where(Role.role_id == role.role_id)
                )
                if role_name:
                    role_names.append(str(role_name).lower())
            allowed_roles = [r.lower() for r in required_roles]
            if not any(role in allowed_roles for role in role_names):
                raise HTTPException(
                    status_code=403,
                    detail=f"User does not have required roles: {', '.join(allowed_roles)}",
                )
            return await func(*args, current_user=current_user, db=db, **kwargs)
        return wrapper
    return decorator


@admin_router.get("/dashboard-stats")
@role_required(["admin", "super_admin", "supervisor"])
async def admin_dashboard_stats(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """
    Get dashboard statistics: total users, active users, deactivated users, blocked users.
    """
    total_users = db.query(User).count()
    active_users = db.query(User).filter(User.status == UserStatus.ACTIVE).count()
    deactivated_users = db.query(User).filter(User.status == UserStatus.DEACTIVATED).count()
    blocked_users = db.query(User).filter(User.status == UserStatus.BLOCKED).count()
    return {
        "total_users": total_users,
        "active_users": active_users,
        "deactivated_users": deactivated_users,
        "blocked_users": blocked_users,
    }


@admin_router.post("/users/bulk-upload", summary="Bulk upload users via CSV or Excel", description="Admin or Supervisor can upload a CSV or Excel file to create multiple users at once.")
@role_required(["admin", "super_admin", "supervisor"])
async def bulk_upload_users(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # Role check is now handled by the decorator

    results = {"created": 0, "failed": 0, "errors": []}

    if file.filename and file.filename.endswith(".csv"):
        content = await file.read()
        decoded = content.decode("utf-8").splitlines()
        reader = csv.DictReader(decoded)
    elif file.filename and file.filename.endswith(".xlsx"):
        content = await file.read()
        df = pd.read_excel(io.BytesIO(content))
        # Clean up column names and normalize to lowercase
        df.columns = [str(col).strip().lower() for col in df.columns]
        # Map possible variants to required names
        col_map = {
            "username": "username",
            "user name": "username",
            "email": "email",
            "e-mail": "email",
            "first_name": "first_name",
            "first name": "first_name",
            "last_name": "last_name",
            "last name": "last_name",
            "address": "address"
        }
        df = df.rename(columns={col: col_map[col] for col in df.columns if col in col_map})
        # Clean up string values
        df = df.applymap(lambda x: str(x).strip() if isinstance(x, str) else x)
        # Replace NaN with empty string for all columns
        df = df.replace({np.nan: ""})
        # Check for required columns
        required_fields = ["username", "email", "first_name", "last_name"]
        missing = [col for col in required_fields if col not in df.columns]
        if missing:
            raise HTTPException(status_code=400, detail=f"Missing required columns in Excel: {missing}")
        # Drop rows missing all required fields
        df = df.dropna(subset=required_fields, how='all')
        reader = df.to_dict(orient="records")
    else:
        raise HTTPException(status_code=400, detail="Only .csv or .xlsx files are supported.")

    for idx, row in enumerate(reader, 1):
        try:
            username = row.get("username") or ""
            email = row.get("email") or ""
            first_name = row.get("first_name") or ""
            last_name = row.get("last_name") or ""
            if not (username and email and first_name and last_name):
                raise ValueError("Missing required user fields (username, email, first_name, last_name)")
            user_data = UserCreate(
                username=username,
                email=email,
                first_name=first_name,
                last_name=last_name,
                address=row.get("address", None)
            )
            user = User(
                username=user_data.username,
                email=user_data.email,
                first_name=user_data.first_name,
                last_name=user_data.last_name,
                password_hash=user_data.username,  # Set default password as username (or change as needed)
                address=user_data.address,
                activated=True,
                status=UserStatus.ACTIVE,
                created_by=current_user.username
            )
            db.add(user)
            db.commit()
            db.refresh(user)
            results["created"] += 1
        except Exception as e:
            db.rollback()
            results["failed"] += 1
            results["errors"].append({"row": idx, "error": str(e)})
    return results


class RoleWorkcenterAssignRequest(BaseModel):
    email: EmailStr
    role_name: str
    work_center_registration_number: str

@admin_router.post("/users/assign-role-workcenter", summary="Assign role and workcenter to user by email", description="Assign a role and workcenter to a user using their email and workcenter registration number.")
@role_required(["admin", "super_admin", "supervisor"])
async def assign_role_and_workcenter(
    payload: RoleWorkcenterAssignRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # Role check is now handled by the decorator

    # Find user by email
    user = db.query(User).filter(User.email == payload.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found with the provided email.")

    # Assign role
    role = db.query(Role).filter(Role.role_name == payload.role_name).first()
    if not role:
        raise HTTPException(status_code=404, detail=f"Role '{payload.role_name}' not found.")
    # Check if user already has this role
    existing = db.query(UserRole).filter(UserRole.user_id == user.user_id, UserRole.role_id == role.role_id).first()
    if not existing:
        user_role = UserRole(user_id=user.user_id, role_id=role.role_id)
        db.add(user_role)

    # Find workcenter by registration number
    workcenter = db.query(WorkCentre).filter(WorkCentre.registration_number == payload.work_center_registration_number).first()
    if not workcenter:
        raise HTTPException(status_code=404, detail=f"Workcenter with registration number '{payload.work_center_registration_number}' not found.")
    
    # Assign workcenter
    user.work_centre_id = workcenter.work_centre_id
    db.commit()
    return {"message": f"Role '{payload.role_name}' and workcenter '{payload.work_center_registration_number}' assigned to user '{payload.email}'."}
