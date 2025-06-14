from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from sqlalchemy import text, or_
import datetime
import secrets
import string
from datetime import date as dt
from typing import List, Optional
from uuid import uuid4

from db.models import (
    User, Role, UserRole, Permission, RolePermission,
    UserStatusAudit, UserAuthProvider, UserAuthMetadata,
    UserNotificationPreferences, NotificationHistory, UserActivityLog
)
from db.database import get_db
from api.services.users import get_current_user, get_user_by_email, admin_required, role_required, user_to_response
from api.schemas import (
    UserResponse, AdminCreateUserRequest,
    PermissionAssignRequest, PermissionCreateRequest
)
from passlib.hash import bcrypt
from api.utils.email import send_email, send_temporary_password_email
from api.utils.util import generate_random_password
from api.services.admin import block_user as admin_block_user

admin_router = APIRouter()

# --- User Management ---
@admin_router.post("/users/{user_id}/deactivate/")
@admin_required
async def deactivate_user(
    user_id: int,
    reason: str = Query(..., min_length=1, max_length=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Deactivate a user account.
    Prevents user login while preserving their data and logs the action.
    """
    try:
        user = db.query(User).filter(User.user_id == user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        if user.status == 'DEACTIVATED':
            raise HTTPException(status_code=400, detail="User is already deactivated")
        if user.status == 'BLOCKED':
            raise HTTPException(status_code=400, detail="User is blocked and cannot be deactivated")

        # Store old status for audit
        old_status = user.status
        
        # Update user status
        user.status = 'DEACTIVATED'
        user.updated_at = datetime.datetime.utcnow()
        user.last_modified_by = current_user.username
        
        # Create status audit record
        audit = UserStatusAudit(
            user_id=user.user_id,
            changed_by=current_user.username,
            old_status=old_status,
            new_status='DEACTIVATED',
            reason=reason,
            changed_at=datetime.datetime.utcnow()
        )
        db.add(audit)
        db.commit()

        return {
            "message": "User deactivated successfully",
            "user_id": user.user_id,
            "status": user.status
        }
    except Exception as e:
        db.rollback()
        print(f"Error deactivating user: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error deactivating user: {str(e)}")

@admin_router.post("/users/{user_id}/reactivate/")
@admin_required
async def reactivate_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Reactivate a deactivated user account.
    Restores user access and logs the reactivation action.
    """
    try:
        user = db.query(User).filter(User.user_id == user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        if user.status != 'DEACTIVATED':
            raise HTTPException(status_code=400, detail="User is not deactivated")

        old_status = user.status
        user.status = 'ACTIVE'
        user.updated_at = datetime.datetime.utcnow()
        user.last_modified_by = current_user.username

        # Create status audit record
        audit = UserStatusAudit(
            user_id=user.user_id,
            changed_by=current_user.username,
            old_status=old_status,
            new_status='ACTIVE',
            reason="User reactivated by admin",
            changed_at=datetime.datetime.utcnow()
        )
        db.add(audit)
        db.commit()

        return {
            "message": "User reactivated successfully",
            "user_id": user.user_id,
            "status": user.status
        }
    except Exception as e:
        db.rollback()
        print(f"Error reactivating user: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error reactivating user: {str(e)}")

@admin_router.get("/admin/users/", response_model=List[UserResponse], dependencies=[Depends(admin_required)])
async def admin_get_users(
    name: Optional[str] = Query(None),
    email: Optional[str] = Query(None),
    role_name: Optional[str] = Query(None),
    status: Optional[str] = Query(None, regex="^(ACTIVE|INACTIVE|BLOCKED|DEACTIVATED)$"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get list of users with filtering options.
    Allows searching users by name, email, role, and status.
    """
    try:
        query = db.query(User)
        if name:
            query = query.filter(
                or_(
                    User.first_name.ilike(f"%{name}%"),
                    User.last_name.ilike(f"%{name}%")
                )
            )
        if email:
            query = query.filter(User.email.ilike(f"%{email}%"))
        if role_name:
            query = query.join(UserRole).join(Role).filter(Role.role_name == role_name)
        if status:
            query = query.filter(User.status == status)

        users = query.all()
        return [user_to_response(user, db) for user in users]
    except Exception as e:
        print(f"Error getting users: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error getting users: {str(e)}")

@admin_router.post("/admin/create-user/", response_model=UserResponse, dependencies=[Depends(admin_required)])
async def admin_create_user(
    user_data: AdminCreateUserRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Create new user account with specified roles.
    Generates random password if none provided and sends email notification.
    """
    try:
        # Check if user exists
        if get_user_by_email(db, user_data.email):
            raise HTTPException(status_code=400, detail="Email already registered")

        # Generate password if not provided
        password = user_data.password or generate_random_password()
        password_hash = bcrypt.hash(password)

        # Create user
        new_user = User(
            uuid=str(uuid4()),
            username=user_data.username,
            email=user_data.email,
            password_hash=password_hash,
            first_name=user_data.first_name,
            last_name=user_data.last_name,
            preferred_lang=user_data.preferred_lang,
            timezone_id=user_data.timezone_id,
            is_2fa_enabled=user_data.is_2fa_enabled,
            created_by=current_user.username,
            status='ACTIVE',
            activated=True
        )
        db.add(new_user)
        db.flush()  # Get the user_id without committing

        # Assign roles
        for role_name in user_data.roles:
            role = db.query(Role).filter(Role.role_name == role_name).first()
            if not role:
                db.rollback()
                raise HTTPException(status_code=400, detail=f"Role {role_name} not found")
            
            user_role = UserRole(
                user_id=new_user.user_id,
                role_id=role.role_id,
                assigned_by=current_user.username,
                active=True
            )
            db.add(user_role)

        db.commit()

        # Send welcome email with credentials
        try:
            send_temporary_password_email(
                email=new_user.email,
                username=new_user.username,
                password=password,
                first_name=new_user.first_name
            )
        except Exception as e:
            print(f"Error sending welcome email: {str(e)}")

        return user_to_response(new_user, db)
    except Exception as e:
        db.rollback()
        print(f"Error creating user: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error creating user: {str(e)}")

# --- Role & Permission Management ---
@admin_router.post("/roles/assign-permissions/")
@admin_required
async def assign_permissions_to_role(
    data: PermissionAssignRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Assign permissions to a role.
    Updates role permissions and logs the changes.
    """
    try:
        # Find the role
        role = db.query(Role).filter(Role.role_name == data.role_name).first()
        if not role:
            raise HTTPException(status_code=404, detail="Role not found")

        # Get existing permissions
        existing_permissions = db.query(Permission).filter(
            Permission.feature.in_(data.permissions)
        ).all()
        existing_features = {p.feature for p in existing_permissions}

        # Create missing permissions
        for feature in data.permissions:
            if feature not in existing_features:
                new_permission = Permission(
                    feature=feature,
                    description=f"Permission for {feature}",
                    created_by=current_user.username,
                    active=True
                )
                db.add(new_permission)
                existing_permissions.append(new_permission)

        db.flush()

        # Assign permissions to role
        for permission in existing_permissions:
            role_permission = RolePermission(
                role_id=role.role_id,
                permission_id=permission.permission_id,
                assigned_by=current_user.username,
                active=True
            )
            db.add(role_permission)

        db.commit()
        return {"message": "Permissions assigned successfully"}
    except Exception as e:
        db.rollback()
        print(f"Error assigning permissions: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error assigning permissions: {str(e)}")

@admin_router.post("/permissions/create")
@admin_required
async def create_permission(
    request: PermissionCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Create new permission in the system.
    Adds new permission with description and logs the creation.
    """
    try:
        # Check if permission exists
        existing = db.query(Permission).filter(Permission.feature == request.name).first()
        if existing:
            raise HTTPException(status_code=400, detail="Permission already exists")

        # Create permission
        permission = Permission(
            feature=request.name,
            description=request.description,
            created_by=current_user.username,
            active=True
        )
        db.add(permission)
        db.commit()

        return {
            "id": permission.permission_id,
            "name": permission.feature,
            "description": permission.description,
            "active": permission.active
        }
    except Exception as e:
        db.rollback()
        print(f"Error creating permission: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error creating permission: {str(e)}")

# --- Notification History ---
@admin_router.get("/notifications/history/")
@admin_required
async def get_notification_history(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    limit: int = 50,
    offset: int = 0
):
    """
    Get system notification history.
    Retrieves paginated list of system notifications.
    """
    try:
        # Get total count
        total = db.query(NotificationHistory).count()
        
        # Get paginated records
        notifications = db.query(NotificationHistory)\
            .order_by(NotificationHistory.created_at.desc())\
            .offset(offset)\
            .limit(limit)\
            .all()
        
        return {
            "total": total,
            "notifications": [
                {
                    "id": n.id,
                    "user_id": n.user_id,
                    "type": n.type,
                    "title": n.title,
                    "message": n.message,
                    "status": n.status,
                    "created_at": n.created_at.isoformat(),
                    "sent_at": n.sent_at.isoformat() if n.sent_at else None,
                    "read_at": n.read_at.isoformat() if n.read_at else None
                }
                for n in notifications
            ]
        }
    except Exception as e:
        print(f"Error getting notification history: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error getting notification history: {str(e)}")