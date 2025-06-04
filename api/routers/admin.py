from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from sqlalchemy import text, or_
import datetime
import secrets
import string
from datetime import date as dt

from db.models import User, Role, UserActivityLog, NotificationHistory,WorkCenter
from db.database import get_db
from api.services.users import get_current_user, get_user_by_email
from api.schemas import UserResponse, AdminCreateUserRequest
from passlib.hash import bcrypt
from api.utils.email import send_email, send_temporary_password_email
from typing import List, Optional
from api.services.users import user_to_response
from api.services.admin import block_user
from api.utils.util import generate_random_password
from api.services.users import get_current_user, get_user_by_email,role_required
from api.services.admin import block_user as admin_block_user,admin_required
from api.schemas import (
    WorkCenterAssignment,
    WorkOrderCreate, WorkOrderUpdate, WorkOrderResponse,  # Use the actual class names you have
    WorkCenterAssignmentResponse,
    PermissionAssignRequest,
    PermissionCreateRequest
)
from db.models import RolePermission, Permission

generated_password = generate_random_password()
admin_router = APIRouter()


@admin_router.post("/users/{user_id}/deactivate/", dependencies=[Depends(admin_required)])
async def deactivate_user(
    user_id: int,
    reason: str = Query(..., min_length=1, max_length=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Deactivate a user by ID (admin only), preventing login but keeping user data.
    """
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        if user.status == 'deactivated':
            raise HTTPException(status_code=400, detail="User is already deactivated")
        if user.status == 'blocked':
            raise HTTPException(status_code=400, detail="User is blocked and cannot be deactivated")

        user.status = 'deactivated'
        user.updated_at = datetime.datetime.utcnow()
        db.commit()

        # Revoke all active tokens for the deactivated user
        db.execute(
            text("UPDATE auth_tokens SET revoked = TRUE WHERE user_id = :user_id AND revoked = FALSE"),
            {"user_id": user.id}
        )

        # Log the deactivation action
        log = UserActivityLog(
            user_id=user.id,
            actor_id=current_user.id,
            action="deactivate",
            details=reason,
            timestamp=datetime.datetime.utcnow()
        )
        db.add(log)
        db.commit()

        return {
            "message": "User deactivated successfully",
            "user_id": user.id,
            "status": user.status
        }
    except Exception as e:
        db.rollback()
        print(f"Error deactivating user: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error deactivating user: {str(e)}")
@admin_router.post("/users/{user_id}/reactivate/", dependencies=[Depends(admin_required)])
async def reactivate_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Reactivate a deactivated user by ID (admin only).
    """
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        if user.status != 'deactivated':
            raise HTTPException(status_code=400, detail="User is not deactivated")

        user.status = 'active'
        user.updated_at = datetime.datetime.utcnow()
        db.commit()

        # Log the reactivation action
        log = UserActivityLog(
            user_id=user.id,
            actor_id=current_user.id,
            action="reactivate",
            details="User reactivated by admin",
            timestamp=datetime.datetime.utcnow()
        )
        db.add(log)
        db.commit()

        return {
            "message": "User reactivated successfully",
            "user_id": user.id,
            "status": user.status
        }
    except Exception as e:
        db.rollback()
        print(f"Error reactivating user: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error reactivating user: {str(e)}")


@admin_router.get("/notifications/history/")
async def get_notification_history(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    limit: int = 50,
    offset: int = 0
):
    history = db.query(NotificationHistory).filter_by(user_id=current_user.id)\
        .order_by(NotificationHistory.sent_at.desc())\
        .limit(limit).offset(offset).all()
    return [
        {
            "id": n.id,
            "type": n.type,
            "event": n.event,
            "message": n.message,
            "status": n.status,
            "sent_at": n.sent_at.isoformat()
        } for n in history
    ]
@admin_router.get("/admin/users/", response_model=List[UserResponse], dependencies=[Depends(admin_required)])
async def admin_get_users(
    name: Optional[str] = Query(None),
    email: Optional[str] = Query(None),
    role_id: Optional[int] = Query(None),
    active: Optional[bool] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(admin_required)
):
    """
    Admin gets all users, with optional filters.
    """
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
    if role_id:
        query = query.filter(User.role_id == role_id)
    if active is not None:
        query = query.filter(User.status == ('active' if active else 'inactive'))
    users = query.all()
    return [user_to_response(user, db) for user in users]

SUPPORTED_EVENTS = {
    "email_notifications": ["account_changes", "login_attempts", "password_changes", "promotional_offers"],
    "sms_notifications": ["login_attempts", "password_changes"],
    "push_notifications": ["account_changes", "login_attempts", "password_changes"]
}
@admin_router.post("/admin/create-user/", response_model=UserResponse, dependencies=[Depends(admin_required)])
async def admin_create_user(
    user_data: AdminCreateUserRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(admin_required)
):
    """
    Admin creates a new user with an auto-generated password.
    """
    existing_user = get_user_by_email(db, user_data.email)
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    # Generate a random password
    password_length = 12
    alphabet = string.ascii_letters + string.digits
    generated_password = ''.join(secrets.choice(alphabet) for _ in range(password_length))
    hashed_password = bcrypt.hash(generated_password)

    # Get or create role
    role = db.query(Role).filter(Role.name == user_data.role).first()
    if not role:
        role = Role(name=user_data.role)
        db.add(role)
        db.commit()
        db.refresh(role)

    new_user = User(
        email=user_data.email,
        first_name=user_data.first_name,
        last_name=user_data.last_name,
        hashed_password=hashed_password,
        role_id=role.id,
        status='active',
        phone_number=user_data.phone_number,
        created_at=datetime.datetime.utcnow(),
        updated_at=datetime.datetime.utcnow()
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    # Send email with the generated password
    send_temporary_password_email(user_data, generated_password)
    # or, if you want to call directly:
    # send_email(
    #     to_email=user_data.email,
    #     subject="Your ENEO Account Password",
    #     plain_text=f"Hello {user_data.first_name},\n\nYour account has been created. Your temporary password is: {generated_password}\n\nPlease log in and change your password."
    # )

    return new_user


@admin_router.get("/admin/users/", response_model=List[UserResponse], dependencies=[Depends(admin_required)])
async def admin_get_users(
    name: Optional[str] = Query(None),
    email: Optional[str] = Query(None),
    role_id: Optional[int] = Query(None),
    active: Optional[bool] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(admin_required)
):
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
    if role_id:
        query = query.filter(User.role_id == role_id)
    if active is not None:
        query = query.filter(User.status == ('active' if active else 'blocked'))
    users = query.all()
    return [user_to_response(user, db) for user in users]

@admin_router.post("/admin/create-user/", response_model=UserResponse, dependencies=[Depends(admin_required)])
async def admin_create_user(
    user_data: AdminCreateUserRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(admin_required)
):
    existing_user = get_user_by_email(db, user_data.email)
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    password_length = 12
    alphabet = string.ascii_letters + string.digits
    generated_password = ''.join(secrets.choice(alphabet) for _ in range(password_length))
    hashed_password = bcrypt.hash(generated_password)
    role = db.query(Role).filter(Role.name == user_data.role).first()
    if not role:
        role = Role(name=user_data.role)
        db.add(role)
        db.commit()
        db.refresh(role)
    new_user = User(
        email=user_data.email,
        first_name=user_data.first_name,
        last_name=user_data.last_name,
        hashed_password=hashed_password,
        role_id=role.id,
        status='active',
        phone_number=user_data.phone_number,
        created_at=dt.datetime.utcnow(),
        updated_at=dt.datetime.utcnow()
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    send_temporary_password_email(user_data, generated_password)
    return new_user

@admin_router.post("/assign-work-center", response_model=WorkCenterAssignmentResponse)
async def assign_work_center(
    request: WorkCenterAssignment,
    db: Session = Depends(get_db),
    current_user: User = Depends(role_required(["super_admin", "manager", "admin"]))
):
    try:
        user = db.query(User).filter(User.email == request.email).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        work_center = db.query(WorkCenter).filter(WorkCenter.id == request.work_center_id).first()
        if not work_center:
            raise HTTPException(status_code=404, detail="Work center not found")
        user.work_center_id = request.work_center_id
        user.updated_at = datetime.datetime.utcnow()
        db.commit()
        return WorkCenterAssignmentResponse(
            user_id=user.id,
            work_center_id=request.work_center_id,
            message=f"User {request.email} assigned to work center {request.work_center_id}"
        )
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        print(f"Error in assign_work_center: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error assigning work center: {str(e)}")

@admin_router.post("/roles/assign-permissions/")
async def assign_permissions_to_role(
    data: PermissionAssignRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # Find the role
    role = db.query(Role).filter(Role.name == data.role_name).first()
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")
    # Remove existing permissions
    db.query(RolePermission).filter(RolePermission.role_id == role.id).delete()
    # Assign new permissions
    for perm_name in data.permissions:
        perm = db.query(Permission).filter(Permission.name == perm_name).first()
        if perm:
            db.add(RolePermission(role_id=role.id, permission_id=perm.id))
    db.commit()
    return {"message": f"Permissions assigned to role '{data.role_name}'"}

@admin_router.post("/permissions/create")
async def create_permission(
    request: PermissionCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # Only admin can create permissions
    role = db.query(Role).filter(Role.id == current_user.role_id).first()
    if not role or role.name.lower() != "admin":
        raise HTTPException(status_code=403, detail="Only admin can create permissions.")

    # Check if permission already exists
    if db.query(Permission).filter(Permission.name == request.name).first():
        raise HTTPException(status_code=400, detail="Permission already exists.")

    permission = Permission(name=request.name, description=request.description)
    db.add(permission)
    db.commit()
    db.refresh(permission)
    return {"message": f"Permission '{request.name}' created.", "id": permission.id}


@admin_router.get("/notifications/history/")
async def get_notification_history(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    limit: int = 50,
    offset: int = 0
):
    history = db.query(NotificationHistory).filter_by(user_id=current_user.id)\
        .order_by(NotificationHistory.sent_at.desc())\
        .limit(limit).offset(offset).all()
    return [
        {
            "id": n.id,
            "type": n.type,
            "event": n.event,
            "message": n.message,
            "status": n.status,
            "sent_at": n.sent_at.isoformat()
        } for n in history
    ]

@admin_router.get("/admin/users/", response_model=List[UserResponse], dependencies=[Depends(admin_required)])
async def admin_get_users(
    name: Optional[str] = Query(None),
    email: Optional[str] = Query(None),
    role_id: Optional[int] = Query(None),
    active: Optional[bool] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(admin_required)
):
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
    if role_id:
        query = query.filter(User.role_id == role_id)
    if active is not None:
        query = query.filter(User.status == ('active' if active else 'blocked'))
    users = query.all()
    return [user_to_response(user, db) for user in users]

@admin_router.post("/admin/create-user/", response_model=UserResponse, dependencies=[Depends(admin_required)])
async def admin_create_user(
    user_data: AdminCreateUserRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(admin_required)
):
    existing_user = get_user_by_email(db, user_data.email)
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    password_length = 12
    alphabet = string.ascii_letters + string.digits
    generated_password = ''.join(secrets.choice(alphabet) for _ in range(password_length))
    hashed_password = bcrypt.hash(generated_password)
    role = db.query(Role).filter(Role.name == user_data.role).first()
    if not role:
        role = Role(name=user_data.role)
        db.add(role)
        db.commit()
        db.refresh(role)
    new_user = User(
        email=user_data.email,
        first_name=user_data.first_name,
        last_name=user_data.last_name,
        hashed_password=hashed_password,
        role_id=role.id,
        status='active',
        phone_number=user_data.phone_number,
        created_at=dt.datetime.utcnow(),
        updated_at=dt.datetime.utcnow()
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    send_temporary_password_email(user_data, generated_password)
    return new_user

@admin_router.post("/assign-work-center", response_model=WorkCenterAssignmentResponse)
async def assign_work_center(
    request: WorkCenterAssignment,
    db: Session = Depends(get_db),
    current_user: User = Depends(role_required(["super_admin", "manager", "admin"]))
):
    try:
        user = db.query(User).filter(User.email == request.email).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        work_center = db.query(WorkCenter).filter(WorkCenter.id == request.work_center_id).first()
        if not work_center:
            raise HTTPException(status_code=404, detail="Work center not found")
        user.work_center_id = request.work_center_id
        user.updated_at = datetime.datetime.utcnow()
        db.commit()
        return WorkCenterAssignmentResponse(
            user_id=user.id,
            work_center_id=request.work_center_id,
            message=f"User {request.email} assigned to work center {request.work_center_id}"
        )
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        print(f"Error in assign_work_center: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error assigning work center: {str(e)}")

@admin_router.post("/roles/assign-permissions/")
async def assign_permissions_to_role(
    data: PermissionAssignRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # Find the role
    role = db.query(Role).filter(Role.name == data.role_name).first()
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")
    # Remove existing permissions
    db.query(RolePermission).filter(RolePermission.role_id == role.id).delete()
    # Assign new permissions
    for perm_name in data.permissions:
        perm = db.query(Permission).filter(Permission.name == perm_name).first()
        if perm:
            db.add(RolePermission(role_id=role.id, permission_id=perm.id))
    db.commit()
    return {"message": f"Permissions assigned to role '{data.role_name}'"}

@admin_router.post("/permissions/create")
async def create_permission(
    request: PermissionCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # Only admin can create permissions
    role = db.query(Role).filter(Role.id == current_user.role_id).first()
    if not role or role.name.lower() != "admin":
        raise HTTPException(status_code=403, detail="Only admin can create permissions.")

    # Check if permission already exists
    if db.query(Permission).filter(Permission.name == request.name).first():
        raise HTTPException(status_code=400, detail="Permission already exists.")

    permission = Permission(name=request.name, description=request.description)
    db.add(permission)
    db.commit()
    db.refresh(permission)
    return {"message": f"Permission '{request.name}' created.", "id": permission.id}