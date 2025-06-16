import datetime
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from sqlalchemy import or_
from typing import List, Optional
from db.models import User, Role, UserRole, Permission, RolePermission, UserStatusAudit, NotificationHistory, UserStatus
from db.database import get_db
from api.services.users import get_current_user, role_required, user_to_response
from api.schemas import (
    UserResponse, UserCreate, RoleResponse, RoleCreate, PermissionResponse, PermissionCreate, PermissionAssignment
)

admin_router = APIRouter()

# --- User Management ---
@admin_router.post("/users/{user_id}/deactivate/")
@role_required(["admin", "super_admin"])
async def deactivate_user(
    user_id: int,
    reason: str = Query(..., min_length=1, max_length=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    user = db.query(User).filter(User.user_id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.status == 'DEACTIVATED':
        raise HTTPException(status_code=400, detail="User is already deactivated")
    if user.status == 'BLOCKED':
        raise HTTPException(status_code=400, detail="User is blocked and cannot be deactivated")
    old_status = user.status
    user.status = 'DEACTIVATED'
    user.updated_at = datetime.datetime.utcnow()
    user.last_modified_by = current_user.username
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
    return {"message": "User deactivated successfully", "user_id": user.user_id, "status": user.status}

@admin_router.post("/users/{user_id}/reactivate/")
@role_required(["admin", "super_admin"])
async def reactivate_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    user = db.query(User).filter(User.user_id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.status != 'DEACTIVATED':
        raise HTTPException(status_code=400, detail="User is not deactivated")
    old_status = user.status
    user.status = 'ACTIVE'
    user.updated_at = datetime.datetime.utcnow()
    user.last_modified_by = current_user.username
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
    return {"message": "User reactivated successfully", "user_id": user.user_id, "status": user.status}

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

@admin_router.post("/users", response_model=UserResponse)
@role_required(["admin", "super_admin"])
async def admin_create_user(
    user: UserCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    existing_user = db.query(User).filter(User.username == user.username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already exists")
    existing_email = db.query(User).filter(User.email == user.email).first()
    if existing_email:
        raise HTTPException(status_code=400, detail="Email already exists")
    valid_roles = db.query(Role).filter(Role.role_name.in_(user.roles)).all()
    if len(valid_roles) != len(user.roles):
        invalid_roles = set(user.roles) - {role.role_name for role in valid_roles}
        raise HTTPException(status_code=400, detail=f"Invalid roles: {', '.join(invalid_roles)}")
    new_user = User(
        username=user.username,
        email=user.email,
        password_hash="hashed_password",  # Replace with actual password logic
        first_name=user.first_name,
        last_name=user.last_name,
        status=UserStatus.ACTIVE,
        created_by=current_user.username,
        last_modified_by=current_user.username
    )
    db.add(new_user)
    db.flush()
    for role in valid_roles:
        user_role = UserRole(
            user_id=new_user.user_id,
            role_id=role.role_id,
            active=True,
            created_by=current_user.username,
            last_modified_by=current_user.username
        )
        db.add(user_role)
    db.commit()
    db.refresh(new_user)
    return user_to_response(new_user, db)

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
                "delivery_timestamp": n.delivery_timestamp.isoformat() if n.delivery_timestamp else None,
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
    return {
        "id": new_role.role_id,
        "name": new_role.role_name,
        "description": new_role.description,
        "permissions": [
            {
                "id": p.permission_id,
                "feature_name": p.feature,
                "description": p.description,
                "created_at": p.created_at
            } for p in perms
        ]
    }

@admin_router.get("/roles")
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
    total = query.count()
    roles = query.offset((page - 1) * limit).limit(limit).all()
    result = []
    for role in roles:
        perms = db.query(Permission).join(RolePermission).filter(RolePermission.role_id == role.role_id).all()
        result.append({
            "id": role.role_id,
            "name": role.role_name,
            "description": role.description,
            "permissions": [
                {
                    "id": p.permission_id,
                    "feature_name": p.feature,
                    "description": p.description,
                    "created_at": p.created_at
                } for p in perms
            ]
        })
    return {"roles": result, "total": total, "page": page, "limit": limit}

# --- Permission Management ---
@admin_router.post("/permissions", response_model=PermissionResponse, status_code=201)
@role_required(["admin", "super_admin"])
async def create_permission(
    permission: PermissionCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if db.query(Permission).filter(Permission.feature == permission.feature_name).first():
        raise HTTPException(status_code=409, detail={"error": "Permission feature_name already exists"})
    new_perm = Permission(feature=permission.feature_name, description=permission.description, created_by=current_user.username)
    db.add(new_perm)
    db.commit()
    db.refresh(new_perm)
    return {
        "permission_id": new_perm.permission_id,
        "feature_name": new_perm.feature,
        "description": new_perm.description,
        "created_at": new_perm.created_at,
        "active": True
    }

@admin_router.get("/permissions")
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
    total = query.count()
    perms = query.offset((page - 1) * limit).limit(limit).all()
    result = [{
        "id": p.permission_id,
        "feature_name": p.feature,
        "description": p.description,
        "created_at": p.created_at
    } for p in perms]
    return {"permissions": result, "total": total, "page": page, "limit": limit}

@admin_router.patch("/roles/{role_id}/permissions")
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
        {
            "id": p.permission_id,
            "feature_name": p.feature,
            "description": p.description,
            "created_at": p.created_at
        } for p in updated_perms
    ]
