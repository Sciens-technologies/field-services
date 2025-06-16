from fastapi import Depends, HTTPException, status
from sqlalchemy.orm import Session
from db.models import User, Role, UserStatusAudit, UserRole, UserStatus
from db.database import get_db
from api.services.users import get_current_user, get_user_by_uuid
import datetime
from typing import List
from api.schemas import UserResponse

def check_admin(db: Session, current_user: User):
    """Helper function to check if a user has admin or super_admin privileges"""
    admin_roles = db.query(Role).filter(Role.role_name.in_(["admin", "super_admin"])).all()
    if not admin_roles:
        raise HTTPException(status_code=403, detail="Admin roles not found")
    
    user_role = db.query(UserRole).filter(
        UserRole.user_id == current_user.user_id,
        UserRole.role_id.in_([role.role_id for role in admin_roles]),
        UserRole.active == True
    ).first()
    
    if not user_role:
        raise HTTPException(status_code=403, detail="Admin or Super Admin access required")
    
    return True

def get_all_users(db: Session, current_user: User) -> List[UserResponse]:
    """Get all users (admin only)"""
    check_admin(db, current_user)
    return db.query(User).all()

def get_user_by_uuid_admin(user_uuid: str, db: Session, current_user: User) -> UserResponse:
    """Get user by UUID (admin only)"""
    check_admin(db, current_user)
    user = db.query(User).filter(User.uuid == user_uuid).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

def update_user_status(user_uuid: str, status: UserStatus, db: Session, current_user: User):
    """Update user status (admin only)"""
    check_admin(db, current_user)
    user = db.query(User).filter(User.uuid == user_uuid).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    old_status = user.status
    user.status = status
    user.updated_at = datetime.datetime.utcnow()
    user.last_modified_by = current_user.username
    
    # Create status audit record
    audit = UserStatusAudit(
        user_id=user.user_id,
        changed_by=current_user.username,
        old_status=old_status,
        new_status=status,
        reason="Status updated by admin",
        changed_at=datetime.datetime.utcnow()
    )
    db.add(audit)
    db.commit()
    
    return {"detail": "User status updated successfully"}

def block_user(user_uuid: str, db: Session, current_user: User):
    """Block a user (admin only)"""
    check_admin(db, current_user)
    user = get_user_by_uuid(db, user_uuid)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Store old status for audit
    old_status = user.status
    
    # Update user status
    user.status = UserStatus.BLOCKED
    user.updated_at = datetime.datetime.utcnow()
    user.last_modified_by = current_user.username
    
    # Create status audit record
    audit = UserStatusAudit(
        user_id=user.user_id,
        changed_by=current_user.username,
        old_status=old_status,
        new_status=UserStatus.BLOCKED,
        reason="User blocked by admin",
        changed_at=datetime.datetime.utcnow()
    )
    db.add(audit)
    db.commit()
    
    return {"detail": "User blocked successfully"}

def unblock_user(user_uuid: str, db: Session, current_user: User):
    """Unblock a user (admin only)"""
    check_admin(db, current_user)
    user = get_user_by_uuid(db, user_uuid)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Store old status for audit
    old_status = user.status
    
    # Update user status
    user.status = UserStatus.ACTIVE
    user.updated_at = datetime.datetime.utcnow()
    user.last_modified_by = current_user.username
    
    # Create status audit record
    audit = UserStatusAudit(
        user_id=user.user_id,
        changed_by=current_user.username,
        old_status=old_status,
        new_status=UserStatus.ACTIVE,
        reason="User unblocked by admin",
        changed_at=datetime.datetime.utcnow()
    )
    db.add(audit)
    db.commit()
    
    return {"detail": "User unblocked successfully"}

