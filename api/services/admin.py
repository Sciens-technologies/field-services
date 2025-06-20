from fastapi import Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import select, update, and_
from db.models import User, Role, UserStatusAudit, UserRole, UserStatus
from db.database import get_db
from api.services.users import get_current_user, get_user_by_uuid
import datetime
from typing import List, Sequence
from api.schemas import UserResponse

def check_admin(db: Session, current_user: User) -> bool:
    """Helper function to check if a user has admin or super_admin privileges"""
    # Get admin roles using select()
    admin_roles_stmt = select(Role).where(Role.role_name.in_(["admin", "super_admin"]))
    admin_roles = db.execute(admin_roles_stmt).scalars().all()
    
    if not admin_roles:
        raise HTTPException(status_code=403, detail="Admin roles not found")
    
    # Check user role using select()
    user_role_stmt = select(UserRole).where(
        and_(
            UserRole.user_id == current_user.user_id,
            UserRole.role_id.in_([role.role_id for role in admin_roles]),
            UserRole.active.is_(True)
        )
    )
    user_role = db.execute(user_role_stmt).scalar_one_or_none()
    
    if not user_role:
        raise HTTPException(status_code=403, detail="Admin or Super Admin access required")
    
    return True

async def get_all_users(db: Session, current_user: User) -> Sequence[User]:
    """Get all users (admin only)"""
    check_admin(db, current_user)
    stmt = select(User)
    users = db.execute(stmt).scalars().all()
    return users

async def get_user_by_uuid_admin(user_uuid: str, db: Session, current_user: User) -> User:
    """Get user by UUID (admin only)"""
    check_admin(db, current_user)
    stmt = select(User).where(User.uuid == user_uuid)
    user = db.execute(stmt).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
<<<<<<< HEAD
    return user

async def update_user_status(user_uuid: str, status: UserStatus, db: Session, current_user: User) -> dict:
    """Update user status (admin only)"""
    check_admin(db, current_user)
    
    # Get user using select()
    stmt = select(User).where(User.uuid == user_uuid)
    user = db.execute(stmt).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    old_status = db.scalar(select(User.status).where(User.user_id == user.user_id))
    
    # Update user using update()
    update_stmt = (
        update(User)
        .where(User.user_id == user.user_id)
        .values(
            status=status,
            updated_at=datetime.datetime.utcnow(),
            last_modified_by=current_user.username
        )
    )
    db.execute(update_stmt)
    
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

async def block_user(user_uuid: str, db: Session, current_user: User) -> dict:
    """Block a user (admin only)"""
    check_admin(db, current_user)
    
    # Get user using select()
    stmt = select(User).where(User.uuid == user_uuid)
    user = db.execute(stmt).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Store old status for audit
    old_status = db.scalar(select(User.status).where(User.user_id == user.user_id))
    
    # Update user using update()
    update_stmt = (
        update(User)
        .where(User.user_id == user.user_id)
        .values(
            status=UserStatus.BLOCKED,
            updated_at=datetime.datetime.utcnow(),
            last_modified_by=current_user.username
        )
    )
    db.execute(update_stmt)
    
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

async def unblock_user(user_uuid: str, db: Session, current_user: User) -> dict:
    """Unblock a user (admin only)"""
    check_admin(db, current_user)
    
    # Get user using select()
    stmt = select(User).where(User.uuid == user_uuid)
    user = db.execute(stmt).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Store old status for audit
    old_status = db.scalar(select(User.status).where(User.user_id == user.user_id))
    
    # Update user using update()
    update_stmt = (
        update(User)
        .where(User.user_id == user.user_id)
        .values(
            status=UserStatus.ACTIVE,
            updated_at=datetime.datetime.utcnow(),
            last_modified_by=current_user.username
        )
    )
    db.execute(update_stmt)
    
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

=======
    user.status = "blocked"
    db.commit()
    return {"detail": "User blocked"}
>>>>>>> device_management
