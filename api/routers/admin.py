from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from sqlalchemy import text, or_
import datetime as dt
import secrets
import string
from typing import List, Optional
from api.services.admin import role_required, admin_required
from db.models import User, Role, UserActivityLog, NotificationHistory, WorkCenter
from db.database import get_db
from api.services.users import get_current_user, get_user_by_email, get_current_user_optional, user_to_response
from api.schemas import UserResponse, AdminCreateUserRequest, WorkCenterAssignment, WorkCenterAssignmentResponse, SignupRequest
from passlib.hash import bcrypt
from api.utils.email import send_temporary_password_email, send_welcome_email
from api.utils.util import generate_random_password

admin_router = APIRouter()

@admin_router.post("/signup/", response_model=UserResponse)
async def signup(
    user_data: SignupRequest,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_optional)
):
    user_count = db.query(User).count()
    if user_count == 0:
        pass
    else:
        admin_roles = [1, 2]
        if not current_user or current_user.role_id not in admin_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to perform this action"
            )
    try:
        existing_user = get_user_by_email(db, user_data.email)
        if existing_user:
            raise HTTPException(status_code=400, detail="Email already registered")
        hashed_password = bcrypt.hash(user_data.password)
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
            created_at=dt.datetime.utcnow(),
            updated_at=dt.datetime.utcnow()
        )
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        try:
            send_welcome_email(
                email=user_data.email,
                username=user_data.email,
                password="[HIDDEN]",
                first_name=user_data.first_name
            )
        except Exception as e:
            print(f"Error sending welcome email: {str(e)}")
        return new_user
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        print(f"Error in signup: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error creating user: {str(e)}")

@admin_router.post("/users/{user_id}/block/", dependencies=[Depends(admin_required)])
async def block_user(
    user_id: int,
    reason: str = Query(..., min_length=1, max_length=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        user.status = 'blocked'
        user.blocked_at = dt.datetime.utcnow()
        user.block_reason = reason
        db.commit()
        db.execute(
            text("UPDATE auth_tokens SET revoked = TRUE WHERE user_id = :user_id AND revoked = FALSE"),
            {"user_id": user.id}
        )
        log = UserActivityLog(
            user_id=user.id,
            actor_id=current_user.id,
            action="block",
            details=reason,
            timestamp=dt.datetime.utcnow()
        )
        db.add(log)
        db.commit()
        return {
            "message": "User blocked successfully",
            "user_id": user.id,
            "status": user.status,
            "blocked_at": user.blocked_at.isoformat(),
            "block_reason": user.block_reason
        }
    except Exception as e:
        db.rollback()
        print(f"Error blocking user: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error blocking user: {str(e)}")

@admin_router.post("/users/{user_id}/unblock/", dependencies=[Depends(admin_required)])
async def unblock_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        if user.status != 'blocked':
            raise HTTPException(status_code=400, detail="User is not blocked")
        user.status = 'active'
        user.blocked_at = None
        user.block_reason = None
        user.updated_at = dt.datetime.utcnow()
        db.commit()
        log = UserActivityLog(
            user_id=user.id,
            actor_id=current_user.id,
            action="unblock",
            details="User unblocked by admin",
            timestamp=dt.datetime.utcnow()
        )
        db.add(log)
        db.commit()
        return {
            "message": "User unblocked successfully",
            "user_id": user.id,
            "status": user.status
        }
    except Exception as e:
        db.rollback()
        print(f"Error unblocking user: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error unblocking user: {str(e)}")

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
        user = get_user_by_email(db, request.email)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        work_center = db.query(WorkCenter).filter(WorkCenter.id == request.work_center_id).first()
        if not work_center:
            raise HTTPException(status_code=404, detail="Work center not found")
        role = db.query(Role).filter(Role.id == user.role_id).first()
        if not role:
            raise HTTPException(status_code=400, detail="User's role is invalid")
        user.work_center_id = request.work_center_id
        db.commit()
        db.execute(
            text("""
                INSERT INTO user_activity_logs (user_id, actor_id, action, details, timestamp)
                VALUES (:user_id, :actor_id, :action, :details, :timestamp)
            """),
            {
                "user_id": user.id,
                "actor_id": current_user.id,
                "action": "work_center_assignment",
                "details": f"Assigned to work center {request.work_center_id}",
                "timestamp": dt.datetime.utcnow()
            }
        )
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



