from fastapi import APIRouter, Depends, HTTPException, status, Query, Request
from sqlalchemy.orm import Session
from typing import List, Optional
from sqlalchemy import text, or_
import os
import jwt
import datetime as dt
from api.utils.email import send_email, send_temporary_password_email, send_support_email, send_welcome_email, send_password_reset_email
import traceback
from pydantic import EmailStr
import secrets
import string
from api.services.users import get_current_user_optional, create_jwt_token, JWT_ACCESS_TOKEN_EXPIRES_IN, JWT_REFRESH_TOKEN_EXPIRES_IN,generate_secure_password
from api.utils.util import generate_random_password, get_db
from api.schemas import (
    UserCreate, UserResponse, UserUpdate, TokenSchema, 
    LoginJSONRequest, SignupRequest, RefreshTokenRequest,
    ChangePasswordRequest, UpdateProfileRequest, AdminCreateUserRequest,
    NotificationPreferencesUpdate, NotificationPreferencesResponse, ResetPasswordRequest,
    FeedbackCreate, FeedbackResponse,
    WorkCenterAssignment, WorkCenterAssignmentResponse, SupportTicketCreate,FeedbackRequest,LoginRequest
)
from api.services.users import (
    get_user_by_email, get_user_by_id, get_current_user, 
    has_role, get_user_from_token, has_permission,generate_tokens
)
from db.models import (
    User, Role, UserRole, Token, LoginActivity, 
    Permission, RolePermission, UserPermission,
    UserNotificationPreferences, NotificationHistory, UserActivityLog, Notification,Feedback
)
from passlib.hash import bcrypt
from fastapi.security import OAuth2PasswordRequestForm

users_router = APIRouter()

SUPPORTED_EVENTS = {
    "email_notifications": ["welcome", "password_reset", "feedback"],
    "sms_notifications": ["otp", "alert"],
    "push_notifications": ["reminder", "update"]
}

INACTIVITY_TIMEOUT_STR = os.getenv("INACTIVITY_TIMEOUT", "900")
INACTIVITY_TIMEOUT = int(INACTIVITY_TIMEOUT_STR.split('#')[0].strip())  # 15 minutes in seconds

# --- Auth ---
@users_router.post("/logout/")
async def logout(token: str = Query(..., description="Access token to invalidate"), 
                db: Session = Depends(get_db)):
    """
    Logout a user by invalidating their token.
    """
    try:
        db_token = db.query(Token).filter(Token.access_token == token).first()
        if not db_token:
            raise HTTPException(status_code=404, detail="Token not found")
        db_token.revoked = True
        db.commit()
        return {"message": "Successfully logged out"}
    except Exception as e:
        db.rollback()
        print(f"Error in logout: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error during logout: {str(e)}")

# --- Signup & Login ---
# Add this to your users.py
@users_router.post("/reset-password")
async def reset_password(request: ResetPasswordRequest, db: Session = Depends(get_db)):
    """
    Resets a user's password.
    """
    try:
        user = get_user_by_email(db, request.email)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        hashed_password = bcrypt.hash(request.new_password)
        db.execute(
            text("""
                UPDATE users
                SET hashed_password = :hashed_password
                WHERE email = :email
            """),
            {"hashed_password": hashed_password, "email": request.email}
        )
        db.commit()
        return {"message": "Password reset successful"}
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        print(f"Error in reset_password: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error during password reset: {str(e)}")

# --- 2. Session & Auth ---
@users_router.get("/session/status", status_code=status.HTTP_200_OK)
async def check_session_status(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Checks if the current user's session is still active based on the inactivity timeout.
    Returns the session status and time remaining before automatic logout.
    """
    try:
        user_id = current_user.id
        current_time = dt.datetime.utcnow()
        result = db.execute(
            text("""
            SELECT last_used_at
            FROM auth_tokens
            WHERE user_id = :user_id AND revoked = FALSE
            ORDER BY last_used_at DESC
            LIMIT 1
            """),
            {"user_id": user_id}
        ).fetchone()
        if not result or not result[0]:
            db.execute(
                text("""
                UPDATE auth_tokens
                SET last_used_at = :last_used_at
                WHERE user_id = :user_id AND revoked = FALSE
                """),
                {"user_id": user_id, "last_used_at": current_time}
            )
            db.commit()
            return {
                "active": True,
                "last_activity": current_time.isoformat(),
                "seconds_remaining": INACTIVITY_TIMEOUT
            }
        last_activity = result[0]
        time_since_last_activity = (current_time - last_activity).total_seconds()
        seconds_remaining = max(0, INACTIVITY_TIMEOUT - time_since_last_activity)
        if seconds_remaining <= 0:
            db.execute(
                text("""
                UPDATE auth_tokens
                SET revoked = TRUE
                WHERE user_id = :user_id AND revoked = FALSE
                """),
                {"user_id": user_id}
            )
            db.commit()
            return {
                "active": False,
                "last_activity": last_activity.isoformat(),
                "seconds_remaining": 0,
                "message": "Session expired due to inactivity"
            }
        db.execute(
            text("""
            UPDATE auth_tokens
            SET last_used_at = :last_used_at
            WHERE user_id = :user_id AND revoked = FALSE
            """),
            {"user_id": user_id, "last_used_at": current_time}
        )
        db.commit()
        return {
            "active": True,
            "last_activity": last_activity.isoformat(),
            "seconds_remaining": int(seconds_remaining)
        }
    except Exception as e:
        db.rollback()
        print(f"Error checking session status: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error checking session status: {str(e)}")

# --- 3. Profile & Password ---
@users_router.put("/profile/", response_model=UserResponse)
async def update_profile(
    profile_data: UpdateProfileRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Update the current user's profile information.
    """
    try:
        if profile_data.first_name:
            current_user.first_name = profile_data.first_name
        if profile_data.last_name:
            current_user.last_name = profile_data.last_name
        if profile_data.email:
            existing_user = get_user_by_email(db, profile_data.email)
            if existing_user and existing_user.id != current_user.id:
                raise HTTPException(status_code=400, detail="Email already in use")
            current_user.email = profile_data.email
        if profile_data.phone_number:
            current_user.phone_number = profile_data.phone_number
        current_user.updated_at = dt.datetime.utcnow()
        db.commit()
        db.refresh(current_user)
        return current_user
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        print(f"Error updating profile: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error updating profile: {str(e)}")

@users_router.post("/change-password/")
async def change_password(
    password_data: ChangePasswordRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.id == current_user.id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    hashed_password = bcrypt.hash(password_data.new_password)
    user.hashed_password = hashed_password
    user.updated_at = dt.datetime.utcnow()
    db.commit()
    db.refresh(user)
    return {"message": "Password updated successfully"}

@users_router.post("/forgot-password/")
async def forgot_password(
    email: EmailStr = Query(..., description="User email address"),
    db: Session = Depends(get_db)
):
    """
    Initiates password reset process by sending a reset link to the user's email.
    """
    try:
        user = get_user_by_email(db, email)
        if not user:
            return {"message": "If the email exists, a password reset link has been sent"}
        reset_token = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(64))
        expires_at = dt.datetime.utcnow() + dt.timedelta(hours=24)
        db.execute(
            text("DELETE FROM password_reset_tokens WHERE user_id = :user_id"),
            {"user_id": user.id}
        )
        db.execute(
            text("""
            INSERT INTO password_reset_tokens (user_id, token, expires_at)
            VALUES (:user_id, :token, :expires_at)
            """),
            {"user_id": user.id, "token": reset_token, "expires_at": expires_at}
        )
        db.commit()
        try:
            send_password_reset_email(
               to_email=user.email,
                reset_token=reset_token,
                first_name=user.first_name
            )
        except Exception as e:
            print(f"Error sending password reset email: {str(e)}")
        return {"message": "If the email exists, a password reset link has been sent"}
    except Exception as e:
        db.rollback()
        print(f"Error in forgot password: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error processing request: {str(e)}")

# Notification preferences endpoints
@users_router.get("/notifications/preferences/", response_model=NotificationPreferencesResponse)
async def get_notification_preferences(
    current_user: UserResponse = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    try:
        prefs = db.query(UserNotificationPreferences).filter_by(user_id=current_user.id).first()
        if not prefs:
            return NotificationPreferencesResponse(
                user_id=current_user.id,
                email=True,
                sms=True,
                push=True
            )
        return NotificationPreferencesResponse(
            user_id=prefs.user_id,
            email=prefs.email_notifications.get("enabled", True),
            sms=prefs.sms_notifications.get("enabled", True),
            push=prefs.push_notifications.get("enabled", True)
        )
    except Exception as e:
        print(f"Error in get_notification_preferences: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@users_router.put("/notifications/preferences/", response_model=NotificationPreferencesResponse)
async def update_notification_preferences(
    preferences: NotificationPreferencesUpdate,
    current_user: UserResponse = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    try:
        prefs = db.query(UserNotificationPreferences).filter_by(user_id=current_user.id).first()
        if not prefs:
            prefs = UserNotificationPreferences(
                user_id=current_user.id,
                email_notifications={"enabled": True, "frequency": "immediate"},
                sms_notifications={"enabled": True, "frequency": "immediate"},
                push_notifications={"enabled": True, "frequency": "immediate"}
            )
            db.add(prefs)
        if preferences.email is not None:
            prefs.email_notifications = {
                "enabled": preferences.email,
                "frequency": prefs.email_notifications.get("frequency", "immediate")
            }
        if preferences.sms is not None:
            prefs.sms_notifications = {
                "enabled": preferences.sms,
                "frequency": prefs.sms_notifications.get("frequency", "immediate")
            }
        if preferences.push is not None:
            prefs.push_notifications = {
                "enabled": preferences.push,
                "frequency": prefs.push_notifications.get("frequency", "immediate")
            }
        prefs.updated_at = dt.datetime.utcnow()
        db.commit()
        db.refresh(prefs)
        return NotificationPreferencesResponse(
            user_id=prefs.user_id,
            email=prefs.email_notifications.get("enabled", True),
            sms=prefs.sms_notifications.get("enabled", True),
            push=prefs.push_notifications.get("enabled", True)
        )
    except Exception as e:
        db.rollback()
        print(f"Error in update_notification_preferences: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

# --- Feedback/Support ---
@users_router.post("/feedback/request", response_model=FeedbackResponse)
async def submit_feedback_request(
    request: FeedbackRequest,
    db: Session = Depends(get_db),
    current_user: UserResponse = Depends(get_current_user)
):
    try:
        feedback = Feedback(
            user_id=current_user.id,
            subject=request.subject,
            message=f"Request ID: {request.request_id}\n{request.description}",
            status="open",
            created_at=dt.datetime.utcnow()
        )
        db.add(feedback)
        db.commit()
        db.refresh(feedback)
        try:
            await send_support_email(
                ticket_id=feedback.id,
                subject=feedback.subject,
                message=feedback.message,
                user_email=current_user.email
            )
            notification = NotificationHistory(
                user_id=current_user.id,
                type="email",
                event="feedback_request_submitted",
                message=f"Feedback request #{feedback.id} sent to support",
                status="delivered",
                sent_at=dt.datetime.utcnow()
            )
        except Exception as e:
            notification = NotificationHistory(
                user_id=current_user.id,
                type="email",
                event="feedback_request_submitted",
                message=f"Failed to send feedback request #{feedback.id}: {str(e)}",
                status="failed",
                sent_at=dt.datetime.utcnow()
            )
        db.add(notification)
        db.commit()
        return FeedbackResponse(
            id=feedback.id,
            subject=feedback.subject,
            message=feedback.message,
            status=feedback.status,
            created_at=feedback.created_at
        )
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        print(f"Error in submit_feedback_request: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@users_router.post("/support/ticket", response_model=FeedbackResponse)
async def submit_support_ticket(
    ticket: SupportTicketCreate,
    db: Session = Depends(get_db),
    current_user: UserResponse = Depends(get_current_user)
):
    try:
        feedback = Feedback(
            user_id=current_user.id,
            subject=ticket.subject,
            message=f"Ticket Type: {ticket.ticket_type}\nDescription: {ticket.description}",
            status="open",
            created_at=dt.datetime.utcnow()
        )
        db.add(feedback)
        db.commit()
        db.refresh(feedback)
        try:
            await send_support_email(
                ticket_id=feedback.id,
                subject=f"Support Ticket: {feedback.subject}",
                message=feedback.message,
                user_email=current_user.email
            )
            notification_user = Notification(
                user_id=current_user.id,
                title="Support Ticket Submitted",
                message=f"Your support ticket #{feedback.id} has been submitted successfully.",
                is_read=False,
                created_at=dt.datetime.utcnow()
            )
            db.add(notification_user)
        except Exception as e:
            db.add(Notification(
                user_id=current_user.id,
                title="Support Ticket Submission Failed",
                message=f"Failed to send email for ticket #{feedback.id}: {str(e)}",
                is_read=False,
                created_at=dt.datetime.utcnow()
            ))
        admins = db.query(User).join(Role).filter(Role.name == "admin").all()
        for admin in admins:
            db.add(Notification(
                user_id=admin.id,
                title="New Support Ticket",
                message=f"User {current_user.name} submitted support ticket #{feedback.id}",
                is_read=False,
                created_at=dt.datetime.utcnow()
            ))
        db.commit()
        return FeedbackResponse(
            id=feedback.id,
            subject=feedback.subject,
            message=feedback.message,
            status=feedback.status,
            created_at=feedback.created_at
        )
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        print(f"Error in submit_support_ticket: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

def login_user_logic(user: User, db: Session):
    tokens = generate_tokens(user.id, user.email, user.role_id)
    role = db.query(Role).filter(Role.id == user.role_id).first()
    return {
        "access_token": tokens["access_token"],
        "refresh_token": tokens["refresh_token"],
        "expires_in": JWT_ACCESS_TOKEN_EXPIRES_IN,
        "user": {
            "email": user.email,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "role": role.name if role else None
        }
    }


@users_router.post("/login/", response_model=TokenSchema)
async def login_user(
    credentials: LoginRequest,
    db: Session = Depends(get_db)
):
    user = get_user_by_email(db, credentials.email)
    if not user or not bcrypt.verify(credentials.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if user.status != 'active':
        raise HTTPException(status_code=401, detail="User is deactivated")
    return login_user_logic(user, db)