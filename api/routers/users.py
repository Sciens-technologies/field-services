from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException, status, Query, UploadFile, File, Body, Form
from sqlalchemy.orm import Session
from pydantic import EmailStr, BaseModel, Field
import os
import secrets
import string
from uuid import uuid4
from passlib.context import CryptContext
from typing import Optional, Dict

from db.database import get_db
from db.models import (
    User, Token, UserActivityLog, UserNotificationPreferences,
    SystemFeedback, SupportTicket, UserStatus
)
from auth.auth import get_current_user, create_access_token
from api.schemas import (
    UserCreate, UserResponse, UserUpdate,
    TokenResponse, LoginRequest, ChangePasswordRequest,NotificationPreferencesUpdate,NotificationChannelPreferences,
    FeedbackCreate, FeedbackResponse, SupportTicketCreate, SupportTicketResponse
)
from passlib.hash import bcrypt
from api.utils.email import send_email, send_password_reset_email
from api.services.users import get_user_roles

# Supported notification types
NOTIFICATION_TYPES = {
    "email": [
        "account_updates",      # Account-related changes
        "security_alerts",      # Security-related notifications
        "work_updates",         # Updates about work/tasks
        "feedback_responses",   # Responses to submitted feedback
        "ticket_updates",       # Updates on support tickets
        "system_announcements"  # System-wide announcements
    ],
    "sms": [
        "security_alerts",      # Critical security notifications
        "urgent_updates",       # Time-sensitive updates
        "work_assignments"      # New work assignments
    ],
    "push": [
        "new_messages",         # New message notifications
        "task_reminders",       # Task deadline reminders
        "status_changes",       # Status change notifications
        "approvals"            # Approval request notifications
    ]
}

# Add this near the top of the file, after imports
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

users_router = APIRouter()


# --- Authentication ---
@users_router.post(
    "/login",
    summary="User login",
    description="Authenticate user and generate access token for API access. Accepts JSON body only.",
    response_description="Access token and user info",
)
async def login_for_access_token(
    login_data: LoginRequest = Body(
        ..., 
        example={
            "username": "user@example.com",
            "password": "yourpassword"
        }
    ),
    db: Session = Depends(get_db)
):
    """
    Authenticate user and generate access token for API access.
    Handles user login by validating credentials and providing authentication token.
    Accepts only JSON body.
    """
    try:
        print("\n=== Login Debug Information ===")
        print(f"Login attempt for username: {login_data.username}")
        
        # Find user
        user = db.query(User).filter(User.email == login_data.username).first()
        if not user:
            print(f"User not found with email: {login_data.username}")
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        print(f"Found user: {user.email}")
        print(f"Stored password hash: {user.password_hash}")
        print(f"Attempting to verify password...")
        
        # Verify password
        if not pwd_context.verify(login_data.password, user.password_hash):
            print("Password verification failed")
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        print("Password verified successfully")
        
        if user.status != UserStatus.ACTIVE:
            print(f"User status is {user.status}")
            raise HTTPException(status_code=401, detail=f"Account is {user.status}")

        # Get user roles
        user_roles = get_user_roles(db, user.user_id)
        print(f"User roles: {user_roles}")

        # Generate JWT token
        token_data = {
            "sub": str(user.user_id),  # Required for get_current_user
            "email": user.email,
            "username": user.username,
            "roles": user_roles  # Include roles in token
        }
        
        print(f"Creating token with data: {token_data}")
        access_token = create_access_token(token_data)
        refresh_token = create_access_token(token_data)

        # Store token in DB
        expires_at = datetime.utcnow() + timedelta(days=1)
        token_record = Token(
            user_id=user.user_id,
            access_token=access_token,
            refresh_token=refresh_token,
            expires_at=expires_at,
            revoked=False,
            created_at=datetime.utcnow()
        )
        db.add(token_record)
        db.commit()

        return {
            "access_token": access_token,
            "token_type": "bearer",
            "id": user.user_id,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "email": user.email,
            "status": user.status,
            "uuid": user.uuid,
            "username": user.username,
            "roles": user_roles  # Include roles in response
        }
    except HTTPException as he:
        raise he
    except Exception as e:
        print(f"\nUnexpected error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@users_router.post("/logout")
async def logout(
    email: EmailStr = Query(..., description="User email to logout"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if current_user.email != email:
        raise HTTPException(status_code=403, detail="Email does not match the authenticated user")
    """
    Securely end user session by invalidating their access token.
    Logs the logout activity and updates token status.
    """
    try:
        token = db.query(Token).filter(
            Token.user_id == current_user.user_id,
            Token.revoked == False
        ).order_by(Token.created_at.desc()).first()
        if not token:
            raise HTTPException(status_code=404, detail="Token not found or already revoked")
        token.revoked = True
        token.last_used_at = datetime.utcnow()
        log = UserActivityLog(
            user_id=current_user.user_id,
            actor_id=current_user.user_id,
            action="logout",
            details="User logged out",
            timestamp=datetime.utcnow()
        )
        db.add(log)
        db.commit()
        return {"message": "Successfully logged out"}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

@users_router.post("/signup")
async def signup(
    user_data: UserCreate,
    db: Session = Depends(get_db)
):
    """
    Register a new user in the system.
    Only the first user can sign up. Further signups are blocked.
    """
    try:
        # Block signup if any user already exists
        if db.query(User).first():
            raise HTTPException(status_code=403, detail="Signup is only allowed for the first user.")
        # Check if user exists (redundant, but safe)
        if db.query(User).filter(User.email == user_data.email).first():
            raise HTTPException(status_code=400, detail="Email already registered")
        # Check if username is taken
        if db.query(User).filter(User.username == user_data.username).first():
            raise HTTPException(status_code=400, detail="Username already taken")
        # Hash password
        hashed_password = pwd_context.hash(user_data.password)
        # Generate UUID
        user_uuid = str(uuid4())
        # Create user
        new_user = User(
            email=user_data.email,
            username=user_data.username,
            password_hash=hashed_password,
            first_name=user_data.first_name,
            last_name=user_data.last_name,
            created_by=user_data.created_by or "SELF_SIGNUP",
            status=UserStatus.ACTIVE,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
            uuid=user_uuid
        )
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        return new_user
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

@users_router.get("/session/status")
async def check_session_status(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Verify if user's session is still valid and active.
    Checks token validity and updates last activity timestamp.
    """
    token = db.query(Token).filter(
        Token.user_id == current_user.user_id,
        Token.revoked == False,
        Token.expires_at > datetime.utcnow()
    ).first()
    
    if not token:
        return {
            "active": False,
            "message": "Session expired"
        }
    
    token.last_used_at = datetime.utcnow()
    db.commit()
    
    return {
        "active": True,
        "last_activity": token.last_used_at.isoformat(),
        "user": {
            "user_id": current_user.user_id,
            "email": current_user.email,
            "status": current_user.status
        }
    }

@users_router.get("/profile")
async def get_profile(
    current_user: User = Depends(get_current_user)
):
    """
    Retrieve current user's profile information.
    Returns user's personal and account details.
    """
    return current_user

@users_router.put("/profile")
async def update_profile(
    update_data: UserUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Update user's profile information.
    Allows users to modify their personal details and account settings.
    """
    try:
        # Check if username is taken (if being updated)
        if update_data.username and update_data.username != current_user.username:
            if db.query(User).filter(User.username == update_data.username).first():
                raise HTTPException(status_code=400, detail="Username already taken")
        
        # Update fields
        if update_data.username:
            current_user.username = update_data.username
        if update_data.first_name:
            current_user.first_name = update_data.first_name
        if update_data.last_name:
            current_user.last_name = update_data.last_name
        
        current_user.updated_at = datetime.utcnow()
        db.commit()
        
        return {
            "message": "Profile updated successfully",
            "user": {
                "username": current_user.username,
                "email": current_user.email,
                "first_name": current_user.first_name,
                "last_name": current_user.last_name
            }
        }
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

@users_router.post("/change-password")
async def change_password(
    password_data: ChangePasswordRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Change user's password.
    Verifies current password and updates to new password.
    """
    try:
        if not pwd_context.verify(password_data.old_password, current_user.password_hash):
            raise HTTPException(status_code=400, detail="Old password is incorrect")
        current_user.password_hash = pwd_context.hash(password_data.new_password)
        db.commit()
        return {"message": "Password changed successfully"}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

@users_router.post("/forgot-password")
async def forgot_password(
    email: EmailStr = Query(..., description="User email address"),
    db: Session = Depends(get_db)
):
    """
    Initiate password reset process.
    Generates reset token and sends it to user's email.
    """
    try:
        user = db.query(User).filter(User.email == email).first()
        if not user:
            raise HTTPException(status_code=404, detail="Email not found")
        # Generate reset token
        reset_token = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(20))
        user.reset_key = reset_token
        user.reset_at = datetime.utcnow()
        db.commit()  # Save token before sending email
        # Send password reset email with link and instructions
        email_sent = send_password_reset_email(
            email=user.email,
            username=user.username,
            reset_key=reset_token
        )
        if not email_sent:
            raise HTTPException(status_code=500, detail="Failed to send password reset email. Please try again later.")
        return {
            "message": "Password reset instructions sent to your email.",
            "reset_token": reset_token
        }
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

@users_router.post("/reset-password")
async def reset_password(
    reset_key: str = Query(..., description="Password reset key"),
    new_password: str = Query(..., min_length=8, description="New password"),
    db: Session = Depends(get_db)
):
    """
    Reset user's password using reset token.
    Validates reset token and updates password.
    """
    try:
        user = db.query(User).filter(User.reset_key == reset_key).first()
        if not user:
            raise HTTPException(status_code=400, detail="Invalid or expired reset token")
        user.password_hash = pwd_context.hash(new_password)
        user.reset_key = None
        user.reset_at = None
        db.commit()
        return {"message": "Password has been reset successfully."}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

@users_router.get("/notifications/preferences")
async def get_notification_preferences(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get user's notification preferences.
    Retrieves or creates default notification settings.
    """
    prefs = db.query(UserNotificationPreferences).filter(
        UserNotificationPreferences.user_id == current_user.user_id
    ).first()
    
    if not prefs:
        prefs = UserNotificationPreferences(
            user_id=current_user.user_id,
            email_enabled=True,
            sms_enabled=True,
            push_enabled=True
        )
        db.add(prefs)
        db.commit()
        db.refresh(prefs)
    
    return {
        "email": {
            "enabled": prefs.email_enabled,
            "types": {
                notification_type: True
                for notification_type in NOTIFICATION_TYPES["email"]
            }
        },
        "sms": {
            "enabled": prefs.sms_enabled,
            "types": {
                notification_type: True
                for notification_type in NOTIFICATION_TYPES["sms"]
            }
        },
        "push": {
            "enabled": prefs.push_enabled,
            "types": {
                notification_type: True
                for notification_type in NOTIFICATION_TYPES["push"]
            }
        }
    }

@users_router.put("/notifications/preferences")
async def update_notification_preferences(
    preferences: NotificationPreferencesUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Update user's notification preferences.
    Modifies notification settings for different channels.
    """
    prefs = db.query(UserNotificationPreferences).filter(
        UserNotificationPreferences.user_id == current_user.user_id
    ).first()
    if not prefs:
        prefs = UserNotificationPreferences(user_id=current_user.user_id)
        db.add(prefs)
    
    # Update channel preferences
    if preferences.email is not None:
        prefs.email_enabled = preferences.email
    if preferences.sms is not None:
        prefs.sms_enabled = preferences.sms
    if preferences.push is not None:
        prefs.push_enabled = preferences.push
    
    prefs.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(prefs)
    
    return {
        "email": {
            "enabled": prefs.email_enabled,
            "types": {
                notification_type: True
                for notification_type in NOTIFICATION_TYPES["email"]
            }
        },
        "sms": {
            "enabled": prefs.sms_enabled,
            "types": {
                notification_type: True
                for notification_type in NOTIFICATION_TYPES["sms"]
            }
        },
        "push": {
            "enabled": prefs.push_enabled,
            "types": {
                notification_type: True
                for notification_type in NOTIFICATION_TYPES["push"]
            }
        }
    }

@users_router.post("/feedback", response_model=FeedbackResponse)
async def submit_feedback(
    feedback: FeedbackCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Submit feedback
    Purpose: Allow users to submit system feedback or suggestions
    """
    new_feedback = SystemFeedback(
        user_id=current_user.user_id,
        category=feedback.category,
        subject=feedback.subject,
        description=feedback.description,
        priority=feedback.priority,
        status="PENDING"
    )
    db.add(new_feedback)
    
    log = UserActivityLog(
        user_id=current_user.user_id,
        actor_id=current_user.user_id,
        action="submit_feedback",
        details=f"Submitted feedback: {feedback.subject}",
        timestamp=datetime.utcnow()
    )
    db.add(log)
    db.commit()
    db.refresh(new_feedback)
    
    return new_feedback

@users_router.post("/tickets", response_model=SupportTicketResponse)
async def create_support_ticket(
    ticket: SupportTicketCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Create a support ticket
    Purpose: Allow users to create support tickets for various issues
    """
    new_ticket = SupportTicket(
        user_id=current_user.user_id,
        category=ticket.category,
        subject=ticket.subject,
        description=ticket.description,
        priority=ticket.priority,
        status="OPEN"
    )
    db.add(new_ticket)
    
    log = UserActivityLog(
        user_id=current_user.user_id,
        actor_id=current_user.user_id,
        action="create_ticket",
        details=f"Created support ticket: {ticket.subject}",
        timestamp=datetime.utcnow()
    )
    db.add(log)
    db.commit()
    db.refresh(new_ticket)
    
    return new_ticket