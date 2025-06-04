from fastapi import APIRouter, Depends, HTTPException, status, Security, Request, Query
from fastapi.security import OAuth2PasswordBearer, HTTPBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from typing import List, Optional
from sqlalchemy import text, or_
import os
import jwt
import datetime
from api.utils.email import send_email, send_temporary_password_email
import traceback
from pydantic import EmailStr
from fastapi import Request
from typing import Optional
from fastapi import FastAPI
from fastapi import APIRouter
import secrets
import string
from api.services.users import get_current_user_optional
from api.services.users import create_jwt_token, JWT_ACCESS_TOKEN_EXPIRES_IN, JWT_REFRESH_TOKEN_EXPIRES_IN
from api.utils.util import generate_random_password
import datetime as dt

# Use in your endpoint:
generated_password = generate_random_password()
users_router = APIRouter()
# At the top of users.py or in a new api/constants.py
SUPPORTED_EVENTS = {
    "email_notifications": ["welcome", "password_reset", "feedback"],
    "sms_notifications": ["otp", "alert"],
    "push_notifications": ["reminder", "update"]
}

# Session timeout settings
INACTIVITY_TIMEOUT_STR = os.getenv("INACTIVITY_TIMEOUT", "900")
INACTIVITY_TIMEOUT = int(INACTIVITY_TIMEOUT_STR.split('#')[0].strip())  # 15 minutes in seconds

from api.schemas import (
    UserCreate, UserResponse, UserUpdate, TokenSchema, 
    LoginRequest, SignupRequest, RefreshTokenRequest,
    ChangePasswordRequest, UpdateProfileRequest, AdminCreateUserRequest,
    NotificationPreferencesUpdate, NotificationPreferencesResponse,
    FeedbackRequest, SupportTicketCreate
)
from api.services.users import (
    get_user_by_email, get_user_by_id, get_current_user, 
    has_role, get_user_from_token, has_permission
)
from api.utils.util import get_db
from api.utils.email import send_welcome_email, send_password_reset_email
from db.models import (
    User, Role, UserRole, Token, LoginActivity, 
    Permission, RolePermission, UserPermission,
    UserNotificationPreferences, NotificationHistory, UserActivityLog,
    Feedback
)
from passlib.hash import bcrypt

# Load environment variables

# --- Auth ---
@users_router.post("/users/token", tags=["Auth"])
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    user = get_user_by_email(db, form_data.username)
    print(f"Login attempt for: {form_data.username}")
    if not user:
        print("User not found")
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not bcrypt.verify(form_data.password, user.hashed_password):
        print("Password mismatch")
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if user.status == 'blocked':
        raise HTTPException(status_code=401, detail="User is blocked")
    if user.status != 'active':
        raise HTTPException(status_code=401, detail="User is deactivated")
    tokens = generate_tokens(user.id, user.email, user.role_id)
    print("Login successful")
    return {
        "access_token": tokens["access_token"],
        "token_type": "bearer",
        "id": user.id,
        "first_name": user.first_name,
        "last_name": user.last_name,
        "role": user.role.name if hasattr(user.role, "name") else user.role,
        "email": user.email
    }

@users_router.post("/logout/")
async def logout(
    token: str = Query(..., description="Access token to invalidate"),
    email: EmailStr = Query(..., description="User email to logout"),
    db: Session = Depends(get_db)
):
    """
    Logout a user by both access token and email.
    Both token and email are required for security.
    """
    try:
        # Find user by email
        user = get_user_by_email(db, email)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        # Find the token in the database and verify it belongs to the user
        db_token = db.query(Token).filter(
            Token.access_token == token,
            Token.user_id == user.id,
            Token.revoked == False
        ).first()
        
        if not db_token:
            raise HTTPException(status_code=404, detail="Token not found or already revoked")
        
        # Mark the token as revoked
        db_token.revoked = True

        # Record logout time in activity logs
        activity = db.query(LoginActivity).filter(
            LoginActivity.agent_id == user.id,
            LoginActivity.logout_time.is_(None)
        ).first()
        
        if activity:
            activity.logout_time = datetime.datetime.utcnow()
        
        db.commit()
        
        return {"message": "Successfully logged out"}
    except Exception as e:
        db.rollback()
        print(f"Error in logout: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error during logout: {str(e)}")

# --- 1. Signup & Login ---
@users_router.post("/signup/", response_model=UserResponse)
async def signup(
    user_data: SignupRequest,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_optional)  # Use an optional dependency
):
    # Allow open signup if no users exist
    user_count = db.query(User).count()
    if user_count == 0:
        # Allow first user to be created as admin
        pass
    else:
        admin_roles = [1, 2]
        if not current_user or current_user.role_id not in admin_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to perform this action"
            )
    
    try:
        # Check if user already exists
        existing_user = get_user_by_email(db, user_data.email)
        if existing_user:
            raise HTTPException(status_code=400, detail="Email already registered")
        
        # Hash the password
        hashed_password = bcrypt.hash(user_data.password)
        
        # Get or create role
        role = db.query(Role).filter(Role.name == user_data.role).first()
        if not role:
            role = Role(name=user_data.role)
            db.add(role)
            db.commit()
            db.refresh(role)
        
        # Create new user
        new_user = User(
            email=user_data.email,
            first_name=user_data.first_name,
            last_name=user_data.last_name,
            hashed_password=hashed_password,
            role_id=role.id,
            status='active',
            created_at=datetime.datetime.utcnow(),
            updated_at=datetime.datetime.utcnow()
        )
        
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        
        # Send welcome email
        try:
            send_welcome_email(
                email=user_data.email,
                username=user_data.email,
                password="[HIDDEN]",  # Don't include password in email for security
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
        current_time = datetime.datetime.utcnow()
        
        # Get the last activity timestamp from the auth_tokens table
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
            # No activity record found, update it now
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
        
        # If the session has timed out, mark the token as revoked
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
        
        # Update the last_used_at timestamp to extend the session
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
@users_router.put("/profile/")
async def update_profile(
    update_data: UpdateProfileRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Update user profile. Email cannot be modified.
    """
    try:
        # Always fetch the user from the current session
        user = db.query(User).filter(User.id == current_user.id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Update fields
        if update_data.first_name:
            user.first_name = update_data.first_name
        if update_data.last_name:
            user.last_name = update_data.last_name
        if update_data.phone_number:
            user.phone_number = update_data.phone_number
        
        user.updated_at = datetime.datetime.utcnow()
        db.commit()
        db.refresh(user)
        
        return {"message": "Profile updated successfully"}
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
    """
    Change the current user's password and revoke all existing tokens.
    """
    try:
        print(f"Attempting to change password for user ID: {current_user.id}")
        
        # Get fresh user data from database
        user = db.query(User).filter(User.id == current_user.id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        # Verify old password
        if not bcrypt.verify(password_data.old_password, user.hashed_password):
            print(f"Password verification failed for user ID: {user.id}")
            raise HTTPException(status_code=400, detail="Incorrect current password")
        
        print(f"Old password verified successfully for user ID: {user.id}")
        
        # Hash and update new password
        new_hashed_password = bcrypt.hash(password_data.new_password)
        
        # Update password and timestamp
        db.execute(
            text("UPDATE users SET hashed_password = :new_password, updated_at = :updated_at WHERE id = :user_id"),
            {
                "new_password": new_hashed_password,
                "updated_at": datetime.datetime.utcnow(),
                "user_id": user.id
            }
        )
        
        print(f"Password updated in database for user ID: {user.id}")
        
        # Revoke all existing tokens
        db.execute(
            text("UPDATE auth_tokens SET revoked = TRUE WHERE user_id = :user_id"),
            {"user_id": user.id}
        )
        
        print(f"Tokens revoked for user ID: {user.id}")
        
        # Log the password change
        log = UserActivityLog(
            user_id=user.id,
            actor_id=user.id,
            action="change_password",
            details="Password changed by user",
            timestamp=datetime.datetime.utcnow()
        )
        db.add(log)
        
        db.commit()
        print(f"Password change completed successfully for user ID: {user.id}")
        
        return {"message": "Password changed successfully"}
    except HTTPException as he:
        print(f"HTTP Exception in change_password: {str(he)}")
        raise he
    except Exception as e:
        db.rollback()
        print(f"Error in change_password: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error changing password: {str(e)}")

@users_router.post("/forgot-password/")
async def forgot_password(
    email: EmailStr = Query(..., description="User email address"),
    db: Session = Depends(get_db)
):
    """
    Initiates password reset process by sending a reset link to the user's email.
    Password reset emails are a special case and will be sent regardless of notification preferences
    as they are critical for account security.
    """
    try:
        # Find user by email
        user = get_user_by_email(db, email)
        if not user:
            print(f"User not found for email: {email}")
            return {"message": "If the email exists, a password reset link has been sent"}
        
        # Generate a secure token
        reset_token = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(64))
        
        # Store token in database with expiration (24 hours)
        expires_at = datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        
        # Delete any existing reset tokens for this user
        db.execute(
            text("DELETE FROM password_reset_tokens WHERE user_id = :user_id"),
            {"user_id": user.id}
        )
        
        # Create new reset token
        db.execute(
            text("""
            INSERT INTO password_reset_tokens (user_id, token, expires_at)
            VALUES (:user_id, :token, :expires_at)
            """),
            {"user_id": user.id, "token": reset_token, "expires_at": expires_at}
        )
        
        # Send password reset email (this is a critical security email, so we send it regardless of preferences)
        reset_link = f"{os.getenv('FRONTEND_URL', 'http://localhost:3000')}/reset-password?token={reset_token}"
        
        try:
            send_email(
                to_email=user.email,
                subject="Password Reset Request - Field Service App",
                plain_text=f"""Hello {user.first_name},

We received a request to reset your password for the Field Service App.

Click here to reset your password: {reset_link}

This link will expire in 24 hours.

If you did not request a password reset, please ignore this email.

Thank you,
The Field Service Team""",
                html_content=f"""
<!DOCTYPE html>
<html>
<body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background-color: #4a90e2; color: white; padding: 15px; text-align: center;">
        <h2>Password Reset Request</h2>
    </div>
    
    <div style="padding: 20px; border: 1px solid #ddd;">
        <p>Hello {user.first_name},</p>
        <p>We received a request to reset your password for the Field Service App.</p>
        
        <p style="text-align: center; margin: 30px 0;">
            <a href="{reset_link}" style="background-color: #4a90e2; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px;">Click here to reset your password</a>
        </p>
        
        <p>This link will expire in 24 hours.</p>
        <p>If you did not request a password reset, please ignore this email.</p>
        
        <p>Thank you,<br>The Field Service Team</p>
    </div>
</body>
</html>""",
                ignore_preferences=True,  # Send regardless of notification preferences
                db=db  # Pass the database session
            )
            
            # Log the password reset request
            log = UserActivityLog(
                user_id=user.id,
                actor_id=user.id,
                action="password_reset_requested",
                details="Password reset requested via forgot password",
                timestamp=datetime.datetime.utcnow()
            )
            db.add(log)
            db.commit()
            
            print(f"Password reset email sent successfully to: {email}")
            return {"message": "If the email exists, a password reset link has been sent"}
            
        except Exception as email_error:
            print(f"Error sending password reset email: {str(email_error)}")
            # Still return success to not reveal if email exists
            return {"message": "If the email exists, a password reset link has been sent"}
            
    except Exception as e:
        db.rollback()
        print(f"Error in forgot password: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error processing request: {str(e)}")

@users_router.post("/reset-password/")
async def reset_password(
    token: str = Query(..., description="Password reset token"),
    new_password: str = Query(..., min_length=8, description="New password"),
    db: Session = Depends(get_db)
):
    """
    Reset password using the reset token.
    """
    try:
        # Find valid reset token
        result = db.execute(
            text("""
            SELECT user_id, expires_at 
            FROM password_reset_tokens 
            WHERE token = :token AND used = FALSE
            """),
            {"token": token}
        ).fetchone()
        
        if not result:
            raise HTTPException(status_code=400, detail="Invalid or expired reset token")
            
        user_id, expires_at = result
        
        if expires_at < datetime.datetime.utcnow():
            raise HTTPException(status_code=400, detail="Reset token has expired")
            
        # Get user
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
            
        # Update password
        user.hashed_password = bcrypt.hash(new_password)
        user.updated_at = datetime.datetime.utcnow()
        
        # Mark token as used
        db.execute(
            text("UPDATE password_reset_tokens SET used = TRUE WHERE token = :token"),
            {"token": token}
        )
        
        # Revoke all existing tokens
        db.execute(
            text("UPDATE auth_tokens SET revoked = TRUE WHERE user_id = :user_id"),
            {"user_id": user.id}
        )
        
        # Log the password reset
        log = UserActivityLog(
            user_id=user.id,
            actor_id=user.id,
            action="password_reset_completed",
            details="Password reset completed via reset token",
            timestamp=datetime.datetime.utcnow()
        )
        db.add(log)
        
        db.commit()
        
        # Send confirmation email
        try:
            send_email(
                to_email=user.email,
                subject="Password Reset Successful",
                plain_text=f"""
                Hello {user.first_name},

                Your password has been successfully reset.
                If you did not perform this action, please contact support immediately.

                Best regards,
                Your Application Team
                """
            )
        except Exception as email_error:
            print(f"Error sending password reset confirmation email: {str(email_error)}")
            
        return {"message": "Password has been reset successfully"}
        
    except HTTPException as he:
        raise he
    except Exception as e:
        db.rollback()
        print(f"Error resetting password: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error resetting password: {str(e)}")

# --- 6. OAuth2 Password Grant ---
@users_router.post("/users/token")
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    user = get_user_by_email(db, form_data.username)
    print(f"Login attempt for: {form_data.username}")
    if not user:
        print("User not found")
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not bcrypt.verify(form_data.password, user.hashed_password):
        print("Password mismatch")
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if user.status == 'blocked':
        raise HTTPException(status_code=401, detail="User is blocked")
    if user.status != 'active':
        raise HTTPException(status_code=401, detail="User is deactivated")
    tokens = generate_tokens(user.id, user.email, user.role_id)
    print("Login successful")
    return {
        "access_token": tokens["access_token"],
        "token_type": "bearer"
    }

def generate_tokens(user_id, email, role_id):
    access_token = create_jwt_token(user_id, email, role_id, JWT_ACCESS_TOKEN_EXPIRES_IN)
    refresh_token = create_jwt_token(user_id, email, role_id, JWT_REFRESH_TOKEN_EXPIRES_IN)
    return {
        "access_token": access_token,
        "refresh_token": refresh_token
    }

@users_router.get("/notifications/preferences/", response_model=NotificationPreferencesResponse)
async def get_notification_preferences(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get current notification preferences
    """
    try:
        prefs = db.query(UserNotificationPreferences).filter_by(user_id=current_user.id).first()
        if not prefs:
            # Create default preferences if none exist
            prefs = UserNotificationPreferences(
                user_id=current_user.id,
                email_enabled=True,
                sms_enabled=True,
                push_enabled=True,
                email_notifications={e: True for e in SUPPORTED_EVENTS["email_notifications"]},
                sms_notifications={e: True for e in SUPPORTED_EVENTS["sms_notifications"]},
                push_notifications={e: True for e in SUPPORTED_EVENTS["push_notifications"]}
            )
            db.add(prefs)
            db.commit()
            db.refresh(prefs)

        return NotificationPreferencesResponse(
            user_id=current_user.id,
            email=prefs.email_enabled,
            sms=prefs.sms_enabled,
            push=prefs.push_enabled
        )
    except Exception as e:
        print(f"Error getting notification preferences: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Error getting notification preferences: {str(e)}"
        )

@users_router.put("/notifications/preferences/", response_model=NotificationPreferencesResponse)
async def update_notification_preferences(
    preferences: NotificationPreferencesUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Update notification preferences. When email is disabled, no emails will be sent.
    When enabled, emails will be sent according to the preferences.
    """
    try:
        print(f"Updating notification preferences for user {current_user.email}")
        print(f"New preferences: {preferences}")
        
        # Get or create user preferences
        prefs = db.query(UserNotificationPreferences).filter_by(user_id=current_user.id).first()
        print(f"Current preferences before update: {prefs}")
        
        if not prefs:
            # Create new preferences if they don't exist
            prefs = UserNotificationPreferences(
                user_id=current_user.id,
                email_enabled=True,
                sms_enabled=True,
                push_enabled=True,
                email_notifications={e: True for e in SUPPORTED_EVENTS["email_notifications"]},
                sms_notifications={e: True for e in SUPPORTED_EVENTS["sms_notifications"]},
                push_notifications={e: True for e in SUPPORTED_EVENTS["push_notifications"]}
            )
            db.add(prefs)

        # Update main toggles and their corresponding notification settings
        if preferences.email is not None:
            print(f"Setting email_enabled to: {preferences.email}")
            prefs.email_enabled = preferences.email
            # When email is disabled, set all email notifications to False
            if not preferences.email:
                prefs.email_notifications = {e: False for e in SUPPORTED_EVENTS["email_notifications"]}
            # When email is enabled, restore all email notifications to True
            else:
                prefs.email_notifications = {e: True for e in SUPPORTED_EVENTS["email_notifications"]}

        if preferences.sms is not None:
            print(f"Setting sms_enabled to: {preferences.sms}")
            prefs.sms_enabled = preferences.sms
            # Update all SMS notifications based on the main toggle
            prefs.sms_notifications = {e: preferences.sms for e in SUPPORTED_EVENTS["sms_notifications"]}

        if preferences.push is not None:
            print(f"Setting push_enabled to: {preferences.push}")
            prefs.push_enabled = preferences.push
            # Update all push notifications based on the main toggle
            prefs.push_notifications = {e: preferences.push for e in SUPPORTED_EVENTS["push_notifications"]}

        prefs.updated_at = datetime.datetime.utcnow()
        
        # Log the preference update
        log = UserActivityLog(
            user_id=current_user.id,
            actor_id=current_user.id,
            action="update_notification_preferences",
            details=f"Updated notification preferences: email={preferences.email}, sms={preferences.sms}, push={preferences.push}",
            timestamp=datetime.datetime.utcnow()
        )
        db.add(log)
        
        # Commit all changes
        db.commit()
        db.refresh(prefs)
        
        print(f"Updated preferences: {prefs}")

        # Return the updated preferences
        return NotificationPreferencesResponse(
            user_id=current_user.id,
            email=prefs.email_enabled,
            sms=prefs.sms_enabled,
            push=prefs.push_enabled
        )

    except Exception as e:
        db.rollback()
        print(f"Error updating notification preferences: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Error updating notification preferences: {str(e)}"
        )

@users_router.get("/profile/", response_model=UserResponse)
async def get_profile(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get the current user's profile information.
    """
    try:
        user = db.query(User).filter(User.id == current_user.id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Convert user object to response format
        response = UserResponse(
            id=user.id,
            email=user.email,
            first_name=user.first_name,
            last_name=user.last_name,
            role=user.role.name if hasattr(user.role, "name") else str(user.role),
            status=user.status,
            phone_number=user.phone_number,
            created_at=user.created_at,
            updated_at=user.updated_at
        )
        return response
    except Exception as e:
        print(f"Error getting profile: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error getting profile: {str(e)}")

@users_router.post("/feedback/response/")
async def submit_feedback_response(
    feedback_data: FeedbackRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Submit a feedback response.
    """
    try:
        feedback = Feedback(
            user_id=current_user.id,
            subject=feedback_data.subject,
            message=feedback_data.description,
            status="open"
        )
        db.add(feedback)
        db.commit()
        db.refresh(feedback)
        return {
            "id": feedback.id,
            "message": "Feedback submitted successfully"
        }
    except Exception as e:
        db.rollback()
        print(f"Error submitting feedback: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error submitting feedback: {str(e)}")

@users_router.post("/tickets/create/")
async def create_ticket(
    ticket_data: SupportTicketCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Create a support ticket.
    """
    try:
        feedback = Feedback(
            user_id=current_user.id,
            subject=ticket_data.subject,
            message=ticket_data.description,
            status="open"
        )
        db.add(feedback)
        db.commit()
        db.refresh(feedback)
        return {
            "id": feedback.id,
            "message": "Support ticket created successfully"
        }
    except Exception as e:
        db.rollback()
        print(f"Error creating ticket: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error creating ticket: {str(e)}")

@users_router.post("/test-email/")
async def test_email_configuration(
    to_email: EmailStr = Query(..., description="Email address to test with"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Test endpoint to verify email configuration
    """
    try:
        # Try to send a test email
        test_subject = "Test Email Configuration"
        test_body = "This is a test email to verify your SMTP configuration is working correctly."
        
        success = send_email(
            to_email=to_email,
            subject=test_subject,
            plain_text=test_body
        )
        
        if success:
            return {
                "status": "success",
                "message": "Test email sent successfully! Please check your inbox.",
                "email_settings": {
                    "provider": os.getenv("MAIL_PROVIDER"),
                    "server": os.getenv("MAIL_SERVER"),
                    "port": os.getenv("MAIL_PORT"),
                    "username": os.getenv("MAIL_USERNAME"),
                    "from_address": os.getenv("MAIL_FROM_ADDRESS"),
                    "from_name": os.getenv("MAIL_FROM_NAME")
                }
            }
        else:
            return {
                "status": "error",
                "message": "Failed to send test email. Check server logs for details.",
                "email_settings": {
                    "provider": os.getenv("MAIL_PROVIDER"),
                    "server": os.getenv("MAIL_SERVER"),
                    "port": os.getenv("MAIL_PORT"),
                    "username": os.getenv("MAIL_USERNAME"),
                    "from_address": os.getenv("MAIL_FROM_ADDRESS"),
                    "from_name": os.getenv("MAIL_FROM_NAME")
                }
            }
            
    except Exception as e:
        print(f"Error in test email: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Error testing email configuration: {str(e)}"
        )