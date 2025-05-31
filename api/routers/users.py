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
    NotificationPreferencesUpdate, NotificationPreferencesResponse
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
    UserNotificationPreferences, NotificationHistory, UserActivityLog
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

# --- Signup ---
@users_router.post("/signup/", response_model=UserResponse)  # Signup (first user or admin)
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

# --- REMOVE THIS LOGIN ENDPOINT ---
# @router.post("/login/", response_model=TokenSchema)
# async def login(user_credentials: Loginrequest, db: Session = Depends(get_db)):
#     """
#     Logs in a user, stores token in database, and records login activity.
#     """
#     try:
#         # Verify user credentials
#         user = get_user_by_email(db, user_credentials.email)
#         if not user or not bcrypt.verify(user_credentials.password, user.hashed_password):
#             raise HTTPException(status_code=401, detail="Invalid credentials")
#         if user.status != 'active':
#             raise HTTPException(status_code=401, detail="User is deactivated")

#         # Generate tokens with updated expiry time
#         tokens = generate_tokens(user.id, user.email, user.role_id)
#         access_token_expires_at = datetime.datetime.utcnow() + datetime.timedelta(seconds=JWT_ACCESS_TOKEN_EXPIRES_IN)
        
#         # Revoke any existing tokens for this user
#         db.execute(
#             text("""
#             UPDATE auth_tokens
#             SET revoked = TRUE
#             WHERE user_id = :user_id AND revoked = FALSE
#             """),
#             {"user_id": user.id}
#         )
        
#         # Store token in auth_tokens table
#         token_entry = {
#             "user_id": user.id,
#             "access_token": tokens["access_token"],
#             "refresh_token": tokens["refresh_token"],
#             "expires_at": access_token_expires_at,
#             "revoked": False,
#             "created_at": datetime.datetime.utcnow(),
#             "last_used_at": datetime.datetime.utcnow(),
#             "ip_address": None,
#             "device_info": None
#         }
        
#         # Insert into auth_tokens table using text()
#         db.execute(
#             text("""
#             INSERT INTO auth_tokens (user_id, access_token, refresh_token, expires_at, revoked, created_at, last_used_at, ip_address, device_info)
#             VALUES (:user_id, :access_token, :refresh_token, :expires_at, :revoked, :created_at, :last_used_at, :ip_address, :device_info)
#             """),
#             token_entry
#         )
        
#         # Record login activity in agent_activity_logs table
#         login_activity = {
#             "agent_id": user.id,
#             "login_time": datetime.datetime.utcnow(),
#             "ip_address": None,
#             "device_info": None
#         }
        
#         # Insert into agent_activity_logs table using text()
#         db.execute(
#             text("""
#             INSERT INTO agent_activity_logs (agent_id, login_time, ip_address, device_info)
#             VALUES (:agent_id, :login_time, :ip_address, :device_info)
#             """),
#             login_activity
#         )
        
#         db.commit()

#         return TokenSchema(
#             access_token=tokens["access_token"],
#             refresh_token=tokens["refresh_token"],
#             expires_in=JWT_ACCESS_TOKEN_EXPIRES_IN,
#         )
#     except Exception as e:
#         db.rollback()
#         print(f"Error in login: {str(e)}")
#         raise HTTPException(status_code=500, detail=f"Error during login: {str(e)}")

@users_router.post("/logout/")
async def logout(token: str = Query(..., description="Access token to invalidate"), 
                db: Session = Depends(get_db)):
    """
    Logout a user by invalidating their token.
    """
    try:
        # Find the token in the database
        db_token = db.query(Token).filter(Token.access_token == token).first()
        if not db_token:
            raise HTTPException(status_code=404, detail="Token not found")
        
        # Mark the token as revoked
        db_token.revoked = True
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

# --- REMOVE THIS LOGIN ENDPOINT ---
# @router.post("/login/", response_model=TokenSchema)
# async def login(user_credentials: Loginrequest, db: Session = Depends(get_db)):
#     """
#     Logs in a user, stores token in database, and records login activity.
#     """
#     try:
#         # Verify user credentials
#         user = get_user_by_email(db, user_credentials.email)
#         if not user or not bcrypt.verify(user_credentials.password, user.hashed_password):
#             raise HTTPException(status_code=401, detail="Invalid credentials")
#         if user.status != 'active':
#             raise HTTPException(status_code=401, detail="User is deactivated")

#         # Generate tokens with updated expiry time
#         tokens = generate_tokens(user.id, user.email, user.role_id)
#         access_token_expires_at = datetime.datetime.utcnow() + datetime.timedelta(seconds=JWT_ACCESS_TOKEN_EXPIRES_IN)
        
#         # Revoke any existing tokens for this user
#         db.execute(
#             text("""
#             UPDATE auth_tokens
#             SET revoked = TRUE
#             WHERE user_id = :user_id AND revoked = FALSE
#             """),
#             {"user_id": user.id}
#         )
        
#         # Store token in auth_tokens table
#         token_entry = {
#             "user_id": user.id,
#             "access_token": tokens["access_token"],
#             "refresh_token": tokens["refresh_token"],
#             "expires_at": access_token_expires_at,
#             "revoked": False,
#             "created_at": datetime.datetime.utcnow(),
#             "last_used_at": datetime.datetime.utcnow(),
#             "ip_address": None,
#             "device_info": None
#         }
        
#         # Insert into auth_tokens table using text()
#         db.execute(
#             text("""
#             INSERT INTO auth_tokens (user_id, access_token, refresh_token, expires_at, revoked, created_at, last_used_at, ip_address, device_info)
#             VALUES (:user_id, :access_token, :refresh_token, :expires_at, :revoked, :created_at, :last_used_at, :ip_address, :device_info)
#             """),
#             token_entry
#         )
        
#         # Record login activity in agent_activity_logs table
#         login_activity = {
#             "agent_id": user.id,
#             "login_time": datetime.datetime.utcnow(),
#             "ip_address": None,
#             "device_info": None
#         }
        
#         # Insert into agent_activity_logs table using text()
#         db.execute(
#             text("""
#             INSERT INTO agent_activity_logs (agent_id, login_time, ip_address, device_info)
#             VALUES (:agent_id, :login_time, :ip_address, :device_info)
#             """),
#             login_activity
#         )
        
#         db.commit()

#         return TokenSchema(
#             access_token=tokens["access_token"],
#             refresh_token=tokens["refresh_token"],
#             expires_in=JWT_ACCESS_TOKEN_EXPIRES_IN,
#         )
#     except Exception as e:
#         db.rollback()
#         print(f"Error in login: {str(e)}")
#         raise HTTPException(status_code=500, detail=f"Error during login: {str(e)}")

@users_router.post("/logout/")
async def logout(token: str = Query(..., description="Access token to invalidate"), 
                db: Session = Depends(get_db)):
    """
    Logout a user by invalidating their token.
    """
    try:
        # Find the token in the database
        db_token = db.query(Token).filter(Token.access_token == token).first()
        if not db_token:
            raise HTTPException(status_code=404, detail="Token not found")
        
        # Mark the token as revoked
        db_token.revoked = True
        db.commit()
        
        return {"message": "Successfully logged out"}
    except Exception as e:
        db.rollback()
        print(f"Error in logout: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error during logout: {str(e)}")

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
        if update_data.email:
            # Check if email is already taken by another user
            existing_user = get_user_by_email(db, update_data.email)
            if existing_user and existing_user.id != current_user.id:
                raise HTTPException(status_code=400, detail="Email already in use")
            user.email = update_data.email
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
    Change the current user's password.
    """
    try:
        # Verify old password
        if not bcrypt.verify(password_data.old_password, current_user.hashed_password):
            raise HTTPException(status_code=400, detail="Incorrect current password")
        
        # Update password
        current_user.hashed_password = bcrypt.hash(password_data.new_password)
        current_user.updated_at = datetime.datetime.utcnow()
        db.commit()
        
        # Revoke all existing tokens for this user
        db.execute(
            text("UPDATE auth_tokens SET revoked = TRUE WHERE user_id = :user_id"),
            {"user_id": current_user.id}
        )
        db.commit()
        
        return {"message": "Password changed successfully"}
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        print(f"Error changing password: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error changing password: {str(e)}")

@users_router.post("/forgot-password/")
async def forgot_password(
    email: EmailStr = Query(..., description="User email address"),
    db: Session = Depends(get_db)
):
    """
    Initiates password reset process by sending a reset link to the user's email.
    """
    try:
        # Find user by email
        user = get_user_by_email(db, email)
        if not user:
            # Don't reveal if email exists or not for security
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
        db.commit()
        
        # Send password reset email
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

@users_router.post("/reset-password/")
async def reset_password(
    email: EmailStr = Query(..., description="User email address"),
    new_password: str = Query(..., min_length=8),
    db: Session = Depends(get_db)
):
    """
    Reset password using the user's email and new password.
    """
    try:
        user = get_user_by_email(db, email)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        user.hashed_password = bcrypt.hash(new_password)
        user.updated_at = datetime.datetime.utcnow()
        db.commit()
        return {"message": "Password has been reset successfully"}
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
    prefs = db.query(UserNotificationPreferences).filter_by(user_id=current_user.id).first()
    if not prefs:
        return NotificationPreferencesResponse(
            user_id=current_user.id,
            email=True,
            sms=True,
            push=True
        )
    return NotificationPreferencesResponse(
        user_id=current_user.id,
        email=all(prefs.email_notifications.values()),
        sms=all(prefs.sms_notifications.values()),
        push=all(prefs.push_notifications.values())
    )

@users_router.put("/notifications/preferences/", response_model=NotificationPreferencesResponse)
async def update_notification_preferences(
    preferences: NotificationPreferencesUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    prefs = db.query(UserNotificationPreferences).filter_by(user_id=current_user.id).first()
    if not prefs:
        prefs = UserNotificationPreferences(
            user_id=current_user.id,
            email_notifications={e: True for e in SUPPORTED_EVENTS["email_notifications"]},
            sms_notifications={e: True for e in SUPPORTED_EVENTS["sms_notifications"]},
            push_notifications={e: True for e in SUPPORTED_EVENTS["push_notifications"]}
        )
        db.add(prefs)
    # Update all events for each type if provided
    if preferences.email is not None:
        for k in prefs.email_notifications.keys():
            prefs.email_notifications[k] = preferences.email
    if preferences.sms is not None:
        for k in prefs.sms_notifications.keys():
            prefs.sms_notifications[k] = preferences.sms
    if preferences.push is not None:
        for k in prefs.push_notifications.keys():
            prefs.push_notifications[k] = preferences.push
    prefs.updated_at = datetime.datetime.utcnow()
    db.commit()
    db.refresh(prefs)
    return NotificationPreferencesResponse(
        user_id=current_user.id,
        email=all(prefs.email_notifications.values()),
        sms=all(prefs.sms_notifications.values()),
        push=all(prefs.push_notifications.values())
    )

@users_router.post("/logout-by-email/")
async def logout_by_email(
    email: EmailStr = Query(..., description="User email address"),
    db: Session = Depends(get_db)
):
    """
    Logout a user by email by revoking all their tokens.
    """
    try:
        user = get_user_by_email(db, email)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        # Revoke all tokens for this user
        db.query(Token).filter(Token.user_id == user.id, Token.revoked == False).update({"revoked": True})
        db.commit()
        return {"message": f"Successfully logged out user {email}"}
    except Exception as e:
        db.rollback()
        print(f"Error in logout by email: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error during logout: {str(e)}")