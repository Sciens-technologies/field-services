from datetime import datetime, timedelta
from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    status,
    Query,
    UploadFile,
    File,
    Body,
    Form,
)
from sqlalchemy.orm import Session
from sqlalchemy import update, select, and_, or_
from pydantic import EmailStr, BaseModel, Field
import os
import secrets
import string
import logging
from uuid import uuid4
from passlib.context import CryptContext
from fastapi.security import HTTPAuthorizationCredentials
from auth.auth import security
import csv

# Set up logging
logger = logging.getLogger(__name__)
from typing import Optional, Dict, cast, Any, List
from sqlalchemy.orm.attributes import InstrumentedAttribute
from sqlalchemy.sql.schema import Column as SAColumn

from db.database import get_db
from db.models import (
    User,
    Token,
    UserActivityLog,
    UserNotificationPreferences,
    SystemFeedback,
    SupportTicket,
    UserStatus,
    UserRole,
    Role,
    Permission,
    RolePermission,
)
from auth.auth import get_current_user, create_access_token
from api.schemas import (
    UserCreate,
    UserResponse,
    UserUpdate,
    TokenResponse,
    LoginRequest,
    ChangePasswordRequest,
    NotificationPreferencesUpdate,
    NotificationChannelPreferences,
    FeedbackCreate,
    FeedbackResponse,
    SupportTicketCreate,
    SupportTicketResponse,
    LoginResponse,
    ForgotPasswordResponse,
    SystemFeedbackRequest,
    SystemFeedbackResponse,
    SignupRequest,
)
from passlib.hash import bcrypt
from api.utils.email import send_email, send_password_reset_email
from api.services.users import get_user_roles, user_to_response

# Supported notification types
NOTIFICATION_TYPES = {
    "email": [
        "account_updates",  # Account-related changes
        "security_alerts",  # Security-related notifications
        "work_updates",  # Updates about work/tasks
        "feedback_responses",  # Responses to submitted feedback
        "ticket_updates",  # Updates on support tickets
        "system_announcements",  # System-wide announcements
    ],
    "sms": [
        "security_alerts",  # Critical security notifications
        "urgent_updates",  # Time-sensitive updates
        "work_assignments",  # New work assignments
    ],
    "push": [
        "new_messages",  # New message notifications
        "task_reminders",  # Task deadline reminders
        "status_changes",  # Status change notifications
        "approvals",  # Approval request notifications
    ],
}

# Add this near the top of the file, after imports
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

users_router = APIRouter()


def extract_value(val, name):
    if isinstance(val, (InstrumentedAttribute, SAColumn)):
        # For SQLAlchemy Column types, get the value from the instance
        if hasattr(val, "value"):
            val = val.value
        else:
            # Try to get the value directly from the instance
            try:
                val = getattr(val, "value", None)
                if val is None:
                    raise HTTPException(
                        status_code=500,
                        detail=f"User attribute '{name}' is not a value",
                    )
            except Exception:
                raise HTTPException(
                    status_code=500, detail=f"User attribute '{name}' is not a value"
                )
    if val is None:
        raise HTTPException(
            status_code=404, detail=f"User data incomplete: {name} is None"
        )
    return val


# --- Authentication ---
@users_router.post(
    "/login",
    summary="User login",
    description="Authenticate user and generate access token for API access. Accepts JSON body only.",
    response_model=LoginResponse,
    response_description="Access token and user info",
)
async def login_for_access_token(
    login_data: LoginRequest = Body(
        ..., example={"username": "user@example.com", "password": "yourpassword"}
    ),
    db: Session = Depends(get_db),
):
    """
    Authenticate user and generate access token for API access.
    Handles user login by validating credentials and providing authentication token.
    Accepts only JSON body.
    """
    try:
        print("\n=== Login Debug Information ===")
        print(f"Login attempt for username: {login_data.username}")

        # Find user using select()
        stmt = select(User).where(User.email == login_data.username)
        user = db.execute(stmt).scalar_one_or_none()

        if not user:
            print(f"User not found with email: {login_data.username}")
            raise HTTPException(status_code=401, detail="Invalid credentials")

        print(f"Found user: {user.email}")

        # Get password hash using scalar()
        password_hash = db.scalar(
            select(User.password_hash).where(User.user_id == user.user_id)
        )
        if password_hash is None:
            raise HTTPException(status_code=401, detail="Invalid credentials")

        print(f"Stored password: '{password_hash}' (length: {len(str(password_hash))})")
        print(
            f"Input password: '{login_data.password}' (length: {len(login_data.password)})"
        )
        print(f"Attempting to verify password...")

        # Verify password - direct string comparison since we store plain text
        stored_password = str(password_hash).strip()
        input_password = login_data.password.strip()

        print(
            f"After strip - Stored: '{stored_password}' (length: {len(stored_password)})"
        )
        print(
            f"After strip - Input: '{input_password}' (length: {len(input_password)})"
        )
        print(f"Comparison result: {stored_password == input_password}")

        if stored_password != input_password:
            print("Password verification failed")
            raise HTTPException(status_code=401, detail="Invalid credentials")

        print("Password verified successfully")

        # Get user status and activation status using scalar()
        user_status = db.scalar(select(User.status).where(User.user_id == user.user_id))
        is_activated = db.scalar(
            select(User.activated).where(User.user_id == user.user_id)
        )
        print(f"User status from DB: {user_status}")
        print(f"User activation status: {is_activated}")

        # Check if user is active
        if not is_activated:
            raise HTTPException(status_code=401, detail="Account is not activated")

        if user_status != UserStatus.ACTIVE:
            raise HTTPException(status_code=401, detail=f"Account is {user_status}")

        # Get user roles
        user_roles = db.query(UserRole).filter(UserRole.user_id == user.user_id, UserRole.active == True).all()
        role_names = []
        permission_names = set()
        for user_role in user_roles:
            role = db.query(Role).filter(Role.role_id == user_role.role_id).first()
            if role:
                role_names.append(role.role_name)
                # Get permissions for this role
                perms = (
                    db.query(Permission)
                    .join(RolePermission)
                    .filter(RolePermission.role_id == role.role_id, Permission.active == True)
                    .all()
                )
                for perm in perms:
                    permission_names.add(perm.feature)

        # Generate JWT token
        token_data = {
            "sub": str(user.user_id),  # Required for get_current_user
            "email": str(user.email),
            "username": str(user.username),
            "roles": role_names,  # Include roles in token
        }

        print(f"Creating token with data: {token_data}")
        access_token = create_access_token(token_data, expires_delta=timedelta(days=1))
        refresh_token = create_access_token(token_data, expires_delta=timedelta(days=7))

        # Store token in DB
        expires_at = datetime.utcnow() + timedelta(days=1)
        user_id = db.scalar(select(User.user_id).where(User.user_id == user.user_id))
        if user_id is None:
            raise HTTPException(status_code=404, detail="User not found")
        token_record = Token(
            user_id=user_id,
            access_token=access_token,
            refresh_token=refresh_token,
            expires_at=expires_at,
            revoked=False,
            created_at=datetime.utcnow(),
        )
        db.add(token_record)
        db.commit()

        # Get user details
        user_details = user_to_response(user, db)

        # Create response with proper type casting
        return LoginResponse(
            token=TokenResponse(
                access_token=access_token,
                token_type="bearer",
                expires_in=86400,  # 24 hours in seconds
            ),
            user=UserResponse(**user_details),
            roles=role_names,
            permissions=list(permission_names),
        )
    except HTTPException as he:
        raise he
    except Exception as e:
        print(f"\nUnexpected error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@users_router.post("/logout")
async def logout(
    email: EmailStr = Query(..., description="User email to logout"),
    current_user: User = Depends(get_current_user),
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
):
    if str(current_user.email) != email:
        raise HTTPException(
            status_code=403, detail="Email does not match the authenticated user"
        )
    """
    Securely end user session by invalidating their access token.
    Logs the logout activity and updates token status.
    """
    try:
        # Get the access token from the request
        access_token = credentials.credentials
        # Get token using select() for this session only
        stmt = (
            select(Token)
            .where(
                and_(
                    Token.user_id == current_user.user_id,
                    Token.access_token == access_token,
                    Token.revoked.is_(False)
                )
            )
        )
        token = db.execute(stmt).scalar_one_or_none()

        if not token:
            raise HTTPException(
                status_code=404, detail="Token not found or already revoked"
            )

        # Update token using update()
        token_update = (
            update(Token)
            .where(Token.id == token.id)
            .values({"revoked": True, "last_used_at": datetime.utcnow()})
        )
        db.execute(token_update)
        db.commit()

        # Extract user_id from SQLAlchemy Column using db.scalar()
        user_id = db.scalar(
            select(User.user_id).where(User.user_id == current_user.user_id)
        )
        if user_id is None:
            raise HTTPException(status_code=404, detail="User not found")

        # Log the logout activity
        activity_log = UserActivityLog(
            user_id=user_id,
            actor_id=user_id,
            action="LOGOUT",
            details="User logged out successfully",
            timestamp=datetime.utcnow(),
            ip_address=None,  # You can add IP address tracking if needed
            user_agent=None,  # You can add user agent tracking if needed
        )
        db.add(activity_log)
        db.commit()

        return {"message": "Successfully logged out"}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))


@users_router.post("/signup", response_model=UserResponse)
async def signup(user_data: SignupRequest, db: Session = Depends(get_db)):
    """
    Register a new user in the system.
    Only the first user can sign up. Further signups are blocked.
    """
    try:
        print("DB URL:", getattr(getattr(db, "bind", None), "url", None))
        print("User count:", db.scalar(select(User)))
        print("All users:", db.execute(select(User)).fetchall())

        # Block signup if any user already exists
        if db.scalar(select(User)):
            raise HTTPException(
                status_code=403, detail="Signup is only allowed for the first user."
            )
        # Check if user exists (redundant, but safe)
        if db.scalar(select(User).where(User.email == user_data.email)):
            raise HTTPException(status_code=400, detail="Email already registered")
        # Create new user
        new_user = User(
            uuid=str(uuid4()),
            username=user_data.username,
            email=user_data.email,
            password_hash=user_data.password,  # Store plain text password
            first_name=user_data.first_name,
            last_name=user_data.last_name,
            status=UserStatus.ACTIVE,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
            activated=True,
            last_login=None,
            last_login_ip=None,
            created_by=user_data.username
        )
        db.add(new_user)
        db.commit()
        db.refresh(new_user)

        # Ensure 'super_admin' role exists
        superadmin_role = db.query(Role).filter_by(role_name="super_admin").first()
        if not superadmin_role:
            superadmin_role = Role(
                role_name="super_admin",
                description="Super Administrator",
                status="ACTIVE",
                active=True,
                created_by=str(new_user.username),
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow(),
            )
            db.add(superadmin_role)
            db.commit()
            db.refresh(superadmin_role)

        # Assign 'super_admin' role to the new user
        user_role = UserRole(
            user_id=new_user.user_id,
            role_id=superadmin_role.role_id,
            active=True,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
            status="ACTIVE",
        )
        db.add(user_role)
        db.commit()

        # Create response using user_to_response helper
        response_data = user_to_response(new_user, db)
        print("DB URL:", getattr(getattr(db, "bind", None), "url", None))
        print("User count:", db.scalar(select(User)))
        print("All users:", db.execute(select(User)).fetchall())
        return UserResponse(**response_data)
    except HTTPException as he:
        raise he
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))


@users_router.get("/session/status")
async def check_session_status(
    current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
):
    """
    Verify if user's session is still valid and active.
    Checks token validity and updates last activity timestamp.
    """
    try:
        # Get token using select()
        stmt = (
            select(Token)
            .where(
                and_(
                    Token.user_id == current_user.user_id,
                    Token.revoked.is_(False),
                    Token.expires_at > datetime.utcnow(),
                )
            )
            .order_by(Token.created_at.desc())
        )
        token = db.execute(stmt).scalar_one_or_none()

        if not token:
            return {"active": False, "message": "Session expired"}

        # Update token using update()
        update_stmt = (
            update(Token)
            .where(Token.token_id == token.token_id)
            .values(last_used_at=datetime.utcnow())
        )
        db.execute(update_stmt)
        db.commit()

        # Get user data using scalar()
        user_id = db.scalar(
            select(User.user_id).where(User.user_id == current_user.user_id)
        )
        email = db.scalar(
            select(User.email).where(User.user_id == current_user.user_id)
        )
        status = db.scalar(
            select(User.status).where(User.user_id == current_user.user_id)
        )

        if any(x is None for x in [user_id, email, status]):
            raise HTTPException(status_code=404, detail="User data incomplete")

        return {
            "active": True,
            "last_activity": token.last_used_at.isoformat(),
            "user": {
                "user_id": int(user_id) if user_id is not None else 0,
                "email": str(email),
                "status": str(status),
            },
        }
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))


@users_router.get("/profile")
async def get_profile(
    current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
):
    """
    Retrieve current user's profile information.
    Returns user's personal and account details.
    """
    try:
        # Get user from database to ensure we have fresh data
        user = db.query(User).filter(User.user_id == current_user.user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        # Use user_to_response to convert user to response format
        response_data = user_to_response(user, db)
        return UserResponse(**response_data)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@users_router.put("/profile", response_model=None)
async def update_profile(
    update_data: UserUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Update user profile information.
    """
    try:
        # Check if username is being updated and if it already exists
        if update_data.username and update_data.username != current_user.username:
            existing_user = (
                db.query(User)
                .filter(
                    User.username == update_data.username,
                    User.user_id != current_user.user_id,  # Exclude current user
                )
                .first()
            )
            if existing_user:
                return {
                    "message": f"Username '{update_data.username}' already exists",
                    "existing_user": {
                        "user_id": existing_user.user_id,
                        "username": existing_user.username,
                        "email": existing_user.email,
                        "first_name": existing_user.first_name,
                        "last_name": existing_user.last_name,
                        "status": existing_user.status,
                    },
                }

        # Build update values dict, only including fields that are provided
        update_values = {}
        update_values["updated_at"] = datetime.utcnow()
        if update_data.username is not None:
            update_values["username"] = update_data.username
        if update_data.first_name is not None:
            update_values["first_name"] = update_data.first_name
        if update_data.last_name is not None:
            update_values["last_name"] = update_data.last_name
        if update_data.address is not None:
            update_values["address"] = update_data.address

        update_stmt = (
            update(User)
            .where(User.user_id == current_user.user_id)
            .values(update_values)
        )
        db.execute(update_stmt)
        db.commit()

        # Get updated user
        user = db.query(User).filter(User.user_id == current_user.user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        # Use user_to_response to convert user to response format
        response_data = user_to_response(user, db)
        return UserResponse(**response_data)
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))


@users_router.post("/change-password")
async def change_password(
    password_data: ChangePasswordRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Change user password.
    """
    try:
        # Get current password
        password_hash = db.scalar(
            select(User.password_hash).where(User.user_id == current_user.user_id)
        )
        if password_hash is None:
            raise HTTPException(status_code=401, detail="Invalid credentials")

        # Verify current password - direct string comparison
        if str(password_hash) != password_data.current_password:
            raise HTTPException(status_code=401, detail="Current password is incorrect")

        # Update password using update() - store plain text
        update_stmt = (
            update(User)
            .where(User.user_id == current_user.user_id)
            .values(
                password_hash=password_data.new_password,  # Store plain text password
                updated_at=datetime.utcnow(),
            )
        )
        db.execute(update_stmt)
        db.commit()
        # Revoke all tokens for this user
        db.execute(
            update(Token)
            .where(Token.user_id == current_user.user_id)
            .values(revoked=True)
        )
        db.commit()
        return {"message": "Password updated successfully. Please log in again."}
    except HTTPException as he:
        raise he
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))


@users_router.post(
    "/forgot-password",
    response_model=ForgotPasswordResponse,
    summary="Initiate password reset process",
    description="Generates a reset key and sends password reset instructions to the user's email",
)
async def forgot_password(
    email: EmailStr = Query(..., description="User email address"),
    db: Session = Depends(get_db),
):
    """
    Initiate password reset process.
    """
    try:
        logger.info(f"Password reset requested for email: {email}")
        
        # Get user using select()
        stmt = select(User).where(User.email == email)
        user = db.execute(stmt).scalar_one_or_none()
        if not user:
            logger.warning(f"Password reset attempted for non-existent email: {email}")
            raise HTTPException(status_code=404, detail="User not found")

        # Generate reset key
        reset_key = "".join(
            secrets.choice(string.ascii_letters + string.digits) for _ in range(32)
        )
        logger.info(f"Generated reset key for user {user.username}")

        # Update user using update()
        update_stmt = (
            update(User)
            .where(User.user_id == user.user_id)
            .values(reset_key=reset_key, reset_at=datetime.utcnow())
        )
        db.execute(update_stmt)
        db.commit()

        # Send reset email
        logger.info(f"Sending password reset email to {email}")
        email_sent = await send_password_reset_email(
            email=str(user.email), username=str(user.username), reset_key=reset_key
        )

        if not email_sent:
            logger.error(f"Failed to send password reset email to {user.email}")
            # Don't rollback the reset key - it's still valid even if email fails
            # The user can request another reset if needed
            return {
                "message": "Password reset key generated but email delivery failed. Please try again or contact support.",
                "reset_key": reset_key,
                "email": str(user.email),
            }

        logger.info(f"Successfully sent password reset email to {email}")
        return {
            "message": "Password reset instructions sent to your email",
            "reset_key": reset_key,
            "email": str(user.email),
        }
    except HTTPException as he:
        raise he
    except Exception as e:
        logger.error(f"Unexpected error in password reset for {email}: {str(e)}")
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Password reset failed: {str(e)}")


@users_router.post("/reset-password")
async def reset_password(
    reset_key: str = Query(..., description="Password reset key"),
    new_password: str = Query(..., min_length=8, description="New password"),
    db: Session = Depends(get_db),
):
    """
    Reset user password using reset key.
    """
    try:
        # Get user using select()
        stmt = select(User).where(User.reset_key == reset_key)
        user = db.execute(stmt).scalar_one_or_none()
        if not user:
            raise HTTPException(status_code=404, detail="Invalid reset key")

        # Check reset key expiration (24 hours)
        reset_at = db.scalar(select(User.reset_at).where(User.user_id == user.user_id))
        if not reset_at or (datetime.utcnow() - reset_at) > timedelta(hours=24):
            raise HTTPException(status_code=400, detail="Reset key has expired")

        # Update password using update() - store plain text
        update_stmt = (
            update(User)
            .where(User.user_id == user.user_id)
            .values(
                password_hash=new_password,  # Store plain text password
                reset_key=None,
                reset_at=None,
                updated_at=datetime.utcnow(),
            )
        )
        db.execute(update_stmt)
        db.commit()
        # Revoke all tokens for this user
        db.execute(
            update(Token).where(Token.user_id == user.user_id).values(revoked=True)
        )
        db.commit()
        return {"message": "Password reset successful. Please log in again."}
    except HTTPException as he:
        raise he
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))


@users_router.get("/notifications/preferences")
async def get_notification_preferences(
    current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
):
    """
    Get user's notification preferences.
    Retrieves or creates default notification settings.
    """
    try:
        # Get preferences using select()
        stmt = select(UserNotificationPreferences).where(
            UserNotificationPreferences.user_id == current_user.user_id
        )
        prefs = db.execute(stmt).scalar_one_or_none()

        if not prefs:
            # Get user_id using scalar()
            user_id = db.scalar(
                select(User.user_id).where(User.user_id == current_user.user_id)
            )
            if user_id is None:
                raise HTTPException(status_code=404, detail="User not found")

            # Create new preferences with proper type casting
            prefs = UserNotificationPreferences(
                user_id=int(user_id) if user_id is not None else 0,
                email_enabled=True,
                sms_enabled=True,
                push_enabled=True,
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow(),
            )
            db.add(prefs)
            db.commit()
            db.refresh(prefs)

        # Ensure boolean values are properly typed
        email_enabled = (
            bool(prefs.email_enabled) if prefs.email_enabled is not None else False
        )
        sms_enabled = (
            bool(prefs.sms_enabled) if prefs.sms_enabled is not None else False
        )
        push_enabled = (
            bool(prefs.push_enabled) if prefs.push_enabled is not None else False
        )

        return {
            "email": {
                "enabled": email_enabled,
                "types": {
                    notification_type: True
                    for notification_type in NOTIFICATION_TYPES["email"]
                },
            },
            "sms": {
                "enabled": sms_enabled,
                "types": {
                    notification_type: True
                    for notification_type in NOTIFICATION_TYPES["sms"]
                },
            },
            "push": {
                "enabled": push_enabled,
                "types": {
                    notification_type: True
                    for notification_type in NOTIFICATION_TYPES["push"]
                },
            },
        }
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))


@users_router.put("/notifications/preferences")
async def update_notification_preferences(
    preferences: NotificationPreferencesUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Update user notification preferences.
    """
    try:
        # Get existing preferences
        stmt = select(UserNotificationPreferences).where(
            UserNotificationPreferences.user_id == current_user.user_id
        )
        existing_prefs = db.execute(stmt).scalar_one_or_none()

        if existing_prefs:
            # Update existing preferences using update()
            update_stmt = (
                update(UserNotificationPreferences)
                .where(UserNotificationPreferences.user_id == current_user.user_id)
                .values(
                    {
                        "email_enabled": bool(preferences.email_enabled),
                        "sms_enabled": bool(preferences.sms_enabled),
                        "push_enabled": bool(preferences.push_enabled),
                        "updated_at": datetime.utcnow(),
                    }
                )
            )
            db.execute(update_stmt)
        else:
            # Create new preferences
            user_id = db.scalar(
                select(User.user_id).where(User.user_id == current_user.user_id)
            )
            if user_id is None:
                raise HTTPException(status_code=404, detail="User not found")

            # Cast SQLAlchemy Column type to Python type
            user_id_int = int(user_id) if user_id is not None else None
            if user_id_int is None:
                raise HTTPException(status_code=404, detail="User not found")

            # Create new preferences with properly typed values
            new_prefs = UserNotificationPreferences(
                user_id=user_id_int,
                email_enabled=bool(preferences.email_enabled),
                sms_enabled=bool(preferences.sms_enabled),
                push_enabled=bool(preferences.push_enabled),
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow(),
            )
            db.add(new_prefs)

        db.commit()
        return {
            "email_enabled": bool(preferences.email_enabled),
            "sms_enabled": bool(preferences.sms_enabled),
            "push_enabled": bool(preferences.push_enabled),
        }
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))


@users_router.post(
    "/feedback",
    summary="Submit system feedback",
    description="Submit feedback about the system",
    response_model=SystemFeedbackResponse,
    status_code=status.HTTP_201_CREATED,
)
async def submit_feedback(
    feedback: SystemFeedbackRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Submit feedback about the system."""
    try:
        # Create feedback object with proper field mapping
        feedback_obj = SystemFeedback(
            user_id=current_user.user_id,
            category="GENERAL",  # Default category
            subject=feedback.subject,
            description=feedback.description,
            priority="MEDIUM",  # Default priority
            status="PENDING",
            submitted_at=datetime.utcnow(),
            active=True,
        )

        db.add(feedback_obj)
        db.commit()
        db.refresh(feedback_obj)

        # Convert to response model
        response = SystemFeedbackResponse(
            feedback_id=feedback_obj.__dict__["feedback_id"],
            user_id=feedback_obj.__dict__["user_id"],
            category=str(feedback_obj.category),
            subject=str(feedback_obj.subject),
            description=str(feedback_obj.description),
            priority=str(feedback_obj.priority),
            status=str(feedback_obj.status),
            submitted_at=feedback_obj.__dict__["submitted_at"],
            active=bool(feedback_obj.active),
        )

        return response
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e)
        )


@users_router.post("/tickets", response_model=SupportTicketResponse)
async def create_support_ticket(
    ticket: SupportTicketCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Create a support ticket
    Purpose: Allow users to create support tickets for various issues
    """
    try:
        # Get user_id using scalar()
        user_id = db.scalar(
            select(User.user_id).where(User.user_id == current_user.user_id)
        )
        if user_id is None:
            raise HTTPException(status_code=404, detail="User not found")

        # Create ticket with proper type casting
        new_ticket = SupportTicket(
            user_id=int(user_id) if user_id is not None else 0,
            category="GENERAL",  # Default category
            subject=str(ticket.subject) if ticket.subject is not None else "",
            description=str(ticket.description)
            if ticket.description is not None
            else "",
            priority="MEDIUM",  # Default priority
            status="OPEN",
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        db.add(new_ticket)

        # Create activity log with proper type casting
        log = UserActivityLog(
            user_id=int(user_id) if user_id is not None else 0,
            actor_id=int(user_id) if user_id is not None else 0,
            action="create_ticket",
            details=f"Created support ticket: {ticket.subject}",
            timestamp=datetime.utcnow(),
        )
        db.add(log)
        db.commit()
        db.refresh(new_ticket)

        return SupportTicketResponse(
            ticket_id=getattr(new_ticket, "ticket_id", 0) or 0,
            user_id=getattr(new_ticket, "user_id", 0) or 0,
            category=getattr(new_ticket, "category", "") or "",
            subject=getattr(new_ticket, "subject", "") or "",
            description=getattr(new_ticket, "description", "") or "",
            priority=getattr(new_ticket, "priority", "") or "",
            status=getattr(new_ticket, "status", "") or "",
            created_at=getattr(new_ticket, "created_at", None) or datetime.utcnow(),
            updated_at=getattr(new_ticket, "updated_at", None) or datetime.utcnow(),
        )
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))


@users_router.get("/tickets", response_model=List[SupportTicketResponse])
async def get_support_tickets(
    db: Session = Depends(get_db),
):
    """
    Get all support tickets (public endpoint).
    """
    try:
        tickets = db.query(SupportTicket).order_by(SupportTicket.created_at.desc()).all()
        return [
            SupportTicketResponse(
                ticket_id=getattr(ticket, "ticket_id", 0),
                user_id=getattr(ticket, "user_id", 0),
                category=getattr(ticket, "category", ""),
                subject=getattr(ticket, "subject", ""),
                description=getattr(ticket, "description", ""),
                priority=getattr(ticket, "priority", ""),
                status=getattr(ticket, "status", ""),
                created_at=getattr(ticket, "created_at", datetime.utcnow()) or datetime.utcnow(),
                updated_at=getattr(ticket, "updated_at", datetime.utcnow()) or datetime.utcnow(),
            )
            for ticket in tickets
        ]
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))


async def _check_permission(
    current_user: User, permission_feature: str, db: Session
) -> bool:
    """Helper function to check permissions asynchronously."""
    try:
        # Get user roles using select()
        stmt = (
            select(UserRole)
            .join(Role)
            .where(
                and_(
                    UserRole.user_id == current_user.user_id, UserRole.active.is_(True)
                )
            )
        )
        user_roles = db.execute(stmt).scalars().all()

        # Check each role for the permission
        for role in user_roles:
            # Get role permissions using select()
            perm_stmt = (
                select(Permission)
                .join(RolePermission)
                .where(
                    and_(
                        RolePermission.role_id == role.role_id,
                        Permission.feature_name == permission_feature,
                        Permission.active.is_(True),
                    )
                )
            )
            permission = db.execute(perm_stmt).scalar_one_or_none()

            if permission is not None:
                return True

        return False
    except Exception as e:
        print(f"Error checking permission: {str(e)}")
        return False
