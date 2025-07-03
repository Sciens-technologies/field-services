import datetime
from typing import (
    List,
    Optional,
    Union,
    Any,
    Awaitable,
    cast,
    Dict,
    TypeVar,
    Callable,
    Sequence,
)
from uuid import UUID, uuid4
from functools import wraps
from datetime import datetime, timedelta
from sqlalchemy import (
    text,
    and_,
    or_,
    exists,
    select,
    Boolean,
    DateTime,
    true,
    false,
    case,
    update,
    inspect,
)
from sqlalchemy.orm import Session
from sqlalchemy.sql import expression
from sqlalchemy.sql.elements import BinaryExpression
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt
import os
import logging
import inspect as inspect_module

logger = logging.getLogger(__name__)
from dotenv import load_dotenv
import json
from pydantic import parse_obj_as

from db.models import (
    User,
    UserRole,
    Role,
    Permission,
    RolePermission,
    UserStatusAudit,
    UserAuthProvider,
    UserAuthMetadata,
)
from db.database import get_db
from auth.auth import create_access_token
from api.schemas import UserResponse

# Type definitions
T = TypeVar("T")
AsyncCallable = Callable[..., Awaitable[T]]
SyncCallable = Callable[..., T]

# Load environment variables
load_dotenv()

# JWT settings
JWT_SECRET_KEY = os.getenv(
    "JWT_SECRET_KEY", "your-secure-secret-key-123"
)  # Use environment variable
JWT_ALGORITHM = "HS256"
JWT_ACCESS_TOKEN_EXPIRES_IN = timedelta(
    seconds=int(os.getenv("JWT_ACCESS_TOKEN_EXPIRES_IN", "86400"))
)  # 24 hours
JWT_REFRESH_TOKEN_EXPIRES_IN = timedelta(
    seconds=int(os.getenv("JWT_REFRESH_TOKEN_EXPIRES_IN", "2592000"))
)  # 30 days

security = HTTPBearer()


async def get_user_by_email(db: Session, email: str) -> Optional[User]:
    result = db.execute(
        select(User).where(User.email.ilike(email.strip()))
    ).scalar_one_or_none()
    return result


async def get_user_by_username(db: Session, username: str) -> Optional[User]:
    result = db.execute(
        select(User).where(User.username.ilike(username.strip()))
    ).scalar_one_or_none()
    return result


async def get_user_by_id(db: Session, user_id: int) -> Optional[User]:
    result = db.execute(
        select(User).where(User.user_id == user_id)
    ).scalar_one_or_none()
    return result


async def get_user_by_uuid(db: Session, uuid: str) -> Optional[User]:
    result = db.execute(select(User).where(User.uuid == uuid)).scalar_one_or_none()
    return result


async def get_user_roles(db: Session, user_id: int) -> List[str]:
    """Get list of active roles for a user."""
    try:
        print(f"\n=== Getting Roles for User {user_id} ===")
        # Get user roles using select()
        stmt = (
            select(UserRole)
            .join(Role)
            .where(and_(UserRole.user_id == user_id, UserRole.active.is_(True)))
        )
        user_roles = db.execute(stmt).scalars().all()

        # Get role names
        role_names = []
        for role in user_roles:
            role_name = db.scalar(
                select(Role.role_name).where(Role.role_id == role.role_id)
            )
            if role_name:
                role_names.append(str(role_name))

        print(f"Found roles: {role_names}")
        return role_names
    except Exception as e:
        print(f"Error getting user roles: {str(e)}")
        return []


async def create_jwt_token(
    data: Dict[str, Any], expires_delta: Optional[timedelta] = None
) -> str:
    """Create a new JWT token with debug logging."""
    try:
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + JWT_ACCESS_TOKEN_EXPIRES_IN
        to_encode.update({"exp": expire})
        print(f"\n=== Token Creation Debug ===")
        print(f"Token payload: {to_encode}")
        print(
            f"Using secret key: {JWT_SECRET_KEY[:10]}..."
        )  # Only show first 10 chars for security
        encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
        return encoded_jwt
    except Exception as e:
        print(f"Error creating token: {str(e)}")
        raise


async def decode_jwt_token(token: str) -> Dict[str, Any]:
    """Decode and validate JWT token with debug logging."""
    try:
        print(f"\n=== Token Decode Debug ===")
        print(f"Attempting to decode token: {token[:20]}...")
        print(
            f"Using secret key: {JWT_SECRET_KEY[:10]}..."
        )  # Only show first 10 chars for security
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        print(f"Successfully decoded payload: {payload}")
        return payload
    except jwt.ExpiredSignatureError:
        print("Token has expired")
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError as e:
        print(f"Invalid token error: {str(e)}")
        raise HTTPException(status_code=401, detail="Invalid token")
    except Exception as e:
        print(f"Unexpected error decoding token: {str(e)}")
        raise HTTPException(status_code=401, detail="Invalid token")


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
) -> User:
    token = credentials.credentials
    try:
        print(f"\n=== User Authentication Debug ===")
        print(f"Received token: {token[:20]}...")
        payload = await decode_jwt_token(token)
        print(f"Decoded payload: {payload}")
        user_id: Optional[int] = payload.get("sub")
        if user_id is None:
            print("No user_id in token payload")
            raise HTTPException(
                status_code=401, detail="Invalid authentication credentials"
            )
        stmt = select(User).where(User.user_id == user_id)
        user = db.execute(stmt).scalar_one_or_none()
        if user is None:
            print(f"User not found for id: {user_id}")
            raise HTTPException(status_code=401, detail="User not found")
        # Check user roles using SQLAlchemy expressions
        role_stmt = (
            select(UserRole)
            .join(Role)
            .where(and_(UserRole.user_id == user.user_id, UserRole.active.is_(True)))
        )
        user_roles = db.execute(role_stmt).scalars().all()
        role_names = []
        for role in user_roles:
            role_name = db.scalar(
                select(Role.role_name).where(Role.role_id == role.role_id)
            )
            if role_name:
                role_names.append(str(role_name))
        print(f"User roles: {role_names}")

        # Only check activation and status for non-admin endpoints
        if not any(role in ["admin", "super_admin"] for role in role_names):
            # Check activation status
            activated = db.scalar(select(User.activated).where(User.user_id == user_id))
            if not bool(activated):
                print(f"User {user_id} is not activated")
                raise HTTPException(status_code=401, detail="User is not activated")

            # Check user status
            user_status = db.scalar(select(User.status).where(User.user_id == user_id))
            if str(user_status) != "ACTIVE":
                print(f"User {user_id} status is {user_status}")
                raise HTTPException(status_code=401, detail=f"User is {user_status}")

        print(f"Successfully authenticated user: {user.email}")
        return user
    except HTTPException as he:
        raise he
    except Exception as e:
        print(f"Unexpected error in get_current_user: {str(e)}")
        raise HTTPException(
            status_code=401, detail="Invalid authentication credentials"
        )


async def get_current_user_optional(
    request: Request, db: Session = Depends(get_db)
) -> Optional[User]:
    try:
        auth = request.headers.get("Authorization")
        if not auth:
            return None

        scheme, token = auth.split()
        if scheme.lower() != "bearer":
            return None

        return await get_current_user(
            credentials=HTTPAuthorizationCredentials(scheme=scheme, credentials=token),
            db=db,
        )
    except Exception:
        return None


def has_role(allowed_roles: List[str]):
    async def role_checker(
        current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
    ) -> User:
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

        # Get role names
        role_names = []
        for role in user_roles:
            role_name = db.scalar(
                select(Role.role_name).where(Role.role_id == role.role_id)
            )
            if role_name:
                role_names.append(str(role_name))

        # Check if user has any of the allowed roles
        if not any(role in allowed_roles for role in role_names):
            raise HTTPException(
                status_code=403,
                detail=f"User does not have required roles: {', '.join(allowed_roles)}",
            )
        return current_user

    return role_checker


async def has_permission(
    current_user: User, permission_feature: str, db: Optional[Session] = None
) -> bool:
    """Check if user has a specific permission."""
    try:
        if db is None:
            return await _async_false()

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
                return await _async_true()

        return await _async_false()
    except Exception as e:
        print(f"Error checking permission: {str(e)}")
        return await _async_false()


async def _async_true() -> bool:
    """Helper function to return True in an async context."""
    return True


async def _async_false() -> bool:
    """Helper function to return False in an async context."""
    return False


async def log_user_status_change(
    db: Session,
    user_uuid: str,
    old_status: str,
    new_status: str,
    changed_by: str,
    reason: str,
    remarks: Optional[str] = None,
) -> UserStatusAudit:
    """Log user status change."""
    try:
        # Get user using select()
        user = db.execute(
            select(User).where(User.uuid == user_uuid)
        ).scalar_one_or_none()

        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        # Create status audit log
        log = UserStatusAudit(
            user_id=db.scalar(select(User.user_id).where(User.uuid == user_uuid)),
            old_status=old_status,
            new_status=new_status,
            changed_by=changed_by,
            reason=reason,
            remarks=remarks,
            changed_at=datetime.utcnow(),
        )
        db.add(log)
        db.commit()
        return log
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))


async def get_user_auth_provider(
    db: Session, user_uuid: str, provider: str
) -> Optional[UserAuthProvider]:
    """Get user auth provider."""
    try:
        # Get user using select()
        user = db.execute(
            select(User).where(User.uuid == user_uuid)
        ).scalar_one_or_none()

        if not user:
            return None

        # Get auth provider using select()
        auth_provider = db.execute(
            select(UserAuthProvider).where(
                and_(
                    UserAuthProvider.user_id == user.user_id,
                    UserAuthProvider.provider == provider,
                )
            )
        ).scalar_one_or_none()

        return auth_provider
    except Exception as e:
        print(f"Error getting auth provider: {str(e)}")
        return None


async def get_user_auth_metadata(
    db: Session, user_uuid: str, provider: str
) -> Optional[UserAuthMetadata]:
    """Get user auth metadata."""
    try:
        # Get user using select()
        user = db.execute(
            select(User).where(User.uuid == user_uuid)
        ).scalar_one_or_none()

        if not user:
            return None

        # Get auth metadata using select()
        auth_metadata = db.execute(
            select(UserAuthMetadata).where(
                and_(
                    UserAuthMetadata.user_id == user.user_id,
                    UserAuthMetadata.provider == provider,
                )
            )
        ).scalar_one_or_none()

        return auth_metadata
    except Exception as e:
        print(f"Error getting auth metadata: {str(e)}")
        return None


async def update_user_auth_metadata(
    db: Session,
    user_uuid: str,
    provider: str,
    access_token: str,
    refresh_token: Optional[str] = None,
    token_expires_at: Optional[datetime] = None,
) -> UserAuthMetadata:
    """Update user auth metadata."""
    try:
        # Get user using select()
        user = db.execute(
            select(User).where(User.uuid == user_uuid)
        ).scalar_one_or_none()

        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        # Get existing metadata using select()
        metadata = db.execute(
            select(UserAuthMetadata).where(
                and_(
                    UserAuthMetadata.user_id == user.user_id,
                    UserAuthMetadata.provider == provider,
                )
            )
        ).scalar_one_or_none()

        if metadata:
            # Update existing metadata using update()
            update_stmt = (
                update(UserAuthMetadata)
                .where(
                    and_(
                        UserAuthMetadata.user_id == user.user_id,
                        UserAuthMetadata.provider == provider,
                    )
                )
                .values(
                    {
                        "access_token": access_token,
                        "refresh_token": refresh_token,
                        "token_expires_at": token_expires_at,
                        "updated_at": datetime.utcnow(),
                    }
                )
            )
            db.execute(update_stmt)
        else:
            # Create new metadata
            metadata = UserAuthMetadata(
                user_id=db.scalar(select(User.user_id).where(User.uuid == user_uuid)),
                provider=provider,
                external_user_id=str(
                    db.scalar(select(User.uuid).where(User.uuid == user_uuid))
                ),
                access_token=access_token,
                refresh_token=refresh_token,
                token_expires_at=token_expires_at,
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow(),
            )
            db.add(metadata)

        db.commit()
        return metadata
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))


async def get_user_from_token(token: str, db: Session) -> Optional[User]:
    """Get user from token."""
    try:
        payload = await decode_jwt_token(token)
        user_id: Optional[int] = payload.get("sub")
        if user_id is None:
            return None

        # Get user using select()
        user = db.execute(
            select(User).where(User.user_id == user_id)
        ).scalar_one_or_none()

        return user
    except Exception as e:
        print(f"Error getting user from token: {str(e)}")
        return None


def role_required(required_roles):
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, current_user, db, **kwargs):
            # Get user roles from DB
            stmt = (
                select(UserRole)
                .join(Role)
                .where(
                    and_(
                        UserRole.user_id == current_user.user_id,
                        UserRole.active.is_(True),
                    )
                )
            )
            user_roles = db.execute(stmt).scalars().all()
            role_names = []
            for role in user_roles:
                role_name = db.scalar(
                    select(Role.role_name).where(Role.role_id == role.role_id)
                )
                if role_name:
                    role_names.append(str(role_name).lower())
            allowed_roles = [r.lower() for r in required_roles]
            if not any(role in allowed_roles for role in role_names):
                raise HTTPException(
                    status_code=403,
                    detail=f"User does not have required roles: {', '.join(allowed_roles)}",
                )
            return await func(*args, current_user=current_user, db=db, **kwargs)
        return wrapper
    return decorator


def user_to_response(user: User, db: Session) -> Dict[str, Any]:
    """Convert user model to response dictionary."""
    try:
        # Get a fresh copy of the user object
        user = db.get(User, user.user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        # Get user roles using select()
        stmt = (
            select(UserRole)
            .join(Role)
            .where(and_(UserRole.user_id == user.user_id, UserRole.active.is_(True)))
        )
        user_roles = db.execute(stmt).scalars().all()
        # Get role names
        role_names = []
        for role in user_roles:
            role_name = db.scalar(
                select(Role.role_name).where(Role.role_id == role.role_id)
            )
            if role_name:
                role_names.append(str(role_name))

        # Create response dictionary using hybrid properties that handle type conversion
        user_dict = {
            "user_id": user.user_id,  # This is already an int
            "uuid": user.uuid_value,
            "username": user.username_value,
            "email": user.email_value,
            "first_name": user.first_name_value,
            "last_name": user.last_name_value,
            "status": user.status_value,
            "created_at": user.created_at_value,
            "updated_at": user.updated_at_value,
            "roles": role_names,  # Always include roles
            "category": getattr(user, "category", "GENERAL") or "GENERAL",
            "address": getattr(user, "address", "") or "",
        }

        # Create UserResponse instance
        user_response = UserResponse(**user_dict)
        return user_response.model_dump()
    except Exception as e:
        print(f"Error converting user to response: {str(e)}")
        raise HTTPException(status_code=500, detail="Error converting user to response")


def admin_required(func):
    """
    Flexible admin_required decorator that works with both sync and async functions.
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        # Extract current_user and db from kwargs
        current_user = kwargs.get('current_user')
        db = kwargs.get('db')
        
        if not current_user or not db:
            raise HTTPException(status_code=401, detail="Authentication required")
        
        # Check if user has admin or super_admin role using select()
        stmt = (
            select(UserRole)
            .join(Role)
            .where(
                and_(
                    UserRole.user_id == current_user.user_id,
                    UserRole.active.is_(True),
                    Role.role_name.in_(["admin", "super_admin"]),
                )
            )
        )
        admin_role = db.execute(stmt).scalar_one_or_none()

        if not admin_role:
            raise HTTPException(status_code=403, detail="Admin privileges required")
        
        # Call the function (sync or async)
        result = func(*args, **kwargs)
        return result

    @wraps(func)
    async def async_wrapper(*args, **kwargs):
        # Extract current_user and db from kwargs
        current_user = kwargs.get('current_user')
        db = kwargs.get('db')
        
        if not current_user or not db:
            raise HTTPException(status_code=401, detail="Authentication required")
        
        # Check if user has admin or super_admin role using select()
        stmt = (
            select(UserRole)
            .join(Role)
            .where(
                and_(
                    UserRole.user_id == current_user.user_id,
                    UserRole.active.is_(True),
                    Role.role_name.in_(["admin", "super_admin"]),
                )
            )
        )
        admin_role = db.execute(stmt).scalar_one_or_none()

        if not admin_role:
            raise HTTPException(status_code=403, detail="Admin privileges required")
        
        # Call the async function
        result = await func(*args, **kwargs)
        return result

    # Return the appropriate wrapper based on whether the function is async
    if inspect_module.iscoroutinefunction(func):
        return async_wrapper
    else:
        return wrapper


def admin_get_users(func):
    """
    Flexible admin_get_users decorator that works with both sync and async functions.
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        # Extract current_user and db from kwargs
        current_user = kwargs.get('current_user')
        db = kwargs.get('db')
        
        if not current_user or not db:
            raise HTTPException(status_code=401, detail="Authentication required")
        
        # Check if user has admin or super_admin role using select()
        stmt = (
            select(UserRole)
            .join(Role)
            .where(
                and_(
                    UserRole.user_id == current_user.user_id,
                    UserRole.active.is_(True),
                    Role.role_name.in_(["admin", "super_admin"]),
                )
            )
        )
        admin_role = db.execute(stmt).scalar_one_or_none()

        if not admin_role:
            raise HTTPException(status_code=403, detail="Admin privileges required")
        
        # Call the function (sync or async)
        result = func(*args, **kwargs)
        return result

    @wraps(func)
    async def async_wrapper(*args, **kwargs):
        # Extract current_user and db from kwargs
        current_user = kwargs.get('current_user')
        db = kwargs.get('db')
        
        if not current_user or not db:
            raise HTTPException(status_code=401, detail="Authentication required")
        
        # Check if user has admin or super_admin role using select()
        stmt = (
            select(UserRole)
            .join(Role)
            .where(
                and_(
                    UserRole.user_id == current_user.user_id,
                    UserRole.active.is_(True),
                    Role.role_name.in_(["admin", "super_admin"]),
                )
            )
        )
        admin_role = db.execute(stmt).scalar_one_or_none()

        if not admin_role:
            raise HTTPException(status_code=403, detail="Admin privileges required")
        
        # Call the async function
        result = await func(*args, **kwargs)
        return result

    # Return the appropriate wrapper based on whether the function is async
    if inspect_module.iscoroutinefunction(func):
        return async_wrapper
    else:
        return wrapper


def admin_get_users_without_password(func):
    """
    Flexible admin_get_users_without_password decorator that works with both sync and async functions.
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        # Extract current_user and db from kwargs
        current_user = kwargs.get('current_user')
        db = kwargs.get('db')
        
        if not current_user or not db:
            raise HTTPException(status_code=401, detail="Authentication required")
        
        # Check if user has admin or super_admin role using select()
        stmt = (
            select(UserRole)
            .join(Role)
            .where(
                and_(
                    UserRole.user_id == current_user.user_id,
                    UserRole.active.is_(True),
                    Role.role_name.in_(["admin", "super_admin"]),
                )
            )
        )
        admin_role = db.execute(stmt).scalar_one_or_none()

        if not admin_role:
            raise HTTPException(status_code=403, detail="Admin privileges required")
        
        # Call the function (sync or async)
        result = func(*args, **kwargs)
        return result

    @wraps(func)
    async def async_wrapper(*args, **kwargs):
        # Extract current_user and db from kwargs
        current_user = kwargs.get('current_user')
        db = kwargs.get('db')
        
        if not current_user or not db:
            raise HTTPException(status_code=401, detail="Authentication required")
        
        # Check if user has admin or super_admin role using select()
        stmt = (
            select(UserRole)
            .join(Role)
            .where(
                and_(
                    UserRole.user_id == current_user.user_id,
                    UserRole.active.is_(True),
                    Role.role_name.in_(["admin", "super_admin"]),
                )
            )
        )
        admin_role = db.execute(stmt).scalar_one_or_none()

        if not admin_role:
            raise HTTPException(status_code=403, detail="Admin privileges required")
        
        # Call the async function
        result = await func(*args, **kwargs)
        return result

    # Return the appropriate wrapper based on whether the function is async
    if inspect_module.iscoroutinefunction(func):
        return async_wrapper
    else:
        return wrapper
