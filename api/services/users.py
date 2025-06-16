import datetime
from typing import List, Optional
from uuid import UUID, uuid4
from functools import wraps

from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer, HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from sqlalchemy import text
import jwt
import os
from dotenv import load_dotenv

from db.models import (
    User, UserRole, Role, Permission, RolePermission,
    UserStatusAudit, UserAuthProvider, UserAuthMetadata
)
from db.database import get_db
from auth.auth import create_access_token, get_current_user

# Load environment variables
load_dotenv()

# JWT settings
JWT_SECRET_KEY = "your-secure-secret-key-123"  # Use a consistent secret key
JWT_ALGORITHM = "HS256"
JWT_ACCESS_TOKEN_EXPIRES_IN = datetime.timedelta(seconds=int(os.getenv("JWT_ACCESS_TOKEN_EXPIRES_IN", "86400")))  # 24 hours
JWT_REFRESH_TOKEN_EXPIRES_IN = datetime.timedelta(seconds=int(os.getenv("JWT_REFRESH_TOKEN_EXPIRES_IN", "2592000")))  # 30 days

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/login")
security = HTTPBearer(auto_error=False)


def get_user_by_email(db: Session, email: str) -> Optional[User]:
    return db.query(User).filter(User.email.ilike(email.strip())).first()

def get_user_by_username(db: Session, username: str) -> Optional[User]:
    return db.query(User).filter(User.username.ilike(username.strip())).first()

def get_user_by_id(db: Session, user_id: int) -> Optional[User]:
    return db.query(User).filter(User.user_id == user_id).first()

def get_user_by_uuid(db: Session, uuid: str) -> Optional[User]:
    return db.query(User).filter(User.uuid == uuid).first()

def get_user_roles(db: Session, user_id: int) -> List[str]:
    """Get list of active roles for a user."""
    try:
        print(f"\n=== Getting Roles for User {user_id} ===")
        user_roles = db.query(UserRole).filter(
            UserRole.user_id == user_id,
            UserRole.active == True
        ).all()
        role_names = [role.role.role_name for role in user_roles]
        print(f"Found roles: {role_names}")
        return role_names
    except Exception as e:
        print(f"Error getting user roles: {str(e)}")
        return []

def create_jwt_token(data: dict, expires_delta: datetime.timedelta = None) -> str:
    """Create a new JWT token with debug logging."""
    try:
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.datetime.utcnow() + expires_delta
        else:
            expire = datetime.datetime.utcnow() + JWT_ACCESS_TOKEN_EXPIRES_IN
        to_encode.update({"exp": expire})
        print(f"\n=== Token Creation Debug ===")
        print(f"Token payload: {to_encode}")
        print(f"Using secret key: {JWT_SECRET_KEY[:10]}...")  # Only show first 10 chars for security
        encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
        return encoded_jwt
    except Exception as e:
        print(f"Error creating token: {str(e)}")
        raise

def decode_jwt_token(token: str) -> dict:
    """Decode and validate JWT token with debug logging."""
    try:
        print(f"\n=== Token Decode Debug ===")
        print(f"Attempting to decode token: {token[:20]}...")
        print(f"Using secret key: {JWT_SECRET_KEY[:10]}...")  # Only show first 10 chars for security
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

def get_current_user(
    db: Session = Depends(get_db),
    token: str = Depends(oauth2_scheme)
) -> User:
    """Get the current authenticated user with debug logging."""
    try:
        print(f"\n=== User Authentication Debug ===")
        print(f"Received token: {token[:20]}...")
        
        payload = decode_jwt_token(token)
        print(f"Decoded payload: {payload}")
        
        user_id = payload.get("sub")
        if user_id is None:
            print("No user_id in token payload")
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")
        
        user = db.query(User).filter(User.user_id == user_id).first()
        if user is None:
            print(f"User not found for id: {user_id}")
            raise HTTPException(status_code=401, detail="User not found")
        
        # Check user roles
        user_roles = db.query(UserRole).filter(
            UserRole.user_id == user.user_id,
            UserRole.active == True
        ).all()
        role_names = [role.role.role_name for role in user_roles]
        print(f"User roles: {role_names}")
        
        if not user.activated:
            print(f"User {user_id} is not activated")
            raise HTTPException(status_code=401, detail="User is not activated")
        
        if user.status != 'ACTIVE':
            print(f"User {user_id} status is {user.status}")
            raise HTTPException(status_code=401, detail=f"User is {user.status}")
        
        print(f"Successfully authenticated user: {user.email}")
        return user
    except HTTPException as he:
        raise he
    except Exception as e:
        print(f"Unexpected error in get_current_user: {str(e)}")
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")

def get_current_user_optional(
    request: Request, 
    db: Session = Depends(get_db)
) -> Optional[User]:
    try:
        auth = request.headers.get("Authorization")
        if not auth:
            return None
        
        scheme, token = auth.split()
        if scheme.lower() != "bearer":
            return None
        
        return get_current_user(db, token)
    except Exception:
        return None

def has_role(allowed_roles: List[str]):
    def role_checker(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
        user_roles = db.query(UserRole).filter(
            UserRole.user_id == current_user.user_id,
            UserRole.active == True
        ).all()
        
        user_role_names = []
        for user_role in user_roles:
            role = db.query(Role).filter(Role.role_id == user_role.role_id).first()
            if role:
                user_role_names.append(role.role_name)
        
        if not any(role in allowed_roles for role in user_role_names):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You don't have permission to access this resource"
            )
        return current_user
    return role_checker

def has_permission(current_user: User, permission_feature: str, db: Session = None) -> bool:
    if not db:
        db = next(get_db())
    
    # Check role permissions
    user_roles = db.query(UserRole).filter(
        UserRole.user_id == current_user.user_id,
        UserRole.active == True
    ).all()
    
    for user_role in user_roles:
        permission = db.query(Permission).join(RolePermission).filter(
            RolePermission.role_id == user_role.role_id,
            Permission.feature == permission_feature,
            Permission.active == True
        ).first()
        
        if permission:
            return True
    
    return False

def log_user_status_change(
    db: Session,
    user_uuid: str,
    old_status: str,
    new_status: str,
    changed_by: str,
    reason: str,
    remarks: Optional[str] = None
):
    user = get_user_by_uuid(db, user_uuid)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
        
    audit = UserStatusAudit(
        user_id=user.user_id,
        old_status=old_status,
        new_status=new_status,
        changed_by=changed_by,
        reason=reason,
        remarks=remarks,
        changed_at=datetime.datetime.utcnow()
    )
    db.add(audit)
    db.commit()
    return audit

def get_user_auth_provider(
    db: Session,
    user_uuid: str,
    provider: str
) -> Optional[UserAuthProvider]:
    user = get_user_by_uuid(db, user_uuid)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
        
    return db.query(UserAuthProvider).filter(
        UserAuthProvider.user_id == user.user_id,
        UserAuthProvider.provider == provider
    ).first()

def get_user_auth_metadata(
    db: Session,
    user_uuid: str,
    provider: str
) -> Optional[UserAuthMetadata]:
    user = get_user_by_uuid(db, user_uuid)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
        
    return db.query(UserAuthMetadata).filter(
        UserAuthMetadata.user_id == user.user_id,
        UserAuthMetadata.provider == provider
    ).first()

def update_user_auth_metadata(
    db: Session,
    user_uuid: str,
    provider: str,
    access_token: str,
    refresh_token: Optional[str] = None,
    token_expires_at: Optional[datetime.datetime] = None
):
    user = get_user_by_uuid(db, user_uuid)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
        
    metadata = get_user_auth_metadata(db, user_uuid, provider)
    if metadata:
        metadata.access_token = access_token
        metadata.refresh_token = refresh_token
        metadata.token_expires_at = token_expires_at
    else:
        metadata = UserAuthMetadata(
            user_id=user.user_id,
            provider=provider,
            external_user_id=user_uuid,  # Using UUID instead of user_id
            access_token=access_token,
            refresh_token=refresh_token,
            token_expires_at=token_expires_at
        )
        db.add(metadata)
    
    db.commit()
    return metadata

def get_user_from_token(token: str, db: Session) -> Optional[User]:
    try:
        payload = decode_jwt_token(token)
        user_uuid = payload.get("user_uuid")
        if user_uuid is None:
            return None
        
        user = get_user_by_uuid(db, user_uuid)
        if user is None or not user.activated or user.status != 'ACTIVE':
            return None
        
        return user
    except jwt.PyJWTError:
        return None

def role_required(required_roles: List[str]):
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, current_user: User = Depends(get_current_user), db: Session = Depends(get_db), **kwargs):
            print(f"\n=== Role Check Debug Information ===")
            print(f"Required roles: {required_roles}")
            
            # Get user's active roles
            user_roles = db.query(UserRole).filter(
                UserRole.user_id == current_user.user_id,
                UserRole.active == True
            ).all()
            
            role_names = [role.role.role_name for role in user_roles]
            print(f"User's roles: {role_names}")
            
            # Check if user has any of the required roles
            has_required_role = any(role.role.role_name in required_roles for role in user_roles)
            
            if not has_required_role:
                print(f"User does not have required roles. Required: {required_roles}, Has: {role_names}")
                raise HTTPException(
                    status_code=403,
                    detail=f"Access denied. Required roles: {', '.join(required_roles)}"
                )
            
            print(f"Role check passed for user {current_user.email}")
            return await func(*args, current_user=current_user, db=db, **kwargs)
        return wrapper
    return decorator

def user_to_response(user: User, db: Session) -> dict:
    """Convert a User model instance to a response dictionary"""
    # Get user roles
    user_roles = db.query(UserRole).filter(
        UserRole.user_id == user.user_id,
        UserRole.active == True
    ).all()
    roles = []
    for user_role in user_roles:
        role = db.query(Role).filter(Role.role_id == user_role.role_id).first()
        if role:
            roles.append(role.role_name)
    return {
        "user_id": user.user_id,
        "uuid": user.uuid,
        "username": user.username,
        "email": user.email,
        "first_name": user.first_name,
        "last_name": user.last_name,
        "profile_image": user.profile_image,
        "preferred_lang": user.preferred_lang,
        "timezone_id": user.timezone_id,
        "status": user.status,
        "is_2fa_enabled": user.is_2fa_enabled,
        "activated": user.activated,
        "roles": roles,
        "created_at": user.created_at.isoformat() if user.created_at else None,
        "updated_at": user.updated_at.isoformat() if user.updated_at else None,
        "last_login": user.last_login.isoformat() if user.last_login else None
    }

def admin_required(func):
    @wraps(func)
    async def wrapper(*args, current_user: User = Depends(get_current_user), db: Session = Depends(get_db), **kwargs):
        # Check if user has admin or super_admin role
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
        
        return await func(*args, current_user=current_user, db=db, **kwargs)
    return wrapper
